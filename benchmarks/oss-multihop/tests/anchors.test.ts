// Static safety, Docker Compose isolation verification, and offline external impact oracle
// unit tests across all 4 Dev OSS multi-hop anchors and 2 clean patched negative controls.
// Pure Node 24+ TypeScript, zero npm deps, zero Docker execution.

import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  CLEAN_CONTROLS_PATH,
  DEV_MANIFEST_PATH,
  assertLocalLabAllowed,
  containsForbiddenSecretPattern,
  isLoopbackBindSpec,
  isSyntheticCredentialRef,
  loadManifestBundle,
  validateExternalImpactOracle,
} from '../run.ts'
import type {
  CleanNegativeControlSpec,
  ComposeServiceRole,
  GuardianCompositeProofReceipt,
  OssAnchorManifest,
} from '../lib/types.ts'
import * as giteaOracle from '../anchors/gitea/oracle.ts'
import * as directusOracle from '../anchors/directus/oracle.ts'
import * as ghostOracle from '../anchors/ghost/oracle.ts'
import * as mattermostOracle from '../anchors/mattermost/oracle.ts'
import * as cleanVikunjaOracle from '../anchors/clean-vikunja/oracle.ts'
import * as cleanOutlineOracle from '../anchors/clean-outline/oracle.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const ANCHORS_DIR = join(ROOT, 'anchors')

const ALL_ANCHOR_DIRS = [
  'gitea',
  'directus',
  'ghost',
  'mattermost',
  'clean-vikunja',
  'clean-outline',
] as const

const PORT_ALLOWED_ROLES = new Set<ComposeServiceRole>(['app', 'lab_proxy'])
const FORBIDDEN_CAPS = new Set([
  'ALL',
  'NET_ADMIN',
  'NET_RAW',
  'SYS_ADMIN',
  'SYS_PTRACE',
  'SYS_MODULE',
  'DAC_OVERRIDE',
  'MKNOD',
])
const SECRET_ENV_KEY_RE = /(PASSWORD|PASSWD|SECRET|KEY|CRED|TOKEN)$/i
const EPHEMERAL_LOOPBACK_BIND_RE = /^127\.0\.0\.1:0:(\d{1,5})$/

interface ParsedComposeNetwork {
  driver?: string
  internal?: boolean
}

interface ParsedComposeService {
  image?: string
  networkMode?: string
  privileged?: boolean
  readOnly?: boolean
  ports: string[]
  networks: string[]
  capDrop: string[]
  capAdd: string[]
  securityOpt: string[]
  environment: Record<string, string>
}

interface ParsedComposeFile {
  networks: Record<string, ParsedComposeNetwork>
  services: Record<string, ParsedComposeService>
}

function unquoteYamlScalar(raw: string): string {
  const trimmed = raw.trim()
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

/**
 * Minimal deterministic YAML subset parser for `docker-compose.lab.yml` static safety checks.
 * Covers top-level `networks:` and `services:` blocks without external YAML dependencies.
 */
function parseLabComposeYaml(rawYaml: string): ParsedComposeFile {
  const result: ParsedComposeFile = { networks: {}, services: {} }
  const lines = rawYaml.split(/\r?\n/)

  let section: 'none' | 'networks' | 'services' = 'none'
  let currentNet: string | null = null
  let currentSvc: string | null = null
  let currentSvcListKey: 'ports' | 'networks' | 'cap_drop' | 'cap_add' | 'security_opt' | null = null
  let currentSvcMapKey: 'environment' | 'labels' | null = null

  for (const rawLine of lines) {
    const trimmed = rawLine.trim()
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue

    const indent = rawLine.length - rawLine.trimStart().length

    if (indent === 0) {
      currentNet = null
      currentSvc = null
      currentSvcListKey = null
      currentSvcMapKey = null
      if (trimmed === 'networks:') {
        section = 'networks'
      } else if (trimmed === 'services:') {
        section = 'services'
      } else {
        section = 'none'
      }
      continue
    }

    if (section === 'networks') {
      if (indent === 2 && trimmed.endsWith(':')) {
        currentNet = trimmed.slice(0, -1).trim()
        result.networks[currentNet] = {}
      } else if (indent === 4 && currentNet) {
        const sep = trimmed.indexOf(':')
        if (sep !== -1) {
          const key = trimmed.slice(0, sep).trim()
          const val = unquoteYamlScalar(trimmed.slice(sep + 1))
          if (key === 'driver') result.networks[currentNet].driver = val
          if (key === 'internal') result.networks[currentNet].internal = val === 'true'
        }
      }
      continue
    }

    if (section === 'services') {
      if (indent === 2 && trimmed.endsWith(':')) {
        currentSvc = trimmed.slice(0, -1).trim()
        currentSvcListKey = null
        currentSvcMapKey = null
        result.services[currentSvc] = {
          ports: [],
          networks: [],
          capDrop: [],
          capAdd: [],
          securityOpt: [],
          environment: {},
        }
        continue
      }

      if (!currentSvc) continue
      const svc = result.services[currentSvc]

      if (indent === 4) {
        currentSvcListKey = null
        currentSvcMapKey = null
        const sep = trimmed.indexOf(':')
        if (sep === -1) continue
        const key = trimmed.slice(0, sep).trim()
        const rawVal = trimmed.slice(sep + 1).trim()

        if (rawVal === '') {
          if (
            key === 'ports' ||
            key === 'networks' ||
            key === 'cap_drop' ||
            key === 'cap_add' ||
            key === 'security_opt'
          ) {
            currentSvcListKey = key
          } else if (key === 'environment' || key === 'labels') {
            currentSvcMapKey = key
          }
          continue
        }

        const val = unquoteYamlScalar(rawVal)
        if (key === 'image') svc.image = val
        else if (key === 'network_mode') svc.networkMode = val
        else if (key === 'privileged') svc.privileged = val === 'true'
        else if (key === 'read_only') svc.readOnly = val === 'true'
      } else if (indent === 6) {
        if (currentSvcListKey && trimmed.startsWith('- ')) {
          const item = unquoteYamlScalar(trimmed.slice(2))
          if (currentSvcListKey === 'ports') svc.ports.push(item)
          else if (currentSvcListKey === 'networks') svc.networks.push(item)
          else if (currentSvcListKey === 'cap_drop') svc.capDrop.push(item)
          else if (currentSvcListKey === 'cap_add') svc.capAdd.push(item)
          else if (currentSvcListKey === 'security_opt') svc.securityOpt.push(item)
        } else if (currentSvcMapKey === 'environment') {
          if (trimmed.startsWith('- ')) {
            const pair = unquoteYamlScalar(trimmed.slice(2))
            const eq = pair.indexOf('=')
            if (eq !== -1) {
              svc.environment[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim()
            }
          } else {
            const sep = trimmed.indexOf(':')
            if (sep !== -1) {
              const key = trimmed.slice(0, sep).trim()
              const val = unquoteYamlScalar(trimmed.slice(sep + 1))
              svc.environment[key] = val
            }
          }
        }
      }
    }
  }

  return result
}

function validateLabComposeStaticSafety(
  rawYaml: string,
  expectedRoles: ReadonlyMap<string, ComposeServiceRole>,
): string[] {
  const issues: string[] = []
  const parsed = parseLabComposeYaml(rawYaml)

  if (/\bprivileged\s*:\s*true\b/i.test(rawYaml)) {
    issues.push('PRIVILEGED_TRUE_FORBIDDEN')
  }
  if (/\bnetwork_mode\s*:\s*['"]?(host|bridge|container:)/i.test(rawYaml)) {
    issues.push('FORBIDDEN_NETWORK_MODE')
  }
  if (/:latest\b/i.test(rawYaml)) {
    issues.push('FLOATING_LATEST_TAG_FORBIDDEN')
  }
  if (containsForbiddenSecretPattern(rawYaml)) {
    issues.push('REAL_SECRET_PATTERN_DETECTED')
  }

  const netNames = Object.keys(parsed.networks)
  if (!parsed.networks.lab_internal) {
    issues.push('MISSING_LAB_INTERNAL_NETWORK')
  }
  for (const netName of netNames) {
    const net = parsed.networks[netName]
    if (net.internal !== true) {
      issues.push(`NON_INTERNAL_NETWORK:${netName}`)
    }
    if (net.driver !== 'bridge') {
      issues.push(`INVALID_NETWORK_DRIVER:${netName}`)
    }
  }

  const svcNames = Object.keys(parsed.services)
  if (svcNames.length === 0) {
    issues.push('NO_SERVICES_DEFINED')
  }

  let hasParameterizedApp = false
  for (const svcName of svcNames) {
    const svc = parsed.services[svcName]
    const role = expectedRoles.get(svcName)

    if (svc.privileged === true) {
      issues.push(`PRIVILEGED_SERVICE:${svcName}`)
    }
    if (svc.networkMode !== undefined) {
      issues.push(`NETWORK_MODE_SET:${svcName}`)
    }
    if (!svc.image || svc.image.trim().length === 0) {
      issues.push(`MISSING_IMAGE:${svcName}`)
    } else if (svc.image.includes('${APP_IMAGE:-') && svc.image.includes('${APP_TAG:-')) {
      hasParameterizedApp = true
    }

    if (svc.networks.length === 0) {
      issues.push(`UNATTACHED_SERVICE:${svcName}`)
    }
    for (const netRef of svc.networks) {
      const net = parsed.networks[netRef]
      if (!net || net.internal !== true) {
        issues.push(`NON_INTERNAL_SERVICE_NET:${svcName}:${netRef}`)
      }
    }

    if (!svc.capDrop.some((c) => c.toUpperCase() === 'ALL')) {
      issues.push(`MISSING_CAP_DROP_ALL:${svcName}`)
    }
    for (const cap of svc.capAdd) {
      if (FORBIDDEN_CAPS.has(cap.toUpperCase())) {
        issues.push(`FORBIDDEN_CAP_ADD:${svcName}:${cap}`)
      }
    }

    if (svc.ports.length > 0) {
      if (role && !PORT_ALLOWED_ROLES.has(role)) {
        issues.push(`INTERNAL_SERVICE_PORT_EXPOSED:${svcName}`)
      }
      for (const bind of svc.ports) {
        if (!isLoopbackBindSpec(bind) || !EPHEMERAL_LOOPBACK_BIND_RE.test(bind)) {
          issues.push(`NON_LOOPBACK_OR_STATIC_PORT:${svcName}:${bind}`)
        }
      }
    }

    for (const [envKey, envVal] of Object.entries(svc.environment)) {
      if (containsForbiddenSecretPattern(envVal)) {
        issues.push(`REAL_SECRET_ENV:${svcName}:${envKey}`)
      }
      if (SECRET_ENV_KEY_RE.test(envKey) && !isSyntheticCredentialRef(envVal)) {
        issues.push(`NON_SYNTHETIC_SECRET_ENV:${svcName}:${envKey}`)
      }
    }
  }

  if (!hasParameterizedApp) {
    issues.push('MISSING_PARAMETERIZED_APP_IMAGE_TAG')
  }

  return issues
}

function makeSyntheticCleanControlReceipt(controlId: string, runId: string): GuardianCompositeProofReceipt {
  return {
    receiptId: `rcpt_fp_${controlId}`,
    chainId: `chain_fp_${controlId}`,
    targetId: controlId,
    terminalVulnClass: 'cross_tenant_rbac_privilege_escalation',
    verified: true,
    attackerOriginVerified: true,
    originPersona: 'clean_origin',
    replayMode: 'fresh_clean_replay',
    hops: [
      {
        hopId: 'H1',
        order: 1,
        surface: 'http',
        actorPersona: 'clean_origin',
        observedAtMs: 1_732_500_000_000,
        exchangeIds: ['ex_1'],
      },
    ],
    causalEdges: [],
    terminalImpact: {
      observed: true,
      observedAtMs: 1_732_500_001_000,
    },
    runId,
  }
}

test('all 6 anchor harness directories exist with docker-compose.lab.yml, oracle.ts, and README.md', () => {
  assertLocalLabAllowed()

  for (const dir of ALL_ANCHOR_DIRS) {
    const base = join(ANCHORS_DIR, dir)
    assert.equal(existsSync(join(base, 'docker-compose.lab.yml')), true, `Missing docker-compose.lab.yml in ${dir}`)
    assert.equal(existsSync(join(base, 'oracle.ts')), true, `Missing oracle.ts in ${dir}`)
    assert.equal(existsSync(join(base, 'README.md')), true, `Missing README.md in ${dir}`)
  }
})

test('all 6 docker-compose.lab.yml files enforce --internal isolation, loopback-only binds, synthetic secrets, and manifest parity', () => {
  const devBundle = loadManifestBundle(DEV_MANIFEST_PATH)
  const cleanBundle = loadManifestBundle(CLEAN_CONTROLS_PATH)
  const anchors = devBundle.anchors ?? []
  const controls = cleanBundle.cleanControls ?? []

  const targets: Array<{
    dir: (typeof ALL_ANCHOR_DIRS)[number]
    manifest: OssAnchorManifest | CleanNegativeControlSpec
    expectedImageRef: string
  }> = [
    {
      dir: 'gitea',
      manifest: anchors.find((a) => a.project === 'gitea')!,
      expectedImageRef: anchors.find((a) => a.project === 'gitea')!.vulnerableBuild.imageRef,
    },
    {
      dir: 'directus',
      manifest: anchors.find((a) => a.project === 'directus')!,
      expectedImageRef: anchors.find((a) => a.project === 'directus')!.vulnerableBuild.imageRef,
    },
    {
      dir: 'ghost',
      manifest: anchors.find((a) => a.project === 'ghost')!,
      expectedImageRef: anchors.find((a) => a.project === 'ghost')!.vulnerableBuild.imageRef,
    },
    {
      dir: 'mattermost',
      manifest: anchors.find((a) => a.project === 'mattermost')!,
      expectedImageRef: anchors.find((a) => a.project === 'mattermost')!.vulnerableBuild.imageRef,
    },
    {
      dir: 'clean-vikunja',
      manifest: controls.find((c) => c.project === 'vikunja')!,
      expectedImageRef: controls.find((c) => c.project === 'vikunja')!.patchedBuild.imageRef,
    },
    {
      dir: 'clean-outline',
      manifest: controls.find((c) => c.project === 'outline')!,
      expectedImageRef: controls.find((c) => c.project === 'outline')!.patchedBuild.imageRef,
    },
  ]

  for (const target of targets) {
    const composePath = join(ANCHORS_DIR, target.dir, 'docker-compose.lab.yml')
    const rawYaml = readFileSync(composePath, 'utf8')
    const roleMap = new Map<string, ComposeServiceRole>()
    for (const [svcName, svcSpec] of Object.entries(target.manifest.composeTemplate.services)) {
      roleMap.set(svcName, svcSpec.role)
    }

    const issues = validateLabComposeStaticSafety(rawYaml, roleMap)
    assert.deepEqual(issues, [], `Compose safety issues in ${target.dir}/docker-compose.lab.yml: ${issues.join(', ')}`)

    const parsed = parseLabComposeYaml(rawYaml)
    assert.deepEqual(
      Object.keys(parsed.services).sort(),
      Object.keys(target.manifest.composeTemplate.services).sort(),
      `Service names mismatch between ${target.dir}/docker-compose.lab.yml and manifest`,
    )

    // Verify parameterized APP_IMAGE/APP_TAG defaults match manifest imageRef
    const [expectedRepo, expectedTag] = target.expectedImageRef.split(':')
    const appSvcEntry = Object.entries(target.manifest.composeTemplate.services).find(
      ([, spec]) => spec.role === 'app',
    )!
    const parsedAppSvc = parsed.services[appSvcEntry[0]]
    assert.equal(
      parsedAppSvc.image,
      `\${APP_IMAGE:-${expectedRepo}}:\${APP_TAG:-${expectedTag}}`,
      `Expected parameterized APP_IMAGE/APP_TAG default in ${target.dir}`,
    )

    // Verify exact port parity with manifest (loopback ephemeral on entry service, zero on internal services)
    for (const [svcName, spec] of Object.entries(target.manifest.composeTemplate.services)) {
      const parsedSvc = parsed.services[svcName]
      assert.deepEqual(
        parsedSvc.ports,
        spec.ports ?? [],
        `Port publication mismatch for ${target.dir}/${svcName}`,
      )
    }
  }
})

test('compose static safety verifier rejects non-internal networks, host networking, privileged mode, public ports, and real secrets', () => {
  const giteaYaml = readFileSync(join(ANCHORS_DIR, 'gitea', 'docker-compose.lab.yml'), 'utf8')
  const roles = new Map<string, ComposeServiceRole>([
    ['gitea_app', 'app'],
    ['gitea_db', 'db'],
    ['internal_runner_meta', 'internal_target'],
  ])

  assert.ok(
    validateLabComposeStaticSafety(giteaYaml.replace('internal: true', 'internal: false'), roles).some(
      (i) => i.startsWith('NON_INTERNAL_NETWORK'),
    ),
  )
  assert.ok(
    validateLabComposeStaticSafety(
      giteaYaml.replace('    networks:\n      - lab_internal', '    network_mode: "host"\n    networks:\n      - lab_internal'),
      roles,
    ).includes('FORBIDDEN_NETWORK_MODE'),
  )
  assert.ok(
    validateLabComposeStaticSafety(
      giteaYaml.replace('    cap_drop:', '    privileged: true\n    cap_drop:'),
      roles,
    ).includes('PRIVILEGED_TRUE_FORBIDDEN'),
  )
  assert.ok(
    validateLabComposeStaticSafety(giteaYaml.replace('127.0.0.1:0:3000', '0.0.0.0:3000:3000'), roles).some(
      (i) => i.startsWith('NON_LOOPBACK_OR_STATIC_PORT'),
    ),
  )
  assert.ok(
    validateLabComposeStaticSafety(giteaYaml.replace('127.0.0.1:0:3000', '3000:3000'), roles).some(
      (i) => i.startsWith('NON_LOOPBACK_OR_STATIC_PORT'),
    ),
  )
  assert.ok(
    validateLabComposeStaticSafety(
      giteaYaml.replace('  gitea_db:\n    image: "postgres:16.4-alpine"', '  gitea_db:\n    image: "postgres:16.4-alpine"\n    ports:\n      - "127.0.0.1:0:5432"'),
      roles,
    ).includes('INTERNAL_SERVICE_PORT_EXPOSED:gitea_db'),
  )
  const syntheticTokenSample = `${'ghp'}_${'A'.repeat(24)}`
  assert.ok(
    validateLabComposeStaticSafety(
      giteaYaml.replace('oss_lab_gitea_secret_01', syntheticTokenSample),
      roles,
    ).includes('REAL_SECRET_PATTERN_DETECTED'),
  )
  assert.ok(
    validateLabComposeStaticSafety(giteaYaml.replace('postgres:16.4-alpine', 'postgres:latest'), roles).includes(
      'FLOATING_LATEST_TAG_FORBIDDEN',
    ),
  )
})

test('gitea oracle.ts evaluates loopback_oob_collector positive, hardened silence, and paired builds', () => {
  const serviceNames = new Set(Object.keys(giteaOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(giteaOracle.ORACLE_SPEC, 'gitea', serviceNames), [])
  assert.doesNotThrow(() => giteaOracle.assertLoopbackCollectorUrl())
  assert.equal(giteaOracle.isRunScopedCanary('oss_canary_gitea_run1'), true)
  assert.equal(giteaOracle.isRunScopedCanary('wrong_prefix_1'), false)

  const ts = 1_732_500_000_000
  const paired = giteaOracle.evaluatePairedBuilds({
    runId: 'run_gitea_unit_01',
    vulnerableEvidence: {
      observedAtMs: ts,
      correlationId: 'corr-gitea-1',
      requests: [
        {
          method: 'POST',
          path: '/oob/gitea/pivot',
          canaryToken: 'oss_canary_gitea_abc123',
          correlationId: 'corr-gitea-1',
          receivedAtMs: ts,
        },
      ],
    },
    patchedEvidence: {
      observedAtMs: ts + 5_000,
      correlationId: 'corr-gitea-1',
      requests: [
        {
          method: 'GET',
          path: '/oob/gitea/pivot',
          canaryToken: 'oss_canary_gitea_abc123',
          receivedAtMs: ts + 5_000,
        },
      ],
    },
  })

  assert.equal(paired.impactConfirmedOnVulnerable, true)
  assert.equal(paired.impactEliminatedOnPatched, true)
  assert.equal(paired.vulnerableObservation.observed, true)
  assert.equal(paired.vulnerableObservation.correlationId, 'corr-gitea-1')
  assert.equal(paired.patchedObservation.observed, false)
  assert.deepEqual(paired.expectedPatchBrokeHopIds, ['H2'])

  // Missing canary token must stay silent
  const noCanary = giteaOracle.evaluateGiteaOracle('run_gitea_unit_01', 'patched', {
    observedAtMs: ts,
    requests: [{ method: 'POST', path: '/oob/gitea/pivot', receivedAtMs: ts }],
  })
  assert.equal(noCanary.observed, false)
})

test('directus oracle.ts evaluates read-only db_query positive, hardened silence, and paired builds', () => {
  const serviceNames = new Set(Object.keys(directusOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(directusOracle.ORACLE_SPEC, 'directus', serviceNames), [])
  assert.ok(directusOracle.getReadOnlyAuditQuery().startsWith('SELECT '))
  assert.equal(directusOracle.isRunScopedCanary('oss_canary_directus_run1'), true)

  const ts = 1_732_500_010_000
  const paired = directusOracle.evaluatePairedBuilds({
    runId: 'run_directus_unit_01',
    vulnerableEvidence: {
      observedAtMs: ts,
      correlationId: 'corr-directus-1',
      rows: [{ id: 101, role_name: 'tenant_a_admin', canary_marker: 'oss_canary_directus_42' }],
    },
    patchedEvidence: {
      observedAtMs: ts + 5_000,
      correlationId: 'corr-directus-1',
      rows: [{ id: 102, role_name: 'editor', canary_marker: 'benign_audit_row' }],
    },
  })

  assert.equal(paired.impactConfirmedOnVulnerable, true)
  assert.equal(paired.impactEliminatedOnPatched, true)
  assert.equal(paired.vulnerableObservation.matchedRows, 1)
  assert.equal(paired.patchedObservation.matchedRows, 0)
  assert.deepEqual(paired.expectedPatchBrokeHopIds, ['H2', 'H3'])
})

test('ghost oracle.ts evaluates file_integrity positive, readAuditMarkerEvidence, hardened silence, and paired builds', () => {
  const serviceNames = new Set(Object.keys(ghostOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(ghostOracle.ORACLE_SPEC, 'ghost', serviceNames), [])
  assert.equal(ghostOracle.isRunScopedCanary('oss_canary_ghost_run1'), true)

  const ts = 1_732_500_020_000
  const tmpDir = mkdtempSync(join(tmpdir(), 'oss-ghost-oracle-'))
  try {
    const markerFile = join(tmpDir, 'audit-marker.txt')
    const missingFile = join(tmpDir, 'absent-marker.txt')
    writeFileSync(markerFile, 'export_audit=oss_canary_ghost_777\n', 'utf8')

    const vulnEvidence = ghostOracle.readAuditMarkerEvidence(markerFile, ts, 'corr-ghost-1')
    const patchedEvidence = ghostOracle.readAuditMarkerEvidence(missingFile, ts + 5_000, 'corr-ghost-1')

    assert.equal(vulnEvidence.exists, true)
    assert.equal(typeof vulnEvidence.sha256, 'string')
    assert.equal(patchedEvidence.exists, false)

    const paired = ghostOracle.evaluatePairedBuilds({
      runId: 'run_ghost_unit_01',
      vulnerableEvidence: vulnEvidence,
      patchedEvidence,
    })

    assert.equal(paired.impactConfirmedOnVulnerable, true)
    assert.equal(paired.impactEliminatedOnPatched, true)
    assert.equal(paired.vulnerableObservation.observed, true)
    assert.equal(paired.patchedObservation.observed, false)
    assert.deepEqual(paired.expectedPatchBrokeHopIds, ['H2'])

    // Benign file content without run-scoped canary must remain silent
    const benignObs = ghostOracle.evaluateGhostOracle('run_ghost_unit_01', 'patched', {
      exists: true,
      contentPreview: 'routine_export=clean_no_canary',
      observedAtMs: ts + 6_000,
    })
    assert.equal(benignObs.observed, false)
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
})

test('mattermost oracle.ts evaluates container_log positive, forbidPattern denial suppression, and paired builds', () => {
  const serviceNames = new Set(Object.keys(mattermostOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(mattermostOracle.ORACLE_SPEC, 'mattermost', serviceNames), [])
  assert.equal(mattermostOracle.isRunScopedCanary('oss_canary_mm_run1'), true)

  const ts = 1_732_500_030_000
  const paired = mattermostOracle.evaluatePairedBuilds({
    runId: 'run_mm_unit_01',
    vulnerableEvidence: {
      observedAtMs: ts,
      correlationId: 'corr-mm-1',
      lines: [
        { stream: 'stdout', text: 'level=info msg=startup_ready', timestampMs: ts - 1000 },
        {
          stream: 'stdout',
          text: 'level=info audit_event=compliance_export_complete run_canary=oss_canary_mm_99',
          timestampMs: ts,
        },
      ],
    },
    patchedEvidence: {
      observedAtMs: ts + 5_000,
      correlationId: 'corr-mm-1',
      lines: [
        {
          stream: 'stdout',
          text: 'level=warn audit_event=compliance_export_denied run_canary=oss_canary_mm_99',
          timestampMs: ts + 5_000,
        },
      ],
    },
  })

  assert.equal(paired.impactConfirmedOnVulnerable, true)
  assert.equal(paired.impactEliminatedOnPatched, true)
  assert.equal(paired.vulnerableObservation.observed, true)
  assert.equal(paired.patchedObservation.observed, false)
  assert.deepEqual(paired.expectedPatchBrokeHopIds, ['H2'])

  // stderr-only line must not match stdout-scoped oracle
  const stderrOnly = mattermostOracle.evaluateMattermostOracle('run_mm_unit_01', 'patched', {
    observedAtMs: ts + 6_000,
    lines: [
      {
        stream: 'stderr',
        text: 'audit_event=compliance_export_complete run_canary=oss_canary_mm_99',
        timestampMs: ts + 6_000,
      },
    ],
  })
  assert.equal(stderrOnly.observed, false)
})

test('clean-vikunja and clean-outline oracle.ts enforce hard 0-FP clean negative-control assertions', () => {
  const ts = 1_732_500_040_000
  const runId = 'run_clean_controls_01'

  // Vikunja: clean silence + 0 receipts -> PASS
  const vikClean = cleanVikunjaOracle.assertVikunjaZeroFalsePositives(runId, [], {
    observedAtMs: ts,
    rows: [],
  })
  assert.equal(vikClean.passed, true)
  assert.equal(vikClean.observation.observed, false)
  assert.equal(vikClean.grade.fpCount, 0)
  assert.equal(vikClean.grade.unexpectedOracleTriggers, 0)

  // Vikunja: unexpected DB row -> FAIL
  const vikOracleTrigger = cleanVikunjaOracle.assertVikunjaZeroFalsePositives(runId, [], {
    observedAtMs: ts,
    rows: [{ id: 7, owner_id: 2 }],
  })
  assert.equal(vikOracleTrigger.passed, false)
  assert.equal(vikOracleTrigger.observation.observed, true)
  assert.equal(vikOracleTrigger.grade.unexpectedOracleTriggers, 1)

  // Vikunja: any receipt emitted -> FAIL 0-FP gate
  const vikFp = cleanVikunjaOracle.assertVikunjaZeroFalsePositives(
    runId,
    [makeSyntheticCleanControlReceipt(cleanVikunjaOracle.CONTROL_ID, runId)],
    { observedAtMs: ts, rows: [] },
  )
  assert.equal(vikFp.passed, false)
  assert.equal(vikFp.grade.fpCount, 1)

  // Outline: clean silence + 0 receipts -> PASS
  const outClean = cleanOutlineOracle.assertOutlineZeroFalsePositives(runId, [], {
    observedAtMs: ts,
    lines: [{ stream: 'stdout', text: 'level=info audit_event=collection_read_denied', timestampMs: ts }],
  })
  assert.equal(outClean.passed, true)
  assert.equal(outClean.observation.observed, false)
  assert.equal(outClean.grade.fpCount, 0)
  assert.equal(outClean.grade.unexpectedOracleTriggers, 0)

  // Outline: unexpected log event -> FAIL
  const outOracleTrigger = cleanOutlineOracle.assertOutlineZeroFalsePositives(runId, [], {
    observedAtMs: ts,
    lines: [
      {
        stream: 'stdout',
        text: 'level=warn audit_event=unauthorized_export canary=oss_canary_clean_outline_1',
        timestampMs: ts,
      },
    ],
  })
  assert.equal(outOracleTrigger.passed, false)
  assert.equal(outOracleTrigger.observation.observed, true)
  assert.equal(outOracleTrigger.grade.unexpectedOracleTriggers, 1)

  // Outline: any receipt emitted -> FAIL 0-FP gate
  const outFp = cleanOutlineOracle.assertOutlineZeroFalsePositives(
    runId,
    [makeSyntheticCleanControlReceipt(cleanOutlineOracle.CONTROL_ID, runId)],
    { observedAtMs: ts, lines: [] },
  )
  assert.equal(outFp.passed, false)
  assert.equal(outFp.grade.fpCount, 1)
})

test('all 6 anchor READMEs document setup, personas, external oracle signal, and patchBrokeHopId / 0-FP gate', () => {
  const devIds = [
    { dir: 'gitea', oracleId: giteaOracle.ORACLE_SPEC.oracleId },
    { dir: 'directus', oracleId: directusOracle.ORACLE_SPEC.oracleId },
    { dir: 'ghost', oracleId: ghostOracle.ORACLE_SPEC.oracleId },
    { dir: 'mattermost', oracleId: mattermostOracle.ORACLE_SPEC.oracleId },
  ]
  for (const item of devIds) {
    const readme = readFileSync(join(ANCHORS_DIR, item.dir, 'README.md'), 'utf8')
    assert.ok(readme.includes('docker-compose.lab.yml'), `${item.dir}/README.md missing compose reference`)
    assert.ok(readme.includes('APP_IMAGE') && readme.includes('APP_TAG'), `${item.dir}/README.md missing APP_IMAGE/APP_TAG`)
    assert.ok(readme.includes(item.oracleId), `${item.dir}/README.md missing oracleId`)
    assert.ok(readme.includes('patchBrokeHopId'), `${item.dir}/README.md missing patchBrokeHopId`)
  }

  const cleanIds = [
    { dir: 'clean-vikunja', oracleId: cleanVikunjaOracle.ORACLE_SPEC.oracleId },
    { dir: 'clean-outline', oracleId: cleanOutlineOracle.ORACLE_SPEC.oracleId },
  ]
  for (const item of cleanIds) {
    const readme = readFileSync(join(ANCHORS_DIR, item.dir, 'README.md'), 'utf8')
    assert.ok(readme.includes('docker-compose.lab.yml'), `${item.dir}/README.md missing compose reference`)
    assert.ok(readme.includes('APP_IMAGE') && readme.includes('APP_TAG'), `${item.dir}/README.md missing APP_IMAGE/APP_TAG`)
    assert.ok(readme.includes(item.oracleId), `${item.dir}/README.md missing oracleId`)
    assert.ok(readme.includes('maxAllowedFindings: 0'), `${item.dir}/README.md missing 0-FP requirement`)
  }
})
