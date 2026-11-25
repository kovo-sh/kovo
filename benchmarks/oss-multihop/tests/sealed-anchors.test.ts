// Offline/Docker-free contract, schema, --internal network isolation, vulnerable-vs-patched
// compose parity, and external impact oracle tests for the 4 M4 Sealed OSS Multi-Hop Anchors
// (keycloak, woodpecker, metabase, saleor).
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
  SEALED_EXAMPLE_PATH,
  assertLocalLabAllowed,
  containsForbiddenSecretPattern,
  gradeOssRun,
  isLoopbackBindSpec,
  isPinnedCommitSha,
  isPinnedImageDigest,
  isSyntheticCredentialRef,
  loadManifestBundle,
  validateExternalImpactOracle,
  validateManifestBundle,
} from '../run.ts'
import type {
  ComposeServiceRole,
  ExternalOracleObservation,
  KovoCompositeProofReceipt,
  OssAnchorManifest,
  PatchRetestRecord,
  RunTelemetry,
} from '../lib/types.ts'
import * as keycloakOracle from '../anchors/keycloak/oracle.ts'
import * as woodpeckerOracle from '../anchors/woodpecker/oracle.ts'
import * as metabaseOracle from '../anchors/metabase/oracle.ts'
import * as saleorOracle from '../anchors/saleor/oracle.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const ANCHORS_DIR = join(ROOT, 'anchors')
const SEALED_MANIFEST_PATH = join(ROOT, 'manifests', 'sealed-anchors.json')

const SEALED_ANCHOR_DIRS = ['keycloak', 'woodpecker', 'metabase', 'saleor'] as const

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

function resolveComposeImage(template: string, vars: Record<string, string>): string {
  return template.replace(/\$\{([A-Z0-9_]+):-([^}]+)\}/g, (_m, name: string, fallback: string) => {
    return vars[name] ?? fallback
  })
}

function validateSealedComposeStaticSafety(
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
    if (!svc.securityOpt.includes('no-new-privileges:true')) {
      issues.push(`MISSING_NO_NEW_PRIVILEGES:${svcName}`)
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

function splitImageRef(ref: string): [string, string] {
  const idx = ref.lastIndexOf(':')
  assert.ok(idx > 0, `Expected versioned imageRef '<repo>:<tag>', got '${ref}'`)
  return [ref.slice(0, idx), ref.slice(idx + 1)]
}

function makeValidReceipt(
  anchor: OssAnchorManifest,
  runId: string,
  baseTs: number,
  correlationId: string,
): KovoCompositeProofReceipt {
  const origin = anchor.personas.find((p) => p.allowedAsChainOrigin)!
  return {
    receiptId: `rcpt_${anchor.anchorId}`,
    chainId: `chain_${anchor.anchorId}`,
    targetId: anchor.anchorId,
    terminalVulnClass: anchor.terminalVulnClass,
    verified: true,
    attackerOriginVerified: true,
    originPersona: origin.personaId,
    replayMode: 'fresh_clean_replay',
    hops: anchor.hops.map((h, idx) => ({
      hopId: h.hopId,
      order: h.order,
      surface: h.surface,
      actorPersona: origin.personaId,
      observedAtMs: baseTs + idx * 1000,
      exchangeIds: [`ex_${anchor.anchorId}_${h.hopId}`],
    })),
    causalEdges: anchor.hops.slice(1).map((h, idx) => ({
      fromHopId: anchor.hops[idx].hopId,
      toHopId: h.hopId,
      bindingKind: h.incomingEdgeKind ?? 'value_binding',
      verified: true,
    })),
    terminalImpact: {
      observed: true,
      oracleId: anchor.impactOracle.oracleId,
      correlationId,
      observedAtMs: baseTs + 5_000,
    },
    runId,
  }
}

test('all 4 sealed anchor directories exist with docker-compose.lab.yml, oracle.ts, and README.md', () => {
  assertLocalLabAllowed()

  assert.equal(existsSync(SEALED_MANIFEST_PATH), true, 'Missing manifests/sealed-anchors.json')
  for (const dir of SEALED_ANCHOR_DIRS) {
    const base = join(ANCHORS_DIR, dir)
    assert.equal(existsSync(join(base, 'docker-compose.lab.yml')), true, `Missing docker-compose.lab.yml in ${dir}`)
    assert.equal(existsSync(join(base, 'oracle.ts')), true, `Missing oracle.ts in ${dir}`)
    assert.equal(existsSync(join(base, 'README.md')), true, `Missing README.md in ${dir}`)
  }
})

test('manifests/sealed-anchors.json passes strict schema validation, pinned versions, and dev-split separation', () => {
  const sealedBundle = loadManifestBundle(SEALED_MANIFEST_PATH)
  const validation = validateManifestBundle(sealedBundle)
  assert.equal(validation.valid, true, `Sealed manifest validation issues: ${JSON.stringify(validation.issues)}`)
  assert.equal(sealedBundle.bundleKind, 'sealed_anchors')

  const anchors = sealedBundle.anchors ?? []
  assert.equal(anchors.length, 4)
  assert.deepEqual(
    anchors.map((a) => a.project),
    ['keycloak', 'woodpecker', 'metabase', 'saleor'],
  )

  // Every sealed anchor must cover 3-4 hops, split='sealed', distinct pinned vulnerable/patched builds
  const oracleKinds = new Set<string>()
  const commitShas = new Set<string>()
  const digests = new Set<string>()

  for (const anchor of anchors) {
    assert.equal(anchor.split, 'sealed')
    assert.ok(anchor.hopCount >= 3 && anchor.hopCount <= 4, `${anchor.anchorId} hopCount must be 3..4`)
    assert.equal(anchor.hops.length, anchor.hopCount)
    assert.equal(isPinnedCommitSha(anchor.vulnerableBuild.commitSha), true)
    assert.equal(isPinnedCommitSha(anchor.patchedBuild.commitSha), true)
    assert.notEqual(anchor.vulnerableBuild.commitSha, anchor.patchedBuild.commitSha)
    assert.equal(isPinnedImageDigest(anchor.vulnerableBuild.imageDigest), true)
    assert.equal(isPinnedImageDigest(anchor.patchedBuild.imageDigest), true)
    assert.notEqual(anchor.vulnerableBuild.imageDigest, anchor.patchedBuild.imageDigest)
    assert.notEqual(anchor.vulnerableBuild.versionTag, anchor.patchedBuild.versionTag)
    assert.ok(anchor.expectedPatchBrokeHopIds.length >= 1)
    assert.ok(anchor.personas.some((p) => p.allowedAsChainOrigin))
    assert.ok(anchor.personas.some((p) => !p.allowedAsChainOrigin))

    oracleKinds.add(anchor.impactOracle.kind)
    commitShas.add(anchor.vulnerableBuild.commitSha)
    commitShas.add(anchor.patchedBuild.commitSha)
    digests.add(anchor.vulnerableBuild.imageDigest)
    digests.add(anchor.patchedBuild.imageDigest)
  }

  assert.deepEqual(
    [...oracleKinds].sort(),
    ['container_log', 'db_query', 'file_integrity', 'loopback_oob_collector'],
  )
  assert.equal(commitShas.size, 8, 'All vulnerable and patched commit SHAs across sealed anchors must be distinct')
  assert.equal(digests.size, 8, 'All vulnerable and patched image digests across sealed anchors must be distinct')

  // Verify dev-anchors.json and sealed-manifest.example.json remain isolated and untouched
  const devBundle = loadManifestBundle(DEV_MANIFEST_PATH)
  const devIds = new Set((devBundle.anchors ?? []).map((a) => a.anchorId))
  const devCommits = new Set(
    (devBundle.anchors ?? []).flatMap((a) => [a.vulnerableBuild.commitSha, a.patchedBuild.commitSha]),
  )
  for (const anchor of anchors) {
    assert.equal(devIds.has(anchor.anchorId), false, `Sealed anchorId '${anchor.anchorId}' collides with dev`)
    assert.equal(devCommits.has(anchor.vulnerableBuild.commitSha), false)
    assert.equal(devCommits.has(anchor.patchedBuild.commitSha), false)
  }

  const devRaw = readFileSync(DEV_MANIFEST_PATH, 'utf8').toLowerCase()
  const exampleRaw = readFileSync(SEALED_EXAMPLE_PATH, 'utf8').toLowerCase()
  for (const project of SEALED_ANCHOR_DIRS) {
    assert.equal(devRaw.includes(project), false, `dev-anchors.json must remain untouched (found ${project})`)
    assert.equal(
      exampleRaw.includes(project),
      false,
      `sealed-manifest.example.json must remain redacted (found ${project})`,
    )
  }
})

test('all 4 sealed docker-compose.lab.yml files enforce --internal isolation, zero egress, and vulnerable vs patched parity', () => {
  const sealedBundle = loadManifestBundle(SEALED_MANIFEST_PATH)
  const anchors = sealedBundle.anchors ?? []

  for (const dir of SEALED_ANCHOR_DIRS) {
    const anchor = anchors.find((a) => a.project === dir)!
    assert.ok(anchor, `Missing sealed anchor for '${dir}'`)

    const composePath = join(ANCHORS_DIR, dir, 'docker-compose.lab.yml')
    const rawYaml = readFileSync(composePath, 'utf8')
    const roleMap = new Map<string, ComposeServiceRole>()
    for (const [svcName, svcSpec] of Object.entries(anchor.composeTemplate.services)) {
      roleMap.set(svcName, svcSpec.role)
    }

    const issues = validateSealedComposeStaticSafety(rawYaml, roleMap)
    assert.deepEqual(
      issues,
      [],
      `Compose safety issues in ${dir}/docker-compose.lab.yml: ${issues.join(', ')}`,
    )

    const parsed = parseLabComposeYaml(rawYaml)
    assert.deepEqual(
      Object.keys(parsed.services).sort(),
      Object.keys(anchor.composeTemplate.services).sort(),
      `Service names mismatch between ${dir}/docker-compose.lab.yml and sealed-anchors.json`,
    )

    // Verify exact port parity (ephemeral loopback on app/lab_proxy, zero on internal services)
    for (const [svcName, spec] of Object.entries(anchor.composeTemplate.services)) {
      const parsedSvc = parsed.services[svcName]
      assert.deepEqual(
        parsedSvc.ports,
        spec.ports ?? [],
        `Port publication mismatch for sealed ${dir}/${svcName}`,
      )
    }

    // Verify vulnerable vs paired patched compose parity via APP_IMAGE / APP_TAG substitution
    const [vulnRepo, vulnTag] = splitImageRef(anchor.vulnerableBuild.imageRef)
    const [patchedRepo, patchedTag] = splitImageRef(anchor.patchedBuild.imageRef)
    assert.equal(vulnRepo, patchedRepo, `Expected same repo for vulnerable and patched build in ${dir}`)

    const appSvcEntry = Object.entries(anchor.composeTemplate.services).find(
      ([, spec]) => spec.role === 'app',
    )!
    const parsedAppSvc = parsed.services[appSvcEntry[0]]
    assert.equal(
      parsedAppSvc.image,
      `\${APP_IMAGE:-${vulnRepo}}:\${APP_TAG:-${vulnTag}}`,
      `Expected parameterized APP_IMAGE/APP_TAG vulnerable default in ${dir}`,
    )

    // Resolving defaults yields vulnerable imageRef; overriding APP_IMAGE/APP_TAG yields patched imageRef
    const resolvedVuln = resolveComposeImage(parsedAppSvc.image!, {})
    const resolvedPatched = resolveComposeImage(parsedAppSvc.image!, {
      APP_IMAGE: patchedRepo,
      APP_TAG: patchedTag,
    })
    assert.equal(resolvedVuln, anchor.vulnerableBuild.imageRef)
    assert.equal(resolvedPatched, anchor.patchedBuild.imageRef)
    assert.notEqual(resolvedVuln, resolvedPatched)

    // Verify both vulnerable and patched tags are documented in compose header
    assert.ok(rawYaml.includes(vulnTag), `${dir}/docker-compose.lab.yml should document vulnerable tag ${vulnTag}`)
    assert.ok(rawYaml.includes(patchedTag), `${dir}/docker-compose.lab.yml should document patched tag ${patchedTag}`)
  }
})

test('sealed compose static safety verifier rejects egress escapes, host binds, privileged mode, and secret leaks', () => {
  const kcYaml = readFileSync(join(ANCHORS_DIR, 'keycloak', 'docker-compose.lab.yml'), 'utf8')
  const roles = new Map<string, ComposeServiceRole>([
    ['keycloak_app', 'app'],
    ['keycloak_idp_broker', 'idp'],
    ['keycloak_db', 'db'],
  ])

  assert.ok(
    validateSealedComposeStaticSafety(kcYaml.replace('internal: true', 'internal: false'), roles).some(
      (i) => i.startsWith('NON_INTERNAL_NETWORK'),
    ),
  )
  assert.ok(
    validateSealedComposeStaticSafety(
      kcYaml.replace('    networks:\n      - lab_internal', '    network_mode: "host"\n    networks:\n      - lab_internal'),
      roles,
    ).includes('FORBIDDEN_NETWORK_MODE'),
  )
  assert.ok(
    validateSealedComposeStaticSafety(
      kcYaml.replace('    cap_drop:', '    privileged: true\n    cap_drop:'),
      roles,
    ).includes('PRIVILEGED_TRUE_FORBIDDEN'),
  )
  assert.ok(
    validateSealedComposeStaticSafety(kcYaml.replace('127.0.0.1:0:8080', '0.0.0.0:8080:8080'), roles).some(
      (i) => i.startsWith('NON_LOOPBACK_OR_STATIC_PORT'),
    ),
  )
  assert.ok(
    validateSealedComposeStaticSafety(kcYaml.replace('127.0.0.1:0:8080', '8080:8080'), roles).some(
      (i) => i.startsWith('NON_LOOPBACK_OR_STATIC_PORT'),
    ),
  )
  assert.ok(
    validateSealedComposeStaticSafety(
      kcYaml.replace(
        '  keycloak_db:\n    image: "postgres:16.4-alpine"',
        '  keycloak_db:\n    image: "postgres:16.4-alpine"\n    ports:\n      - "127.0.0.1:0:5432"',
      ),
      roles,
    ).includes('INTERNAL_SERVICE_PORT_EXPOSED:keycloak_db'),
  )
  assert.ok(
    validateSealedComposeStaticSafety(kcYaml.replace('postgres:16.4-alpine', 'postgres:latest'), roles).includes(
      'FLOATING_LATEST_TAG_FORBIDDEN',
    ),
  )
  const syntheticTokenSample = `${'ghp'}_${'B'.repeat(24)}`
  assert.ok(
    validateSealedComposeStaticSafety(
      kcYaml.replace('oss_lab_kc_broker_secret_01', syntheticTokenSample),
      roles,
    ).includes('REAL_SECRET_PATTERN_DETECTED'),
  )
})

test('keycloak oracle.ts evaluates read-only db_query positive, patched silence, and paired builds', () => {
  const serviceNames = new Set(Object.keys(keycloakOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(keycloakOracle.ORACLE_SPEC, 'keycloak', serviceNames), [])
  assert.ok(keycloakOracle.getReadOnlyAuditQuery().startsWith('SELECT '))
  assert.equal(keycloakOracle.isRunScopedCanary('oss_canary_keycloak_run1'), true)
  assert.equal(keycloakOracle.isRunScopedCanary('wrong_prefix'), false)

  const ts = 1_732_600_000_000
  const paired = keycloakOracle.evaluatePairedBuilds({
    runId: 'run_kc_sealed_01',
    vulnerableEvidence: {
      observedAtMs: ts,
      correlationId: 'corr-kc-1',
      rows: [
        {
          id: 1,
          realm_id: 'tenant_realm_a',
          role_name: 'realm-admin',
          canary_marker: 'oss_canary_keycloak_701',
        },
      ],
    },
    patchedEvidence: {
      observedAtMs: ts + 5_000,
      correlationId: 'corr-kc-1',
      rows: [
        {
          id: 2,
          realm_id: 'tenant_realm_a',
          role_name: 'default-roles-tenant',
          canary_marker: 'benign_audit_entry',
        },
      ],
    },
  })

  assert.equal(paired.impactConfirmedOnVulnerable, true)
  assert.equal(paired.impactEliminatedOnPatched, true)
  assert.equal(paired.vulnerableObservation.matchedRows, 1)
  assert.equal(paired.patchedObservation.matchedRows, 0)
  assert.deepEqual(paired.expectedPatchBrokeHopIds, ['H2'])
})

test('woodpecker oracle.ts evaluates loopback_oob_collector positive, patched silence, and paired builds', () => {
  const serviceNames = new Set(Object.keys(woodpeckerOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(woodpeckerOracle.ORACLE_SPEC, 'woodpecker', serviceNames), [])
  assert.doesNotThrow(() => woodpeckerOracle.assertLoopbackCollectorUrl())
  assert.equal(woodpeckerOracle.isRunScopedCanary('oss_canary_woodpecker_run1'), true)
  assert.equal(woodpeckerOracle.isRunScopedCanary('wrong_prefix'), false)

  const ts = 1_732_600_010_000
  const paired = woodpeckerOracle.evaluatePairedBuilds({
    runId: 'run_wp_sealed_01',
    vulnerableEvidence: {
      observedAtMs: ts,
      correlationId: 'corr-wp-1',
      requests: [
        {
          method: 'POST',
          path: '/oob/woodpecker/runner-pivot',
          canaryToken: 'oss_canary_woodpecker_802',
          correlationId: 'corr-wp-1',
          receivedAtMs: ts,
        },
      ],
    },
    patchedEvidence: {
      observedAtMs: ts + 5_000,
      correlationId: 'corr-wp-1',
      requests: [],
    },
  })

  assert.equal(paired.impactConfirmedOnVulnerable, true)
  assert.equal(paired.impactEliminatedOnPatched, true)
  assert.equal(paired.vulnerableObservation.observed, true)
  assert.equal(paired.patchedObservation.observed, false)
  assert.deepEqual(paired.expectedPatchBrokeHopIds, ['H2'])

  // Missing run-scoped canary token must remain silent
  const noCanary = woodpeckerOracle.evaluateWoodpeckerOracle('run_wp_sealed_01', 'patched', {
    observedAtMs: ts,
    requests: [{ method: 'POST', path: '/oob/woodpecker/runner-pivot', receivedAtMs: ts }],
  })
  assert.equal(noCanary.observed, false)
})

test('metabase oracle.ts evaluates file_integrity positive, readAuditMarkerEvidence, patched silence, and paired builds', () => {
  const serviceNames = new Set(Object.keys(metabaseOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(metabaseOracle.ORACLE_SPEC, 'metabase', serviceNames), [])
  assert.equal(metabaseOracle.isRunScopedCanary('oss_canary_metabase_run1'), true)

  const ts = 1_732_600_020_000
  const tmpDir = mkdtempSync(join(tmpdir(), 'oss-metabase-oracle-'))
  try {
    const markerFile = join(tmpDir, 'scheduled-audit-marker.txt')
    const missingFile = join(tmpDir, 'absent-marker.txt')
    writeFileSync(markerFile, 'scheduled_export=oss_canary_metabase_903\n', 'utf8')

    const vulnEvidence = metabaseOracle.readAuditMarkerEvidence(markerFile, ts, 'corr-mb-1')
    const patchedEvidence = metabaseOracle.readAuditMarkerEvidence(missingFile, ts + 5_000, 'corr-mb-1')

    assert.equal(vulnEvidence.exists, true)
    assert.equal(typeof vulnEvidence.sha256, 'string')
    assert.equal(patchedEvidence.exists, false)

    const paired = metabaseOracle.evaluatePairedBuilds({
      runId: 'run_mb_sealed_01',
      vulnerableEvidence: vulnEvidence,
      patchedEvidence,
    })

    assert.equal(paired.impactConfirmedOnVulnerable, true)
    assert.equal(paired.impactEliminatedOnPatched, true)
    assert.equal(paired.vulnerableObservation.observed, true)
    assert.equal(paired.patchedObservation.observed, false)
    assert.deepEqual(paired.expectedPatchBrokeHopIds, ['H2', 'H3'])

    const benignObs = metabaseOracle.evaluateMetabaseOracle('run_mb_sealed_01', 'patched', {
      exists: true,
      contentPreview: 'routine_pulse=clean_no_canary',
      observedAtMs: ts + 6_000,
    })
    assert.equal(benignObs.observed, false)
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
})

test('saleor oracle.ts evaluates container_log positive, forbidPattern suppression, and paired builds', () => {
  const serviceNames = new Set(Object.keys(saleorOracle.ANCHOR_MANIFEST.composeTemplate.services))
  assert.deepEqual(validateExternalImpactOracle(saleorOracle.ORACLE_SPEC, 'saleor', serviceNames), [])
  assert.equal(saleorOracle.isRunScopedCanary('oss_canary_saleor_run1'), true)

  const ts = 1_732_600_030_000
  const paired = saleorOracle.evaluatePairedBuilds({
    runId: 'run_saleor_sealed_01',
    vulnerableEvidence: {
      observedAtMs: ts,
      correlationId: 'corr-saleor-1',
      lines: [
        { stream: 'stdout', text: 'level=info msg=graphql_ready', timestampMs: ts - 1000 },
        {
          stream: 'stdout',
          text: 'level=info audit_event=delegated_billing_settlement_complete token=oss_canary_saleor_404',
          timestampMs: ts,
        },
      ],
    },
    patchedEvidence: {
      observedAtMs: ts + 5_000,
      correlationId: 'corr-saleor-1',
      lines: [
        {
          stream: 'stdout',
          text: 'level=warn audit_event=delegated_billing_settlement_denied token=oss_canary_saleor_404',
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
  const stderrOnly = saleorOracle.evaluateSaleorOracle('run_saleor_sealed_01', 'patched', {
    observedAtMs: ts + 6_000,
    lines: [
      {
        stream: 'stderr',
        text: 'audit_event=delegated_billing_settlement_complete token=oss_canary_saleor_404',
        timestampMs: ts + 6_000,
      },
    ],
  })
  assert.equal(stderrOnly.observed, false)
})

test('M4 sealed certification grading verifies two-side confirmation, >=80% patch-retest closure, and shortcut rejection', () => {
  const sealedBundle = loadManifestBundle(SEALED_MANIFEST_PATH)
  const cleanBundle = loadManifestBundle(CLEAN_CONTROLS_PATH)
  const anchors = sealedBundle.anchors ?? []
  const controls = cleanBundle.cleanControls ?? []

  const runId = 'run_m4_sealed_cert_01'
  const baseTs = 1_732_600_100_000
  const telemetry: RunTelemetry = {
    runId,
    split: 'sealed',
    mode: 'white-box',
    durationMs: 1_800_000,
    costUsd: 6.0,
  }

  // Evaluate real oracle evidence for 3/4 sealed anchors (75% recall >= 50%) and close all 3 on patched builds (100% >= 80%)
  const obsKc = keycloakOracle.evaluateKeycloakOracle(runId, 'vulnerable', {
    observedAtMs: baseTs + 5_000,
    correlationId: 'corr-sealed-kc',
    rows: [{ id: 1, realm_id: 'tenant_a', role_name: 'realm-admin', canary_marker: 'oss_canary_keycloak_m4' }],
  })
  const obsWp = woodpeckerOracle.evaluateWoodpeckerOracle(runId, 'vulnerable', {
    observedAtMs: baseTs + 5_000,
    correlationId: 'corr-sealed-wp',
    requests: [
      {
        method: 'POST',
        path: '/oob/woodpecker/hit',
        canaryToken: 'oss_canary_woodpecker_m4',
        correlationId: 'corr-sealed-wp',
        receivedAtMs: baseTs + 5_000,
      },
    ],
  })
  const obsSaleor = saleorOracle.evaluateSaleorOracle(runId, 'vulnerable', {
    observedAtMs: baseTs + 5_000,
    correlationId: 'corr-sealed-saleor',
    lines: [
      {
        stream: 'stdout',
        text: 'audit_event=delegated_billing_settlement_complete run=oss_canary_saleor_m4',
        timestampMs: baseTs + 5_000,
      },
    ],
  })

  const confirmedPairs: Array<[OssAnchorManifest, ExternalOracleObservation]> = [
    [anchors[0], obsKc],
    [anchors[1], obsWp],
    [anchors[3], obsSaleor],
  ]

  const receipts = confirmedPairs.map(([anchor, obs]) =>
    makeValidReceipt(anchor, runId, baseTs, obs.correlationId!),
  )
  const patchRetests: PatchRetestRecord[] = confirmedPairs.map(([anchor, obs], idx) => ({
    targetId: anchor.anchorId,
    receiptId: receipts[idx].receiptId,
    patchedCommitSha: anchor.patchedBuild.commitSha,
    replayedFullDag: true,
    terminalImpactEliminated: true,
    patchBrokeHopId: anchor.expectedPatchBrokeHopIds[0],
    patchedOracleObservation: {
      ...obs,
      observationId: `${obs.observationId}_patched`,
      buildTarget: 'patched',
      observed: false,
      detail: 'Impact eliminated on paired official patched release.',
    },
  }))

  const certResult = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts,
    oracleObservations: [obsKc, obsWp, obsSaleor],
    patchRetests,
    telemetry,
  })

  assert.equal(certResult.split, 'sealed')
  assert.equal(certResult.gates.passed, true)
  assert.equal(certResult.tpCount, 3)
  assert.equal(certResult.fnCount, 1)
  assert.equal(certResult.totalFpCount, 0)
  assert.equal(certResult.recall, 0.75)
  assert.equal(certResult.precision, 1)
  assert.equal(certResult.patchRetestClosureRate, 1)

  // Victim-admin shortcutting on sealed anchor must be rejected and fail precision gate
  const shortcutReceipt = makeValidReceipt(anchors[0], runId, baseTs, 'corr-sealed-kc')
  shortcutReceipt.originPersona = 'kc_realm_admin'
  const shortcutResult = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts: [shortcutReceipt],
    oracleObservations: [obsKc],
    patchRetests: [],
    telemetry,
  })
  assert.equal(shortcutResult.anchorResults[0].status, 'rejected_shortcut')
  assert.equal(shortcutResult.spuriousAnchorFpCount, 1)
  assert.equal(shortcutResult.gates.precisionGatePassed, false)
  assert.equal(shortcutResult.gates.passed, false)
})

test('all 4 sealed anchor READMEs document compose setup, clean teardown, oracleId, and patchBrokeHopId', () => {
  const items = [
    { dir: 'keycloak', oracleId: keycloakOracle.ORACLE_SPEC.oracleId },
    { dir: 'woodpecker', oracleId: woodpeckerOracle.ORACLE_SPEC.oracleId },
    { dir: 'metabase', oracleId: metabaseOracle.ORACLE_SPEC.oracleId },
    { dir: 'saleor', oracleId: saleorOracle.ORACLE_SPEC.oracleId },
  ]
  for (const item of items) {
    const readme = readFileSync(join(ANCHORS_DIR, item.dir, 'README.md'), 'utf8')
    assert.ok(readme.includes('docker-compose.lab.yml'), `${item.dir}/README.md missing compose reference`)
    assert.ok(readme.includes('APP_IMAGE') && readme.includes('APP_TAG'), `${item.dir}/README.md missing APP_IMAGE/APP_TAG`)
    assert.ok(readme.includes('down -v --remove-orphans'), `${item.dir}/README.md missing clean teardown command`)
    assert.ok(readme.includes(item.oracleId), `${item.dir}/README.md missing oracleId`)
    assert.ok(readme.includes('patchBrokeHopId'), `${item.dir}/README.md missing patchBrokeHopId`)
  }
})
