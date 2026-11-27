/**
 * Kovo v3 boundary suite (SPEC-v3 §2 invariants, §7 threat model, §9 exit gates).
 *
 * Part A — subsystems that do not depend on RequestBroker v3:
 *   A1 hardened air-gapped worker (real Docker): flags, UID, SAST masking, offline scripts, static AST re-verification
 *   A2 local-lab gating (domain origins + LabRunner) and live --internal lab isolation
 *   A3 submission-time dedupe
 *   A4 air-gapped patch author/reviewer (withholding breaks_callers)
 *   A5 OASIS SARIF 2.1.0 export (structural validation + zero secret leaks)
 *   A6 headless CLI exit codes 0/1/2
 */
import assert from 'node:assert/strict'
import { Resolver } from 'node:dns/promises'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import type { Finding } from '../src/domain.ts'
import { assetOriginForEnvironment, labAssetOrigin, publicAssetOrigin, scopedAssetOrigin } from '../src/domain.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { checkStructuralDuplicate, evaluateSubmissionDedupe, normalizeEndpointTemplate } from '../src/server/dedupe.ts'
import type { ExistingFindingRef } from '../src/server/dedupe.ts'
import { LabRunner, assertLocalLabAllowed } from '../src/server/lab-runner.ts'
import { generateAndReviewPatch } from '../src/server/patch-workflow.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { buildSarifLog } from '../src/server/sarif-export.ts'
import type { SarifFindingInput } from '../src/server/sarif-export.ts'
import { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { listSkills } from '../src/server/skills.ts'
import { Store } from '../src/server/store.ts'
import { probeDifferential, probeSurface, runSafeTemplates } from '../src/server/surface-engine.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import { loadSafeTemplates, parseSafeTemplateYaml, TemplateValidationError } from '../src/templates/loader.ts'
import { determineExitCode, loadPersonaFile, parseCliArgs } from '../scripts/cli.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'
import { createSuiteBLab, LAB_PERSONA_A_TOKEN } from './v3-fullstack-lab/lab-server.ts'
import { createSuiteBMockRepo } from './v3-fullstack-lab/mock-repo.ts'
import { validateSarif21 } from './v3-fullstack-lab/sarif-validate.ts'

const exec = promisify(execFile)
const repoRootDir = new URL('..', import.meta.url).pathname

const RAW_STRIPE = 'sk_live_TESTFIXTURE000000000000000000'
const RAW_AWS = 'AKIAIOSFODNN7EXAMPLE'

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const prev: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

async function hostFixture(host = '0.0.0.0') {
  const server = createServer((_req, res) => res.end('HOST-SERVICE-REACHED')).listen(0, host)
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('no address')
  return {
    port: addr.port,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: randomUUID(),
    origin: 'http://127.0.0.1:9',
    title: 'Server Action missing invoice ownership check',
    status: 'confirmed',
    severity: 'high',
    reason: 'persona_b read persona_a invoice inv_a_1001 via getInvoiceAction.',
    remediation: 'Compare invoice.ownerId to the session user before returning.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    ...overrides,
  }
}

// ============================================================================
// A1. Hardened air-gapped worker (kovo-worker:local v3) — real Docker
// ============================================================================

test('A1 worker v3: --network none/read-only/cap-drop ALL/no-new-privileges/UID 10001 with v3 limits, masked SAST, offline scripts, static AST re-verification', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-v3-worker-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const reposDir = join(root, 'repos')
  mkdirSync(reposDir, { recursive: true })
  createSuiteBMockRepo(reposDir)
  const wsDir = join(root, 'ws')
  mkdirSync(wsDir)

  const backend = new LinuxWorkerBackend({ workspace: { id: 'v3-worker-ws', directory: wsDir } })
  const assignmentId = randomUUID()
  const abort = new AbortController()
  const session = await backend.openSession(assignmentId, abort.signal, { reposDir })
  t.after(() => session.close())

  let containerId = ''
  for (let i = 0; i < 60 && !containerId; i++) {
    containerId = (await exec('docker', ['ps', '-q', '--filter', `label=dev.kovo.assignment=${assignmentId}`])).stdout.trim()
    if (!containerId) await delay(50)
  }
  assert.ok(containerId, 'session container must be running')
  const inspect = JSON.parse((await exec('docker', ['inspect', containerId])).stdout)[0]
  const hc = inspect.HostConfig
  assert.equal(hc.NetworkMode, 'none')
  assert.equal(hc.ReadonlyRootfs, true)
  assert.equal(hc.Privileged, false)
  assert.deepEqual(hc.CapDrop, ['ALL'])
  assert.ok((hc.SecurityOpt ?? []).some((o: string) => /no-new-privileges/.test(o)))
  assert.equal(inspect.Config.User, '10001:10001')
  assert.equal(hc.Memory, 1536 * 1024 * 1024)
  assert.equal(hc.MemorySwap, 1536 * 1024 * 1024)
  assert.equal(hc.NanoCpus, 2_000_000_000)
  assert.equal(hc.PidsLimit, 256)
  assert.match(hc.Tmpfs['/tmp'], /noexec/)
  assert.match(hc.Tmpfs['/tmp'], /size=128m/)
  const reposMount = (inspect.Mounts as Array<{ Destination: string; RW: boolean }>).find(m => m.Destination === '/repos')
  assert.ok(reposMount, '/repos must be mounted')
  assert.equal(reposMount.RW, false, '/repos must be read-only')
  assert.equal((inspect.Mounts as unknown[]).length, 1, 'only /repos may be bind-mounted')

  // Real offline SAST: secret engines + structural engines; raw secrets never leave the container.
  const sast = await session.sast({ repo: 'northstar-app', engines: ['gitleaks', 'trufflehog', 'opengrep', 'ast-grep'] }, AbortSignal.timeout(120_000))
  const serialized = JSON.stringify(sast)
  assert.ok(!serialized.includes(RAW_STRIPE), 'raw Stripe-style fixture secret must be masked')
  assert.ok(!serialized.includes(RAW_AWS), 'raw AWS fixture key must be masked')
  assert.ok(sast.totalFindings > 0, 'SAST must report findings on the planted repo')
  for (const engine of ['gitleaks', 'opengrep', 'ast-grep'] as const) {
    assert.ok(sast.enginesRun.includes(engine), `${engine} must run`)
    assert.equal(sast.engineStatus[engine]?.ok, true, `${engine} must succeed offline: ${sast.engineStatus[engine]?.note ?? ''}`)
  }
  const secretHits = sast.findings.filter(f => f.engine === 'gitleaks' || f.engine === 'trufflehog')
  assert.ok(secretHits.length > 0, 'secret scanners must detect the planted fixture secrets')
  assert.ok(secretHits.every(f => /masked/.test(f.maskedPreview) || f.maskedPreview === ''), 'secret previews must be masked')
  assert.ok(sast.findings.some(f => f.file.includes('src/routes/search.ts') || f.file.includes('src/client/preview-frame.ts') || f.file.includes('src/middleware/cors.ts')),
    'structural engines must flag at least one planted sink')

  // Traversal is rejected before any engine runs.
  await assert.rejects(session.sast({ repo: '../etc', engines: ['gitleaks'] }, AbortSignal.timeout(20_000)))
  await assert.rejects(session.sast({ repo: 'northstar-app', engines: ['gitleaks'], paths: ['../../etc'] }, AbortSignal.timeout(20_000)))

  // Offline Python/Node: no sockets, UID 10001, /repos read-only, timeout enforced, stdout secret-masked.
  const py = await session.runScript({
    runtime: 'python',
    code: [
      'import os, socket',
      'print("uid", os.getuid())',
      's = socket.socket(); s.settimeout(1)',
      'try:',
      '    s.connect(("1.1.1.1", 80)); print("NET-REACHED")',
      'except Exception as e:',
      '    print("net-blocked", type(e).__name__)',
      'try:',
      '    open("/repos/northstar-app/pwned.txt", "w").write("x"); print("REPOS-WRITABLE")',
      'except Exception as e:',
      '    print("repos-readonly", type(e).__name__)',
      `print("${RAW_AWS}")`,
    ].join('\n'),
  }, AbortSignal.timeout(60_000))
  assert.match(py.stdout, /uid 10001/)
  assert.match(py.stdout, /net-blocked/)
  assert.ok(!py.stdout.includes('NET-REACHED'))
  assert.match(py.stdout, /repos-readonly/)
  assert.ok(!py.stdout.includes(RAW_AWS), 'script stdout must be secret-masked')

  const node = await session.runScript({
    runtime: 'node',
    code: "fetch('http://1.1.1.1', { signal: AbortSignal.timeout(1500) }).then(() => console.log('NET-REACHED'), () => console.log('net-blocked'))",
  }, AbortSignal.timeout(60_000))
  assert.match(node.stdout, /net-blocked/)

  const spin = await session.runScript({ runtime: 'python', code: 'while True:\n    pass', timeoutMs: 2_000 }, AbortSignal.timeout(60_000))
  assert.equal(spin.timedOut, true)

  // static_ast_proof re-verification: real code lines verified; hallucinated ranges / files fail closed.
  const positive = await session.verifyStaticAst({
    repo: 'northstar-app', file: 'src/client/preview-frame.ts', startLine: 1, endLine: 8, engine: 'ast-grep', ruleOrPattern: '$EL.innerHTML = $V',
  }, AbortSignal.timeout(60_000))
  assert.equal(positive.verified, true, positive.reason ?? '')
  assert.ok(positive.matchedLines.includes(5))
  const wrongRange = await session.verifyStaticAst({
    repo: 'northstar-app', file: 'src/client/preview-frame.ts', startLine: 1, endLine: 2, engine: 'ast-grep', ruleOrPattern: '$EL.innerHTML = $V',
  }, AbortSignal.timeout(60_000))
  assert.equal(wrongRange.verified, false)
  await assert.rejects(session.verifyStaticAst({
    repo: 'northstar-app', file: 'src/does-not-exist.ts', startLine: 1, endLine: 3, engine: 'ast-grep', ruleOrPattern: '$X',
  }, AbortSignal.timeout(60_000)))

  // Fresh one-shot container path used by ReplayVerifier.
  const oneShot = await backend.verifyStaticAst(randomUUID(), {
    repo: 'northstar-app', file: 'src/routes/search.ts', startLine: 1, endLine: 5, engine: 'ast-grep', ruleOrPattern: 'const sql = `$$$`',
  }, AbortSignal.timeout(60_000), { reposDir })
  assert.equal(oneShot.verified, true, oneShot.reason ?? '')
})

// ============================================================================
// A2. local-lab gating + live --internal lab isolation (Invariant #7)
// ============================================================================

test('A2 local-lab origin gating: public projects never relax; lab origins need local-lab + KOVO_ALLOW_LOCAL_LAB=1', async () => {
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, () => {
    for (const bad of ['http://127.0.0.1:8080', 'https://example.com:8443', 'https://10.0.0.5', 'http://example.com']) {
      assert.equal(publicAssetOrigin.safeParse(bad).success, false, `public must reject ${bad}`)
      assert.equal(scopedAssetOrigin.safeParse(bad).success, false, `scoped must reject ${bad} without env`)
    }
    assert.equal(labAssetOrigin.safeParse('http://127.0.0.1:8080').success, false)
    assert.equal(assetOriginForEnvironment('local-lab').safeParse('http://127.0.0.1:8080').success, false)
    assert.throws(() => assertLocalLabAllowed('local-lab'), /KOVO_ALLOW_LOCAL_LAB/)
    assert.equal(publicAssetOrigin.parse('example.com'), 'https://example.com')
  })
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => {
    assert.equal(labAssetOrigin.parse('http://127.0.0.1:8080'), 'http://127.0.0.1:8080')
    assert.equal(labAssetOrigin.parse('http://localhost:3000'), 'http://localhost:3000')
    assert.equal(labAssetOrigin.safeParse('http://169.254.169.254').success, false, 'metadata IP never allowed')
    assert.equal(labAssetOrigin.safeParse('http://metadata.google.internal').success, false)
    assert.equal(labAssetOrigin.safeParse('http://8.8.8.8:80').success, false, 'public IP literals are not lab origins')
    assert.equal(publicAssetOrigin.safeParse('http://127.0.0.1:8080').success, false, 'public schema unchanged even with env')
    assert.equal(assetOriginForEnvironment('public').safeParse('http://127.0.0.1:8080').success, false)
    assert.throws(() => assertLocalLabAllowed('public'), /forbidden/)
  })
})

function labRepo(root: string): string {
  const dir = join(root, 'lab-app')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'server.js'), [
    "const http = require('http')",
    "const VERSION = 'v1-vulnerable'",
    "http.createServer((req, res) => {",
    "  if (req.url === '/health') return res.end('ok')",
    "  res.end(VERSION)",
    "}).listen(Number(process.env.PORT || 8080), '0.0.0.0')",
    '',
  ].join('\n'))
  writeFileSync(join(dir, '.env'), 'PRODUCTION_DB_PASSWORD=real-prod-secret-should-never-copy\n')
  writeFileSync(join(dir, 'deploy.pem'), '-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n')
  return dir
}

test('A2 LabRunner: hard-blocked on public / without env; live --internal target is cap-dropped, sanitized, egress-blocked, patchable, and leaves no orphans', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-v3-lab-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const repoDir = labRepo(root)
  const runner = new LabRunner()
  const runId = randomUUID()
  t.after(() => runner.stopAll())

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    await assert.rejects(runner.startLabTarget({ runId, environment: 'public', repoDir }), /forbidden/)
  })
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, async () => {
    await assert.rejects(runner.startLabTarget({ runId, environment: 'local-lab', repoDir }), /KOVO_ALLOW_LOCAL_LAB/)
  })
  assert.equal((await exec('docker', ['ps', '-aq', '--filter', `label=dev.kovo.run=${runId}`])).stdout.trim(), '', 'blocked starts must create nothing')

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const handle = await runner.startLabTarget({
      runId, environment: 'local-lab', repoDir,
      labConfig: { internalPort: 8080, healthPath: '/health', image: 'node:24-bookworm-slim' },
      signal: AbortSignal.timeout(90_000),
    })
    assert.match(handle.origin, /^http:\/\/127\.0\.0\.1:\d+$/)
    assert.equal(await (await fetch(handle.origin + '/')).text(), 'v1-vulnerable')

    const net = JSON.parse((await exec('docker', ['network', 'inspect', handle.networkName])).stdout)[0]
    assert.equal(net.Internal, true, 'lab network must be --internal')
    const c = JSON.parse((await exec('docker', ['inspect', handle.containerName])).stdout)[0]
    assert.deepEqual(c.HostConfig.CapDrop, ['ALL'])
    assert.ok((c.HostConfig.SecurityOpt ?? []).some((o: string) => /no-new-privileges/.test(o)))
    assert.ok(c.HostConfig.Memory > 0 && c.HostConfig.PidsLimit > 0 && c.HostConfig.NanoCpus > 0)
    assert.equal(c.HostConfig.Privileged, false)
    assert.deepEqual(Object.keys(c.NetworkSettings.Networks), [handle.networkName], 'lab app must only join its internal network')
    assert.equal(Object.keys(c.HostConfig.PortBindings ?? {}).length, 0, 'no published host ports')

    // Sanitized copy: no .env / keys; and not visible inside the container.
    assert.equal(existsSync(join(handle.sanitizedRepoDir, '.env')), false)
    assert.equal(existsSync(join(handle.sanitizedRepoDir, 'deploy.pem')), false)
    const envProbe = await exec('docker', ['exec', handle.containerName, 'node', '-e',
      "console.log(require('fs').existsSync('/app/.env') ? 'ENV-PRESENT' : 'env-absent', JSON.stringify(process.env).includes('real-prod-secret') ? 'SECRET-IN-ENV' : 'env-clean')"])
    assert.match(envProbe.stdout, /env-absent env-clean/)

    // Zero internet egress from the lab app.
    const egress = await exec('docker', ['exec', handle.containerName, 'node', '-e',
      "fetch('http://1.1.1.1',{signal:AbortSignal.timeout(2000)}).then(()=>console.log('INTERNET-REACHED'),e=>console.log('internet-blocked',e.cause?.code||e.name))"])
    assert.match(egress.stdout, /internet-blocked/)

    // Patch rebuild keeps the same loopback origin and serves patched code.
    const diff = [
      '--- a/server.js', '+++ b/server.js', '@@ -1,3 +1,3 @@',
      " const http = require('http')", "-const VERSION = 'v1-vulnerable'", "+const VERSION = 'v2-patched'", ' http.createServer((req, res) => {', '',
    ].join('\n')
    const rebuilt = await runner.rebuildWithPatch(runId, diff, AbortSignal.timeout(90_000))
    assert.equal(rebuilt.origin, handle.origin)
    assert.equal(await (await fetch(rebuilt.origin + '/')).text(), 'v2-patched')
    assert.match(readFileSync(join(repoDir, 'server.js'), 'utf8'), /v1-vulnerable/, 'original repo must never be mutated')
    await assert.rejects(runner.rebuildWithPatch(runId, '--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n'), /Unsafe|escapes/)

    await runner.stopAll()
    assert.equal((await exec('docker', ['ps', '-aq', '--filter', `label=dev.kovo.run=${runId}`])).stdout.trim(), '')
    assert.equal((await exec('docker', ['network', 'ls', '-q', '--filter', `name=${handle.networkName}`])).stdout.trim(), '')
  })
})

test('A2 LabRunner Invariant #7: lab app container has zero access to host services (bridge gateway)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-v3-lab-host-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const repoDir = labRepo(root)
  const runner = new LabRunner()
  t.after(() => runner.stopAll())
  const host = await hostFixture('0.0.0.0')
  t.after(() => host.close())

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const handle = await runner.startLabTarget({
      runId: randomUUID(), environment: 'local-lab', repoDir,
      labConfig: { internalPort: 8080, healthPath: '/health', image: 'node:24-bookworm-slim' },
      signal: AbortSignal.timeout(90_000),
    })
    const targets = new Set<string>(['host.docker.internal'])
    try {
      const net = JSON.parse((await exec('docker', ['network', 'inspect', handle.networkName])).stdout)[0]
      for (const cfg of net.IPAM?.Config ?? []) if (cfg.Gateway) targets.add(cfg.Gateway)
    } catch { /* --network none style runners have no network to inspect */ }
    targets.add('172.17.0.1')
    for (const target of targets) {
      const probe = await exec('docker', ['exec', handle.containerName, 'node', '-e',
        `fetch('http://${target}:${host.port}/',{signal:AbortSignal.timeout(1500)}).then(r=>r.text()).then(t=>console.log(t),e=>console.log('host-blocked',e.cause?.code||e.name))`])
      assert.ok(!probe.stdout.includes('HOST-SERVICE-REACHED'), `lab app reached host service via ${target}:${host.port}`)
    }
  })
})

// ============================================================================
// A3. Submission-time dedupe (§4.5B)
// ============================================================================

test('A3 dedupe: structural fingerprint rejects duplicates, normalizes IDs, upgrades higher severity, collapses v2 CORS pairs, accepts distinct bugs', async () => {
  const origin = 'https://bulletin.dyad.sh'
  const existing: ExistingFindingRef[] = [
    { id: 'f-cors-low', origin, title: 'CORS reflects arbitrary origin', status: 'confirmed', cwe: 'CWE-942', category: 'cors-client-side', severity: 'low', endpoint: '/', authState: 'anonymous', specKind: 'http_chain' },
    { id: 'f-bola', origin, title: 'Invoice BOLA', status: 'confirmed', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', endpoint: '/api/invoices/1001', authState: 'persona', specKind: 'http_chain' },
  ]
  assert.equal(normalizeEndpointTemplate('/api/invoices/1001?x=1'), normalizeEndpointTemplate('/api/invoices/2002'))
  assert.equal(normalizeEndpointTemplate('/api/orgs/0b8f8a8e-1111-4c4c-9d9d-1234567890ab/members'), normalizeEndpointTemplate('/api/orgs/9f9f9f9f-2222-4c4c-9d9d-abcdefabcdef/members'))

  const dupBola = await evaluateSubmissionDedupe({
    candidate: { origin, title: 'IDOR on invoices', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', endpoint: '/api/invoices/2002', authState: 'persona', specKind: 'http_chain' },
    existingFindings: existing,
  })
  assert.equal(dupBola.action, 'reject_duplicate')
  assert.equal(dupBola.stage, 'structural')
  assert.equal(dupBola.duplicateOfId, 'f-bola')
  assert.match(dupBola.instruction ?? '', /update_proposed_finding/)

  const upgrade = await evaluateSubmissionDedupe({
    candidate: { origin, title: 'IDOR on invoices (critical: write access)', cwe: 'CWE-639', category: 'broken-access-control', severity: 'critical', endpoint: '/api/invoices/7', authState: 'persona', specKind: 'http_chain' },
    existingFindings: existing,
  })
  assert.equal(upgrade.action, 'upgrade_existing')
  assert.equal(upgrade.duplicateOfId, 'f-bola')

  // v2 dyad-v2-smoke regression: Low + Medium credentialed CORS on the same host collapse into one finding.
  const corsMedium = await evaluateSubmissionDedupe({
    candidate: { origin, title: 'Credentialed CORS reflection on session API', cwe: 'CWE-942', category: 'cors-client-side', severity: 'medium', endpoint: '/api/session', authState: 'anonymous', specKind: 'http_chain' },
    existingFindings: existing,
  })
  assert.equal(corsMedium.isDuplicate, true)
  assert.equal(corsMedium.duplicateOfId, 'f-cors-low')
  assert.equal(corsMedium.action, 'upgrade_existing')

  const distinct = await evaluateSubmissionDedupe({
    candidate: { origin, title: 'Boolean SQLi in product filter', cwe: 'CWE-89', category: 'injection-input', severity: 'high', endpoint: '/api/products', authState: 'anonymous', specKind: 'sql_boolean_diff' },
    existingFindings: existing,
  })
  assert.equal(distinct.action, 'accept')
  const otherHost = checkStructuralDuplicate(
    { origin: 'https://accounts.dyad.sh', title: 'Invoice BOLA', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', endpoint: '/api/invoices/1001', authState: 'persona', specKind: 'http_chain' },
    existing,
  )
  assert.equal(otherHost.isDuplicate, false, 'same bug on a different origin is a distinct finding')

  // An LLM judge cannot invent a duplicate target outside the nearby set.
  const llmLies = await evaluateSubmissionDedupe({
    candidate: { origin, title: 'Webhook fails open', cwe: 'CWE-347', category: 'auth-identity', severity: 'high', endpoint: '/api/webhooks/billing', authState: 'anonymous', specKind: 'http_chain' },
    existingFindings: existing,
    llmCall: async () => JSON.stringify({ isDuplicate: true, duplicateOfId: 'f-nonexistent', shouldUpgrade: false, rationale: 'x' }),
  })
  assert.equal(llmLies.action, 'accept')
})

// ============================================================================
// A4. Air-gapped patch author + independent reviewer (§4.6)
// ============================================================================

test('A4 patch workflow: attacker_only patch approved; breaks_callers patch withheld (offline AND even when an LLM reviewer approves it); repo never mutated', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-v3-patch-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const reposDir = join(root, 'repos')
  mkdirSync(reposDir)
  const repoDir = createSuiteBMockRepo(reposDir)
  const original = readFileSync(join(repoDir, 'app/actions/invoice.ts'), 'utf8')
  const finding = baseFinding({ codeLocations: [{ repo: 'northstar-app', file: 'app/actions/invoice.ts', startLine: 6, endLine: 7 }] as never })
  const fixBefore = '  // BUG: missing ownership check comparing invoice.ownerId === _sessionUserId\n  return { ok: true, invoice }'

  const good = await generateAndReviewPatch({
    runId: randomUUID(), finding, repo: 'northstar-app', reposDir,
    candidatePatch: {
      fixBefore,
      fixAfter: '  if (invoice.ownerId !== _sessionUserId) return { ok: false, error: "not_found" }\n  return { ok: true, invoice }',
      codeLocations: [{ repo: 'northstar-app', file: 'app/actions/invoice.ts', startLine: 6, endLine: 7 }],
      rationale: 'Enforce ownership before returning invoice.',
    },
  })
  assert.equal(good.status, 'approved', good.reviewNotes)
  assert.equal(good.callerCompatibility, 'attacker_only')
  assert.equal(good.gates.length, 6)
  assert.deepEqual(good.gates.map(g => g.gate), [1, 2, 3, 4, 5, 6])
  assert.match(good.diff, /^\+.*ownerId !== _sessionUserId/m)
  assert.equal(good.dynamicRetestVerdict, 'skipped')

  const breaking = {
    fixBefore,
    fixAfter: '  return new Response("forbidden", { status: 403 })\n  return { ok: true, invoice }',
    codeLocations: [{ repo: 'northstar-app', file: 'app/actions/invoice.ts', startLine: 6, endLine: 7 }],
    rationale: 'Block everything.',
  }
  const offlineBad = await generateAndReviewPatch({ runId: randomUUID(), finding, repo: 'northstar-app', reposDir, candidatePatch: breaking })
  assert.equal(offlineBad.callerCompatibility, 'breaks_callers')
  assert.equal(offlineBad.status, 'withheld')

  const optimisticReviewer = async () => JSON.stringify({
    approved: true,
    callerCompatibility: 'attacker_only',
    enforcingLocation: 'app/actions/invoice.ts:6',
    gates: {
      applicability: { passed: true, detail: 'ok' },
      security_closure: { passed: true, detail: 'ok', enforcingLocation: 'app/actions/invoice.ts:6' },
      sibling_coverage: { passed: true, detail: 'ok' },
      caller_compatibility: { passed: true, detail: 'looks fine' },
      repo_conventions: { passed: true, detail: 'ok' },
    },
    reviewNotes: 'LGTM',
  })
  const llmBad = await generateAndReviewPatch({ runId: randomUUID(), finding, repo: 'northstar-app', reposDir, candidatePatch: breaking, reviewerLlmCall: optimisticReviewer })
  assert.equal(llmBad.status, 'withheld', 'deterministic breaks_callers detection must override an optimistic LLM reviewer')
  assert.equal(llmBad.callerCompatibility, 'breaks_callers')

  const notVerbatim = await generateAndReviewPatch({
    runId: randomUUID(), finding, repo: 'northstar-app', reposDir,
    candidatePatch: { ...breaking, fixBefore: '  return { ok: true, invoice: hallucinated }', fixAfter: '  return null' },
  }).catch(err => ({ status: 'error', err }))
  assert.notEqual((notVerbatim as { status: string }).status, 'approved', 'non-verbatim fixBefore can never be approved')

  await assert.rejects(generateAndReviewPatch({ runId: randomUUID(), finding, repo: '../../etc', reposDir, candidatePatch: breaking }))
  assert.equal(readFileSync(join(repoDir, 'app/actions/invoice.ts'), 'utf8'), original, '/repos must never be mutated by patch workflow')
})

// ============================================================================
// A5. OASIS SARIF 2.1.0 export (§4.7B)
// ============================================================================

test('A5 SARIF 2.1.0: valid structure, tier separation, approved-only fixes, non-failing coverage rows, scope filtering, zero secret leaks', () => {
  const origin = 'https://app.northstar.example'
  const secret = 'opaque-persona-secret-for-sarif-31337'
  const confirmed: SarifFindingInput = {
    ...baseFinding({ origin, id: 'f-runtime', title: 'Invoice BOLA', reason: `persona leaked ${secret} in body`, severity: 'critical', replaySpecId: 'spec-1', exchangeIds: ['ex-1', 'ex-out'] }),
    status: 'confirmed',
    verificationTier: 'runtime_confirmed',
    endpoint: '/_actions/getInvoice',
    codeLocations: [{ repo: 'northstar-app', file: 'app/actions/invoice.ts', startLine: 6, endLine: 7, snippet: `return { ok: true, invoice } // ${secret}` }],
  }
  const staticOnly: SarifFindingInput = {
    ...baseFinding({ origin, id: 'f-static', title: 'SQL string interpolation', cwe: 'CWE-89', category: 'injection-input', severity: 'high' }),
    status: 'static_verified',
    verificationTier: 'static_verified',
    runtimeProofGap: 'Runtime reproduction requires local-lab.',
    codeLocations: [{ repo: 'northstar-app', file: 'src/routes/search.ts', startLine: 3, endLine: 3 }],
  }
  const pending: SarifFindingInput = { ...baseFinding({ origin, id: 'f-pending', cwe: 'CWE-79', title: 'Unverified XSS lead' }), status: 'pending' }
  const dismissed: SarifFindingInput = { ...baseFinding({ origin, id: 'f-dismissed', cwe: 'CWE-1336', title: 'Reflected template decoy' }), status: 'dismissed' }
  const outOfScope: SarifFindingInput = { ...baseFinding({ origin: 'https://other.example', id: 'f-oos', cwe: 'CWE-352' }), status: 'confirmed' }

  const log = buildSarifLog({
    runId: randomUUID(), reportVersion: 1, goal: 'Suite B', capabilityTier: 2, scopeRevision: 1, goalRevision: 0,
    approvedOrigins: [origin],
    findings: [confirmed, staticOnly, pending, dismissed, outOfScope],
    coverageEntries: [
      { origin, category: 'broken-access-control', status: 'reported', summary: 'BOLA reported', linkedFindingId: 'f-runtime' },
      { origin, category: 'ssrf-redirects', status: 'ruled_out', summary: 'No fetch sinks', enforcingControl: 'src/routes/webhook-preview.ts:3' },
      { origin, category: 'upload-storage', status: 'needs_follow_up', summary: 'Upload pipeline', proofGapReason: `Needs Tier 3 approval (token ${secret})` },
      { origin, category: 'llm-ai-security', status: 'not_applicable', summary: 'No LLM features' },
    ],
    patches: [
      { id: randomUUID(), findingId: 'f-runtime', repo: 'northstar-app', status: 'approved', callerCompatibility: 'attacker_only', dynamicRetestVerdict: 'fixed',
        diff: '--- a/app/actions/invoice.ts\n+++ b/app/actions/invoice.ts\n@@ -6,2 +6,2 @@\n-  // BUG\n+  if (invoice.ownerId !== _sessionUserId) return { ok: false }\n   return { ok: true, invoice }\n', reviewNotes: 'approved' },
      { id: randomUUID(), findingId: 'f-static', repo: 'northstar-app', status: 'withheld', callerCompatibility: 'breaks_callers',
        diff: '--- a/src/routes/search.ts\n+++ b/src/routes/search.ts\n@@ -3,1 +3,1 @@\n-  const sql = x\n+  throw new Error("disabled")\n', reviewNotes: 'withheld' },
    ],
    replaySpecShaById: new Map([['spec-1', 'a'.repeat(64)]]),
    approvedExchangeIds: new Set(['ex-1']),
    secrets: [{ value: secret, placeholder: '[redacted:persona]' }],
  })

  const errors = validateSarif21(log)
  assert.deepEqual(errors, [], `SARIF 2.1.0 violations:\n${errors.join('\n')}`)
  const serialized = JSON.stringify(log)
  assert.ok(!serialized.includes(secret), 'SARIF must not leak registered secrets')

  const results = log.runs[0].results
  const fails = results.filter(r => r.kind === 'fail')
  assert.deepEqual(fails.map(r => r.properties.kovo.findingId).sort(), ['f-runtime', 'f-static'])
  const runtime = fails.find(r => r.properties.kovo.findingId === 'f-runtime')!
  const stat = fails.find(r => r.properties.kovo.findingId === 'f-static')!
  assert.equal(runtime.properties.kovo.verificationTier, 'runtime_confirmed')
  assert.equal(stat.properties.kovo.verificationTier, 'static_verified')
  assert.ok(stat.properties.kovo.runtimeProofGap)
  assert.notEqual(stat.properties.kovo.status, 'confirmed')
  assert.equal(runtime.ruleId, 'CWE-639')
  assert.equal(runtime.properties.kovo.replaySpecSha256, 'a'.repeat(64))
  assert.deepEqual(runtime.properties.kovo.exchangeIds, ['ex-1'], 'only approved-scope exchanges are exported')
  assert.equal(runtime.fixes?.length, 1, 'approved patch emits SARIF fixes')
  assert.equal(stat.fixes, undefined, 'withheld patches never emit fixes')
  assert.equal(runtime.locations[0].physicalLocation?.artifactLocation.uri, 'northstar-app/app/actions/invoice.ts')

  const coverage = results.filter(r => r.properties.kovo.recordType === 'coverage_entry')
  assert.deepEqual(coverage.map(r => r.kind).sort(), ['notApplicable', 'open', 'pass', 'pass'])
  assert.ok(coverage.every(r => r.level === 'none'), 'non-failing rows must have level "none"')
  const rule = log.runs[0].tool.driver.rules.find(r => r.id === 'CWE-639')!
  assert.equal(rule.properties['security-severity'], '9.5')
  assert.ok(rule.properties.tags.includes('external/cwe/cwe-639'))
})

// ============================================================================
// A6. Headless CLI: deterministic exit codes 0/1/2 (§4.7A)
// ============================================================================

test('A6 CLI: exit codes 0/1/2, --help, flag validation, local-lab gate, 0600 persona enforcement', async t => {
  const cli = join(repoRootDir, 'scripts', 'cli.ts')
  const run = (args: string[], env: Record<string, string | undefined> = {}) => new Promise<{ code: number; stdout: string; stderr: string }>(resolve => {
    const childEnv = { ...process.env, ...env } as NodeJS.ProcessEnv
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete childEnv[k]
    execFile(process.execPath, [...HARDENED_NODE_FLAGS, cli, ...args], { env: childEnv, timeout: 60_000 }, (error, stdout, stderr) => {
      resolve({ code: error ? (typeof error.code === 'number' ? error.code : 1) : 0, stdout, stderr })
    })
  })

  const help = await run(['scan', '--help'])
  assert.equal(help.code, 0)
  assert.match(help.stdout, /Exit Codes/)
  assert.equal((await run(['scan', '--bogus-flag'])).code, 1)
  assert.equal((await run(['scan', '--tier', '7', '--origin', 'example.com'])).code, 1)
  assert.equal((await run(['scan'])).code, 1, 'no target is a usage error')
  const labBlocked = await run(['scan', '--local-lab', '--origin', 'http://127.0.0.1:8080'], { KOVO_ALLOW_LOCAL_LAB: undefined })
  assert.equal(labBlocked.code, 1)
  assert.match(labBlocked.stderr, /KOVO_ALLOW_LOCAL_LAB/)
  assert.equal((await run(['scan', '--origin', 'http://127.0.0.1:8080'], { KOVO_ALLOW_LOCAL_LAB: undefined })).code, 1, 'public scans reject lab origins')

  const dir = mkdtempSync(join(tmpdir(), 'kovo-v3-cli-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const loose = join(dir, 'loose.json')
  writeFileSync(loose, JSON.stringify({ secret: 'cli-persona-secret-9911', authKind: 'bearer' }))
  chmodSync(loose, 0o644)
  assert.throws(() => loadPersonaFile(`tenant_a:${loose}`, ['https://staging.example.com']), /0600/)
  const looseRun = await run(['scan', '--origin', 'staging.example.com', '--persona', `tenant_a:${loose}`, '--output-dir', join(dir, 'out')])
  assert.equal(looseRun.code, 1)
  assert.ok(!looseRun.stderr.includes('cli-persona-secret-9911') && !looseRun.stdout.includes('cli-persona-secret-9911'))
  chmodSync(loose, 0o600)
  assert.equal(loadPersonaFile(`tenant_a:${loose}`, ['https://staging.example.com']).originAllowlist[0], 'https://staging.example.com')

  const opts = parseCliArgs(['scan', '--repo', '.', '--diff-base', 'origin/main', '--tier', '0', '--budget-usd', '5', '--sarif', 'out.sarif', '--fail-on', 'medium'])
  assert.equal(opts.tier, 0)
  assert.equal(opts.failOn, 'medium')
  assert.equal(opts.diffBase, 'origin/main')

  const f = (status: string, severity: Finding['severity'], verificationTier?: string) => ({ status, severity, verificationTier })
  assert.equal(determineExitCode([], 'high', 'complete'), 0)
  assert.equal(determineExitCode([f('confirmed', 'medium')], 'high', 'complete'), 0)
  assert.equal(determineExitCode([f('pending', 'critical'), f('dismissed', 'critical'), f('inconclusive', 'critical')], 'high', 'complete'), 0, 'unverified findings never fail CI')
  assert.equal(determineExitCode([f('confirmed', 'high')], 'high', 'complete'), 2)
  assert.equal(determineExitCode([f('static_verified', 'critical', 'static_verified')], 'high', 'complete'), 2)
  assert.equal(determineExitCode([f('confirmed', 'medium')], 'medium', 'complete'), 2)
  assert.equal(determineExitCode([], 'high', 'failed'), 1)
  for (const incomplete of ['stopped', 'budget_paused', 'paused', 'running']) {
    assert.equal(determineExitCode([], 'high', incomplete), 1, `incomplete run (${incomplete}) must exit 1`)
  }
})


// ============================================================================
// Part B — RequestBroker v3, Surface/Template Engines, Browser, WS, DNS Canary,
//          Replay Verifier v3, and SQLite v2->v3 Compatibility
// ============================================================================

function makeLabGrant(origin: string, overrides: Partial<Grant> = {}): Grant {
  return {
    origin,
    tier: 2,
    maxRpsPerOrigin: 30,
    allowLocalLab: true,
    canRead: o => o === origin,
    audit: () => {},
    ...overrides,
  }
}

test('B1 surface-engine & safe templates: 100% broker-routed, SPA calibration, circuit-breaker stop, non-destructive denylist, template safety validation', async t => {
  const lab = await createSuiteBLab()
  t.after(() => lab.close())

  // All shipped YAML templates load cleanly with zero validation errors
  const loaded = loadSafeTemplates({ refresh: true })
  assert.equal(loaded.errors.length, 0, `Template errors: ${JSON.stringify(loaded.errors)}`)
  assert.ok(loaded.templates.length >= 25, `Expected >=25 templates, got ${loaded.templates.length}`)

  // Unsafe templates are rejected at parse/load time (mutating without Tier 3, internal IP, third-party OAST, missing control/spaExclusion)
  assert.throws(() => parseSafeTemplateYaml([
    'id: bad-mutating-template',
    'name: Mutating without Tier 3',
    'severity: high',
    'description: Should fail because POST requires requiresTier3',
    'tech: [generic]',
    'spaExclusion: true',
    'request:',
    '  method: POST',
    '  path: /api/test',
    'matchers:',
    '  - type: word',
    '    words: [ok]',
  ].join('\n')), TemplateValidationError)

  assert.throws(() => parseSafeTemplateYaml([
    'id: bad-oast-template',
    'name: Third-party callback template',
    'severity: high',
    'description: Should fail because third-party callback domains are forbidden',
    'tech: [generic]',
    'spaExclusion: true',
    'request:',
    '  method: GET',
    '  path: /api/check?u=https://x.interact.sh/abc',
    'matchers:',
    '  - type: word',
    '    words: [ok]',
  ].join('\n')), TemplateValidationError)

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const grant = makeLabGrant(lab.origin, { tier: 2 })
    const sig = AbortSignal.timeout(30_000)

    // Tier 0 blocks active discovery
    await assert.rejects(
      probeSurface({ origin: lab.origin, mode: 'paths', paths: ['/health'] }, broker, makeLabGrant(lab.origin, { tier: 0 }), sig),
      BrokerDenied,
    )

    // Out-of-scope origin blocked
    await assert.rejects(
      probeSurface({ origin: 'http://127.0.0.1:9', mode: 'paths', paths: ['/health'] }, broker, grant, sig),
      BrokerDenied,
    )

    // SPA catch-all calibration suppresses /actuator/env (200 index.html) while surfacing distinct /health & /api/me
    const surf = await probeSurface({
      origin: lab.origin,
      mode: 'paths',
      paths: ['/health', '/api/me', '/actuator/env', '/nonexistent-spa-route'],
    }, broker, grant, sig)
    assert.equal(surf.calibration?.spaCatchall, true, 'SPA catch-all must be detected by calibration')
    assert.ok(surf.anomalies.some(a => a.path === '/health'), 'distinct /health endpoint must be reported')
    assert.ok(!surf.anomalies.some(a => a.path === '/actuator/env'), 'SPA catch-all /actuator/env must be suppressed')

    // Vetted template run suppresses SPA catch-all decoys and surfaces CVE-2025-29927 only as hypothesis/lead
    const tmpl = await runSafeTemplates({
      origin: lab.origin,
      techFingerprint: ['nextjs', 'springboot'],
      maxTemplates: 20,
    }, broker, grant, undefined, sig)
    assert.ok(tmpl.matches.every(m => m.factKind === 'cve_hypothesis' || m.factKind === 'candidate_lead'))
    assert.ok(!tmpl.matches.some(m => m.path === '/actuator/env'), 'SPA catch-all decoy must not match templates')

    // Circuit breaker: 5xx spike aborts probeSurface immediately
    let fiveXXCount = 0
    const errServer = createServer((_req, res) => {
      fiveXXCount += 1
      res.writeHead(503, { 'Content-Type': 'text/plain' }).end('service unavailable')
    }).listen(0, '127.0.0.1')
    await once(errServer, 'listening')
    t.after(() => { errServer.closeAllConnections(); return new Promise<void>(r => errServer.close(() => r())) })
    const errAddr = errServer.address()
    if (!errAddr || typeof errAddr === 'string') throw new Error('no address')
    const errOrigin = `http://127.0.0.1:${errAddr.port}`
    const cbBroker = new RequestBroker({ circuit5xxThreshold: 5, circuitWindowMs: 30_000 })
    const cbRes = await probeSurface({
      origin: errOrigin,
      mode: 'paths',
      paths: Array.from({ length: 40 }, (_, i) => `/p${i}`),
    }, cbBroker, makeLabGrant(errOrigin, { tier: 1, maxRpsPerOrigin: 50 }), sig)
    assert.equal(cbRes.stoppedReason, 'circuit_open', 'probeSurface must stop cleanly when circuit breaker opens')
    assert.ok(fiveXXCount < 15, `circuit breaker must halt probing early (sent ${fiveXXCount})`)
  })
})

test('B2 RequestBroker v3: DELETE & multipart/form-data hard-blocked at Tiers 0-2, HITL-gated at Tier 3, size/filter checked', async t => {
  const lab = await createSuiteBLab()
  t.after(() => lab.close())

  const personas = new Map<string, ResolvedPersona>([
    ['user_a', {
      id: 'pa', handle: 'user_a', roleLabel: 'User A', authKind: 'bearer', headerName: 'Authorization',
      originAllowlist: [lab.origin], secret: LAB_PERSONA_A_TOKEN, canaryMarkers: [],
    }],
  ])

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const sig = AbortSignal.timeout(15_000)

    // DELETE hard-blocked at Tiers 0, 1, 2
    for (const tier of [0, 1, 2] as const) {
      await assert.rejects(
        broker.executeHttp({ origin: lab.origin, method: 'DELETE', pathAndQuery: '/api/orgs/org-a/members/mem_a_2', persona: tier >= 2 ? 'user_a' : undefined }, makeLabGrant(lab.origin, { tier, personas }), sig),
        BrokerDenied,
        `DELETE must be denied at Tier ${tier}`,
      )
    }

    // DELETE HITL-gated at Tier 3 when isStateChangeApproved returns false
    await assert.rejects(
      broker.executeHttp(
        { origin: lab.origin, method: 'DELETE', pathAndQuery: '/api/orgs/org-a/members/mem_a_2', persona: 'user_a' },
        makeLabGrant(lab.origin, { tier: 3, personas, isStateChangeApproved: () => false }),
        sig,
      ),
      BrokerApprovalRequired,
    )

    // DELETE succeeds at Tier 3 when approved
    const delRes = await broker.executeHttp(
      { origin: lab.origin, method: 'DELETE', pathAndQuery: '/api/orgs/org-a/members/mem_a_2', persona: 'user_a' },
      makeLabGrant(lab.origin, { tier: 3, personas, isStateChangeApproved: () => true }),
      sig,
    )
    assert.equal(delRes.status, 200)
    assert.ok(!delRes.body.includes(LAB_PERSONA_A_TOKEN))

    // multipart/form-data hard-blocked at Tiers 0-2 and HITL-gated at Tier 3
    const benignPart = [{ name: 'file', filename: 'note.svg', contentType: 'image/svg+xml', content: '<svg xmlns="http://www.w3.org/2000/svg"><text>benign</text></svg>' }]
    for (const tier of [0, 1, 2] as const) {
      await assert.rejects(
        broker.executeHttp({ origin: lab.origin, method: 'POST', pathAndQuery: '/api/uploads', multipartParts: benignPart }, makeLabGrant(lab.origin, { tier }), sig),
        BrokerDenied,
        `multipart must be denied at Tier ${tier}`,
      )
    }
    await assert.rejects(
      broker.executeHttp({ origin: lab.origin, method: 'POST', pathAndQuery: '/api/uploads', multipartParts: benignPart }, makeLabGrant(lab.origin, { tier: 3, isStateChangeApproved: () => false }), sig),
      BrokerApprovalRequired,
    )

    // Blocked active-script upload signature & >256 KiB upload cap
    const blockedMarker = ['<', '?php echo 1; ?', '>'].join('')
    await assert.rejects(
      broker.executeHttp(
        { origin: lab.origin, method: 'POST', pathAndQuery: '/api/uploads', multipartParts: [{ name: 'file', filename: 'x.txt', contentType: 'text/plain', content: blockedMarker }] },
        makeLabGrant(lab.origin, { tier: 3, isStateChangeApproved: () => true }),
        sig,
      ),
      BrokerDenied,
    )
    await assert.rejects(
      broker.executeHttp(
        { origin: lab.origin, method: 'POST', pathAndQuery: '/api/uploads', multipartParts: [{ name: 'file', filename: 'big.txt', contentType: 'text/plain', content: 'A'.repeat(260 * 1024) }] },
        makeLabGrant(lab.origin, { tier: 3, isStateChangeApproved: () => true }),
        sig,
      ),
      BrokerDenied,
    )

    // Benign Tier-3 approved multipart upload succeeds
    const upRes = await broker.executeHttp(
      { origin: lab.origin, method: 'POST', pathAndQuery: '/api/uploads', multipartParts: benignPart },
      makeLabGrant(lab.origin, { tier: 3, isStateChangeApproved: () => true }),
      sig,
    )
    assert.equal(upRes.status, 201)
  })
})

test('B3 probeWebsocket & interactive ScopedBrowser: 100% broker-proxied, origin/scope enforced, sink hook active, secrets redacted', async t => {
  const lab = await createSuiteBLab()
  t.after(() => lab.close())

  const personas = new Map<string, ResolvedPersona>([
    ['user_a', {
      id: 'pa', handle: 'user_a', roleLabel: 'User A', authKind: 'bearer', headerName: 'Authorization',
      originAllowlist: [lab.origin], secret: LAB_PERSONA_A_TOKEN, canaryMarkers: [],
    }],
  ])

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const sig = AbortSignal.timeout(30_000)

    // WebSocket blocked at Tier 0 & out-of-scope
    await assert.rejects(
      broker.probeWebsocket({ origin: lab.origin, pathAndQuery: '/ws/notifications' }, makeLabGrant(lab.origin, { tier: 0 }), sig),
      BrokerDenied,
    )
    await assert.rejects(
      broker.probeWebsocket({ origin: 'http://127.0.0.1:9', pathAndQuery: '/ws/notifications' }, makeLabGrant(lab.origin, { tier: 2 }), sig),
      BrokerDenied,
    )

    // Live WebSocket probe through RequestBroker with persona auth + custom Origin header
    const wsRes = await broker.probeWebsocket({
      origin: lab.origin,
      pathAndQuery: '/ws/notifications',
      originHeader: 'https://evil.invalid',
      persona: 'user_a',
      sendMessages: ['ping-check'],
      maxFrames: 4,
      timeoutMs: 2_500,
    }, makeLabGrant(lab.origin, { tier: 2, personas }), sig)
    assert.equal(wsRes.connected, true, `WS should connect: ${wsRes.error ?? ''}`)
    assert.equal(wsRes.upgradeStatus, 101)
    assert.ok(wsRes.receivedFrames >= 1, 'should receive initial account frame')
    assert.ok(wsRes.frames.some(f => f.data.includes('user_a')), 'persona auth must reach WS handshake')
    assert.ok(!JSON.stringify(wsRes).includes(LAB_PERSONA_A_TOKEN), 'persona token must never leak in WS result')

    // Interactive ScopedBrowser: 100% broker-proxied page with external third-party script blocked + fill/click/sink hook
    let thirdPartyHit = false
    const thirdParty = createServer((_req, res) => {
      thirdPartyHit = true
      res.writeHead(200, { 'Content-Type': 'application/javascript' }).end('window.__thirdParty = 1;')
    }).listen(0, '127.0.0.1')
    await once(thirdParty, 'listening')
    t.after(() => { thirdParty.closeAllConnections(); return new Promise<void>(r => thirdParty.close(() => r())) })
    const tpAddr = thirdParty.address()
    if (!tpAddr || typeof tpAddr === 'string') throw new Error('no address')
    const tpOrigin = `http://127.0.0.1:${tpAddr.port}`

    const interactiveApp = createServer((req, res) => {
      if (req.url === '/api/ping') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ pong: true }))
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(`<!doctype html><html><body>
        <script src="${tpOrigin}/evil.js"></script>
        <input id="q" />
        <button id="go">Go</button>
        <div id="sink"></div>
        <script>
          document.getElementById('go').addEventListener('click', () => {
            const v = document.getElementById('q').value;
            document.getElementById('sink').innerHTML = '<span>' + v + '</span>';
            fetch('/api/ping');
          });
        </script>
      </body></html>`)
    }).listen(0, '127.0.0.1')
    await once(interactiveApp, 'listening')
    t.after(() => { interactiveApp.closeAllConnections(); return new Promise<void>(r => interactiveApp.close(() => r())) })
    const iaAddr = interactiveApp.address()
    if (!iaAddr || typeof iaAddr === 'string') throw new Error('no address')
    const iaOrigin = `http://127.0.0.1:${iaAddr.port}`

    const browser = new ScopedBrowser(broker)
    const canary = 'kovoSinkMarker9876'
    const visit = await browser.visitPage({
      origin: iaOrigin,
      pathAndQuery: '/',
      canaryToken: canary,
      enableSinkHook: true,
      actions: [
        { type: 'fill', selector: '#q', value: canary },
        { type: 'click', selector: '#go' },
        { type: 'wait_for_xhr', urlPattern: '/api/ping', timeoutMs: 4_000 },
        { type: 'evaluate_builtin', builtinCheck: 'dom_sinks' },
      ],
      timeoutMs: 20_000,
    }, makeLabGrant(iaOrigin, { tier: 2 }), sig)

    assert.equal(thirdPartyHit, false, 'unapproved third-party origin must NEVER be dialed directly')
    assert.ok(visit.blockedOrigins.includes(tpOrigin), 'unapproved third-party origin must appear in blockedOrigins')
    assert.ok(visit.exchanges.length >= 2, 'document and XHR must be fulfilled through RequestBroker')
    assert.ok(visit.domSinkTraces.some(tr => tr.sink === 'innerHTML' && tr.containsCanary), 'dom_xss_sink_hook must capture innerHTML canary trace')
    assert.ok(visit.actionResults?.every(r => r.ok), `all safe browser actions must succeed: ${JSON.stringify(visit.actionResults)}`)
  })
})

test('B4 dual HTTP + authoritative UDP DNS CanaryBroker receives both protocols and shuts down cleanly', async t => {
  const canaryBroker = new CanaryBroker({ dnsDomain: 'canary.local.invalid' })
  t.after(() => canaryBroker.stopListener())

  const info = await canaryBroker.startListener({
    host: '127.0.0.1', port: 0,
    enableDns: true, dnsHost: '127.0.0.1', dnsPort: 0, dnsSinkIp: '127.0.0.1',
  })
  assert.equal(info.running, true)
  assert.equal(info.dnsRunning, true)
  assert.ok(info.dnsPort && info.dnsPort > 0)

  const minted = canaryBroker.mintCanary(randomUUID(), 'dual-oob', 'http://127.0.0.1:8080')
  assert.equal(minted.listenerActive, true)
  assert.equal(minted.dnsListenerActive, true)

  // Real UDP DNS lookup against CanaryBroker authoritative DNS listener
  const resolver = new Resolver({ timeout: 2_000, tries: 1 })
  resolver.setServers([`127.0.0.1:${info.dnsPort}`])
  const answers = await resolver.resolve4(minted.dnsHost)
  assert.deepEqual(answers, ['127.0.0.1'])

  // Real HTTP callback against CanaryBroker HTTP listener
  const resp = await fetch(minted.httpUrl, { method: 'GET' })
  assert.equal(resp.status, 200)

  const check = canaryBroker.checkCanary(minted.token)
  assert.equal(check.hit, true)
  assert.ok(check.hits.some(h => h.protocol === 'dns' && h.queryType === 'A'), 'must record DNS A hit')
  assert.ok(check.hits.some(h => h.protocol === 'http'), 'must record HTTP hit')

  await canaryBroker.stopListener()
  const after = canaryBroker.listenerInfo()
  assert.equal(after.running, false)
  assert.equal(after.dnsRunning, false)
})

test('B5 ReplayVerifier v3: static_ast_proof strictly static_verified (never confirmed); requireControlNonError returns inconclusive on unexpected 404/5xx', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-v3-ver-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const reposDir = join(root, 'repos')
  mkdirSync(reposDir)
  createSuiteBMockRepo(reposDir)

  const backend = new LinuxWorkerBackend()
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const sig = AbortSignal.timeout(90_000)

  // 1. static_ast_proof works in Tier 0 and NEVER produces verdict === 'confirmed'
  const staticRes = await verifyReplaySpec({
    spec: {
      version: 1,
      kind: 'static_ast_proof',
      origin: 'https://static-analysis.invalid',
      title: 'Unparameterized SQL string interpolation',
      category: 'injection-input',
      cwe: 'CWE-89',
      severity: 'high',
      severityRationale: 'Direct template interpolation into SQL query string.',
      impact: 'Untrusted filter can alter SQL WHERE predicate.',
      remediation: 'Use parameterized queries.',
      recheckInstructions: 'Re-run static AST proof after parameterizing.',
      repo: 'northstar-app',
      file: 'src/routes/search.ts',
      startLine: 1,
      endLine: 5,
      engine: 'ast-grep',
      ruleOrPattern: 'const sql = `$$$`',
      runtimeProofGap: 'Verified offline via AST re-execution without runtime execution.',
      assertionsJq: '{ controlPassed: .static.verified, confirmed: (.static.verified and .static.matchCount >= 1), observed: ("matches=" + (.static.matchCount | tostring)), expected: "no SQL string interpolation" }',
    },
    broker,
    backend,
    reposDir,
    grant: makeLabGrant('https://static-analysis.invalid', { tier: 0, allowLocalLab: false }),
    signal: sig,
  })
  assert.equal(staticRes.verdict, 'static_verified', `static_ast_proof must return static_verified, got ${staticRes.verdict}: ${staticRes.outcome.observed}`)
  assert.notEqual(staticRes.verdict as string, 'confirmed', 'static_ast_proof must NEVER promote to confirmed')
  assert.equal(staticRes.verificationTier, 'static_verified')

  // 2. requireControlNonError guardrail: unexpected 404 on a posture spec returns inconclusive (prevents dyad-v2-smoke 404 false retests)
  const err404 = createServer((_req, res) => {
    res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not Found')
  }).listen(0, '127.0.0.1')
  await once(err404, 'listening')
  t.after(() => { err404.closeAllConnections(); return new Promise<void>(r => err404.close(() => r())) })
  const addr404 = err404.address()
  if (!addr404 || typeof addr404 === 'string') throw new Error('no address')
  const origin404 = `http://127.0.0.1:${addr404.port}`

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const posture404 = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: origin404,
        title: 'Header posture check on missing page',
        category: 'misconfig-exposure',
        cwe: 'CWE-693',
        severity: 'low',
        severityRationale: 'Missing security header.',
        impact: 'Reduced browser hardening.',
        remediation: 'Add security header.',
        recheckInstructions: 'Verify header on 200 response.',
        steps: [
          { id: 'control', role: 'control', description: 'Baseline GET', request: { origin: origin404, method: 'GET', pathAndQuery: '/missing' } },
          { id: 'probe', role: 'probe', description: 'Probe GET', request: { origin: origin404, method: 'GET', pathAndQuery: '/missing' } },
        ],
        assertionsJq: '{ controlPassed: true, confirmed: ((.steps.probe.headers["content-security-policy"] // "") == ""), observed: "no csp", expected: "csp present" }',
      },
      broker,
      backend,
      grant: makeLabGrant(origin404, { tier: 1 }),
      signal: sig,
    })
    assert.equal(posture404.verdict, 'inconclusive', `unexpected 404 posture check must return inconclusive, got ${posture404.verdict}`)
  })
})

test('B6 v2->v3 SQLite auto-migration & Store 3-state closure persistence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v3-store-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const v2SmokeDb = join(repoRootDir, '.kovo', 'dyad-v2-smoke', 'data', 'kovo.sqlite')

  // If the read-only v2 smoke DB exists, copy it to /tmp and verify lossless v3 auto-migration (NEVER touching original!)
  if (existsSync(v2SmokeDb)) {
    const copyDir = join(dir, 'v2-copy')
    mkdirSync(copyDir)
    copyFileSync(v2SmokeDb, join(copyDir, 'kovo.sqlite'))
    const migrated = new Store(copyDir)
    t.after(() => migrated.close())
    const { projects } = migrated.listWorkspace()
    assert.ok(projects.length > 0, 'migrated v2 DB must preserve existing projects')
  }

  // Fresh Store: verify v3 tables & openProofGaps
  const freshDir = join(dir, 'fresh')
  mkdirSync(freshDir)
  const store = new Store(freshDir)
  t.after(() => store.close())
  const { id: projectId } = store.createProject({ requestId: randomUUID(), name: 'Closure Test', seeds: ['https://closure.example'], environment: 'public' })
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Verify closure ledger', sourceMode: 'public',
    capabilityTier: 1, budgetUsd: 1, budgetRequests: 50, maxRpsPerOrigin: 5, workerConcurrency: 2, workerMaxTurns: 10,
  })
  const run = store.run(runId)
  store.upsertCoverageEntry(run, 'assign-closure-1', {
    origin: 'https://closure.example', category: 'upload-storage', status: 'needs_follow_up',
    summary: 'Upload form requires Tier 3 approval', proofGapReason: 'Requires Tier 3 multipart HITL approval',
  })
  const gaps = store.listOpenProofGaps(runId)
  assert.equal(gaps.length, 1)
  assert.equal(gaps[0].proofGapReason, 'Requires Tier 3 multipart HITL approval')
})
