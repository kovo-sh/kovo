// @kernel @fixes R3-H-7
/**
 * R3-H-7 Regression Tests — Authoritative POSIX single-quote shell escaping
 * for Copy-as-cURL (`formatExchangeAsCurl`) and receipt reproducer (`buildCommandHint`).
 *
 * Verifies under real `/bin/sh` with a stubbed `curl` binary in `PATH`:
 *  1. `quotePosixShellArg` neutralizes NUL bytes and quotes all shell metacharacters safely.
 *  2. `normalizeCurlHttpMethod` restricts methods strictly to the `HttpMethod` enum.
 *  3. Adversarial paths, header names, header values, persona handles, methods, and bodies
 *     containing single quotes, double quotes, `$()`, backticks, `$VAR`, `;`, `|`, `&`,
 *     spaces, and newlines NEVER execute shell commands and arrive as exact single `argv` elements.
 *  4. End-to-end signed receipt bundle export (`exportRunReceiptBundle`) produces a safe
 *     `reproducer.commandHint` that preserves exact `argv` under `/bin/sh`.
 *  5. Static invariants: `curl-parser.ts` remains browser-safe (zero `node:*` imports) and
 *     `receipt-export.ts` shares the single authoritative helper with zero double-quoted curl templates.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  formatExchangeAsCurl,
  normalizeCurlHttpMethod,
  quotePosixShellArg,
  tokenizeShellArgs,
} from '../src/components/curl-parser.ts'
import { httpMethods } from '../src/domain.ts'
import {
  buildCommandHint,
  exportRunReceiptBundle,
  verifyProofReceiptBundle,
} from '../src/server/receipt-export.ts'
import { findings as findingsTable, replaySpecs } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

interface StubCurlHarness {
  dir: string
  sentinelPath: string
  runShell: (command: string) => { argv: string[] | null; stdout: string }
}

function createStubCurlHarness(t: { after: (fn: () => void) => void }): StubCurlHarness {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-curl-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const binDir = join(dir, 'bin')
  mkdirSync(binDir, { recursive: true })
  const argvFile = join(dir, 'argv.json')
  const sentinelPath = join(dir, 'sentinel-must-not-exist')

  const stubScript = [
    `#!${process.execPath}`,
    "const fs = require('node:fs')",
    'fs.writeFileSync(process.env.KOVO_STUB_ARGV_FILE, JSON.stringify(process.argv.slice(2)), "utf8")',
  ].join('\n') + '\n'
  const stubPath = join(binDir, 'curl')
  writeFileSync(stubPath, stubScript, { mode: 0o755 })
  chmodSync(stubPath, 0o755)

  return {
    dir,
    sentinelPath,
    runShell(command: string) {
      rmSync(argvFile, { force: true })
      const stdout = execFileSync('/bin/sh', ['-c', command], {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${binDir}:${process.env.PATH ?? '/usr/bin:/bin'}`,
          KOVO_STUB_ARGV_FILE: argvFile,
          KOVO_SENTINEL: sentinelPath,
        },
      })
      const argv = existsSync(argvFile) ? (JSON.parse(readFileSync(argvFile, 'utf8')) as string[]) : null
      return { argv, stdout }
    },
  }
}

function buildAdversarialToken(sentinelPath: string, tag: string): string {
  // Construct test input systematically across all POSIX shell metacharacter classes:
  // single quote, double quote, $(), backticks, $VAR, ;, |, &, spaces, tabs, and newlines.
  const parts = [
    tag,
    `'`,
    `"`,
    `$(touch ${sentinelPath})`,
    `\`touch ${sentinelPath}\``,
    `$KOVO_SENTINEL`,
    `\${KOVO_SENTINEL}`,
    `; touch ${sentinelPath} ;`,
    `| touch ${sentinelPath}`,
    `& touch ${sentinelPath}`,
    `a b\tc`,
    `line1\nline2`,
  ]
  return parts.join('_')
}

// ============================================================================
// 1. Unit tests for quotePosixShellArg & normalizeCurlHttpMethod
// ============================================================================

test('R3-H-7: quotePosixShellArg wraps in single quotes, escapes single quotes, and strips NUL bytes', () => {
  assert.equal(quotePosixShellArg(''), "''")
  assert.equal(quotePosixShellArg('plain'), "'plain'")
  assert.equal(quotePosixShellArg("a'b"), "'a'\\''b'")
  assert.equal(quotePosixShellArg("'''"), "''\\'''\\'''\\'''")
  assert.equal(quotePosixShellArg('a\0b\0c'), "'abc'")
  assert.equal(quotePosixShellArg('"$HOME" $(id) `id` ; | &'), '\'"$HOME" $(id) `id` ; | &\'')
})

test('R3-H-7: normalizeCurlHttpMethod restricts strictly to HttpMethod enum and defaults invalid methods to GET', () => {
  for (const m of httpMethods) {
    assert.equal(normalizeCurlHttpMethod(m), m)
    assert.equal(normalizeCurlHttpMethod(`  ${m.toLowerCase()}  `), m)
  }
  const invalidMethods: Array<string | null | undefined> = [
    '',
    '   ',
    null,
    undefined,
    'WS',
    'TRACE',
    'CONNECT',
    'GET; touch /tmp/x',
    'POST $(id)',
    "GET' ; id #",
    'GET\nPOST',
    'GET\0POST',
  ]
  for (const bad of invalidMethods) {
    assert.equal(normalizeCurlHttpMethod(bad), 'GET', `invalid method ${JSON.stringify(bad)} must default to GET`)
  }
})

// ============================================================================
// 2. Stubbed-curl `/bin/sh` execution for formatExchangeAsCurl
// ============================================================================

test('R3-H-7: formatExchangeAsCurl blocks all shell injection classes and preserves exact single argv elements under /bin/sh', (t) => {
  const harness = createStubCurlHarness(t)
  const origin = 'https://app.example.test'
  const rawPath = `/api/v1/items/${buildAdversarialToken(harness.sentinelPath, 'path')}\0tail?q=${buildAdversarialToken(harness.sentinelPath, 'query')}`
  const expectedUrl = `${origin}${rawPath}`.replace(/\0/g, '')

  const advHeaderName = `X-${buildAdversarialToken(harness.sentinelPath, 'hdr-key')}`
  const advHeaderVal = buildAdversarialToken(harness.sentinelPath, 'hdr-val')
  const advPersona = buildAdversarialToken(harness.sentinelPath, 'persona')
  const advBody = JSON.stringify({ payload: buildAdversarialToken(harness.sentinelPath, 'body') }) + "\0"

  const cmd = formatExchangeAsCurl({
    method: `POST; touch ${harness.sentinelPath}`,
    origin,
    pathAndQuery: rawPath,
    reqHeaders: {
      Host: 'app.example.test',
      [advHeaderName]: advHeaderVal,
      'X-Simple': "v1'v2\"v3",
    },
    personaHandle: advPersona,
    body: advBody,
  })

  const { argv } = harness.runShell(cmd)
  assert.equal(existsSync(harness.sentinelPath), false, 'no injected shell command may execute')
  assert.deepEqual(argv, [
    '-i',
    '-X',
    'GET',
    expectedUrl,
    '-H',
    `${advHeaderName}: ${advHeaderVal}`,
    '-H',
    `X-Simple: v1'v2"v3`,
    '-H',
    `Cookie: [persona:${advPersona}:secret]`,
    '--data-raw',
    advBody.replace(/\0/g, ''),
  ])

  // Also verify valid methods pass through uppercased and round-trip cleanly via tokenizeShellArgs
  for (const m of httpMethods) {
    const validCmd = formatExchangeAsCurl({
      method: m.toLowerCase(),
      origin,
      pathAndQuery: "/safe/item'1?k=v",
      reqHeaders: { 'X-Check': 'ok' },
    })
    const res = harness.runShell(validCmd)
    assert.deepEqual(res.argv, ['-i', '-X', m, `${origin}/safe/item'1?k=v`, '-H', 'X-Check: ok'])
    assert.deepEqual(tokenizeShellArgs(validCmd), ['curl', '-i', '-X', m, `${origin}/safe/item'1?k=v`, '-H', 'X-Check: ok'])
  }
})

// ============================================================================
// 3. Stubbed-curl `/bin/sh` execution for buildCommandHint
// ============================================================================

test('R3-H-7: buildCommandHint eliminates double quotes, blocks command substitution, and preserves exact argv under /bin/sh', (t) => {
  const harness = createStubCurlHarness(t)
  const origin = 'https://target.example.test'
  const rawPath = `/v2/search?q=${buildAdversarialToken(harness.sentinelPath, 'hint-path')}\0end`
  const expectedUrl = `${origin}${rawPath}`.replace(/\0/g, '')

  const advHeaderName = `X-${buildAdversarialToken(harness.sentinelPath, 'hint-hkey')}`
  const advHeaderVal = buildAdversarialToken(harness.sentinelPath, 'hint-hval')
  const advPersona = buildAdversarialToken(harness.sentinelPath, 'hint-persona')
  const advBody = `body=${buildAdversarialToken(harness.sentinelPath, 'hint-body')}`

  const cmd = buildCommandHint([
    {
      method: 'GET',
      origin,
      pathAndQuery: '/setup',
      personaHandle: null,
      headers: {},
      observedStatus: 200,
    },
    {
      method: `$(touch ${harness.sentinelPath})`,
      origin,
      pathAndQuery: rawPath,
      personaHandle: advPersona,
      headers: {
        Host: 'target.example.test',
        Authorization: '[redacted]',
        [advHeaderName]: advHeaderVal,
      },
      observedStatus: 200,
      body: advBody,
    },
  ])

  const { argv } = harness.runShell(cmd)
  assert.equal(existsSync(harness.sentinelPath), false, 'no injected shell command may execute from commandHint')
  assert.deepEqual(argv, [
    '-i',
    '-X',
    'GET',
    '-H',
    `Authorization: Bearer <token:${advPersona}>`,
    '-H',
    `${advHeaderName}: ${advHeaderVal}`,
    '--data-raw',
    advBody,
    expectedUrl,
  ])

  // Empty steps return a shell comment that never invokes curl
  const emptyHint = buildCommandHint([])
  assert.equal(emptyHint, '# No HTTP exchange recorded for this receipt.')
  const emptyRes = harness.runShell(emptyHint)
  assert.equal(emptyRes.argv, null)
  assert.equal(existsSync(harness.sentinelPath), false)
})

// ============================================================================
// 4. End-to-end exportRunReceiptBundle commandHint safety
// ============================================================================

test('R3-H-7: exportRunReceiptBundle emits a shell-safe commandHint for adversarial recorded exchanges', (t) => {
  const prevLocalLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLocalLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLocalLab
  })

  const harness = createStubCurlHarness(t)
  const dataDir = mkdtempSync(join(tmpdir(), 'kovo-r3-curl-store-'))
  t.after(() => rmSync(dataDir, { recursive: true, force: true }))
  const storage = new Store(dataDir)
  t.after(() => storage.close())

  const origin = 'http://127.0.0.1:4907'
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'R3-H-7 Receipt Curl Escaping',
    seeds: [origin],
    environment: 'local-lab',
  })
  const run = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify receipt commandHint quoting',
    sourceMode: 'public',
    capabilityTier: 1,
    budgetUsd: 1,
    budgetRequests: 10,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 3,
  })
  storage.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })
  const asset = storage.run(run.id).candidates[0]!
  storage.command({
    requestId: randomUUID(),
    runId: run.id,
    action: 'scope',
    expectedScopeRevision: 0,
    assetIds: [asset.id],
    consent: true,
    capabilityTier: 1,
  })
  const hydratedRun = storage.run(run.id)
  const worker = storage.makeWorker(hydratedRun, 'investigation', asset, 'Probe', 'R3-H-7 worker')

  const advPath = `/api/records/${buildAdversarialToken(harness.sentinelPath, 'e2e-path')}`
  const advHdrKey = `X-${buildAdversarialToken(harness.sentinelPath, 'e2e-key')}`
  const advHdrVal = buildAdversarialToken(harness.sentinelPath, 'e2e-val')

  const ex = storage.recordExchange({
    runId: hydratedRun.id,
    assignmentId: worker.id,
    scopeRevision: hydratedRun.scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [],
    method: 'PATCH',
    pathAndQuery: advPath,
    personaHandle: "bob'$(id)",
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {
      Host: '127.0.0.1:4907',
      [advHdrKey]: advHdrVal,
    },
    respHeaders: { 'content-type': 'application/json' },
    body: '{"ok":true}',
    durationMs: 3,
  })

  const findingId = randomUUID()
  const specId = randomUUID()
  const now = Date.now()
  storage.db.insert(replaySpecs).values({
    id: specId,
    runId: hydratedRun.id,
    findingId,
    assignmentId: worker.id,
    scopeRevision: hydratedRun.scopeRevision,
    goalRevision: 0,
    spec: {
      kind: 'idor',
      origin,
      pathAndQuery: advPath,
    } as never,
    specSha256: createHash('sha256').update(specId).digest('hex'),
    sourceOrigins: [origin],
    lastVerificationDiff: { verdict: 'confirmed' } as never,
    proofKind: 'agent_script',
    proofVerdict: 'confirmed',
    proofRuntime: 'ts',
    proofScriptSha256: createHash('sha256').update('verify-r3-h-7').digest('hex'),
    proofArtifactId: null,
    proofReceipt: {
      receipt: {
        vulnClass: 'bola',
        target: { origin, method: 'PATCH', pathAndQuery: advPath },
        exchangeIds: [ex.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Unauthorized patch succeeded',
      },
      verification: {
        confirmed: true,
        vulnClass: 'bola',
        rule: 'test:r3-h-7',
        reason: 'Confirmed',
        observed: '200 OK',
        expected: '403 Forbidden',
      },
    } as never,
    createdAt: now,
  }).run()

  storage.db.insert(findingsTable).values({
    id: findingId,
    runId: hydratedRun.id,
    assetId: asset.id,
    goalRevision: 0,
    checkId: 'chain',
    caseId: 'r3-h-7-case',
    findingKind: 'multi_step_chain',
    replaySpecId: specId,
    provenance: 'floor',
    verificationClass: 'runtime_confirmed',
    sourceOrigins: [origin],
    verificationTier: 'runtime_confirmed',
    fingerprintHash: createHash('sha256').update(`r3-h-7:${origin}`).digest('hex'),
    finding: {
      id: findingId,
      origin,
      title: 'R3-H-7 test finding',
      cwe: 'CWE-639',
      category: 'broken-access-control',
      severity: 'medium',
      status: 'confirmed',
      reason: 'Confirmed for R3-H-7 test.',
      verification: 'ProofReceipt: r3-h-7',
      remediation: 'Fix authz.',
      evidenceIds: [],
      exchangeIds: [ex.id],
      scopeRevision: hydratedRun.scopeRevision,
      replaySpecId: specId,
    } as never,
  }).run()

  const secret = 'r3-h-7-hmac-test-secret'
  const bundle = exportRunReceiptBundle(storage, hydratedRun.id, {
    signing: { algorithm: 'hmac-sha256', secret },
  })
  assert.equal(verifyProofReceiptBundle(bundle, { secret }).valid, true)
  assert.equal(bundle.payload.records.length, 1)

  const commandHint = bundle.payload.records[0]!.reproducer.commandHint
  const { argv } = harness.runShell(commandHint)
  assert.equal(existsSync(harness.sentinelPath), false, 'exported receipt commandHint must never execute shell commands')
  assert.deepEqual(argv, [
    '-i',
    '-X',
    'PATCH',
    '-H',
    "Authorization: Bearer <token:bob'$(id)>",
    '-H',
    `${advHdrKey}: ${advHdrVal}`,
    `${origin}${advPath}`,
  ])
})

// ============================================================================
// 5. Static invariants (browser bundle safety + single authoritative path)
// ============================================================================

test('R3-H-7: static guards enforce browser-safe curl-parser.ts and single POSIX quoting path in receipt-export.ts', () => {
  const curlParserSrc = readFileSync(join(repoRoot, 'src/components/curl-parser.ts'), 'utf8')
  const receiptExportSrc = readFileSync(join(repoRoot, 'src/server/receipt-export.ts'), 'utf8')

  assert.equal(/from\s+['"]node:/.test(curlParserSrc), false, 'curl-parser.ts must have zero node:* imports for browser bundle')
  assert.match(receiptExportSrc, /import\s*\{[^}]*quotePosixShellArg[^}]*\}\s*from\s*['"]\.\.\/components\/curl-parser\.ts['"]/)
  assert.match(receiptExportSrc, /import\s*\{[^}]*normalizeCurlHttpMethod[^}]*\}\s*from\s*['"]\.\.\/components\/curl-parser\.ts['"]/)
  assert.equal(/curl -i -X \$\{(?!quotePosixShellArg\()/.test(receiptExportSrc), false, 'receipt-export.ts must never interpolate raw method into curl template')
  assert.equal(/curl -i -X \$\{(?!quotePosixShellArg\()/.test(curlParserSrc), false, 'curl-parser.ts must quote -X method via quotePosixShellArg')
  assert.equal(/ -H ['"]/.test(curlParserSrc), false, 'curl-parser.ts must never hand-quote -H arguments')
  assert.equal(/ -H ['"]/.test(receiptExportSrc), false, 'receipt-export.ts must never hand-quote -H arguments')
})
