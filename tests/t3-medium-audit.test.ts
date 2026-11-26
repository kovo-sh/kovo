import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'
import type { Finding } from '../src/domain.ts'
import { applyUnifiedDiffToDirectory } from '../src/server/lab-runner.ts'
import {
  checkModelConnection,
  computeCredentialEndpointPin,
  deleteModelProfile,
  privateModelProfiles,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import { generateAndReviewPatch, runPatchReviewer } from '../src/server/patch-workflow.ts'
import {
  exportRunReceiptBundle,
  getReceiptSigningPublicKey,
  loadOrCreateReceiptSigningKeyPair,
  verifyProofReceiptBundle,
} from '../src/server/receipt-export.ts'
import { buildSarifLog } from '../src/server/sarif-export.ts'
import { modelProfiles } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  UnifiedDiffError,
  parseUnifiedDiff,
  validateDiffPath,
  validateUnifiedDiff,
} from '../src/server/unified-diff.ts'

async function startCapturingProvider(): Promise<{
  endpoint: string
  seenAuthHeaders: string[]
  close: () => Promise<void>
}> {
  const seenAuthHeaders: string[] = []
  const server = createServer((req, res) => {
    seenAuthHeaders.push(String(req.headers.authorization ?? req.headers['x-api-key'] ?? ''))
    req.resume()
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.end([
        'event: response.completed',
        'data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}}',
        '',
      ].join('\n'))
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  return {
    endpoint: `http://127.0.0.1:${port}/v1`,
    seenAuthHeaders,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  }
}

function makeSampleFinding(repo: string, file: string, startLine = 2, endLine = 3): Finding & {
  codeLocations: Array<{ repo: string; file: string; startLine: number; endLine: number }>
} {
  return {
    id: `finding-${randomUUID().slice(0, 8)}`,
    origin: 'http://127.0.0.1:3000',
    title: 'Missing ownership enforcement',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    status: 'confirmed',
    reason: 'Record returned without verifying owner identity.',
    remediation: 'Verify record.ownerId matches current user.',
    evidenceIds: [],
    scopeRevision: 1,
    codeLocations: [{ repo, file, startLine, endLine }],
  }
}

// ============================================================================
// M-15: API-Key Endpoint/Protocol Pinning
// ============================================================================

test('M-15: stored model profile API key is pinned to (endpoint, protocol); changing either without a new key is rejected and never leaks the stored key', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m15-pin-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const legitProvider = await startCapturingProvider()
  const attackerProvider = await startCapturingProvider()
  t.after(async () => {
    await legitProvider.close()
    await attackerProvider.close()
  })

  const secretKey = 'sk-or-v1-pinned-secret-key-987654321'
  const saved = await saveModelProfile({
    name: 'Primary Provider',
    endpoint: legitProvider.endpoint,
    model: 'deepseek/deepseek-v4.1-flash-1017',
    protocol: 'responses',
    key: secretKey,
  }, storage, { skipConnectionCheck: true })

  // Verify 0600 pin file was written alongside credential file
  const row = storage.db.select().from(modelProfiles).where(eq(modelProfiles.id, saved.id)).get()!
  const pinPath = join(dir, 'credentials', `${row.credentialId}.pin`)
  assert.equal(existsSync(pinPath), true, 'expected .pin sidecar file')
  assert.equal(statSync(pinPath).mode & 0o077, 0, '.pin file must be 0600 owner-only')
  const pinData = JSON.parse(readFileSync(pinPath, 'utf8')) as { pinSha256: string }
  assert.equal(pinData.pinSha256, computeCredentialEndpointPin(legitProvider.endpoint, 'responses'))

  // 1. Attempting checkModelConnection against a DIFFERENT endpoint without a new key MUST reject
  //    and NEVER send the stored secret to attackerProvider.
  await assert.rejects(
    checkModelConnection({
      id: saved.id,
      name: 'Primary Provider',
      endpoint: attackerProvider.endpoint,
      model: 'deepseek/deepseek-v4.1-flash-1017',
      protocol: 'responses',
      key: '',
    }, storage),
    /endpoint or protocol requires re-entering the API key/i,
  )
  assert.equal(attackerProvider.seenAuthHeaders.length, 0, 'stored key must NEVER be sent to a new endpoint')

  // 2. Attempting saveModelProfile with a DIFFERENT endpoint without a new key MUST reject.
  await assert.rejects(
    saveModelProfile({
      id: saved.id,
      name: 'Primary Provider',
      endpoint: attackerProvider.endpoint,
      model: 'deepseek/deepseek-v4.1-flash-1017',
      protocol: 'responses',
      key: '',
    }, storage, { skipConnectionCheck: true }),
    /endpoint or protocol requires re-entering the API key/i,
  )

  // 3. Attempting checkModelConnection or saveModelProfile with a DIFFERENT protocol without a new key MUST reject.
  await assert.rejects(
    checkModelConnection({
      id: saved.id,
      name: 'Primary Provider',
      endpoint: legitProvider.endpoint,
      model: 'deepseek/deepseek-v4.1-flash-1017',
      protocol: 'messages',
      key: '',
    }, storage),
    /endpoint or protocol requires re-entering the API key/i,
  )
  await assert.rejects(
    saveModelProfile({
      id: saved.id,
      name: 'Primary Provider',
      endpoint: legitProvider.endpoint,
      model: 'deepseek/deepseek-v4.1-flash-1017',
      protocol: 'messages',
      key: '',
    }, storage, { skipConnectionCheck: true }),
    /endpoint or protocol requires re-entering the API key/i,
  )

  // 4. Editing model/priority/name on the SAME endpoint + protocol without re-entering key STILL succeeds.
  await saveModelProfile({
    id: saved.id,
    name: 'Primary Provider Renamed',
    endpoint: legitProvider.endpoint,
    model: 'anthropic/claude-sonnet-4.5',
    protocol: 'responses',
    priority: 200,
    key: '',
  }, storage, { skipConnectionCheck: true })
  assert.equal(privateModelProfiles(storage).length, 1)
  assert.equal(privateModelProfiles(storage)[0]!.key, secretKey)

  // 5. Direct SQLite endpoint tampering without rotating credential is refused by privateModelProfiles().
  storage.db.update(modelProfiles)
    .set({ endpoint: attackerProvider.endpoint })
    .where(eq(modelProfiles.id, saved.id))
    .run()
  assert.equal(
    privateModelProfiles(storage).length,
    0,
    'privateModelProfiles must refuse to load a key whose .pin does not match row (endpoint, protocol)',
  )

  // Restore endpoint and verify supplying a new key cleanly rotates credential + pin.
  const rotatedKey = 'sk-or-v1-rotated-secret-key-11223344'
  await saveModelProfile({
    id: saved.id,
    name: 'Primary Provider',
    endpoint: attackerProvider.endpoint,
    model: 'deepseek/deepseek-v4.1-flash-1017',
    protocol: 'messages',
    key: rotatedKey,
  }, storage, { skipConnectionCheck: true })
  assert.equal(existsSync(pinPath), false, 'old .pin file must be unlinked on key rotation')
  const loadedAfterRotate = privateModelProfiles(storage)
  assert.equal(loadedAfterRotate.length, 1)
  assert.equal(loadedAfterRotate[0]!.key, rotatedKey)
  assert.equal(loadedAfterRotate[0]!.endpoint, attackerProvider.endpoint)

  // Delete cleans up both credential and .pin sidecar
  const newRow = storage.db.select().from(modelProfiles).where(eq(modelProfiles.id, saved.id)).get()!
  const newPinPath = join(dir, 'credentials', `${newRow.credentialId}.pin`)
  assert.equal(existsSync(newPinPath), true)
  deleteModelProfile(saved.id, storage)
  assert.equal(existsSync(newPinPath), false)
})

test('M-15: legacy profiles without a .pin file keep working and are lazy-pinned on first save', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m15-legacy-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const endpoint = 'https://openrouter.ai/api/v1'
  const saved = await saveModelProfile({
    name: 'Legacy OpenRouter',
    endpoint,
    model: 'deepseek/deepseek-v4.1-flash-1017',
    protocol: 'responses',
    key: 'sk-or-v1-legacy-profile-key-abcdef',
  }, storage, { skipConnectionCheck: true })

  // Simulate a pre-M-15 workspace (like existing ~/guardian-data) by deleting .pin
  const row = storage.db.select().from(modelProfiles).where(eq(modelProfiles.id, saved.id)).get()!
  const pinPath = join(dir, 'credentials', `${row.credentialId}.pin`)
  unlinkSync(pinPath)
  assert.equal(existsSync(pinPath), false)

  // Must still load cleanly without breaking existing unpinned profiles
  const loaded = privateModelProfiles(storage)
  assert.equal(loaded.length, 1)
  assert.equal(loaded[0]!.key, 'sk-or-v1-legacy-profile-key-abcdef')

  // Even without a .pin file, changing endpoint without supplying a key is rejected via existing DB record check
  await assert.rejects(
    saveModelProfile({
      id: saved.id,
      name: 'Legacy OpenRouter',
      endpoint: 'https://evil.example/v1',
      model: 'deepseek/deepseek-v4.1-flash-1017',
      protocol: 'responses',
      key: '',
    }, storage, { skipConnectionCheck: true }),
    /endpoint or protocol requires re-entering the API key/i,
  )

  // First save/update on unchanged (endpoint, protocol) lazy-pins the credential
  await saveModelProfile({
    id: saved.id,
    name: 'Legacy OpenRouter Updated',
    endpoint,
    model: 'deepseek/deepseek-v4.1-flash-1017',
    protocol: 'responses',
    priority: 150,
    key: '',
  }, storage, { skipConnectionCheck: true })
  assert.equal(existsSync(pinPath), true, 'legacy profile must be lazy-pinned on first save')
  assert.equal(statSync(pinPath).mode & 0o077, 0)
})

// ============================================================================
// M-22: Fail-Closed Patch Review
// ============================================================================

test('M-22: LLM patch reviewer errors, malformed/truncated JSON, and missing verdict fields ALWAYS fail closed', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-m22-patch-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const repo = 'demo-app'
  const repoDir = join(root, repo)
  mkdirSync(join(repoDir, 'src'), { recursive: true })
  writeFileSync(
    join(repoDir, 'src/orders.ts'),
    [
      'export function getOrder(order: { ownerId: string }, userId: string) {',
      '  return order',
      '}',
      '',
    ].join('\n'),
  )
  writeFileSync(join(repoDir, 'src/unrelated.ts'), 'export const VERSION = 1\n')

  const finding = makeSampleFinding(repo, 'src/orders.ts', 2, 2)
  const fixBefore = '  return order'
  const fixAfter = '  if (order.ownerId !== userId) return null\n  return order'
  const candidatePatch = {
    fixBefore,
    fixAfter,
    codeLocations: [{ repo, file: 'src/orders.ts', startLine: 2, endLine: 2 }],
    rationale: 'Verify order ownership.',
  }

  const failureCases: Array<{ name: string; reviewerLlmCall: () => Promise<string> }> = [
    { name: 'provider 429 error', reviewerLlmCall: async () => { throw new Error('HTTP 429 rate limited') } },
    { name: 'empty response', reviewerLlmCall: async () => '' },
    { name: 'malformed JSON', reviewerLlmCall: async () => '{"approved": true, "gates": { broken' },
    { name: 'truncated fenced JSON', reviewerLlmCall: async () => '```json\n{"approved": true, "callerCompatibility": "attacker_only"' },
    {
      name: 'missing verdict fields (missing approved & gates)',
      reviewerLlmCall: async () => JSON.stringify({ callerCompatibility: 'attacker_only', reviewNotes: 'looks ok' }),
    },
    {
      name: 'non-boolean approved string',
      reviewerLlmCall: async () => JSON.stringify({
        approved: 'true',
        callerCompatibility: 'attacker_only',
        enforcingLocation: 'src/orders.ts:2',
        gates: {
          applicability: { passed: true, detail: 'ok' },
          security_closure: { passed: true, detail: 'ok', enforcingLocation: 'src/orders.ts:2' },
          sibling_coverage: { passed: true, detail: 'ok' },
          caller_compatibility: { passed: true, detail: 'ok' },
          repo_conventions: { passed: true, detail: 'ok' },
        },
        reviewNotes: 'ok',
      }),
    },
    {
      name: 'incomplete gate array (missing security_closure)',
      reviewerLlmCall: async () => JSON.stringify({
        approved: true,
        callerCompatibility: 'attacker_only',
        enforcingLocation: 'src/orders.ts:2',
        gates: [
          { gate: 1, name: 'applicability', passed: true, detail: 'ok' },
          { gate: 3, name: 'sibling_coverage', passed: true, detail: 'ok' },
          { gate: 4, name: 'caller_compatibility', passed: true, detail: 'ok' },
          { gate: 5, name: 'repo_conventions', passed: true, detail: 'ok' },
        ],
        reviewNotes: 'ok',
      }),
    },
  ]

  for (const tc of failureCases) {
    const res = await generateAndReviewPatch({
      runId: randomUUID(),
      finding,
      repo,
      reposDir: root,
      candidatePatch,
      reviewerLlmCall: tc.reviewerLlmCall,
    })
    assert.equal(res.status, 'rejected', `${tc.name} must fail closed as rejected (got ${res.status})`)
    const gate2 = res.gates.find(g => g.gate === 2)!
    assert.equal(gate2.passed, false, `${tc.name}: Gate 2 must not pass`)
    assert.match(res.reviewNotes, /failed closed/i, `${tc.name}: reviewNotes must record fail-closed reason`)
  }

  // Gate 2 hardening: a diff touching ONLY an unrelated file (never modifying the cited file)
  // MUST fail Gate 2 even in deterministic offline review!
  const unrelatedDiff = [
    '--- a/src/unrelated.ts',
    '+++ b/src/unrelated.ts',
    '@@ -1,1 +1,1 @@',
    '-export const VERSION = 1',
    '+export const VERSION = 2',
    '',
  ].join('\n')
  const unrelatedRes = await runPatchReviewer({
    finding,
    repo,
    reposDir: root,
    authorOutput: {
      repo,
      coverageInventory: [{ file: 'src/orders.ts', line: 2, symbol: 'getOrder', role: 'primary_sink', coveredByPatch: true, notes: 'claimed' }],
      fixBefore,
      fixAfter,
      diff: unrelatedDiff,
      codeLocations: [{ repo, file: 'src/orders.ts', startLine: 2, endLine: 2 }],
      rationale: 'Unrelated file edit.',
      syntaxCheck: { ran: true, passed: true },
    },
  })
  assert.equal(unrelatedRes.approved, false)
  assert.equal(unrelatedRes.status, 'rejected')
  assert.equal(unrelatedRes.gates.find(g => g.gate === 2)?.passed, false)
})

// ============================================================================
// M-23: Random 0600 Ed25519 Receipt Signing Key
// ============================================================================

test('M-23: default receipt bundle uses a randomly generated 0600 Ed25519 keypair in credentials/ and rejects workspace-UUID HMAC forgery', t => {
  const dir1 = mkdtempSync(join(tmpdir(), 'kovo-m23-ws1-'))
  const dir2 = mkdtempSync(join(tmpdir(), 'kovo-m23-ws2-'))
  t.after(() => {
    rmSync(dir1, { recursive: true, force: true })
    rmSync(dir2, { recursive: true, force: true })
  })

  const prevEnv = process.env.KOVO_RECEIPT_SIGNING_KEY
  delete process.env.KOVO_RECEIPT_SIGNING_KEY
  t.after(() => {
    if (prevEnv !== undefined) process.env.KOVO_RECEIPT_SIGNING_KEY = prevEnv
    else delete process.env.KOVO_RECEIPT_SIGNING_KEY
  })

  const storage1 = new Store(dir1)
  const storage2 = new Store(dir2)
  t.after(() => {
    storage1.close()
    storage2.close()
  })

  const project = storage1.createProject({
    requestId: randomUUID(),
    name: 'M-23 Receipt Project',
    seeds: ['https://app.example.com'],
    environment: 'public',
  })
  const run = storage1.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'M-23 receipt signing test',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 10,
    budgetRequests: 50,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })

  const bundle = exportRunReceiptBundle(storage1, run.id)
  assert.equal(bundle.algorithm, 'ed25519', 'default receipt signing algorithm must be ed25519')
  assert.match(bundle.keyId ?? '', /^ed25519:[0-9a-f]{16}$/)

  const keyPath = join(dir1, 'credentials', 'receipt-signing.ed25519.pem')
  assert.equal(existsSync(keyPath), true, 'Ed25519 private key must be persisted in credentials/')
  assert.equal(statSync(keyPath).mode & 0o077, 0, 'Ed25519 private key must have strict 0600 permissions')

  // Verifies with workspace Ed25519 public key
  const pubKey1 = getReceiptSigningPublicKey(storage1)
  assert.equal(verifyProofReceiptBundle(bundle, { algorithm: 'ed25519', publicKey: pubKey1 }).valid, true)

  // Keypair is stable across reloads in the same workspace
  const reloaded = loadOrCreateReceiptSigningKeyPair(storage1)
  assert.equal(reloaded.keyId, bundle.keyId)

  // Different workspace generates an independent random keypair that does NOT verify workspace 1's bundle
  const pubKey2 = getReceiptSigningPublicKey(storage2)
  assert.equal(verifyProofReceiptBundle(bundle, { algorithm: 'ed25519', publicKey: pubKey2 }).valid, false)

  // Old deterministic workspace-UUID HMAC secret cannot verify the bundle
  const oldDerivedSecret = createHash('sha256')
    .update(`kovo.receipt-export.v1\0${storage1.workspace.id}`)
    .digest('hex')
  assert.equal(verifyProofReceiptBundle(bundle, { algorithm: 'hmac-sha256', secret: oldDerivedSecret }).valid, false)

  // Loose permissions (0644) on the private key file MUST be rejected fail-closed!
  chmodSync(keyPath, 0o644)
  assert.throws(
    () => loadOrCreateReceiptSigningKeyPair(storage1),
    /owner-only \(0600\) permissions/i,
  )
  chmodSync(keyPath, 0o600)
})

// ============================================================================
// M-24: Unified Hunk-Counted Diff Parser
// ============================================================================

test('M-24: hunk-counted parser preserves removed `-- ` lines and added `++ ` lines inside hunks and applies cleanly', t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-m24-sql-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const sqlFile = 'db/query.sql'
  mkdirSync(join(root, 'db'), { recursive: true })
  writeFileSync(
    join(root, sqlFile),
    [
      'SELECT id, total FROM invoices',
      '-- legacy unsafe interpolation comment',
      'WHERE id = $raw',
      '-- trailing comment',
      '',
    ].join('\n'),
  )

  // Notice line 2 removed becomes `--- legacy unsafe interpolation comment` (starts with `--- `)!
  // The old naive parser broke the hunk early on `--- ` and dropped lines 3-4!
  const diffWithSqlCommentRemoval = [
    'diff --git a/db/query.sql b/db/query.sql',
    '--- a/db/query.sql',
    '+++ b/db/query.sql',
    '@@ -1,4 +1,5 @@',
    ' SELECT id, total FROM invoices',
    '--- legacy unsafe interpolation comment',
    '-WHERE id = $raw',
    '+++ parameterized filter',
    '+-- parameterized filter',
    '+WHERE id = $1 AND tenant_id = $2',
    ' -- trailing comment',
    '',
  ].join('\n')

  const parsed = parseUnifiedDiff(diffWithSqlCommentRemoval)
  assert.equal(parsed.length, 1)
  assert.equal(parsed[0]!.normalizedPath, 'db/query.sql')
  assert.equal(parsed[0]!.hunks.length, 1)
  assert.equal(parsed[0]!.hunks[0]!.entries.length, 7)

  const applied = applyUnifiedDiffToDirectory(root, diffWithSqlCommentRemoval)
  assert.deepEqual(applied.filesModified, ['db/query.sql'])
  assert.equal(
    readFileSync(join(root, sqlFile), 'utf8'),
    [
      'SELECT id, total FROM invoices',
      '++ parameterized filter',
      '-- parameterized filter',
      'WHERE id = $1 AND tenant_id = $2',
      '-- trailing comment',
      '',
    ].join('\n'),
  )

  // SARIF export preserves the complete hunk AND emits zero-width regions for pure insertions (`oldCount === 0`)
  const insertionOnlyDiff = [
    '--- a/db/query.sql',
    '+++ b/db/query.sql',
    '@@ -1,0 +2,2 @@',
    '+-- inserted guard 1',
    '+-- inserted guard 2',
    '',
  ].join('\n')

  const sarifWithFix = buildSarifLog({
    runId: 'run-m24',
    reportVersion: 1,
    goal: 'M-24 SARIF zero-width insert check',
    capabilityTier: 2,
    scopeRevision: 1,
    goalRevision: 1,
    approvedOrigins: ['http://127.0.0.1:3000'],
    findings: [{ ...makeSampleFinding('app', 'db/query.sql', 1, 2), id: 'f-1' }],
    patches: [{
      id: 'p-1',
      findingId: 'f-1',
      repo: 'app',
      status: 'approved',
      diff: insertionOnlyDiff,
    }],
  })
  assert.equal(sarifWithFix.version, '2.1.0')
  const replacement = sarifWithFix.runs[0]!.results[0]!.fixes?.[0]?.artifactChanges[0]?.replacements[0]
  assert.ok(replacement, 'expected SARIF replacement for insertion-only hunk')
  assert.deepEqual(
    replacement.deletedRegion,
    { startLine: 2, startColumn: 1, endLine: 2, endColumn: 1 },
    'insertion-only hunk (oldCount === 0) must emit a zero-width deletedRegion',
  )
})

test('M-24: strict parser rejects path traversal, binary patches, symlink modes, mismatched hunk counts, and malformed headers', () => {
  // 1. Path traversal & unsafe paths
  assert.throws(() => validateDiffPath('a/../../etc/passwd', 'old'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('/etc/passwd', 'new'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('a\\..\\secret.txt', 'old'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('a/foo\0bar.ts', 'old'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('C:/windows/win.ini', 'old'), UnifiedDiffError)

  // 2. Binary patch rejection
  const binaryDiff = [
    'diff --git a/bin/tool b/bin/tool',
    'GIT binary patch',
    'literal 4',
    'LcmZQzU|<0R00031',
    '',
  ].join('\n')
  assert.equal(validateUnifiedDiff(binaryDiff).ok, false)

  // 3. Symlink (mode 120000) rejection
  const symlinkDiff = [
    'diff --git a/link.txt b/link.txt',
    'new file mode 120000',
    '--- /dev/null',
    '+++ b/link.txt',
    '@@ -0,0 +1,1 @@',
    '+/etc/passwd',
    '',
  ].join('\n')
  const symRes = validateUnifiedDiff(symlinkDiff)
  assert.equal(symRes.ok, false)
  assert.match(symRes.error, /120000|symlink/i)

  // 4. Mismatched hunk line count (header claims 3 old / 3 new, body only has 1 old / 1 new)
  const truncatedHunk = [
    '--- a/src/a.ts',
    '+++ b/src/a.ts',
    '@@ -1,3 +1,3 @@',
    '-const a = 1',
    '+const a = 2',
    '',
  ].join('\n')
  const truncRes = validateUnifiedDiff(truncatedHunk)
  assert.equal(truncRes.ok, false)
  assert.match(truncRes.error, /Truncated hunk|mismatch/i)

  // 5. Extra uncounted line after declared hunk end
  const extraLineHunk = [
    '--- a/src/a.ts',
    '+++ b/src/a.ts',
    '@@ -1,1 +1,1 @@',
    '-const a = 1',
    '+const a = 2',
    '+const extra = 3',
    '',
  ].join('\n')
  const extraRes = validateUnifiedDiff(extraLineHunk)
  assert.equal(extraRes.ok, false)
  assert.match(extraRes.error, /extra uncounted line|mismatch/i)

  // 6. Malformed hunk header
  const malformedHeader = [
    '--- a/src/a.ts',
    '+++ b/src/a.ts',
    '@@ -x,y +z,w @@',
    '-a',
    '+b',
    '',
  ].join('\n')
  assert.equal(validateUnifiedDiff(malformedHeader).ok, false)

  // 7. Missing +++ header after ---
  const missingPlus = [
    '--- a/src/a.ts',
    '@@ -1,1 +1,1 @@',
    '-a',
    '+b',
    '',
  ].join('\n')
  assert.equal(validateUnifiedDiff(missingPlus).ok, false)
})
