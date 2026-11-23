import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, Grant, PublicAddress } from '../src/server/broker.ts'
import { redact, scanSecretHeaders, scanSecrets, sha256Prefix } from '../src/server/redact.ts'
import type { NamedSecret, SecretMatch } from '../src/server/redact.ts'
import { Store } from '../src/server/store.ts'

// Secret-shaped fixture values are synthetic canaries for detection only and never correspond to
// real credentials.
const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZW5hbnQtYSIsInJvbGUiOiJhZG1pbiJ9.c2lnbmF0dXJlLXZhbHVl'
const apiKey = 'sk-or-v1-0123456789abcdef0123456789abcdef'
const rbsSecret = 'rbs_live_9f8e7d6c5b4a3210fedcba9876543210'
const namedSecrets: NamedSecret[] = [{ value: rbsSecret, placeholder: '[redacted:tenant]' }]

const northstar = 'https://northstar.example'
const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: northstar,
    tier: 1,
    maxRpsPerOrigin: 20,
    canRead: origin => origin === northstar,
    audit: () => {},
    ...overrides,
  }
}

function brokerReturning(response: { status?: number; headers?: Record<string, string>; body: string }) {
  return new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async () => ({
      status: response.status ?? 200,
      headers: { 'content-type': 'application/json', ...(response.headers ?? {}) },
      body: response.body,
    }),
  })
}

async function exchangeFor(response: { status?: number; headers?: Record<string, string>; body: string }, grant = makeGrant()): Promise<BrokerExchangeResult> {
  return brokerReturning(response).executeHttp(
    { origin: northstar, method: 'GET', pathAndQuery: '/api/resource' },
    grant,
    AbortSignal.timeout(5_000),
  )
}

function assertNoRawSecrets(serialized: string, secrets: readonly string[]): void {
  for (const secret of secrets) {
    assert.ok(!serialized.includes(secret), `serialized exchange leaked a raw secret value (${secret.slice(0, 4)}…)`)
  }
}

function artifactContents(dir: string): string {
  return readdirSync(dir, { withFileTypes: true })
    .map(entry => {
      const path = join(dir, entry.name)
      return entry.isDirectory() ? artifactContents(path) : readFileSync(path, 'utf8')
    })
    .join('\n')
}

// ============================================================================
// 1. Pre-redaction structural scan keeps disclosure evidence without the value
// ============================================================================

test('broker records redacted secretMatches from the pre-scrub body while body output stays redacted', async () => {
  const rawBody = JSON.stringify({
    token: jwt,
    nested: { users: [{ api_key: apiKey }] },
    tenant: rbsSecret,
  })
  const ex = await exchangeFor({ body: rawBody }, makeGrant({ secrets: namedSecrets }))

  // Redaction output is byte-for-byte what the previous pipeline produced.
  assert.equal(ex.body, redact(rawBody, namedSecrets))
  assert.ok(ex.body.includes('[redacted]'))
  assert.ok(!ex.body.includes(jwt))
  assert.ok(!ex.body.includes(apiKey))
  assert.ok(!ex.body.includes(rbsSecret))

  const matches = ex.secretMatches ?? []
  assert.ok(matches.length >= 3, `expected several structural matches, got ${matches.length}`)

  const jwtMatch = matches.find(m => m.kind === 'jwt')
  assert.ok(jwtMatch, 'JWT shape must be fingerprinted')
  assert.equal(jwtMatch.sha256Prefix, sha256Prefix(jwt))
  assert.equal(jwtMatch.fieldPath, 'body.token')

  const credentialMatch = matches.find(m => m.kind === 'credential' && m.sha256Prefix === sha256Prefix(apiKey))
  assert.ok(credentialMatch, 'API-key shape must be fingerprinted')
  assert.equal(credentialMatch.fieldPath, 'body.nested.users[0].api_key')
  assert.equal(credentialMatch.count, 1)

  const namedMatch = matches.find(m => m.kind === 'named_secret')
  assert.ok(namedMatch, 'registered NamedSecret must be fingerprinted even without a known shape')
  assert.equal(namedMatch.sha256Prefix, sha256Prefix(rbsSecret))
  assert.equal(namedMatch.fieldPath, 'body.tenant')
  assert.equal(namedMatch.count, 1)

  // The exchange (including its metadata) never carries the raw values.
  assertNoRawSecrets(JSON.stringify(ex), [jwt, apiKey, rbsSecret])
  for (const match of matches) {
    assert.deepEqual(Object.keys(match).sort(), ['count', 'fieldPath', 'kind', 'sha256Prefix'])
    assert.match(match.sha256Prefix, /^[0-9a-f]{12}$/)
  }
})

test('response header secrets are fingerprinted with header field paths', async () => {
  const ex = await exchangeFor(
    {
      body: '{"ok":true}',
      headers: { authorization: `Bearer ${jwt}`, 'set-cookie': `session=${rbsSecret}; Path=/; HttpOnly` },
    },
    makeGrant({ secrets: namedSecrets }),
  )

  const matches = ex.secretMatches ?? []
  const bearer = matches.find(m => m.kind === 'bearer' && m.sha256Prefix === sha256Prefix(jwt))
  assert.ok(bearer, 'authorization header bearer token must be fingerprinted')
  assert.equal(bearer.fieldPath, 'headers.authorization')

  const cookie = matches.find(m => m.kind === 'named_secret' && m.fieldPath === 'headers.set-cookie')
  assert.ok(cookie, 'registered cookie secret must be fingerprinted from headers')
  assert.equal(cookie.sha256Prefix, sha256Prefix(rbsSecret))

  // Header redaction is unchanged: sensitive headers remain fully scrubbed.
  assert.equal(ex.respHeaders.authorization, '[redacted]')
  assert.equal(ex.respHeaders['set-cookie'], '[redacted]')
  assertNoRawSecrets(JSON.stringify(ex), [jwt, rbsSecret])
})

test('non-secret bodies and headers yield an empty match list', async () => {
  const ex = await exchangeFor({ body: JSON.stringify({ status: 'ok', count: 3, label: 'nothing-sensitive' }) })
  assert.deepEqual(ex.secretMatches, [])
  assert.equal(ex.body, JSON.stringify({ status: 'ok', count: 3, label: 'nothing-sensitive' }))

  const plain = await exchangeFor({ body: 'plain text body with no credentials' })
  assert.deepEqual(plain.secretMatches, [])
  assert.deepEqual(scanSecrets(''), [])
})

test('plain-text key/value shapes are fingerprinted by their extracted value', async () => {
  const text = 'config: api_key=sk-live-0123456789abcdef status=ok'
  const matches = scanSecrets(text)
  const kv = matches.filter(m => m.kind === 'key_value')
  assert.equal(kv.length, 1)
  assert.equal(kv[0]!.sha256Prefix, sha256Prefix('sk-live-0123456789abcdef'))
  assert.equal(kv[0]!.fieldPath, 'body')
  // And the raw value never appears in the metadata.
  assertNoRawSecrets(JSON.stringify(matches), ['sk-live-0123456789abcdef'])
})

test('scan bounds the number of matches and per-entry counts', () => {
  const body = Array.from({ length: 120 }, (_, i) => `{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJrZXktJHt9In0.sig${String(i).padStart(8, '0')}${i}"`)
    .join('\n')
  const matches = scanSecrets(body)
  assert.ok(matches.length > 0)
  assert.ok(matches.length <= 64, `match array must be bounded, got ${matches.length}`)
  for (const match of matches) assert.ok(match.count >= 1 && match.count <= 1_000)

  const repeated = scanSecrets(`x ${apiKey} y ${apiKey} z ${apiKey}`)
  const apiMatch = repeated.find(m => m.kind === 'credential')
  assert.equal(apiMatch?.count, 3)
})

test('scanSecretHeaders bounds and sanitizes field paths without leaking values', () => {
  const matches = scanSecretHeaders({
    authorization: `Bearer ${jwt}`,
    'x-weird\u0000name': `token=${apiKey}`,
  })
  assert.ok(matches.length >= 1)
  for (const match of matches) {
    assert.match(match.sha256Prefix, /^[0-9a-f]{12}$/)
    assert.ok(!(match.fieldPath ?? '').includes('\u0000'))
  }
  assertNoRawSecrets(JSON.stringify(matches), [jwt, apiKey])
})

test('redaction behavior is unchanged for representative inputs', () => {
  assert.equal(redact('Authorization: Bearer abcdefgh12345'), '[redacted]')
  assert.equal(redact('api_key = "super-secret-value"'), '[redacted]')
  assert.equal(redact('plain body text'), 'plain body text')
  assert.equal(redact(`tenant ${rbsSecret}`, namedSecrets), 'tenant [redacted:tenant]')
  assert.equal(redact(`${jwt}`), '[redacted]')
})

// ============================================================================
// 2. Persistence: metadata survives the exchange row, raw values never reach disk
// ============================================================================

function makeRun(storage: Store, origin: string) {
  const { id: projectId } = storage.createProject({ requestId: randomUUID(), name: 'Secret meta', seeds: [origin], environment: 'public' })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Secret metadata persistence', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 5, budgetRequests: 50, maxRpsPerOrigin: 5, workerConcurrency: 1, workerMaxTurns: 10,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]!
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true, capabilityTier: 2 })
  const worker = storage.makeWorker(storage.run(runId), 'investigation', asset, 'Probe', 'Secret meta test')
  return { runId, worker }
}

test('secretMatches persist with the exchange and raw values never reach the database or artifacts', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-secret-meta-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const ex = await exchangeFor(
    { body: JSON.stringify({ token: jwt, tenant: rbsSecret }) },
    makeGrant({ secrets: namedSecrets }),
  )
  const { runId, worker } = makeRun(storage, northstar)

  const saved = storage.recordExchange({
    runId,
    assignmentId: worker.id,
    scopeRevision: 0,
    origin: ex.origin,
    finalOrigin: ex.finalOrigin,
    redirectOrigins: ex.redirectOrigins,
    method: ex.method,
    pathAndQuery: ex.pathAndQuery,
    personaHandle: ex.personaHandle,
    status: ex.status,
    mediaType: ex.mediaType,
    reqHeaders: ex.reqHeaders,
    respHeaders: ex.respHeaders,
    body: ex.body,
    durationMs: ex.durationMs,
    secrets: namedSecrets,
    secretMatches: ex.secretMatches,
  })

  assert.deepEqual(saved.secretMatches, ex.secretMatches)
  const read = storage.getExchange(runId, saved.id)
  assert.deepEqual(read.secretMatches, ex.secretMatches)
  assert.ok(read.secretMatches.some((m: SecretMatch) => m.kind === 'jwt'))

  // Nothing written to disk (row, blob artifact, or full DB file) carries the raw values.
  const dbBytes = readFileSync(join(dir, 'guardian.sqlite')).toString('utf8')
  assertNoRawSecrets(dbBytes, [jwt, rbsSecret])
  const artifactsDir = join(dir, 'artifacts')
  const artifactText = artifactContents(artifactsDir)
  assertNoRawSecrets(artifactText, [jwt, rbsSecret])
  assertNoRawSecrets(JSON.stringify(read), [jwt, rbsSecret])
})

test('store whitelists secret metadata fields so a caller cannot smuggle raw values', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-secret-meta-sanitize-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const { runId, worker } = makeRun(storage, northstar)
  const smuggled = {
    kind: 'named_secret',
    sha256Prefix: sha256Prefix(rbsSecret),
    fieldPath: `body.${rbsSecret}`,
    count: 2,
    // Deliberately invalid extra fields; the store must project them away.
    value: rbsSecret,
    raw: rbsSecret,
  } as unknown as SecretMatch

  const saved = storage.recordExchange({
    runId,
    assignmentId: worker.id,
    scopeRevision: 0,
    origin: northstar,
    finalOrigin: northstar,
    redirectOrigins: [northstar],
    method: 'GET',
    pathAndQuery: '/api/resource',
    personaHandle: null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: '{"ok":true}',
    durationMs: 1,
    secretMatches: [smuggled],
  })

  assert.equal(saved.secretMatches.length, 1)
  // The secret-shaped field path is dropped entirely rather than persisted.
  assert.deepEqual(Object.keys(saved.secretMatches[0]!).sort(), ['count', 'kind', 'sha256Prefix'])
  assertNoRawSecrets(JSON.stringify(saved.secretMatches), [rbsSecret])
  assertNoRawSecrets(
    readFileSync(join(dir, 'guardian.sqlite')).toString('utf8'),
    [rbsSecret],
  )
  assert.equal(createHash('sha256').update(rbsSecret).digest('hex').slice(0, 12), saved.secretMatches[0]!.sha256Prefix)
})
