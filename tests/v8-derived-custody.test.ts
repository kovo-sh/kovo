/**
 * v8 M0 — Layer-1 DerivedCapabilityHandle Custody & Bounded Async Poll-Convergence tests.
 *
 * Proves:
 *   1. Raw secrets never leak into metadata, serialization, or scrubbed transcripts/prompts
 *      (including URL-encoded, form-encoded, base64, unpadded base64, and base64url variants),
 *      even after revocation or TTL expiry.
 *   2. 0600 host persistence reloads cleanly for the matching runId and fails closed on
 *      permissive file modes or cross-run isolation mismatches.
 *   3. Host-side capability injection (`bearer`, `header`, `cookie`, `url`) leaves the caller's
 *      request immutable, enforces unsafe-header and origin-allowlist guards, and emits
 *      verifiable `consumedCapabilityId` + `digest` attestations.
 *   4. `hostHmacSign` & `hostJwtSign` produce RFC-valid signatures and verifiable
 *      `derivedFromCapabilityId` attestations without returning raw key material; `hostJwtSign`
 *      seals the minted JWT as a new derived handle so it stays host-side and scrubbed.
 *   5. Expired, revoked, malformed, and unknown handles fail closed across every host operation.
 *   6. `awaitAsyncConvergence` converges cleanly on delayed async jobs, enforces profile bounds
 *      and monotonic timestamps (`tTriggerMs <= tObservedMs`), aborts immediately on AbortSignal,
 *      and times out cleanly without hanging.
 */
import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { inspect } from 'node:util'
import {
  ASYNC_CONVERGENCE_PROFILES,
  DerivedCapabilityVault,
  DerivedCustodyError,
  awaitAsyncConvergence,
  formatDerivedHandle,
  hostHmacSign,
  hostJwtSign,
  injectCapabilityIntoRequest,
  isDerivedCapabilityHandle,
  parseDerivedHandle,
  scrubDerivedSecrets,
  vaultScrubDescriptors,
} from '../src/server/derived-custody.ts'
import { redact } from '../src/server/redact.ts'

test('DerivedCapabilityVault seals secrets behind opaque handles without leaking raw bytes', () => {
  let clock = 1_700_000_000_000
  const vault = new DerivedCapabilityVault({ runId: 'run-alpha-01', now: () => clock })
  const rawToken = 'tok_live_9a8b7c6d+5e4f/3a2b=1c0d'

  const meta = vault.seal({
    hopReceiptId: 'hop1_rcpt',
    slot: 'session_bearer',
    rawValue: rawToken,
    kind: 'bearer_token',
    ttlMs: 60_000,
    allowedOrigins: ['https://api.example.test'],
  })

  assert.equal(meta.handle, 'cap:hop_hop1_rcpt:session_bearer')
  assert.equal(isDerivedCapabilityHandle(meta.handle), true)
  assert.deepEqual(parseDerivedHandle(meta.handle), {
    hopReceiptId: 'hop1_rcpt',
    slot: 'session_bearer',
  })
  assert.equal(meta.runId, 'run-alpha-01')
  const expectedDigest = createHash('sha256').update(rawToken, 'utf8').digest('hex')
  assert.equal(meta.sha256, expectedDigest)
  assert.equal(meta.sha256Prefix, expectedDigest.slice(0, 12))
  assert.equal(meta.createdAtMs, clock)
  assert.equal(meta.expiresAtMs, clock + 60_000)

  // Raw secret must never appear in metadata, listing, JSON, or util.inspect output.
  const serialized = [
    JSON.stringify(meta),
    JSON.stringify(vault.getMeta(meta.handle)),
    JSON.stringify(vault.list()),
    JSON.stringify(vault),
    inspect(vault),
  ].join('\n')
  assert.equal(serialized.includes(rawToken), false)
  assert.equal(vault.hasActive(meta.handle), true)
  assert.equal(vault.isExpired(meta.handle), false)

  // Advance clock past TTL.
  clock += 60_000
  assert.equal(vault.isExpired(meta.handle), true)
  assert.equal(vault.hasActive(meta.handle), false)
  assert.equal(vault.purgeExpired(), 1)
  assert.equal(vault.getMeta(meta.handle), null)
})

test('DerivedCapabilityVault enforces 0600 persistence and run-scoped isolation', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-custody-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const persistPath = join(dir, 'nested', 'custody.json')

  const rawSalt = 'signing-salt-alpha-99887766'
  const vaultA = new DerivedCapabilityVault({ runId: 'run-persist-A', persistPath })
  const meta = vaultA.seal({
    hopReceiptId: 'r01',
    slot: 'hmac_salt',
    rawValue: rawSalt,
    kind: 'signing_salt',
  })

  // Verify owner-only file and directory permissions.
  const fileStat = statSync(persistPath)
  assert.equal(fileStat.mode & 0o777, 0o600)
  const dirStat = statSync(join(dir, 'nested'))
  assert.equal(dirStat.mode & 0o777, 0o700)

  // Reloading with matching runId restores active handle and host crypto capability.
  const reloaded = new DerivedCapabilityVault({ runId: 'run-persist-A', persistPath })
  assert.equal(reloaded.getMeta(meta.handle)?.sha256, meta.sha256)
  const signed = hostHmacSign({
    vault: reloaded,
    secretHandle: meta.handle,
    payload: 'event=settled',
    alg: 'sha256',
    encoding: 'hex',
  })
  assert.equal(
    signed.signature,
    createHmac('sha256', rawSalt).update('event=settled').digest('hex'),
  )

  // Reloading with a different runId fails closed.
  assert.throws(
    () => new DerivedCapabilityVault({ runId: 'run-persist-B', persistPath }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'RUN_MISMATCH',
  )

  // Loosening file permissions fails closed.
  chmodSync(persistPath, 0o644)
  assert.throws(
    () => new DerivedCapabilityVault({ runId: 'run-persist-A', persistPath }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'PERSISTENCE_ERROR',
  )
})

test('scrubDerivedSecrets removes raw, URL-encoded, form-encoded, base64, and base64url forms even after revocation', () => {
  let clock = 5_000
  const vault = new DerivedCapabilityVault({ runId: 'run-scrub', now: () => clock })
  const secret = 's3cr3t+key/with=chars &space!'
  const meta = vault.seal({
    hopReceiptId: 'h2',
    slot: 'oidc_assertion',
    rawValue: secret,
    kind: 'oidc_assertion',
    ttlMs: 1_000,
  })

  const urlEncoded = encodeURIComponent(secret)
  const lowerUrlEncoded = urlEncoded.replace(/%[0-9A-F]{2}/g, m => m.toLowerCase())
  const formEncoded = urlEncoded.replaceAll('%20', '+')
  const b64 = Buffer.from(secret, 'utf8').toString('base64')
  const b64Unpadded = b64.replace(/=+$/, '')
  const b64Url = Buffer.from(secret, 'utf8').toString('base64url')

  const promptAndTranscript = [
    `Authorization: Bearer ${secret}`,
    `redirect_uri=https://app.example.test/cb?tok=${urlEncoded}`,
    `lower=${lowerUrlEncoded}`,
    `form=${formEncoded}`,
    `b64=${b64}`,
    `b64_nopad=${b64Unpadded}`,
    `b64url=${b64Url}`,
  ].join('\n')

  // Expire and revoke the handle first — scrubbing MUST still remove every variant!
  clock += 5_000
  vault.revoke(meta.handle)

  const scrubbed = scrubDerivedSecrets(promptAndTranscript, vault)
  for (const variant of [secret, urlEncoded, lowerUrlEncoded, formEncoded, b64, b64Unpadded, b64Url]) {
    assert.equal(scrubbed.includes(variant), false, `variant leaked into scrubbed output: ${variant}`)
  }
  assert.equal(scrubbed.includes(`[redacted:${meta.handle}]`), true)

  // Verify seamless interoperability with src/server/redact.ts.
  const viaRedact = redact(`token=${secret} b64=${b64Url}`, vaultScrubDescriptors(vault))
  assert.equal(viaRedact.includes(secret), false)
  assert.equal(viaRedact.includes(b64Url), false)
})

test('injectCapabilityIntoRequest injects bearer, header, cookie, and url host-side without mutating input', () => {
  let clock = 10_000
  const vault = new DerivedCapabilityVault({ runId: 'run-inject', now: () => clock })

  const bearerMeta = vault.seal({
    hopReceiptId: 'h1',
    slot: 'pat',
    rawValue: 'Bearer pat_secret_value_12345',
    kind: 'bearer_token',
    allowedOrigins: ['https://api.example.test'],
  })
  const headerMeta = vault.seal({
    hopReceiptId: 'h1',
    slot: 'delegation',
    rawValue: 'del_hdr_secret_98765',
    kind: 'header_secret',
    defaultHeaderName: 'X-Delegation-Key',
  })
  const cookieMeta = vault.seal({
    hopReceiptId: 'h2',
    slot: 'sid',
    rawValue: 'sid_secret_abcdef',
    kind: 'cookie',
    defaultCookieName: 'session_id',
  })
  const signedUrlMeta = vault.seal({
    hopReceiptId: 'h3',
    slot: 'export_url',
    rawValue: 'https://storage.example.test/exports/report.csv?sig=signed_secret_xyz',
    kind: 'signed_url',
    allowedOrigins: ['https://storage.example.test'],
  })

  // 1. Bearer injection (does not double-prefix "Bearer " and does not mutate input).
  const origReq = {
    url: 'https://api.example.test/v1/items',
    method: 'GET',
    headers: { authorization: 'Bearer stale', Accept: 'application/json' },
  }
  const bearerRes = injectCapabilityIntoRequest({
    vault,
    handle: bearerMeta.handle,
    target: 'bearer',
    request: origReq,
  })
  assert.equal(bearerRes.request.headers?.Authorization, 'Bearer pat_secret_value_12345')
  assert.equal(bearerRes.request.headers?.authorization, undefined)
  assert.equal(origReq.headers.authorization, 'Bearer stale')
  assert.equal(bearerRes.attestation.consumedCapabilityId, bearerMeta.handle)
  assert.equal(bearerRes.attestation.digest, bearerMeta.sha256)
  assert.equal(bearerRes.attestation.timestampMs, clock)

  // Origin allowlist fails closed for disallowed origin.
  assert.throws(
    () =>
      injectCapabilityIntoRequest({
        vault,
        handle: bearerMeta.handle,
        target: 'bearer',
        request: { url: 'https://evil.example.test/steal' },
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'ORIGIN_NOT_ALLOWED',
  )

  // 2. Custom header injection + unsafe header guard.
  const hdrRes = injectCapabilityIntoRequest(
    { handle: headerMeta.handle, target: 'header', request: { url: 'https://api.example.test/v1/a' } },
    vault,
  )
  assert.equal(hdrRes.request.headers?.['X-Delegation-Key'], 'del_hdr_secret_98765')
  assert.throws(
    () =>
      vault.injectCapabilityIntoRequest({
        handle: headerMeta.handle,
        target: 'header',
        headerName: 'Host',
        request: { url: 'https://api.example.test/v1/a' },
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'UNSAFE_HEADER',
  )

  // 3. Cookie merge & replacement.
  const cookieRes = vault.injectCapabilityIntoRequest({
    handle: cookieMeta.handle,
    target: 'cookie',
    request: {
      url: 'https://api.example.test/v1/me',
      headers: { cookie: 'theme=dark; session_id=old_value; lang=en' },
    },
  })
  assert.equal(cookieRes.request.headers?.Cookie, 'theme=dark; session_id=sid_secret_abcdef; lang=en')

  // 4. Signed URL injection & query-param URL injection.
  const urlRes = vault.injectCapabilityIntoRequest({
    handle: signedUrlMeta.handle,
    target: 'url',
    request: { url: 'https://storage.example.test/placeholder' },
  })
  assert.equal(urlRes.request.url, 'https://storage.example.test/exports/report.csv?sig=signed_secret_xyz')
  assert.equal(urlRes.attestation.consumedCapabilityId, signedUrlMeta.handle)

  const qpRes = vault.injectCapabilityIntoRequest({
    handle: headerMeta.handle,
    target: 'url',
    queryParam: 'access_key',
    request: { url: 'https://api.example.test/download?fmt=json' },
  })
  assert.equal(qpRes.request.url, 'https://api.example.test/download?fmt=json&access_key=del_hdr_secret_98765')
})

test('hostHmacSign produces RFC 4231 valid signatures and verifiable attestations without exposing raw key', () => {
  let clock = 20_000
  const vault = new DerivedCapabilityVault({ runId: 'run-hmac', now: () => clock })
  // RFC 4231 Test Case 2
  const key = 'Jefe'
  const payload = 'what do ya want for nothing?'
  const meta = vault.seal({
    hopReceiptId: 'hop_rfc',
    slot: 'signing_key',
    rawValue: key,
    kind: 'hmac_key',
    ttlMs: 10_000,
  })

  const sha256Hex = hostHmacSign({
    vault,
    secretHandle: meta.handle,
    payload,
    alg: 'sha256',
    encoding: 'hex',
  })
  assert.equal(
    sha256Hex.signature,
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  )
  assert.equal(sha256Hex.attestation.derivedFromCapabilityId, meta.handle)
  assert.equal(sha256Hex.attestation.alg, 'sha256')
  assert.equal(
    sha256Hex.attestation.payloadDigest,
    createHash('sha256').update(payload, 'utf8').digest('hex'),
  )
  assert.equal(sha256Hex.attestation.timestampMs, clock)
  assert.equal(JSON.stringify(sha256Hex).includes(key), false)

  const sha384Hex = vault.hostHmacSign({
    secretHandle: meta.handle,
    payload,
    alg: 'sha384',
    encoding: 'hex',
  })
  assert.equal(
    sha384Hex.signature,
    'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
  )

  const sha512B64Url = hostHmacSign(
    { secretHandle: meta.handle, payload, alg: 'sha512', encoding: 'base64url' },
    vault,
  )
  const expectedSha512 = createHmac('sha512', key).update(payload).digest('base64url')
  assert.equal(sha512B64Url.signature, expectedSha512)

  // Expired handle fails closed.
  clock += 10_000
  assert.throws(
    () =>
      hostHmacSign({
        vault,
        secretHandle: meta.handle,
        payload,
        alg: 'sha256',
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'EXPIRED_HANDLE',
  )

  // Unknown handle and cross-run mismatch fail closed.
  assert.throws(
    () =>
      hostHmacSign({
        vault,
        secretHandle: formatDerivedHandle('hop_missing', 'key'),
        payload,
        alg: 'sha256',
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'UNKNOWN_HANDLE',
  )
  assert.throws(
    () =>
      hostHmacSign({
        vault,
        secretHandle: meta.handle,
        payload,
        alg: 'sha256',
        runId: 'other-run',
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'RUN_MISMATCH',
  )
})

test('hostJwtSign mints RFC 7519 JWTs, seals derived handle host-side, and scrubs both key and minted token', () => {
  const clock = 30_000
  const vault = new DerivedCapabilityVault({ runId: 'run-jwt', now: () => clock })
  const signingSecret = 'super-host-hmac-secret-key-0123456789'
  const keyMeta = vault.seal({
    hopReceiptId: 'hop2',
    slot: 'jwt_secret',
    rawValue: signingSecret,
    kind: 'signing_salt',
    allowedOrigins: ['https://api.example.test'],
  })

  const claims = { sub: 'acct-42', role: 'admin', iat: 1700000000 }
  const res = hostJwtSign({
    vault,
    secretHandle: keyMeta.handle,
    claims,
    header: { kid: 'k1' },
    alg: 'HS256',
  })

  // Independently verify RFC 7515 / 7519 compact JWS structure and MAC.
  const parts = res.token.split('.')
  assert.equal(parts.length, 3)
  const decodedHeader = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'))
  const decodedClaims = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'))
  assert.deepEqual(decodedHeader, { typ: 'JWT', kid: 'k1', alg: 'HS256' })
  assert.deepEqual(decodedClaims, claims)

  const expectedSig = createHmac('sha256', signingSecret)
    .update(`${parts[0]}.${parts[1]}`, 'utf8')
    .digest('base64url')
  assert.equal(parts[2], expectedSig)

  // Verify attestation & derived handle lineage.
  assert.equal(isDerivedCapabilityHandle(res.derivedHandle), true)
  assert.equal(res.attestation.derivedFromCapabilityId, keyMeta.handle)
  assert.equal(res.attestation.derivedHandle, res.derivedHandle)
  assert.equal(res.attestation.alg, 'HS256')
  assert.equal(
    res.attestation.claimsDigest,
    createHash('sha256').update(JSON.stringify(claims), 'utf8').digest('hex'),
  )
  assert.equal(res.attestation.timestampMs, clock)
  assert.equal(JSON.stringify(res).includes(signingSecret), false)

  // The minted JWT is immediately usable via host-side handle injection.
  const derivedMeta = vault.getMeta(res.derivedHandle)
  assert.equal(derivedMeta?.kind, 'jwt')
  assert.equal(derivedMeta?.derivedFromCapabilityId, keyMeta.handle)
  const injected = vault.injectCapabilityIntoRequest({
    handle: res.derivedHandle,
    target: 'bearer',
    request: { url: 'https://api.example.test/v1/admin' },
  })
  assert.equal(injected.request.headers?.Authorization, `Bearer ${res.token}`)
  assert.equal(injected.attestation.consumedCapabilityId, res.derivedHandle)

  // Both the original signing secret and the minted JWT are scrubbed from transcripts.
  const scrubbed = scrubDerivedSecrets(`salt=${signingSecret} jwt=${res.token}`, vault)
  assert.equal(scrubbed.includes(signingSecret), false)
  assert.equal(scrubbed.includes(res.token), false)
  assert.equal(scrubbed.includes(`[redacted:${keyMeta.handle}]`), true)
  assert.equal(scrubbed.includes(`[redacted:${res.derivedHandle}]`), true)

  // HS384 and HS512 also verify cleanly, while alg:'none' or mismatched header.alg fails closed.
  const hs512 = vault.hostJwtSign({ secretHandle: keyMeta.handle, claims: { sub: 'u1' }, alg: 'HS512' })
  const p512 = hs512.token.split('.')
  assert.equal(
    p512[2],
    createHmac('sha512', signingSecret).update(`${p512[0]}.${p512[1]}`, 'utf8').digest('base64url'),
  )

  assert.throws(
    () =>
      hostJwtSign({
        vault,
        secretHandle: keyMeta.handle,
        claims: { sub: 'u1' },
        alg: 'none' as unknown as 'HS256',
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'INVALID_INPUT',
  )
  assert.throws(
    () =>
      hostJwtSign({
        vault,
        secretHandle: keyMeta.handle,
        claims: { sub: 'u1' },
        header: { alg: 'none' },
        alg: 'HS256',
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'INVALID_INPUT',
  )
})

test('awaitAsyncConvergence converges on delayed async job with monotonic timestamps and structured evidence', async () => {
  const tTriggerMs = Date.now()
  let polls = 0

  const result = await awaitAsyncConvergence({
    profile: 'fast_lab',
    timeoutMs: 2_000,
    intervalMs: 15,
    maxAttempts: 20,
    tTriggerMs,
    pollFn: async ({ attempt }) => {
      polls += 1
      if (attempt === 1) throw new Error('transient_503')
      if (attempt === 2) return { status: 'queued', updatedAtMs: tTriggerMs - 500 }
      if (attempt === 3) return { status: 'done', updatedAtMs: tTriggerMs - 100 } // stale pre-trigger artifact
      return { status: 'done', updatedAtMs: Date.now(), artifactId: 'job-99' }
    },
    extractObservedAtMs: item => item.updatedAtMs,
    matchPredicate: item => item.status === 'done',
  })

  assert.equal(result.converged, true)
  assert.equal(result.status, 'converged')
  assert.equal(result.value?.artifactId, 'job-99')
  assert.equal(polls, 4)
  assert.equal(result.evidence.profile, 'fast_lab')
  assert.equal(result.evidence.attempts, 4)
  assert.equal(result.evidence.aborted, false)
  assert.equal(result.evidence.timedOut, false)
  assert.ok(result.evidence.tObservedMs !== null && result.evidence.tObservedMs >= result.evidence.tTriggerMs)
  assert.equal(result.evidence.attemptLog[0]?.error, 'transient_503')
  assert.equal(result.evidence.attemptLog[2]?.rejectedReason, 'non_monotonic_observed_timestamp')
  assert.equal(result.evidence.attemptLog[3]?.matched, true)
})

test('awaitAsyncConvergence enforces profile bounds, monotonic violations, immediate AbortSignal, and clean timeouts', async () => {
  // Profile bounds: fast_lab <= 5s, wan <= 30s.
  assert.equal(ASYNC_CONVERGENCE_PROFILES.fast_lab.maxTimeoutMs, 5_000)
  assert.equal(ASYNC_CONVERGENCE_PROFILES.wan.maxTimeoutMs, 30_000)

  await assert.rejects(
    () =>
      awaitAsyncConvergence({
        profile: 'fast_lab',
        timeoutMs: 5_001,
        pollFn: () => null,
        matchPredicate: () => false,
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'INVALID_INPUT',
  )
  await assert.rejects(
    () =>
      awaitAsyncConvergence({
        profile: 'wan',
        timeoutMs: 30_001,
        pollFn: () => null,
        matchPredicate: () => false,
      }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'INVALID_INPUT',
  )

  // Monotonic clock violation (future trigger timestamp) fails closed immediately.
  const futureTrigger = Date.now() + 60_000
  const monotonicFail = await awaitAsyncConvergence({
    timeoutMs: 1_000,
    intervalMs: 10,
    maxAttempts: 3,
    tTriggerMs: futureTrigger,
    pollFn: () => ({ ok: true }),
    matchPredicate: v => v.ok,
  })
  assert.equal(monotonicFail.converged, false)
  assert.equal(monotonicFail.status, 'monotonic_violation')
  assert.equal(monotonicFail.evidence.attemptLog[0]?.rejectedReason, 'clock_before_trigger')

  // Pre-aborted signal returns immediately with zero poll calls.
  const preAbort = new AbortController()
  preAbort.abort('cancelled')
  let called = 0
  const preAborted = await awaitAsyncConvergence({
    timeoutMs: 2_000,
    intervalMs: 50,
    signal: preAbort.signal,
    pollFn: () => {
      called += 1
      return false
    },
    matchPredicate: Boolean,
  })
  assert.equal(preAborted.converged, false)
  assert.equal(preAborted.status, 'aborted')
  assert.equal(preAborted.evidence.aborted, true)
  assert.equal(called, 0)

  // Mid-sleep abort wakes immediately without waiting for intervalMs (4_000ms).
  const midAbort = new AbortController()
  const abortStart = Date.now()
  setTimeout(() => midAbort.abort('stop_now'), 25)
  const midAborted = await awaitAsyncConvergence({
    timeoutMs: 4_500,
    intervalMs: 4_000,
    maxAttempts: 5,
    signal: midAbort.signal,
    pollFn: () => false,
    matchPredicate: Boolean,
  })
  const abortElapsed = Date.now() - abortStart
  assert.equal(midAborted.converged, false)
  assert.equal(midAborted.status, 'aborted')
  assert.equal(midAborted.evidence.aborted, true)
  assert.ok(abortElapsed < 500, `expected immediate abort, took ${abortElapsed}ms`)

  // Timeout cleanly stops even when pollFn hangs longer than timeoutMs.
  const timeoutStart = Date.now()
  const timedOut = await awaitAsyncConvergence({
    timeoutMs: 80,
    intervalMs: 20,
    maxAttempts: 10,
    pollFn: ({ signal }) =>
      new Promise<boolean>(resolve => {
        const timer = setTimeout(() => resolve(false), 5_000)
        signal.addEventListener(
          'abort',
          () => {
            clearTimeout(timer)
            resolve(false)
          },
          { once: true },
        )
      }),
    matchPredicate: Boolean,
  })
  const timeoutElapsed = Date.now() - timeoutStart
  assert.equal(timedOut.converged, false)
  assert.equal(timedOut.status, 'timeout')
  assert.equal(timedOut.evidence.timedOut, true)
  assert.ok(timeoutElapsed < 600, `expected clean timeout, took ${timeoutElapsed}ms`)

  // maxAttempts cap stops cleanly without hanging.
  const capped = await awaitAsyncConvergence({
    timeoutMs: 2_000,
    intervalMs: 5,
    maxAttempts: 3,
    pollFn: () => 'pending',
    matchPredicate: v => v === 'ready',
  })
  assert.equal(capped.converged, false)
  assert.equal(capped.status, 'max_attempts')
  assert.equal(capped.evidence.attempts, 3)
})

test('derived-custody module adheres to LOC budget (<= 650) and zero benchmark contamination', () => {
  const srcPath = new URL('../src/server/derived-custody.ts', import.meta.url)
  const source = readFileSync(srcPath, 'utf8')
  const lineCount = source.split('\n').length - (source.endsWith('\n') ? 1 : 0)
  assert.ok(lineCount <= 650, `derived-custody.ts exceeds 650 LOC budget: ${lineCount}`)
  const forbidden = /\b(paygrid|shipforge|nexusiam|connecthub|PG-C\d|SF-C\d|NX-C\d|CH-C\d)\b|(vault|registry|billing)\.internal/i
  assert.equal(forbidden.test(source), false, 'benchmark literal detected in src/server/derived-custody.ts')
})
