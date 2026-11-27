/**
 * Stream B (v8 M2 SDK & RPC Ergonomics) behavioral regression tests.
 *
 * Covers:
 *  1. `causalEdges[].kind` alias normalization (`type`, `bindingKind`, `binding`, shorthand literals)
 *     plus actionable invalid-kind error listing all 4 valid literals.
 *  2. `ChainBuilder.build()` routing control-only hops into `preChainControlExchangeIds` instead of
 *     leaving orphaned control nodes in `hops[]`.
 *  3. Differentiated, zero-secret-leakage `capability.seal` failure diagnostics via `ctx.seal_capability`
 *     while preserving the host `VerifyRpcServer` C-3 constant-error security invariant.
 *  4. Unmistakable single-script Mode-A wording in `verify-runner.ts` (`checkpoint_only` hint).
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'
import { compositeProofReceiptSchema } from '../src/server/composite-receipt.ts'
import { resetRunCustodyBudgets, SEAL_FIELD_NOT_FOUND_ERROR } from '../src/server/derived-custody.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  TranscriptStore,
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import {
  verifyScript,
  type VerifyAttemptSession,
  type VerifyScriptOptions,
} from '../src/server/verify-runner.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const HIDDEN_SECRET = 'sec_hidden_vault_only_99441122'
const SECRET_HTML_BODY = 'sec_html_raw_body_leak_88332211'
const SECRET_OBJ_VAL = 'sec_obj_nested_val_77221100'
const SECRET_ARR_VAL = 'sec_arr_nested_val_66110099'
const SECRET_LOC_VAL = 'sec_loc_query_val_55009988'
const VALID_MINT_TOK = 'mint_opaque_tok_alpha_11223344'
const VALID_SIGN_KEY = 'hmac_signing_key_beta_44332211'

function makeGrant(origin: string, port: number, secrets: Array<{ value: string; placeholder: string }> = []): Grant {
  const memberA: ResolvedPersona = {
    id: 'member_a',
    handle: 'member_a',
    roleLabel: 'member (tenant-a)',
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret: 'member-a-session-token-998877',
    canaryMarkers: [],
    session: { headerType: 'bearer', value: 'member-a-session-token-998877', adapterUsed: 'static' },
  }
  return {
    origin,
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    allowedPorts: [port],
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map([['member_a', memberA]]),
    secrets,
  }
}

async function startFixture(t: TestContext, runId: string): Promise<{ origin: string; server: VerifyRpcServer; ctx: VerifyContext }> {
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const jobs = new Map<string, { status: string; tenant: string }>()
  const httpServer = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')

    if (u.pathname === '/api/non-json') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(`<html><body>Login failed: ${SECRET_HTML_BODY}</body></html>`)
      return
    }
    if (u.pathname === '/api/seal-cases') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'x-short-hdr': 'ab',
        'x-valid-hdr': 'hdr_valid_opaque_token_998877',
      })
      res.end(JSON.stringify({
        nested: { token: SECRET_OBJ_VAL, id: 'obj-1' },
        items: [{ secret: SECRET_ARR_VAL, code: 'c1' }],
        shortVal: 'ab',
        repVal: 'aaaaaaaaaaaa',
        hidden: HIDDEN_SECRET,
        realTok: VALID_MINT_TOK,
      }))
      return
    }
    if (u.pathname === '/api/no-location') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true }))
      return
    }
    if (u.pathname === '/api/redirect-params') {
      res.writeHead(302, {
        'content-type': 'text/plain',
        location: `/cb?state=abc123&nonce=${SECRET_LOC_VAL}#short=xy`,
      })
      res.end('redirecting')
      return
    }
    if (u.pathname === '/api/set-cookie-case') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': 'short_ck=xy; Path=/; HttpOnly',
      })
      res.end(JSON.stringify({ ok: true }))
      return
    }
    if (u.pathname === '/api/v1/mint' && req.method === 'POST') {
      jobs.set('job-9001', { status: 'ready', tenant: 'tenant-b' })
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ token: VALID_MINT_TOK, signingKey: VALID_SIGN_KEY, jobId: 'job-9001' }))
      return
    }
    if (u.pathname === '/api/v1/export') {
      if (auth === `Bearer ${VALID_MINT_TOK}`) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ tenant: 'tenant-b', records: [{ id: 'rec-b-1', email: 'victim@tenant-b.test' }] }))
        return
      }
      res.writeHead(403, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'not_found' }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(resolve => httpServer.close(() => resolve())))
  await once(httpServer, 'listening')
  const port = (httpServer.address() as AddressInfo).port
  const origin = `http://127.0.0.1:${port}`

  const server = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin, port, [{ value: HIDDEN_SECRET, placeholder: '[redacted:hidden]' }]),
    runId,
    assignmentId: `asg-${runId}`,
    targetOrigins: [origin],
    maxSealsPerExchange: 40,
  })
  await server.start()
  t.after(() => server.close())

  const prev = {
    sock: process.env[VERIFY_RPC_SOCKET_ENV],
    tok: process.env[VERIFY_RPC_TOKEN_ENV],
    ctx: process.env[VERIFY_RPC_CONTEXT_ENV],
    nonce: process.env[VERIFY_NONCE_ENV],
  }
  process.env[VERIFY_RPC_SOCKET_ENV] = server.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(server.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(server.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = server.nonce
  t.after(() => {
    if (prev.sock === undefined) delete process.env[VERIFY_RPC_SOCKET_ENV]; else process.env[VERIFY_RPC_SOCKET_ENV] = prev.sock
    if (prev.tok === undefined) delete process.env[VERIFY_RPC_TOKEN_ENV]; else process.env[VERIFY_RPC_TOKEN_ENV] = prev.tok
    if (prev.ctx === undefined) delete process.env[VERIFY_RPC_CONTEXT_ENV]; else process.env[VERIFY_RPC_CONTEXT_ENV] = prev.ctx
    if (prev.nonce === undefined) delete process.env[VERIFY_NONCE_ENV]; else process.env[VERIFY_NONCE_ENV] = prev.nonce
  })

  return { origin, server, ctx: new VerifyContext() }
}

test('causalEdges[].kind normalizes aliases (type/bindingKind/binding/shorthands) and fails with all 4 valid kinds on unknown', async t => {
  const { ctx } = await startFixture(t, 'run-sdk-rpc-edge-aliases')

  const ctrl = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'control' })
  assert.equal(ctrl.status, 403)
  const mint = await ctx.http_send('/api/v1/mint', { method: 'POST', as: 'member_a', role: 'probe' })
  assert.equal(mint.status, 200)
  const cap = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'tok', jsonPath: '$.token', kind: 'bearer_token' })
  const exp = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: { handle: cap.handle, target: 'bearer' } })
  assert.equal(exp.status, 200)

  // 1) Alias `type: 'value'` + `edges` + top-level `controlExchanges` normalizes & confirms live
  const confirmed = await ctx.prove_composite({
    chainId: 'chain-alias-value',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', target: 'POST /api/v1/mint', exchangeIds: [mint.exchangeId], claimedDelta: 'Minted token.', producedCapabilities: [cap.handle] },
      { hopId: 'hop_2', target: 'GET /api/v1/export', exchangeIds: [exp.exchangeId], claimedDelta: 'Read foreign tenant export.', consumedCapabilities: [cap.handle] },
    ],
    edges: [{ type: 'value', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap.handle }],
    controlExchanges: [ctrl],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Cross-tenant read via aliased edge kind.', terminalExchangeId: exp.exchangeId },
  } as never)
  assert.equal(confirmed.confirmed, true, `Expected aliased value edge to confirm: ${JSON.stringify(confirmed)}`)

  // 2) ChainBuilder.edge() normalizes all 4 alias families cleanly and validates against compositeProofReceiptSchema
  const c = ctx.chain('chain-edge-norm', 'cross_tenant_read')
  c.recordHop({ hopId: 'h1', target: 'POST /api/v1/mint', exchangeIds: [mint.exchangeId], claimedDelta: 'h1', producedCapabilities: [cap.handle] })
  c.recordHop({ hopId: 'h2', target: 'GET /api/v1/export', exchangeIds: [exp.exchangeId], claimedDelta: 'h2', consumedCapabilities: [cap.handle] })
  c.recordHop({ hopId: 'h3', target: 'GET /api/v1/export', exchangeIds: [exp.exchangeId], claimedDelta: 'h3' })
  c.recordHop({ hopId: 'h4', target: 'GET /api/v1/export', exchangeIds: [exp.exchangeId], claimedDelta: 'h4' })
  c.edge({ bindingKind: 'state_transition', fromHopId: 'h1', toHopId: 'h2', entityId: 'job-9001', ablationExchange: ctrl } as never)
  c.edge({ binding: 'hmac_sign', fromHopId: 'h2', toHopId: 'h3', sourceCapabilityId: cap.handle } as never)
  c.edge({ type: 'await_async', fromHopId: 'h3', toHopId: 'h4', correlationId: 'job-9001', channel: 'poll_convergence' } as never)
  const built = c.build({ control: ctrl })
  const parsed = compositeProofReceiptSchema.safeParse(built)
  assert.equal(parsed.success, true, `Normalized ChainBuilder receipt must pass schema: ${JSON.stringify(parsed)}`)
  const kinds = (built.causalEdges ?? []).map(e => e.kind)
  assert.ok(kinds.includes('state_transition_binding'))
  assert.ok(kinds.includes('derived_crypto_binding'))
  assert.ok(kinds.includes('async_pivot_binding'))

  // 3) Aliased state_transition_binding still enforces explicit entityId + ablationExchangeIds
  assert.throws(
    () => c.edge({ type: 'state_transition', fromHopId: 'h1', toHopId: 'h2', entityId: 'job-9001' } as never),
    /ablationExchangeIds/i,
  )

  // 4) Unknown kind fails with actionable error listing all 4 canonical literals
  await assert.rejects(
    () => ctx.prove_composite({
      chainId: 'chain-bad-kind',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_1', target: 'POST /api/v1/mint', exchangeIds: [mint.exchangeId], claimedDelta: 'h1' },
        { hopId: 'hop_2', target: 'GET /api/v1/export', exchangeIds: [exp.exchangeId], claimedDelta: 'h2' },
      ],
      causalEdges: [{ kind: 'custom_unknown_edge', fromHopId: 'hop_1', toHopId: 'hop_2' } as never],
      terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'test' },
    }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /value_binding/)
      assert.match(msg, /derived_crypto_binding/)
      assert.match(msg, /state_transition_binding/)
      assert.match(msg, /async_pivot_binding/)
      return true
    },
  )
})

test('ChainBuilder.build() promotes unlinked control-only hops into preChainControlExchangeIds instead of orphaned hops[]', async t => {
  const { ctx } = await startFixture(t, 'run-sdk-rpc-control-hop')
  const chain = ctx.chain('chain-ctrl-promote', 'cross_tenant_read')

  // Worker accidentally wraps a role:'control' exchange inside chain.hop(...)
  const ctrl1 = await chain.hop('ctrl_implicit', () => ctx.http_send('/api/v1/export', { as: 'member_a', role: 'control' }))
  assert.equal(ctrl1.status, 403)

  // Worker explicitly passes role:'control' on hop metadata
  const ctrl2 = await chain.hop('ctrl_explicit', { role: 'control' }, () => ctx.http_send('/api/v1/export', { as: 'member_a' }))
  assert.equal(ctrl2.status, 403)

  // Normal setup + probe hops
  const cap = await chain.hop('hop_1', { claimedDelta: 'Minted bearer token.' }, async () => {
    const r = await ctx.http_send('/api/v1/mint', { method: 'POST', as: 'member_a', role: 'setup' })
    return ctx.seal_capability({ exchange: r, hopReceiptId: 'hop_1', slot: 'tok', jsonPath: '$.token', kind: 'bearer_token' })
  })
  const finalEx = await chain.hop('hop_2', { claimedDelta: 'Exported foreign tenant data.' }, () =>
    ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: { handle: cap.handle, target: 'bearer' } }),
  )
  assert.equal(finalEx.status, 200)

  const receipt = chain.build({ claimedImpact: 'Control hops promoted cleanly without orphaned DAG nodes.' })
  assert.deepEqual(receipt.hops.map(h => h.hopId), ['hop_1', 'hop_2'], 'control-only hops must not appear as orphaned nodes in hops[]')
  assert.ok(receipt.terminalImpact.preChainControlExchangeIds?.includes(ctrl1.exchangeId))
  assert.ok(receipt.terminalImpact.preChainControlExchangeIds?.includes(ctrl2.exchangeId))

  const proved = await chain.prove({ claimedImpact: 'Control hops promoted cleanly without orphaned DAG nodes.' })
  assert.equal(proved.confirmed, true, `Expected chain with promoted control hops to confirm: ${JSON.stringify(proved)}`)
})

test('ctx.seal_capability differentiates all 5 failure modes with ZERO raw secret leakage while host RPC preserves C-3', async t => {
  const { server, ctx } = await startFixture(t, 'run-sdk-rpc-seal-diag')

  const nonJson = await ctx.http_send('/api/non-json', { as: 'member_a' })
  const sealCases = await ctx.http_send('/api/seal-cases', { as: 'member_a' })
  const noLoc = await ctx.http_send('/api/no-location', { as: 'member_a' })
  const redir = await ctx.http_send('/api/redirect-params', { as: 'member_a', followRedirects: false })
  const setCk = await ctx.http_send('/api/set-cookie-case', { as: 'member_a' })

  const assertNoSecrets = (msg: string) => {
    for (const secret of [HIDDEN_SECRET, SECRET_HTML_BODY, SECRET_OBJ_VAL, SECRET_ARR_VAL, SECRET_LOC_VAL, VALID_MINT_TOK]) {
      assert.equal(msg.includes(secret), false, `Diagnostic leaked secret material: ${msg}`)
    }
  }

  // 1) Non-JSON response body when jsonPath requested -> HTTP status + content-type, zero raw body
  await assert.rejects(
    () => ctx.seal_capability({ exchange: nonJson, slot: 's1', jsonPath: '$.token' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /non-JSON/i)
      assert.match(msg, /HTTP 200/)
      assert.match(msg, /text\/html/i)
      assert.equal(msg.includes('<html>'), false, 'must not leak raw HTML body')
      assertNoSecrets(msg)
      return true
    },
  )

  // 2a) Value at jsonPath is an object -> type + subkeys, zero values
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's2', jsonPath: '$.nested' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /resolved to object/i)
      assert.match(msg, /subkeys=\[token, id\]/)
      assertNoSecrets(msg)
      return true
    },
  )

  // 2b) Value at jsonPath is an array -> type + length + [0] subkeys, zero values
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's3', jsonPath: '$.items' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /resolved to array/i)
      assert.match(msg, /length=1/)
      assert.match(msg, /\[0\] subkeys=\[secret, code\]/)
      assertNoSecrets(msg)
      return true
    },
  )

  // 3a) locationQuery requested when Location header is absent -> followRedirects: false hint
  await assert.rejects(
    () => ctx.seal_capability({ exchange: noLoc, slot: 's4', locationQuery: 'code' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /no Location header/i)
      assert.match(msg, /followRedirects:\s*false/)
      assertNoSecrets(msg)
      return true
    },
  )

  // 3b) locationQuery requested when Location header is present but param missing -> param names only, zero values
  await assert.rejects(
    () => ctx.seal_capability({ exchange: redir, slot: 's5', locationQuery: 'code' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /available params=\[state, nonce, short\]/)
      assertNoSecrets(msg)
      return true
    },
  )

  // 4) Value found at selector but failed min-length / entropy validation -> NEVER echo value
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's6', jsonPath: '$.shortVal' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /too short \(<6 chars\) or low entropy/i)
      assert.equal(msg.includes('"ab"'), false)
      assertNoSecrets(msg)
      return true
    },
  )
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's7', jsonPath: '$.repVal' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /too short \(<6 chars\) or low entropy/i)
      assert.equal(msg.includes('aaaaaaaaaaaa'), false)
      assertNoSecrets(msg)
      return true
    },
  )
  await assert.rejects(
    () => ctx.seal_capability({ exchange: redir, slot: 's8', locationQuery: 'short' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /too short \(<6 chars\) or low entropy/i)
      assert.equal(msg.includes('xy'), false)
      assertNoSecrets(msg)
      return true
    },
  )
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's9', header: 'x-short-hdr' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /too short \(<6 chars\) or low entropy/i)
      assertNoSecrets(msg)
      return true
    },
  )

  // 5) value selector not found in host-visible transcript -> selector hint, NEVER echo secret
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's10', value: HIDDEN_SECRET }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /Use jsonPath \/ header \/ setCookie \/ locationQuery selector/i)
      assertNoSecrets(msg)
      return true
    },
  )

  // 6) Missing jsonPath key preserves [status=..., topKeys=[...]] hint, and missing setCookie/header report cleanly
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's11', jsonPath: '$.doesNotExist' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /\[status=200, topKeys=\[/)
      assert.match(msg, /realTok/)
      assertNoSecrets(msg)
      return true
    },
  )
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sealCases, slot: 's12', setCookie: 'sid' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /no Set-Cookie header/i)
      return true
    },
  )
  await assert.rejects(
    () => ctx.seal_capability({ exchange: setCk, slot: 's13', setCookie: 'short_ck' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /too short \(<6 chars\) or low entropy/i)
      return true
    },
  )

  // 7) Host VerifyRpcServer C-3 invariant check: valid seal still succeeds cleanly
  const okSeal = await ctx.seal_capability({ exchange: sealCases, slot: 's_ok', jsonPath: '$.realTok' })
  assert.match(okSeal.handle, /^cap:/)
  assert.ok(server.capabilityVault.getMeta(okSeal.handle))
  assert.ok(SEAL_FIELD_NOT_FOUND_ERROR.includes('structured field not found'))
})

test('verify-runner checkpoint_only hint drops misleading "Checkpoint saved" and explicitly warns handles expire across scripts', async () => {
  const candidate: VerifyScriptOptions['candidate'] = {
    name: 'seal-only-hint.ts',
    runtime: 'ts',
    title: 'Seal only',
    code: 'return ctx.result({ title: "Seal only" })',
  }
  const verdict = await verifyScript({
    candidate,
    fastFailOnAttempt1: true,
    openAttempt: async ({ nonce }): Promise<VerifyAttemptSession> => {
      const transcript = new TranscriptStore(Buffer.from('hint-test-key'))
      transcript.record({
        op: 'capability',
        startedAt: Date.now(),
        durationMs: 1,
        request: { origin: 'http://127.0.0.1:9999', method: 'SEAL', pathAndQuery: '/capability/seal/tok', headers: {}, bodyBytes: 0, bodySha256: 'abc', nonce },
        artifact: { kind: 'capability', capabilityHandle: 'cap:hop_1:tok', artifactDigest: 'abc' },
      })
      return {
        nonce,
        transcript,
        async execute() {
          return { result: { sdk: 'kovo_verify.ts', nonce, title: 'Seal only', claims: [] }, stdout: '', stderr: '', exitCode: 0, durationMs: 5 }
        },
        async close() { /* noop */ },
      }
    },
  })

  assert.equal(verdict.confirmed, false)
  assert.equal(verdict.reason, 'checkpoint_only')
  assert.equal(verdict.rejectedBy, 'checkpoint')
  assert.doesNotMatch(verdict.detail, /Checkpoint saved/i, 'must never mislead workers with "Checkpoint saved"')
  assert.match(verdict.detail, /NO cross-script state saved/i)
  assert.match(verdict.detail, /sealed handles expire when this script exits/i)
  assert.match(verdict.detail, /Hop 1->N in ONE ctx\.chain\(\.\.\.\)\.prove\(\)/)
  assert.match(verdict.detail, /ctx\.prove_composite/)
  assert.match(verdict.detail, /cap:hop_1:tok/)
  assert.ok(verdict.usageHint && !/Checkpoint saved/i.test(verdict.usageHint))
})
