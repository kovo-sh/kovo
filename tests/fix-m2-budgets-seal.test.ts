/**
 * Regression suite for M2 WB blockers in `verify-rpc.ts` and `derived-custody.ts`:
 *  1. Raised finite DoS budget caps (`composite.verify` 1024/run, custody 4096/run,
 *     per-endpoint seal 256/endpoint/run, env-configurable within hard ceilings).
 *  2. Invalid/malformed RPC calls that fail argument validation do NOT consume budget.
 *  3. Structured `capability.seal` extraction (`$.` and bare dot `jsonPath`, `header`,
 *     `setCookie`/`cookie` with multi-cookie/Expires commas, `locationQuery`/`queryParam`
 *     on `Location` redirects, visible-only `value`).
 *  4. R2-C-3 security invariant: `regex` remains strictly retired before reading response
 *     bytes with a distinct non-secret message; all extraction/validation misses collapse
 *     to one constant non-secret message without echoing secret values.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN,
  DEFAULT_MAX_SEALS_PER_ENDPOINT,
  DEFAULT_MAX_SEALS_PER_RUN,
  DerivedCapabilityVault,
  DerivedCustodyError,
  SEAL_FIELD_NOT_FOUND_ERROR,
  SEAL_REGEX_RETIRED_ERROR,
  consumeRunCompositeVerifyBudget,
  consumeRunSealBudget,
  getRunCustodyBudgetUsage,
  resetRunCustodyBudgets,
} from '../src/server/derived-custody.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

interface RpcResp {
  ok: boolean
  result?: unknown
  error?: string
}

function rpcCall(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResp> {
  return new Promise((resolvePromise, reject) => {
    const body = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, res => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolvePromise(JSON.parse(data) as RpcResp) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

function makeGrant(origin: string, secrets: Array<{ value: string; placeholder: string }> = []): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(),
    secrets,
  }
}

function sha256(val: string): string {
  return createHash('sha256').update(val, 'utf8').digest('hex')
}

test('M2 budgets: default ceilings are 1024 composite / 4096 run seals / 256 per-endpoint seals and remain strictly bounded', (t) => {
  assert.equal(DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN, 1024)
  assert.equal(DEFAULT_MAX_SEALS_PER_RUN, 4096)
  assert.equal(DEFAULT_MAX_SEALS_PER_ENDPOINT, 256)

  const runComp = 'run-m2-comp-cap'
  const runEp = 'run-m2-ep-cap'
  const runTotal = 'run-m2-total-cap'
  const runEnv = 'run-m2-env-cap'
  t.after(() => {
    resetRunCustodyBudgets(runComp)
    resetRunCustodyBudgets(runEp)
    resetRunCustodyBudgets(runTotal)
    resetRunCustodyBudgets(runEnv)
  })

  // 1) composite.verify allows 1024 calls, blocks 1025th
  for (let i = 1; i <= DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN; i += 1) {
    assert.equal(consumeRunCompositeVerifyBudget(runComp), i)
  }
  assert.throws(
    () => consumeRunCompositeVerifyBudget(runComp),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'CAPACITY_EXCEEDED' && /max 1024 per run/.test(err.message),
  )

  // 2) per-endpoint seal allows 256 calls on one endpoint, blocks 257th
  for (let i = 1; i <= DEFAULT_MAX_SEALS_PER_ENDPOINT; i += 1) {
    assert.equal(consumeRunSealBudget(runEp, 'http://app|/api/token|user_a').endpointTotal, i)
  }
  assert.throws(
    () => consumeRunSealBudget(runEp, 'http://app|/api/token|user_a'),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'CAPACITY_EXCEEDED' && /max 256 per endpoint per run/.test(err.message),
  )

  // 3) run-wide capability custody allows 4096 across 16 endpoints, blocks 4097th
  for (let ep = 0; ep < 16; ep += 1) {
    for (let i = 0; i < DEFAULT_MAX_SEALS_PER_ENDPOINT; i += 1) {
      consumeRunSealBudget(runTotal, `http://app|/api/ep-${ep}|user_a`)
    }
  }
  assert.equal(getRunCustodyBudgetUsage(runTotal).sealTotal, 4096)
  assert.throws(
    () => consumeRunSealBudget(runTotal, 'http://app|/api/ep-17|user_a'),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'CAPACITY_EXCEEDED' && /max 4096 per run/.test(err.message),
  )

  // 4) Env override works and explicit option takes precedence over env
  const prevCompEnv = process.env.KOVO_MAX_COMPOSITE_VERIFIES_PER_RUN
  t.after(() => {
    if (prevCompEnv === undefined) delete process.env.KOVO_MAX_COMPOSITE_VERIFIES_PER_RUN
    else process.env.KOVO_MAX_COMPOSITE_VERIFIES_PER_RUN = prevCompEnv
  })
  process.env.KOVO_MAX_COMPOSITE_VERIFIES_PER_RUN = '2'
  assert.equal(consumeRunCompositeVerifyBudget(runEnv), 1)
  assert.equal(consumeRunCompositeVerifyBudget(runEnv), 2)
  assert.throws(() => consumeRunCompositeVerifyBudget(runEnv), /max 2 per run/)
  // Explicit override supersedes env
  assert.equal(consumeRunCompositeVerifyBudget(runEnv, 5), 3)

  // 5) Shared DerivedCapabilityVault default capacity exceeds legacy 512 ceiling
  const vault = new DerivedCapabilityVault({ runId: 'run-m2-vault-cap' })
  for (let i = 0; i < 600; i += 1) {
    vault.seal({ hopReceiptId: `h${i}`, slot: 'tok', rawValue: `secret_val_${String(i).padStart(6, '0')}` })
  }
  assert.equal(vault.list().length, 600)
})

test('M2 budgets: invalid/malformed RPC calls fail argument validation WITHOUT consuming run/endpoint budgets', async (t) => {
  const runId = 'run-m2-malformed-no-drain'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const target = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ access_token: 'oidc_tok_live_88990011' }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker(), grant: makeGrant(origin), runId, assignmentId: 'a-malformed', targetOrigins: [origin],
    maxSealsPerRun: 2, maxSealsPerEndpoint: 2, maxCompositeVerifiesPerRun: 2,
  })
  await rpc.start()
  t.after(() => rpc.close())

  const ex = await rpcCall(rpc, 'http.send', { path: '/oidc/token', method: 'POST' })
  assert.equal(ex.ok, true)
  const exchangeId = (ex.result as { exchangeId: string }).exchangeId

  // All malformed capability.seal calls must fail validation and consume 0 budget
  const badSealCalls: Array<Record<string, unknown>> = [
    {},
    { exchangeId: 'non-existent-ex', slot: 's', jsonPath: '$.access_token' },
    { exchangeId, slot: '', jsonPath: '$.access_token' },
    { exchangeId, slot: 'bad/slot with spaces', jsonPath: '$.access_token' },
    { exchangeId, slot: 's1', jsonPath: '$.access_token', kind: 42 },
    { exchangeId, slot: 's1', jsonPath: '$.access_token', ttlMs: -5 },
    { exchangeId, slot: 's1' }, // missing selector
    { exchangeId, slot: 's1', regex: '"access_token":"([^"]+)"' }, // retired regex
    { exchangeId, slot: 's1', jsonPath: '$.access_token', regex: '"access_token":"([^"]+)"' }, // retired regex alongside jsonPath
  ]
  for (const args of badSealCalls) {
    const r = await rpcCall(rpc, 'capability.seal', args)
    assert.equal(r.ok, false, `expected failure for ${JSON.stringify(args)}`)
  }
  // Malformed crypto.hmacSign / crypto.jwtSign calls must consume 0 budget
  for (const [op, args] of [
    ['crypto.hmacSign', {}],
    ['crypto.hmacSign', { secretHandle: 'cap:hop_1:k', literalKey: 'x', payload: 'p' }],
    ['crypto.hmacSign', { literalKey: 'k', payload: 123 }],
    ['crypto.hmacSign', { literalKey: 'public-literal-key-123', payload: 'p', alg: 'md5' }],
    ['crypto.hmacSign', { literalKey: 'public-literal-key-123', payload: 'p', encoding: 'ascii' }],
    ['crypto.jwtSign', {}],
    ['crypto.jwtSign', { secretHandle: 'cap:hop_1:k', claims: 'not-obj' }],
    ['crypto.jwtSign', { secretHandle: 'cap:hop_1:k', claims: { sub: 'u' }, alg: 'none' }],
    ['crypto.jwtSign', { secretHandle: 'cap:hop_1:k', claims: { sub: 'u' }, alg: 'HS256', header: { alg: 'HS512' } }],
  ] as const) {
    const r = await rpcCall(rpc, op, args as unknown as Record<string, unknown>)
    assert.equal(r.ok, false, `expected ${op} failure`)
  }

  // Malformed composite.verify calls must consume 0 budget
  for (const args of [
    {},
    { receipt: null },
    { receipt: 'invalid' },
    { receipt: { chainId: 'c1', hops: [] } },
    { receipt: { chainId: 'c1', hops: 'not-array' } },
  ]) {
    const r = await rpcCall(rpc, 'composite.verify', args)
    assert.equal(r.ok, false)
    assert.match(r.error ?? '', /non-empty hops array/i)
  }

  assert.deepEqual(getRunCustodyBudgetUsage(runId), { sealTotal: 0, compositeVerifyTotal: 0, sealByEndpoint: {} })

  // Valid seal now succeeds and consumes exactly 1 budget (duplicate immutable slot does not consume extra budget!)
  const okSeal = await rpcCall(rpc, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oidcAccessToken', jsonPath: '$.access_token', kind: 'bearer_token',
  })
  assert.equal(okSeal.ok, true, okSeal.error ?? '')
  assert.equal(getRunCustodyBudgetUsage(runId).sealTotal, 1)

  const dupSeal = await rpcCall(rpc, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oidcAccessToken', jsonPath: '$.access_token',
  })
  assert.equal(dupSeal.ok, false)
  assert.match(dupSeal.error ?? '', /immutable/i)
  assert.equal(getRunCustodyBudgetUsage(runId).sealTotal, 1, 'immutable handle rejection must not consume budget')
})

test('M2 capability.seal: handles $. and bare jsonPath, header, setCookie, locationQuery/queryParam, BOM, and clear non-secret errors', async (t) => {
  const runId = 'run-m2-seal-selectors'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const OIDC_TOK = 'oidc_access_tok_alpha_99887766'
  const TPL_ID = 'tpl_prod_44556677'
  const JOB_ID = 'job_export_11223344'
  const ITEM_ID = 'item_nested_55667788'
  const HDR_TOK = 'hdr_secret_x_api_33445566'
  const CK_ONE = 'ck_first_val_112233=='
  const CK_TWO = 'ck_second_val_99887766'
  const LOC_CODE = 'auth_code_redirect_77665544'
  const LOC_FRAG = 'frag_access_tok_66554433'
  const HIDDEN_SECRET = 'hidden_vault_secret_00998877'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/oidc/token') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'x-api-token': HDR_TOK,
        'set-cookie': [
          `first_sid=${CK_ONE}; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; HttpOnly`,
          `second_sid=${CK_TWO}; Path=/; SameSite=Lax`,
        ],
      })
      // Include UTF-8 BOM to verify BOM-tolerant JSON parsing
      res.end('\uFEFF' + JSON.stringify({
        access_token: OIDC_TOK,
        template: { id: TPL_ID },
        jobId: JOB_ID,
        items: [{ id: ITEM_ID }],
        hidden: HIDDEN_SECRET,
      }))
      return
    }
    if (url.pathname === '/oauth/authorize') {
      res.writeHead(302, {
        location: `https://client.example.invalid/callback?code=${LOC_CODE}&state=ok#access_token=${LOC_FRAG}&token_type=bearer`,
      })
      res.end('')
      return
    }
    if (url.pathname === '/oauth/rel-redirect') {
      res.writeHead(302, { location: `/next/step?token=${LOC_CODE}` })
      res.end('')
      return
    }
    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin, [{ value: HIDDEN_SECRET, placeholder: '[redacted:hidden]' }]),
    runId, assignmentId: 'a-selectors', targetOrigins: [origin],
    maxSealsPerExchange: 30,
  })
  await rpc.start()
  t.after(() => rpc.close())

  const exJson = await rpcCall(rpc, 'http.send', { path: '/oidc/token', method: 'POST' })
  assert.equal(exJson.ok, true)
  const jsonId = (exJson.result as { exchangeId: string }).exchangeId

  const exRedir = await rpcCall(rpc, 'http.send', { path: '/oauth/authorize', method: 'GET', followRedirects: false })
  assert.equal(exRedir.ok, true)
  const redirId = (exRedir.result as { exchangeId: string }).exchangeId

  const exRelRedir = await rpcCall(rpc, 'http.send', { path: '/oauth/rel-redirect', method: 'GET', followRedirects: false })
  assert.equal(exRelRedir.ok, true)
  const relRedirId = (exRelRedir.result as { exchangeId: string }).exchangeId

  // Cookie attribute name (e.g. Path) must NOT be matched as a cookie name
  const attrMiss = await rpcCall(rpc, 'capability.seal', { exchangeId: jsonId, hopReceiptId: '1', slot: 'attr_miss', setCookie: 'Path' })
  assert.equal(attrMiss.ok, false)
  assert.equal(attrMiss.error, SEAL_FIELD_NOT_FOUND_ERROR)

  // 1) Both $. and bare dot-paths work cleanly
  const cases: Array<{ exId: string; slot: string; args: Record<string, unknown>; expectedRaw: string; expectedKind: string }> = [
    { exId: jsonId, slot: 'oidc_dollar', args: { jsonPath: '$.access_token', kind: 'bearer_token' }, expectedRaw: OIDC_TOK, expectedKind: 'bearer_token' },
    { exId: jsonId, slot: 'oidc_bare', args: { jsonPath: 'access_token', kind: 'bearer_token' }, expectedRaw: OIDC_TOK, expectedKind: 'bearer_token' },
    { exId: jsonId, slot: 'tpl_dollar', args: { jsonPath: '$.template.id' }, expectedRaw: TPL_ID, expectedKind: 'generic_secret' },
    { exId: jsonId, slot: 'tpl_bare', args: { jsonPath: 'template.id' }, expectedRaw: TPL_ID, expectedKind: 'generic_secret' },
    { exId: jsonId, slot: 'job_dollar', args: { jsonPath: '$.jobId' }, expectedRaw: JOB_ID, expectedKind: 'generic_secret' },
    { exId: jsonId, slot: 'item_dollar', args: { jsonPath: '$.items[0].id' }, expectedRaw: ITEM_ID, expectedKind: 'generic_secret' },
    { exId: jsonId, slot: 'item_bare', args: { jsonPath: 'items[0].id' }, expectedRaw: ITEM_ID, expectedKind: 'generic_secret' },
    { exId: jsonId, slot: 'hdr_ci', args: { header: 'X-API-Token' }, expectedRaw: HDR_TOK, expectedKind: 'header_secret' },
    { exId: jsonId, slot: 'setck_1', args: { setCookie: 'first_sid' }, expectedRaw: CK_ONE, expectedKind: 'cookie' },
    { exId: jsonId, slot: 'setck_2', args: { setCookie: 'second_sid' }, expectedRaw: CK_TWO, expectedKind: 'cookie' },
    { exId: jsonId, slot: 'ck_alias', args: { cookie: 'second_sid' }, expectedRaw: CK_TWO, expectedKind: 'cookie' },
    { exId: redirId, slot: 'loc_code', args: { locationQuery: 'code' }, expectedRaw: LOC_CODE, expectedKind: 'generic_secret' },
    { exId: redirId, slot: 'loc_frag', args: { locationQuery: 'access_token', kind: 'bearer_token' }, expectedRaw: LOC_FRAG, expectedKind: 'bearer_token' },
    { exId: relRedirId, slot: 'loc_qparam', args: { queryParam: 'token' }, expectedRaw: LOC_CODE, expectedKind: 'generic_secret' },
  ]
  for (const c of cases) {
    const res = await rpcCall(rpc, 'capability.seal', { exchangeId: c.exId, hopReceiptId: '1', slot: c.slot, ...c.args })
    assert.equal(res.ok, true, `case ${c.slot} failed: ${res.error ?? ''}`)
    const out = res.result as { handle: string; meta: { kind: string; defaultCookieName?: string } }
    assert.equal(out.meta.kind, c.expectedKind, `unexpected kind for ${c.slot}`)
    assert.equal(rpc.capabilityVault.getMeta(out.handle)?.sha256, sha256(c.expectedRaw), `wrong sealed bytes for ${c.slot}`)
    assert.equal(JSON.stringify(res).includes(c.expectedRaw), false, `raw value leaked for ${c.slot}`)
    if (c.slot === 'setck_1') assert.equal(out.meta.defaultCookieName, 'first_sid')
  }

  // 2) R2-C-3: regex selector strictly rejected with clear non-secret message (byte-identical for true vs false lookahead)
  const rxTrue = await rpcCall(rpc, 'capability.seal', { exchangeId: jsonId, hopReceiptId: '2', slot: 'rx1', regex: '(?="hidden":"hidden_)access_token' })
  const rxFalse = await rpcCall(rpc, 'capability.seal', { exchangeId: jsonId, hopReceiptId: '2', slot: 'rx2', regex: '(?="hidden":"zzz_)access_token' })
  assert.equal(rxTrue.ok, false)
  assert.equal(rxFalse.ok, false)
  assert.equal(rxTrue.error, SEAL_REGEX_RETIRED_ERROR)
  assert.equal(rxFalse.error, SEAL_REGEX_RETIRED_ERROR)

  // 3) Extraction misses return crystal-clear constant non-secret message and never echo secrets
  const misses = await Promise.all([
    rpcCall(rpc, 'capability.seal', { exchangeId: jsonId, hopReceiptId: '2', slot: 'm1', jsonPath: '$.nonexistent' }),
    rpcCall(rpc, 'capability.seal', { exchangeId: jsonId, hopReceiptId: '2', slot: 'm2', header: 'x-missing' }),
    rpcCall(rpc, 'capability.seal', { exchangeId: jsonId, hopReceiptId: '2', slot: 'm3', setCookie: 'missing_cookie' }),
    rpcCall(rpc, 'capability.seal', { exchangeId: redirId, hopReceiptId: '2', slot: 'm4', locationQuery: 'missing_param' }),
    rpcCall(rpc, 'capability.seal', { exchangeId: jsonId, hopReceiptId: '2', slot: 'm5', value: HIDDEN_SECRET }),
  ])
  for (const m of misses) {
    assert.equal(m.ok, false)
    assert.equal(m.error, SEAL_FIELD_NOT_FOUND_ERROR)
    assert.equal((m.error ?? '').includes(HIDDEN_SECRET), false)
    assert.equal((m.error ?? '').includes(OIDC_TOK), false)
  }
})

test('M2 invariants: verify-rpc.ts <= 2300 LOC, derived-custody.ts <= 650 LOC, zero direct egressHttp2 bypasses', () => {
  const rpcSrc = readFileSync(join(REPO_ROOT, 'src/server/verify-rpc.ts'), 'utf8')
  const rpcLoc = rpcSrc.trimEnd().split('\n').length
  assert.ok(rpcLoc <= 2300, `verify-rpc.ts is ${rpcLoc} LOC (must be <= 2300)`)
  assert.equal(/\begressHttp2\s*\(/.test(rpcSrc), false, 'verify-rpc.ts must not call egressHttp2 directly (C-1)')
  const custodyLoc = readFileSync(join(REPO_ROOT, 'src/server/derived-custody.ts'), 'utf8').trimEnd().split('\n').length
  assert.ok(custodyLoc <= 650, `derived-custody.ts is ${custodyLoc} LOC (must be <= 650)`)
})
