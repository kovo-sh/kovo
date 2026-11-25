/**
 * Focused unit + type-level tests for the `kovo_verify.ts` CompositeProofReceipt SDK types,
 * target shorthand normalization, strict camelCase RPC serialization, and `HttpOptions.role` usage.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { compositeProofReceiptSchema } from '../src/server/composite-receipt.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'
import type {
  CausalEdgeInput,
  CompositeProofReceiptInput,
  HopReceiptInput,
  HttpOptions,
  TerminalImpactInput,
} from '../worker/kovo_verify/kovo_verify.ts'

const DEFAULT_ORIGIN = 'https://api.example.test'
const IDP_ORIGIN = 'https://idp.example.test'

interface CapturedRpcCall {
  op: string
  args: Record<string, unknown>
}

async function withMockRpcServer(
  t: test.TestContext,
  confirm = true,
): Promise<{ calls: CapturedRpcCall[] }> {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-sdk-types-'))
  const sockPath = join(dir, 'verify.sock')
  const contextFile = join(dir, 'context.json')
  const tokenFile = join(dir, 'token')
  const calls: CapturedRpcCall[] = []

  writeFileSync(contextFile, JSON.stringify({
    nonce: 'nonce-test-1',
    runId: 'run-sdk-types-1',
    targetOrigins: [DEFAULT_ORIGIN],
    sdkVersion: 'kovo_verify/v8',
  }))
  writeFileSync(tokenFile, 'test-rpc-token')

  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as CapturedRpcCall
      calls.push(parsed)
      const receipt = parsed.args.receipt as Record<string, unknown>
      const response = {
        ok: true,
        result: {
          confirmed: confirm,
          chainId: String(receipt.chainId ?? 'invalid'),
          terminalVulnClass: String(receipt.terminalVulnClass ?? 'unknown'),
          replayMode: String(receipt.replayMode ?? 'fresh_clean_replay'),
          modeBVerified: false,
          hopCount: Array.isArray(receipt.hops) ? receipt.hops.length : 0,
          verifiedEdges: [],
          reason: confirm ? 'confirmed' : 'rejected',
          claim: {
            kind: 'composite_receipt',
            verificationId: 'gc-test-1',
            chainId: String(receipt.chainId ?? 'invalid'),
            terminalVulnClass: String(receipt.terminalVulnClass ?? 'unknown'),
            exchangeIds: ['ex-1'],
            hopCount: Array.isArray(receipt.hops) ? receipt.hops.length : 0,
          },
        },
      }
      const body = JSON.stringify(response)
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
      res.end(body)
    })
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(sockPath, resolve)
  })

  const prevEnv = {
    KOVO_RPC_SOCKET: process.env.KOVO_RPC_SOCKET,
    KOVO_RPC_CONTEXT_FILE: process.env.KOVO_RPC_CONTEXT_FILE,
    KOVO_RPC_TOKEN_FILE: process.env.KOVO_RPC_TOKEN_FILE,
    KOVO_VERIFY_NONCE: process.env.KOVO_VERIFY_NONCE,
  }
  process.env.KOVO_RPC_SOCKET = sockPath
  process.env.KOVO_RPC_CONTEXT_FILE = contextFile
  process.env.KOVO_RPC_TOKEN_FILE = tokenFile
  process.env.KOVO_VERIFY_NONCE = 'nonce-test-1'

  t.after(async () => {
    for (const [k, v] of Object.entries(prevEnv)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
    await new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) })
    rmSync(dir, { recursive: true, force: true })
  })

  return { calls }
}

test('prove_composite normalizes shorthand string & partial targets to canonical strict camelCase objects', async (t) => {
  const { calls } = await withMockRpcServer(t, true)
  const ctx = new VerifyContext()

  const receipt: CompositeProofReceiptInput = {
    chainId: 'chain-sdk-norm-1',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: '/api/orders?filter=pending',
        method: 'post',
        exchangeIds: ['ex-1'],
        producedCapabilities: ['cap:hop_1:order_tok'],
        claimedDelta: 'Created order capability via shorthand path + hop.method.',
      },
      {
        hopId: 'hop_2',
        surface: 'idp',
        target: `PUT ${IDP_ORIGIN}/oauth/session?mode=delegated`,
        exchangeIds: ['ex-2'],
        consumedCapabilities: ['cap:hop_1:order_tok'],
        producedCapabilities: ['cap:hop_2:session_jwt'],
        claimedDelta: 'Exchanged capability via method-prefixed full URL.',
      },
      {
        hopId: 'hop_3',
        target: '/api/records/export',
        exchangeIds: ['ex-3'],
        claimedDelta: 'Bare path shorthand without explicit method.',
      },
      {
        hopId: 'hop_4',
        surface: 'storage',
        target: { origin: DEFAULT_ORIGIN, method: 'get', pathAndQuery: '/api/vault/items' },
        exchangeIds: ['ex-4'],
        consumedCapabilities: ['cap:hop_2:session_jwt'],
        claimedDelta: 'Canonical object target with lowercase method normalized to uppercase.',
      },
    ],
    causalEdges: [
      {
        kind: 'value_binding',
        fromHopId: 'hop_1',
        toHopId: 'hop_2',
        capabilityHandle: 'cap:hop_1:order_tok',
      },
      {
        kind: 'value_binding',
        fromHopId: 'hop_2',
        toHopId: 'hop_4',
        capabilityHandle: 'cap:hop_2:session_jwt',
      },
      {
        kind: 'state_transition_binding',
        fromHopId: 'hop_3',
        toHopId: 'hop_4',
        entityId: 'ord-100',
        ablationExchangeIds: ['ex-ctrl-1'],
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop_4',
      terminalExchangeId: 'ex-4',
      claimedImpact: 'Cross-tenant readback confirmed.',
      preChainControlExchangeIds: ['ex-ctrl-1'],
      postChainReadbackExchangeIds: ['ex-4'],
    },
    replayMode: 'fresh_clean_replay',
  }

  const verdict = await ctx.prove_composite(receipt)
  assert.equal(verdict.confirmed, true)
  assert.equal(ctx.claims.length, 1)
  assert.equal(calls.length, 1)
  assert.equal(calls[0]!.op, 'composite.verify')

  const sent = calls[0]!.args.receipt as Record<string, unknown>
  const parsed = compositeProofReceiptSchema.safeParse(sent)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))

  const sentHops = sent.hops as Array<Record<string, unknown>>
  assert.deepEqual(sentHops[0]!.target, {
    origin: DEFAULT_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/orders?filter=pending',
  })
  assert.equal('method' in sentHops[0]!, false, 'client-side shorthand hop.method must not leak as a top-level hop property')

  assert.deepEqual(sentHops[1]!.target, {
    origin: IDP_ORIGIN,
    method: 'PUT',
    pathAndQuery: '/oauth/session?mode=delegated',
  })

  assert.deepEqual(sentHops[2]!.target, {
    origin: DEFAULT_ORIGIN,
    pathAndQuery: '/api/records/export',
  })

  assert.deepEqual(sentHops[3]!.target, {
    origin: DEFAULT_ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/vault/items',
  })

  // Strict camelCase serialization invariant (zero snake_case keys anywhere in the serialized receipt)
  const serialized = JSON.stringify(sent)
  for (const snakeKey of [
    '"chain_id"',
    '"terminal_vuln_class"',
    '"hop_id"',
    '"path_and_query"',
    '"exchange_ids"',
    '"claimed_delta"',
    '"produced_capabilities"',
    '"consumed_capabilities"',
    '"causal_edges"',
    '"from_hop_id"',
    '"to_hop_id"',
    '"capability_handle"',
    '"ablation_exchange_ids"',
    '"terminal_impact"',
    '"terminal_hop_id"',
    '"replay_mode"',
  ]) {
    assert.equal(serialized.includes(snakeKey), false, `unexpected snake_case key ${snakeKey}`)
  }
})

test('proveComposite alias delegates to prove_composite and falls back to defaultOrigin when object target omits origin', async (t) => {
  const { calls } = await withMockRpcServer(t, false)
  const ctx = new VerifyContext()

  const partialTarget = { method: 'POST', pathAndQuery: 'api/submit' } as unknown as HopReceiptInput['target']
  const verdict = await ctx.proveComposite({
    chainId: 'chain-sdk-alias-1',
    terminalVulnClass: 'auth_bypass',
    hops: [
      {
        hopId: 'hop_1',
        target: partialTarget,
        exchangeIds: ['ex-1'],
        claimedDelta: 'Submitted payload.',
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Attempted auth bypass.',
    },
  })

  assert.equal(verdict.confirmed, false)
  assert.equal(ctx.claims.length, 0)
  assert.equal(ctx.effectiveClaims().length, 1)

  const sent = calls[0]!.args.receipt as Record<string, unknown>
  const parsed = compositeProofReceiptSchema.safeParse(sent)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))

  const sentHops = sent.hops as Array<Record<string, unknown>>
  assert.deepEqual(sentHops[0]!.target, {
    origin: DEFAULT_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/submit',
  })
})

test('compile-time TypeScript checks enforce strict camelCase CompositeProofReceiptInput and HttpOptions.role', () => {
  const validRoleSetup: HttpOptions = { role: 'setup' }
  const validRoleControl: HttpOptions = { role: 'control' }
  const validRoleProbe: HttpOptions = { role: 'probe' }
  const validRoleCleanup: HttpOptions = { role: 'cleanup' }
  assert.equal(validRoleSetup.role, 'setup')
  assert.equal(validRoleControl.role, 'control')
  assert.equal(validRoleProbe.role, 'probe')
  assert.equal(validRoleCleanup.role, 'cleanup')

  // @ts-expect-error ProofRole values like 'control_denied' are invalid for HttpOptions.role
  const invalidProofRoleOnHttp: HttpOptions = { role: 'control_denied' }
  // @ts-expect-error ProofRole values like 'mutation' are invalid for HttpOptions.role
  const invalidMutationRoleOnHttp: HttpOptions = { role: 'mutation' }
  void invalidProofRoleOnHttp
  void invalidMutationRoleOnHttp

  const validValueEdge: CausalEdgeInput = {
    kind: 'value_binding',
    fromHopId: 'hop_1',
    toHopId: 'hop_2',
    capabilityHandle: 'cap:hop_1:tok',
  }
  const validDigestEdge: CausalEdgeInput = {
    kind: 'value_binding',
    fromHopId: 'hop_1',
    toHopId: 'hop_2',
    valueDigest: 'a'.repeat(64),
  }
  const validCryptoEdge: CausalEdgeInput = {
    kind: 'derived_crypto_binding',
    fromHopId: 'hop_1',
    toHopId: 'hop_2',
    sourceCapabilityId: 'cap:hop_1:salt',
    derivedCapabilityId: 'cap:hop_2:jwt',
    alg: 'HS256',
  }
  const validStateEdge: CausalEdgeInput = {
    kind: 'state_transition_binding',
    fromHopId: 'hop_1',
    toHopId: 'hop_2',
    entityId: 'ent-1',
    ablationExchangeIds: ['ex-ab-1'],
  }
  const validAsyncEdge: CausalEdgeInput = {
    kind: 'async_pivot_binding',
    fromHopId: 'hop_2',
    toHopId: 'hop_3',
    correlationId: 'corr-1',
    channel: 'poll_convergence',
    pollRecordId: 'poll-1',
  }
  assert.equal(validValueEdge.kind, 'value_binding')
  assert.equal(validDigestEdge.kind, 'value_binding')
  assert.equal(validCryptoEdge.kind, 'derived_crypto_binding')
  assert.equal(validStateEdge.kind, 'state_transition_binding')
  assert.equal(validAsyncEdge.kind, 'async_pivot_binding')

  // @ts-expect-error value_binding requires capabilityHandle or valueDigest
  const badValueEdge: CausalEdgeInput = { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }
  // @ts-expect-error state_transition_binding requires ablationExchangeIds
  const badStateEdge: CausalEdgeInput = { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'e1' }
  void badValueEdge
  void badStateEdge

  // @ts-expect-error HopReceiptInput requires strict camelCase (not snake_case hop_id)
  const badSnakeHop: HopReceiptInput = { hop_id: 'hop_1', target: '/api/x', claimedDelta: 'ok' }
  // @ts-expect-error HopReceiptInput requires claimedDelta
  const badMissingDelta: HopReceiptInput = { hopId: 'hop_1', target: '/api/x' }
  void badSnakeHop
  void badMissingDelta

  const validTerminal: TerminalImpactInput = {
    terminalHopId: 'hop_2',
    claimedImpact: 'Unauthorized readback.',
    oracleFamily: 'dual_tenant_abac',
  }
  assert.equal(validTerminal.terminalHopId, 'hop_2')

  const badSnakeReceipt: CompositeProofReceiptInput = {
    // @ts-expect-error CompositeProofReceiptInput rejects snake_case chain_id
    chain_id: 'c1',
    terminalVulnClass: 'auth_bypass',
    hops: [{ hopId: 'hop_1', target: '/api/x', claimedDelta: 'ok' }],
    terminalImpact: { terminalHopId: 'hop_1' },
  }
  void badSnakeReceipt
})
