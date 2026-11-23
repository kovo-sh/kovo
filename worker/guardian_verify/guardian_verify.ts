/**
 * guardian_verify (TypeScript) — zero-dependency verification SDK for Guardian v6 Layer 3.
 *
 * A verification script runs inside a `--network none` worker sandbox. Every network/DOM/OOB
 * action is an RPC call over a Unix-domain socket into the Guardian process, which owns scope,
 * persona credentials and the signed transcript. The script only ever sees response data and
 * exchange ids; it never sees a credential.
 *
 * Contract:
 *   setup(ctx)   optional — create synthetic entities (tagged by run)
 *   verify(ctx)  required — control/variant exchanges + assertions returning transcript ids
 *   cleanup(ctx) optional — remove synthetic entities
 *
 * Assertions are *claims*, not results. Guardian re-evaluates every claim against its own
 * transcript, then re-runs the whole script in a fresh session. Stdout is never evidence.
 *
 * Zero runtime dependencies; only `node:http` and `node:fs`/`node:path` builtins.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { dirname, join } from 'node:path'

export type ClaimKind = 'status' | 'header' | 'body_contains' | 'jsonpath' | 'css' | 'dom_sentinel' | 'oob' | 'timing'

export interface StatusClaim { kind: 'status'; exchangeId: string; expected: number | number[]; message?: string }
export interface HeaderClaim { kind: 'header'; exchangeId: string; name: string; equals?: string; matches?: string; absent?: boolean; message?: string }
export interface BodyClaim { kind: 'body_contains'; exchangeId: string; text: string; absent?: boolean; message?: string }
export interface JsonPathClaim { kind: 'jsonpath'; exchangeId: string; path: string; equals?: unknown; matches?: string; exists?: boolean; message?: string }
export interface CssClaim { kind: 'css'; exchangeId: string; selector: string; exists?: boolean; count?: number; textEquals?: string; textContains?: string; message?: string }
export interface SentinelsClaim { kind: 'dom_sentinel'; exchangeId: string; sentinel: string; mode?: 'source' | 'executed'; message?: string }
export interface OobClaim { kind: 'oob'; exchangeId: string; expectHit?: boolean; message?: string }
export interface TimingClaim { kind: 'timing'; controlIds: string[]; variantIds: string[]; minPairs?: number; maxPValue?: number; message?: string }
export type VerifyClaim = StatusClaim | HeaderClaim | BodyClaim | JsonPathClaim | CssClaim | SentinelsClaim | OobClaim | TimingClaim

export interface ProofResult {
  sdk: 'guardian_verify.ts'
  nonce: string
  title: string
  severity: string
  description?: string
  claims: VerifyClaim[]
}

export interface RpcContext {
  nonce: string
  runId: string
  targetOrigins: string[]
  sdkVersion: string
}

interface RpcEnvelope {
  ok: boolean
  result?: unknown
  error?: string
}

function readContext(): RpcContext {
  const contextPath = process.env.GUARDIAN_RPC_CONTEXT_FILE ?? '/guardian-rpc/context.json'
  const raw = JSON.parse(readFileSync(contextPath, 'utf8')) as {
    nonce?: string
    runId?: string
    targetOrigins?: string[]
    sdkVersion?: string
  }
  return {
    nonce: typeof raw.nonce === 'string' ? raw.nonce : '',
    runId: typeof raw.runId === 'string' ? raw.runId : 'unknown-run',
    targetOrigins: Array.isArray(raw.targetOrigins) ? raw.targetOrigins.filter((v): v is string => typeof v === 'string') : [],
    sdkVersion: typeof raw.sdkVersion === 'string' ? raw.sdkVersion : 'guardian_verify/v6-mvp',
  }
}

function readToken(): string {
  const tokenPath = process.env.GUARDIAN_RPC_TOKEN_FILE ?? '/guardian-rpc/token'
  return readFileSync(tokenPath, 'utf8').trim()
}

function rpc(op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> {
  const socketPath = process.env.GUARDIAN_RPC_SOCKET ?? '/guardian-rpc/verify.sock'
  const context = readContext()
  const nonce = process.env.GUARDIAN_VERIFY_NONCE ?? context.nonce
  const token = readToken()
  const payload = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-guardian-rpc-token': token,
        'x-guardian-verify-nonce': nonce,
      },
      timeout: timeoutMs,
    }, res => {
      const chunks: Buffer[] = []
      let size = 0
      res.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > 8 * 1024 * 1024) {
          res.destroy()
          reject(new Error('Verification RPC response exceeded the SDK limit.'))
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => {
        let body: RpcEnvelope
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcEnvelope } catch {
          reject(new Error('Verification RPC returned malformed JSON.'))
          return
        }
        if (!body.ok) reject(new Error(body.error ?? 'Verification RPC call failed.'))
        else resolve(body.result)
      })
    })
    req.on('timeout', () => { req.destroy(new Error('Verification RPC call timed out.')) })
    req.on('error', reject)
    req.end(payload)
  })
}

export interface HttpExchange {
  exchangeId: string
  status: number
  method: string
  pathAndQuery: string
  finalPathAndQuery?: string
  redirectOrigins?: string[]
  mediaType: string
  headers: Record<string, string>
  body: string
  bodyPreview: string
  bodyBytes: number
  bodySha256: string
  durationMs: number
  personaHandle: string | null
  protocol?: 'h2'
}

export interface BrowserExchange {
  exchangeId: string
  status: number
  url: string
  html: string
  title?: string
  executedSentinels: string[]
  durationMs: number
}

export interface OobHandle {
  exchangeId: string
  token: string
  url: string
  dnsHost: string
}

export interface OobCheck extends OobHandle {
  hit: boolean
  checkExchangeId?: string
  hits: Array<{ protocol: string; token: string; remoteIp?: string; timestamp?: number }>
}

export type HttpTarget = string | { url: string; origin?: string }

export interface HttpOptions {
  /** Approved persona handle; Layer 1 injects the credential. */
  as?: string
  session?: string
  role?: 'setup' | 'control' | 'probe' | 'cleanup'
  method?: string
  headers?: Record<string, string>
  body?: string
  followRedirects?: boolean
  timeoutMs?: number
}

function splitTarget(input: HttpTarget, defaultOrigin: string | undefined): { origin?: string; path: string } {
  if (typeof input === 'string') {
    if (/^https?:\/\//i.test(input)) {
      const url = new URL(input)
      return { origin: url.origin, path: url.pathname + url.search }
    }
    if (!input.startsWith('/')) throw new Error('Relative verification paths must start with "/".')
    return { path: input }
  }
  if (typeof input?.url !== 'string') throw new Error('HTTP target requires a url string.')
  if (/^https?:\/\//i.test(input.url)) {
    const url = new URL(input.url)
    return { origin: input.origin ?? url.origin, path: url.pathname + url.search }
  }
  return { ...(input.origin ? { origin: input.origin } : {}), path: input.url }
}

export interface TimingResult {
  controlIds: string[]
  variantIds: string[]
  claim: TimingClaim
}

export interface Expectations {
  status(exchange: { exchangeId: string }, expected: number | number[], message?: string): StatusClaim
  statusNot(exchange: { exchangeId: string }, unexpected: number, message?: string): StatusClaim
  header(exchange: { exchangeId: string }, name: string, expected?: string | { equals?: string; matches?: string; absent?: boolean }, message?: string): HeaderClaim
  bodyContains(exchange: { exchangeId: string }, text: string, message?: string): BodyClaim
  bodyAbsent(exchange: { exchangeId: string }, text: string, message?: string): BodyClaim
  jsonPath(exchange: { exchangeId: string }, path: string, expected?: unknown, message?: string): JsonPathClaim
  css(exchange: { exchangeId: string }, selector: string, expected?: { exists?: boolean; count?: number; textEquals?: string; textContains?: string }, message?: string): CssClaim
  domSentinel(exchange: { exchangeId: string }, sentinel: string, mode?: 'source' | 'executed', message?: string): SentinelsClaim
  oob(exchange: { exchangeId: string }, expectHit?: boolean, message?: string): OobClaim
  timing(result: TimingResult, message?: string): TimingClaim
}

export class VerifyContext {
  readonly nonce: string
  readonly runId: string
  readonly targetOrigins: string[]
  readonly sdkVersion: string
  readonly claims: VerifyClaim[] = []
  readonly expect: Expectations
  /** Alias for `expect`. */
  readonly assert: Expectations
  private readonly defaultOrigin: string | undefined

  constructor() {
    const context = readContext()
    this.nonce = process.env.GUARDIAN_VERIFY_NONCE ?? context.nonce
    this.runId = context.runId
    this.targetOrigins = context.targetOrigins
    this.sdkVersion = context.sdkVersion
    this.defaultOrigin = this.targetOrigins[0]
    const push = (claim: VerifyClaim): VerifyClaim => { this.claims.push(claim); return claim }
    const expectations: Expectations = {
      status(exchange, expected, message) {
        return push({ kind: 'status', exchangeId: exchange.exchangeId, expected, ...(message ? { message } : {}) }) as StatusClaim
      },
      statusNot(exchange, unexpected, message) {
        const expected = [200, 201, 202, 204, 301, 302, 400, 401, 403, 404, 405].filter(code => code !== unexpected)
        return push({ kind: 'status', exchangeId: exchange.exchangeId, expected, ...(message ? { message } : {}) }) as StatusClaim
      },
      header(exchange, name, expected, message) {
        const spec = typeof expected === 'string' ? { equals: expected } : (expected ?? {})
        return push({ kind: 'header', exchangeId: exchange.exchangeId, name, ...spec, ...(message ? { message } : {}) }) as HeaderClaim
      },
      bodyContains(exchange, text, message) {
        return push({ kind: 'body_contains', exchangeId: exchange.exchangeId, text, ...(message ? { message } : {}) }) as BodyClaim
      },
      bodyAbsent(exchange, text, message) {
        return push({ kind: 'body_contains', exchangeId: exchange.exchangeId, text, absent: true, ...(message ? { message } : {}) }) as BodyClaim
      },
      jsonPath(exchange, path, expected, message) {
        return push({ kind: 'jsonpath', exchangeId: exchange.exchangeId, path, ...(expected === undefined ? { exists: true } : { equals: expected }), ...(message ? { message } : {}) }) as JsonPathClaim
      },
      css(exchange, selector, expected, message) {
        return push({ kind: 'css', exchangeId: exchange.exchangeId, selector, ...(expected ?? {}), ...(message ? { message } : {}) }) as CssClaim
      },
      domSentinel(exchange, sentinel, mode, message) {
        return push({ kind: 'dom_sentinel', exchangeId: exchange.exchangeId, sentinel, mode: mode ?? 'executed', ...(message ? { message } : {}) }) as SentinelsClaim
      },
      oob(exchange, expectHit, message) {
        return push({ kind: 'oob', exchangeId: exchange.exchangeId, expectHit: expectHit ?? true, ...(message ? { message } : {}) }) as OobClaim
      },
      timing(result, message) {
        return push({ ...result.claim, ...(message ? { message } : {}) }) as TimingClaim
      },
    }
    this.expect = expectations
    this.assert = expectations
  }

  async http(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    const result = await rpc('http', {
      ...(target.origin ? { origin: target.origin } : {}),
      path: target.path,
      method: options.method ?? 'GET',
      ...(options.headers ? { headers: options.headers } : {}),
      ...(options.body !== undefined ? { body: options.body } : {}),
      ...(options.as ? { persona: options.as } : {}),
      ...(options.session ? { session: options.session } : {}),
      ...(options.role ? { sessionGroupRole: options.role } : {}),
      ...(options.followRedirects !== undefined ? { followRedirects: options.followRedirects } : {}),
    }, (options.timeoutMs ?? 60_000) + 10_000)
    return result as HttpExchange
  }

  async http2(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    const result = await rpc('http2', {
      ...(target.origin ? { origin: target.origin } : {}),
      path: target.path,
      method: options.method ?? 'GET',
      ...(options.headers ? { headers: options.headers } : {}),
      ...(options.body !== undefined ? { body: options.body } : {}),
      ...(options.as ? { persona: options.as } : {}),
      ...(options.session ? { session: options.session } : {}),
      ...(options.role ? { sessionGroupRole: options.role } : {}),
    }, (options.timeoutMs ?? 60_000) + 10_000)
    return result as HttpExchange
  }

  async browser(input: HttpTarget, options: { as?: string; waitForSelector?: string; timeoutMs?: number } = {}): Promise<BrowserExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    const result = await rpc('browser', {
      ...(target.origin ? { origin: target.origin } : {}),
      path: target.path,
      ...(options.as ? { persona: options.as } : {}),
      ...(options.waitForSelector ? { waitForSelector: options.waitForSelector } : {}),
    }, (options.timeoutMs ?? 60_000) + 10_000)
    return result as BrowserExchange
  }

  readonly oob = {
    mint: async (label: string, origin?: string): Promise<OobHandle> => {
      const result = await rpc('oob', { action: 'mint', label, ...(origin ? { origin } : {}) }, 30_000)
      return result as OobHandle
    },
    check: async (handle: OobHandle): Promise<OobCheck> => {
      const result = await rpc('oob', { action: 'check', token: handle.token, exchangeId: handle.exchangeId }, 30_000)
      return { ...handle, ...(result as OobCheck) }
    },
  }

  readonly timing = {
    /**
     * Interleaved control/variant timing with 5–7 pairs. The oracle evaluates the recorded
     * durations with Mann-Whitney U + median/MAD separation, so a single lucky sample cannot
     * confirm a timing side channel.
     */
    compare: async (
      control: { target: HttpTarget; options?: HttpOptions },
      variant: { target: HttpTarget; options?: HttpOptions },
      options: { pairs?: number } = {},
    ): Promise<TimingResult> => {
      const pairs = Math.max(5, Math.min(Math.round(options.pairs ?? 6), 7))
      const controlIds: string[] = []
      const variantIds: string[] = []
      for (let i = 0; i < pairs; i += 1) {
        const order: Array<'control' | 'variant'> = i % 2 === 0 ? ['control', 'variant'] : ['variant', 'control']
        for (const which of order) {
          const call = which === 'control' ? control : variant
          const exchange = await this.http(call.target, call.options)
          if (which === 'control') controlIds.push(exchange.exchangeId)
          else variantIds.push(exchange.exchangeId)
        }
      }
      return {
        controlIds,
        variantIds,
        claim: { kind: 'timing', controlIds, variantIds, minPairs: pairs, maxPValue: 0.05 },
      }
    },
  }

  result(input: { title: string; severity?: string; description?: string }): ProofResult {
    if (!input.title || !input.title.trim()) throw new Error('Proof result requires a title.')
    return {
      sdk: 'guardian_verify.ts',
      nonce: this.nonce,
      title: input.title.slice(0, 300),
      severity: (input.severity ?? 'high').slice(0, 32),
      ...(input.description ? { description: input.description.slice(0, 4000) } : {}),
      claims: [...this.claims],
    }
  }
}

export interface VerificationScript {
  setup?(ctx: VerifyContext): Promise<void> | void
  verify(ctx: VerifyContext): Promise<ProofResult> | ProofResult
  cleanup?(ctx: VerifyContext): Promise<void> | void
}

export function defineVerification(script: VerificationScript): VerificationScript {
  return script
}

function resultPath(): string {
  return process.env.GUARDIAN_PROOF_RESULT_FILE ?? join(dirname(process.env.GUARDIAN_RPC_CONTEXT_FILE ?? '/guardian-rpc/context.json'), 'result.json')
}

function writeResult(value: unknown): void {
  const path = resultPath()
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 })
}

/** Run the 3-hook contract and emit the claims document. Never prints success as evidence. */
export async function runVerification(script: VerificationScript): Promise<void> {
  const ctx = new VerifyContext()
  let result: ProofResult | null = null
  try {
    await script.setup?.(ctx)
    result = await script.verify(ctx)
    await script.cleanup?.(ctx)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Verification script failed.'
    writeResult({ sdk: 'guardian_verify.ts', nonce: ctx.nonce, error: message.slice(0, 2000), claims: [] })
    process.stderr.write(`guardian_verify: ${message}\n`)
    process.exitCode = 1
    return
  }
  writeResult(result)
  process.stdout.write(`guardian_verify: ${result.claims.length} transcript-backed claim(s) recorded\n`)
}
