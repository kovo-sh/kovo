/**
 * Layer-3 verification support primitives shared by the replay verifier.
 *
 * Two responsibilities:
 *   1. Noise-tolerant structural comparison for boolean/content differentials. Per-request
 *      tokens (CSRF nonces, UUIDs, ISO timestamps, request ids, long hex/base64 blobs) are
 *      normalized before similarity, so a rotating nonce never fakes a differential and a single
 *      real field delta inside a large HTML shell is still detected when it is stable across
 *      rounds.
 *   2. Two-stage async OOB correlation: a durable `pending_oob` subscription plus a short
 *      immediate check, then `awaitAny()` up to the caller's run budget and `promoteLate()` so
 *      background-worker callbacks are promoted into verified candidates.
 *
 * This module is stateless and imports only the public relay/broker seam.
 */
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import type { CanaryBroker } from './canary-broker.ts'
import { responseSimilarity } from './probes/context.ts'
import type { Store } from './store.ts'

// ---------------------------------------------------------------------------
// Structural (noise-tolerant) comparison
// ---------------------------------------------------------------------------

const STRUCTURAL_KEYED_TOKEN_RE = /(["']?(?:csrf|xsrf|nonce|authenticity[_-]?token|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|session[_-]?id|etag|server[_-]?time|request[_-]?time)["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&}<]+)/gi
const STRUCTURAL_TAG_NONCE_RE = /(\b(?:name|id)\s*=\s*["'][^"']*(?:csrf|xsrf|nonce|authenticity|request[_-]?id)[^"']*["'][^>]{0,200}?\b(?:content|value)\s*=\s*)("(?:[^"\\]|\\.)*"|'[^']*')/gi
const STRUCTURAL_UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
const STRUCTURAL_ISO_TS_RE = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?/g
const STRUCTURAL_EPOCH_RE = /\b1[5-9]\d{11}\b|\b2\d{12}\b/g
const STRUCTURAL_LONG_HEX_RE = /\b[0-9a-f]{16,}\b/gi
const STRUCTURAL_LONG_OPAQUE_RE = /[A-Za-z0-9+/_=-]{24,}/g

/** Strip run-scoped nonces and other dynamic tokens before structural comparison. */
export function normalizeStructuralTokens(input: string): string {
  if (!input) return input
  let out = input
    .replace(STRUCTURAL_KEYED_TOKEN_RE, '$1"<dynamic>"')
    .replace(STRUCTURAL_TAG_NONCE_RE, '$1"<dynamic>"')
    .replace(STRUCTURAL_UUID_RE, '<uuid>')
    .replace(STRUCTURAL_ISO_TS_RE, '<timestamp>')
    .replace(STRUCTURAL_EPOCH_RE, '<epoch>')
    .replace(STRUCTURAL_LONG_HEX_RE, '<hex>')
  // Long opaque values are dynamic when they mix letters and digits (base64url/ULID/idempotency
  // keys). Plain prose and long alphabetic DOM class names are preserved.
  out = out.replace(STRUCTURAL_LONG_OPAQUE_RE, token =>
    /[A-Za-z]/.test(token) && /\d/.test(token) ? '<opaque>' : token)
  return out
}

export interface StructuralDiff {
  similarity: number
  changedTokens: string[]
  normalizedEqual: boolean
}

function structuralTokenSet(normalized: string): Set<string> {
  return new Set(normalized.toLowerCase().split(/[^a-z0-9]+/).filter(token => token.length >= 2))
}

/** Structural comparison that ignores dynamic tokens and reports the field-level delta. */
export function structuralDiff(a: string, b: string, maxTokens = 32): StructuralDiff {
  const normalizedA = normalizeStructuralTokens(a)
  const normalizedB = normalizeStructuralTokens(b)
  if (normalizedA === normalizedB) {
    return { similarity: 1, changedTokens: [], normalizedEqual: true }
  }
  const tokensA = structuralTokenSet(normalizedA)
  const tokensB = structuralTokenSet(normalizedB)
  const changed = new Set<string>()
  for (const token of tokensA) if (!tokensB.has(token)) changed.add(token)
  for (const token of tokensB) if (!tokensA.has(token)) changed.add(token)
  return {
    similarity: responseSimilarity(normalizedA, normalizedB),
    changedTokens: [...changed].sort().slice(0, maxTokens),
    normalizedEqual: false,
  }
}

/** Similarity over noise-normalized tokens (1 = structurally identical). */
export function structuralSimilarity(a: string, b: string): number {
  return structuralDiff(a, b).similarity
}

/** Tokens that changed in every round (a stable field delta, not per-request jitter). */
export function intersectStructuralDeltas(deltas: readonly (readonly string[])[]): string[] {
  if (deltas.length === 0) return []
  const [first, ...rest] = deltas
  return first.filter(token => rest.every(other => other.includes(token)))
}

// ---------------------------------------------------------------------------
// Async OOB correlation
// ---------------------------------------------------------------------------

export interface CanaryWaitOutcome {
  triggered: boolean
  stage: 'immediate' | 'late' | 'none'
  detail: Record<string, unknown> | null
  subscriptionId: string | null
  promoted: boolean
}

export interface ReplayCanaryWaitOptions {
  immediateMs?: number
  /** Total polling budget; bounded by the caller's run deadline signal. */
  budgetMs?: number
  pollMs?: number
  now?: () => number
  signal?: AbortSignal
}

export const defaultReplayCanaryImmediateMs = 3_000

/**
 * Registers a durable `pending_oob` subscription, performs an immediate in-memory check, then
 * polls via `awaitAny` up to the run budget and `promoteLate()`s any callback that landed outside
 * the immediate window. The subscription stays pending (and promotes later at run level) when no
 * callback arrived in the budget.
 */
export async function awaitReplayCanary(
  broker: CanaryBroker,
  input: { runId: string; assignmentId: string; token: string; canaryId?: string },
  options: ReplayCanaryWaitOptions = {},
): Promise<CanaryWaitOutcome> {
  const now = options.now ?? (() => Date.now())
  const immediateMs = Math.max(0, options.immediateMs ?? defaultReplayCanaryImmediateMs)
  const budgetMs = Math.max(0, options.budgetMs ?? immediateMs)
  let subscriptionId: string | null = null
  let subscriptionCreatedAt: number | null = null
  try {
    const subscription = broker.subscribe({
      runId: input.runId,
      assignmentId: input.assignmentId,
      // The canary id binds the subscription to the minted token; fall back to the token itself
      // when the caller only has an opaque handle.
      canaryId: input.canaryId ?? input.token,
      token: input.token,
      // Empty artifact: real callbacks rarely carry Guardian's artifact header, and a truthy
      // artifact would reject them at ingest. Token↔canary binding is the causal link.
      artifact: '',
      immediateMs,
    })
    subscriptionId = subscription.id
    subscriptionCreatedAt = subscription.createdAt
  } catch {
    // Relays that cannot persist subscriptions must not break a synchronous OOB proof.
    subscriptionId = null
  }
  // Anchor the immediate window at subscription creation, not at this call: a repeated check
  // for an existing pending subscription must still classify a late callback as late.
  const immediateDeadline = (subscriptionCreatedAt ?? now()) + immediateMs
  const readCheck = () => broker.checkCanary(input.token, { runId: input.runId })
  let check = readCheck()
  if (check.hit) {
    broker.promoteLate({ runId: input.runId, now: now() })
    const at = typeof check.detail?.timestamp === 'number'
      ? check.detail.timestamp
      : typeof check.detail?.receivedAt === 'number' ? check.detail.receivedAt : null
    const stage = at !== null && at > immediateDeadline ? 'late' : 'immediate'
    return { triggered: true, stage, detail: check.detail ?? null, subscriptionId, promoted: false }
  }
  let callbackReceivedAt: number | null = null
  try {
    const awaited = await broker.awaitAny({ token: input.token, runId: input.runId }, {
      timeoutMs: budgetMs,
      pollMs: options.pollMs ?? 150,
      ...(options.signal ? { signal: options.signal } : {}),
    })
    callbackReceivedAt = awaited.callback?.receivedAt ?? null
  } catch {
    // Polling failures fall through to the recorded in-memory hit check below.
  }
  const promotions = broker.promoteLate({ runId: input.runId, now: now() })
  const promotion = promotions.find(item => item.subscription.token === input.token)
  if (promotion?.subscription.id) subscriptionId = promotion.subscription.id
  check = readCheck()
  if (check.hit || promotion) {
    const receivedAt = callbackReceivedAt ?? promotion?.callback.receivedAt ?? null
    const stage = receivedAt !== null && receivedAt > immediateDeadline ? 'late' : 'immediate'
    return { triggered: true, stage, detail: check.detail ?? null, subscriptionId, promoted: Boolean(promotion) }
  }
  return { triggered: false, stage: 'none', detail: check.detail ?? null, subscriptionId, promoted: false }
}

// ---------------------------------------------------------------------------
// Canary session (brokered relay or standalone loopback)
// ---------------------------------------------------------------------------

export interface EphemeralCanarySession {
  mint(purpose: string): { token: string; url: string; dnsHost: string }
  check(token: string): { triggered: boolean; detail: Record<string, unknown> | null }
  /** Two-stage wait: short immediate window, then a durable subscription with late promotion. */
  waitForCallback(token: string, signal: AbortSignal, options?: { immediateMs?: number; budgetMs?: number }): Promise<CanaryWaitOutcome>
  close(): Promise<void>
}

export async function openCanarySession(
  canaryBroker: CanaryBroker | undefined,
  storage: Store | undefined,
  runId: string | undefined,
  assignmentId: string,
  origin?: string,
): Promise<EphemeralCanarySession> {
  if (canaryBroker) {
    const info = await canaryBroker.startListener()
    const effectiveRunId = runId ?? 'replay-verifier'
    const baseUrl = info.effectiveBaseUrl ?? ''
    const canaryIds = new Map<string, string>()
    return {
      mint(purpose: string) {
        const minted = canaryBroker.mintCanary(
          effectiveRunId,
          purpose,
          origin,
          storage ? { storage, assignmentId } : undefined,
        )
        canaryIds.set(minted.token, minted.id)
        return {
          token: minted.token,
          url: minted.httpUrl || `${baseUrl}/c/${minted.token}`,
          dnsHost: minted.dnsHost,
        }
      },
      check(token: string) {
        const res = canaryBroker.checkCanary(token, storage ? { storage, runId: effectiveRunId } : undefined)
        return { triggered: res.hit, detail: res.detail }
      },
      waitForCallback(token, signal, options = {}) {
        return awaitReplayCanary(canaryBroker, {
          runId: effectiveRunId,
          assignmentId,
          token,
          ...(canaryIds.has(token) ? { canaryId: canaryIds.get(token)! } : {}),
        }, {
          ...(options.immediateMs !== undefined ? { immediateMs: options.immediateMs } : {}),
          ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
          signal,
        })
      },
      async close() { /* Managed by host CanaryBroker lifecycle */ },
    }
  }

  // Standalone ephemeral loopback canary listener (used in unit tests without a CanaryBroker).
  const callbacks = new Map<string, Record<string, unknown>>()
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const match = /^\/c\/(guardian-canary-[a-f0-9]{24})$/.exec(url.pathname)
    if (match) {
      callbacks.set(match[1], {
        method: req.method ?? 'GET',
        path: url.pathname,
        receivedAt: new Date().toISOString(),
      })
    }
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('guardian-canary-ok')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') {
    server.close()
    throw new Error('Could not bind ephemeral replay canary listener.')
  }
  const baseUrl = `http://127.0.0.1:${addr.port}`
  return {
    mint() {
      const token = `guardian-canary-${randomBytes(12).toString('hex')}`
      return { token, url: `${baseUrl}/c/${token}`, dnsHost: `${token}.canary.guardian.invalid` }
    },
    check(token: string) {
      const detail = callbacks.get(token) ?? null
      return { triggered: Boolean(detail), detail }
    },
    async waitForCallback(token, signal) {
      // Unchanged no-relay behaviour: ten 150 ms polls (1.5 s total).
      let detail = callbacks.get(token) ?? null
      for (let attempt = 0; attempt < 10 && !detail; attempt += 1) {
        await sleepAbortable(150, signal)
        detail = callbacks.get(token) ?? null
      }
      return {
        triggered: Boolean(detail),
        stage: detail ? 'immediate' : 'none',
        detail,
        subscriptionId: null,
        promoted: false,
      }
    },
    async close() {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

async function sleepAbortable(ms: number, signal: AbortSignal) {
  if (signal.aborted) throw signal.reason
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}
