// Impact oracle: a side-channel that records what actually happened during a request so the grader
// can tell a real security impact from a mere claim. It is NEVER exposed on the app's HTTP surface
// and NEVER fed into a scanner under test.
import { AsyncLocalStorage } from 'node:async_hooks'
import type {
  AppName, Actor, OracleEvent, ReasonOracleEventKind, RequestLogEntry, EgressLogEntry, OracleHandle,
} from './types.ts'

export interface RequestCtx {
  routeKey: string | null
  method: string
  path: string
  actor: Actor
  tenant: string | null
  sessionId: string | null
  inputs: string[] // every query/body/header/cookie/path value observed this request
  inputSet: Set<string>
  startedAt: number
}

const als = new AsyncLocalStorage<RequestCtx>()

export function currentCtx(): RequestCtx | undefined {
  return als.getStore()
}

export function runWithCtx<T>(ctx: RequestCtx, fn: () => T): T {
  return als.run(ctx, fn)
}

/** Record an input value against the current request so sinks can check taint. */
export function noteInput(value: unknown): void {
  const ctx = als.getStore()
  if (!ctx) return
  const s = String(value ?? '')
  if (s.length === 0) return
  ctx.inputs.push(s)
  ctx.inputSet.add(s)
}

/** True if `value` (verbatim) came from request input this request. */
export function isFromInput(value: string): boolean {
  const ctx = als.getStore()
  return ctx ? ctx.inputSet.has(value) : false
}

export interface Oracle extends OracleHandle {
  emit(kind: ReasonOracleEventKind, detail?: Record<string, string | number | boolean>, sink?: string): void
  logRequest(entry: Omit<RequestLogEntry, 'seq' | 'ts'>): RequestLogEntry
  logEgress(entry: Omit<EgressLogEntry, 'seq' | 'ts'>): EgressLogEntry
  readonly app: AppName
}

export function createOracle(opts: { app: AppName; now?: () => number }): Oracle {
  const app = opts.app
  const clock = opts.now ?? Date.now
  const _events: OracleEvent[] = []
  const _requests: RequestLogEntry[] = []
  const _egress: EgressLogEntry[] = []
  let seq = 0

  return {
    app,
    emit(kind, detail = {}, sink) {
      const ctx = als.getStore()
      _events.push({
        seq: seq++,
        ts: clock(),
        kind,
        app,
        routeKey: ctx?.routeKey ?? null,
        method: ctx?.method ?? 'GET',
        path: ctx?.path ?? '',
        actor: ctx?.actor ?? 'unknown',
        sessionId: ctx?.sessionId ?? undefined,
        sink,
        detail,
      })
    },
    logRequest(entry) {
      const full: RequestLogEntry = { seq: seq++, ts: clock(), ...entry }
      _requests.push(full)
      return full
    },
    logEgress(entry) {
      const full: EgressLogEntry = { seq: seq++, ts: clock(), ...entry }
      _egress.push(full)
      return full
    },
    events: () => _events.slice(),
    requests: () => _requests.slice(),
    egress: () => _egress.slice(),
    reset() {
      _events.length = 0
      _requests.length = 0
      _egress.length = 0
      seq = 0
    },
  }
}
