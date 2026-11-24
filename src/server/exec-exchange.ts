import type { BrokerExchangeResult } from './broker.ts'
import type { NamedSecret } from './redact.ts'
import type { Run, Store } from './store.ts'

export interface RecordBrokerExchangeOptions {
  trackResources?: boolean
  markCoverage?: (run: Run, origin: string, method: string, pathAndQuery: string) => void
  onSaved?: (run: Run, ex: BrokerExchangeResult, exchangeId: string) => void
}

/**
 * Persist a brokered HTTP/WebSocket exchange with consistent redaction, optional resource
 * harvesting, endpoint coverage tracking, and caller-provided post-save hooks.
 */
export function recordBrokerExchange(
  storage: Store,
  run: Run,
  assignmentId: string,
  ex: BrokerExchangeResult,
  secrets: readonly NamedSecret[],
  options: RecordBrokerExchangeOptions = {},
): { id: string } {
  const saved = storage.recordExchange({
    runId: run.id,
    assignmentId,
    scopeRevision: run.scopeRevision,
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
    secretMatches: ex.secretMatches,
    secrets,
  })
  if (options.trackResources) {
    storage.trackExchangeResources({
      runId: run.id,
      scopeRevision: run.scopeRevision,
      exchange: ex,
      source: 'surface_probe',
    })
  }
  options.markCoverage?.(run, ex.origin, ex.method, ex.pathAndQuery)
  options.onSaved?.(run, ex, saved.id)
  return saved
}

/** Build an `onExchange` callback bound to a dynamic run/secrets supplier. */
export function createExchangeRecorder(
  storage: Store,
  resolveRun: () => Run,
  assignmentId: string,
  resolveSecrets: () => readonly NamedSecret[],
  options: RecordBrokerExchangeOptions = {},
): (ex: BrokerExchangeResult) => string {
  return (ex: BrokerExchangeResult) =>
    recordBrokerExchange(storage, resolveRun(), assignmentId, ex, resolveSecrets(), options).id
}
