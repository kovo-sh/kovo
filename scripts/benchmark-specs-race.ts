/**
 * race_burst spec synthesis from a concurrent-duplicate probe signal.
 *
 * Evidence contract (strict; nothing is synthesized from a bare "interesting" status):
 *  - the probe observed more successful writes than the resource allowed
 *    (`successes > allowed`, with `attempts >= 2`),
 *  - it also observed a state route (`readPath`/`postCheckPath`) whose pre- and post-burst
 *    payloads differ, which gives the replay a deterministic control-vs-parallel assertion.
 */
import { baseFields, is2xx, stepOf } from './benchmark-specs-common.ts'
import type { SynthesizedSpec } from './benchmark-specs-common.ts'
import { fillPlaceholders, hasPathPlaceholder } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

const RACE_ANOMALY_TYPES = new Set([
  'race_condition_differential',
  'concurrent_double_spend',
  'race_burst_differential',
  'concurrent_limit_bypass',
])

const SAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const SAFE_STATUS = [200, 201, 202, 204]

interface RaceEvidence {
  attempts: number
  successes: number
  allowed: number
  readPath: string
  pathAndQuery: string
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  jsonBody: Record<string, unknown>
}

function positiveInt(v: unknown): number | null {
  const n = Number(v)
  return Number.isInteger(n) && n > 0 ? n : null
}

function extractEvidence(o: HypothesisOutcome): RaceEvidence | null {
  const anomaly = o.anomalies.find(a => RACE_ANOMALY_TYPES.has(String(a.type)))
  if (!anomaly) return null
  const attempts = positiveInt(anomaly.concurrent ?? anomaly.attempts ?? anomaly.total)
  const successes = positiveInt(anomaly.successes ?? anomaly.successCount ?? anomaly.confirmedSuccesses)
  const allowed = positiveInt(anomaly.allowed ?? anomaly.expectedSuccesses ?? 1) ?? 1
  if (!attempts || !successes) return null
  if (attempts < 2 || attempts > 10 || successes < 2 || successes <= allowed) return null

  const readRaw = anomaly.readPath ?? anomaly.postCheckPath ?? anomaly.statePath
  const readPath = typeof readRaw === 'string' ? readRaw : ''
  if (!readPath.startsWith('/') || readPath.startsWith('//') || readPath.length > 2048) return null

  const methodRaw = String(anomaly.method ?? o.hyp.method ?? 'POST').toUpperCase()
  if (!SAFE_METHODS.has(methodRaw)) return null

  const pathRaw = typeof anomaly.pathAndQuery === 'string' ? anomaly.pathAndQuery
    : typeof anomaly.path === 'string' ? anomaly.path
      : hasPathPlaceholder(o.hyp.endpoint.path)
        ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(String(anomaly.resourceId ?? '1')))
        : o.hyp.endpoint.path
  if (!pathRaw.startsWith('/') || pathRaw.startsWith('//') || pathRaw.length > 2048) return null

  const body = anomaly.jsonBody && typeof anomaly.jsonBody === 'object' && !Array.isArray(anomaly.jsonBody)
    ? anomaly.jsonBody as Record<string, unknown>
    : {}
  return { attempts, successes, allowed, readPath, pathAndQuery: pathRaw, method: methodRaw as RaceEvidence['method'], jsonBody: body }
}

export function synthRaceBurst(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const evidence = extractEvidence(o)
  if (!evidence) return []
  const { attempts, successes, allowed, readPath, pathAndQuery, method, jsonBody } = evidence
  const minSuccesses = Math.max(2, allowed + 1)
  const observed = `more than ${allowed} of ${attempts} concurrent requests succeeded (observed successes=${successes})`
  const jq = `{ controlPassed: ((${is2xx('c1')}) and (.steps.c1.status < 500)), ` +
    `confirmed: ((([.burst.summary.statuses[] | select(. >= 200 and . < 300)] | length) >= ${minSuccesses}) and (${is2xx('c2')}) and (.steps.c2.body != .steps.c1.body)), ` +
    `observed: ("burst 2xx=" + ([.burst.summary.statuses[] | select(. >= 200 and . < 300)] | length | tostring) + " stateChanged=" + ((.steps.c2.body != .steps.c1.body) | tostring)), ` +
    `expected: ${JSON.stringify(`at most ${allowed} concurrent request may succeed`)} }`
  const burst = Array.from({ length: attempts }, () => ({
    origin: env.origin,
    method,
    pathAndQuery,
    ...(Object.keys(jsonBody).length > 0 ? { jsonBody } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    followRedirects: false,
  }))
  return [{
    kind: 'race_burst',
    spec: {
      ...baseFields(env, 'Concurrent duplicate-write limit bypass (TOCTOU)', 'CWE-362', 'business-logic-race', 'high', jq),
      kind: 'race_burst',
      ...(env.owner ? { persona: env.owner } : {}),
      controlStep: stepOf(env, 'c1', 'control', 'Read the resource state before the parallel burst', { method: 'GET', pathAndQuery: readPath }, env.owner, {}, SAFE_STATUS),
      burst,
      postCheckStep: stepOf(env, 'c2', 'probe', 'Re-read the resource state after the parallel burst', { method: 'GET', pathAndQuery: readPath }, env.owner, {}, SAFE_STATUS),
    },
  }]
}
