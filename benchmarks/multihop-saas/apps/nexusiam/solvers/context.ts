// Shared context for deterministic reference solvers. Solvers only speak HTTP to the loopback
// services; they never read the causal monitor or the chain specifications.
import { createHash, createHmac } from 'node:crypto'
import type { CompositeProofReceipt, PersonaId } from '../../../lib/types.ts'
import type { ServiceName } from '../src/shared.ts'
import type { StartedNexusiam } from '../index.ts'

export interface SolverResponse {
  status: number
  text: string
  headers: Record<string, string>
  json<T>(): T
}

export interface SolverRequest {
  method?: string
  token?: string
  body?: unknown
  rawBody?: string
  headers?: Record<string, string>
}

export interface SolverContext {
  lab: StartedNexusiam
  runId: string
  http(service: ServiceName, path: string, request?: SolverRequest): Promise<SolverResponse>
  httpUrl(url: string, request?: SolverRequest): Promise<SolverResponse>
  login(persona: PersonaId, tenantSlug?: string): Promise<string>
  confirm(chainId: string): CompositeProofReceipt | null
  digest(value: string): string
  hmac(secret: string, payload: string): string
}

function response(status: number, text: string, headers: Headers): SolverResponse {
  const map: Record<string, string> = {}
  headers.forEach((value, key) => {
    map[key.toLowerCase()] = value
  })
  return {
    status,
    text,
    headers: map,
    json<T>(): T {
      return JSON.parse(text) as T
    },
  }
}

export function createSolverContext(lab: StartedNexusiam): SolverContext {
  const call = async (url: string, request: SolverRequest = {}): Promise<SolverResponse> => {
    const headers: Record<string, string> = {
      'x-guardian-run-id': lab.runId,
      ...(request.headers ?? {}),
    }
    if (request.token) headers.authorization = `Bearer ${request.token}`
    let body: string | undefined
    if (request.rawBody !== undefined) {
      body = request.rawBody
      headers['content-type'] = headers['content-type'] ?? 'application/json'
    } else if (request.body !== undefined) {
      body = JSON.stringify(request.body)
      headers['content-type'] = 'application/json'
    }
    const res = await fetch(url, { method: request.method ?? 'GET', headers, body, redirect: 'manual' })
    return response(res.status, await res.text(), res.headers)
  }

  return {
    lab,
    runId: lab.runId,
    http(service, path, request) {
      return call(`${lab.origins[service]}${path}`, request)
    },
    httpUrl(url, request) {
      return call(url, request)
    },
    async login(persona, tenantSlug) {
      const record = lab.plan.personas[persona]
      const tenant = tenantSlug ?? lab.plan.tenants[
        record.tenantId === 'org_a' ? 'a' : record.tenantId === 'org_b' ? 'b' : 'c'
      ].slug
      const res = await call(`${lab.origins.idp}/login`, {
        method: 'POST',
        body: { email: record.email, password: record.password, tenant },
      })
      if (res.status !== 200) throw new Error(`login ${persona} failed: ${res.status}`)
      return res.json<{ token: string }>().token
    },
    confirm(chainId) {
      const evaluation = lab.oracle.evaluate(chainId)
      if (!evaluation.completed) return null
      return lab.oracle.mintReceipt(chainId)
    },
    digest(value) {
      return createHash('sha256').update(value).digest('hex')
    },
    hmac(secret, payload) {
      return createHmac('sha256', secret).update(payload).digest('hex')
    },
  }
}

/** Local sha256 used by solvers that need an attestation digest. */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}
