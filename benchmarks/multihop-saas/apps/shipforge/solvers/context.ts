// Shared context for deterministic reference solvers. Solvers only speak HTTP to the loopback
// services; they never inspect host state or chain specs.
import { createHash, createHmac } from 'node:crypto'
import type { CompositeProofReceipt, PersonaId } from '../../../lib/types.ts'
import type { StartedShipforge } from '../index.ts'
import type { ServiceName } from '../src/shared.ts'

export interface SolverResponse {
  status: number
  text: string
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
  lab: StartedShipforge
  runId: string
  http(service: ServiceName, path: string, request?: SolverRequest): Promise<SolverResponse>
  httpUrl(url: string, request?: SolverRequest): Promise<SolverResponse>
  login(persona: PersonaId, tenantSlug?: string): Promise<string>
  confirm(chainId: string): CompositeProofReceipt | null
  digest(value: string): string
  hmac(secret: string, payload: string): string
}

function response(status: number, text: string): SolverResponse {
  return {
    status,
    text,
    json<T>(): T {
      return JSON.parse(text) as T
    },
  }
}

export function createSolverContext(lab: StartedShipforge): SolverContext {
  const call = async (url: string, request: SolverRequest = {}): Promise<SolverResponse> => {
    const headers: Record<string, string> = {
      'x-kovo-run-id': lab.runId,
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
    return response(res.status, await res.text())
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
      const tenantKey = record.tenantId
      const tenant = tenantSlug ?? lab.plan.tenants[
        tenantKey === 'org_a' ? 'a' : tenantKey === 'org_b' ? 'b' : 'c'
      ].slug
      const res = await call(`${lab.origins.scm}/login`, {
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export { sleep }
