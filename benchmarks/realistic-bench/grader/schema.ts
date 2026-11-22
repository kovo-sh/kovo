// Hand-written validators (no zod). Return {ok, value?, errors[]} with JSON-path-ish messages.
// Also exports a plain-object JSON schema for GroundTruth and a writeSchema() helper.
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import type {
  GradeInput, GroundTruth, GroundTruthEntry, SubmittedFinding,
} from '../lib/types.ts'

export interface ValidationResult<T> {
  ok: boolean
  value?: T
  errors: string[]
}

type Rec = Record<string, unknown>
function isObj(x: unknown): x is Rec {
  return typeof x === 'object' && x !== null && !Array.isArray(x)
}

class Ctx {
  errors: string[] = []
  err(path: string, msg: string): void {
    this.errors.push(`${path}: ${msg}`)
  }
  str(x: unknown, path: string, required = true): boolean {
    if (x === undefined) { if (required) this.err(path, 'missing required string'); return false }
    if (typeof x !== 'string') { this.err(path, 'expected string'); return false }
    return true
  }
  num(x: unknown, path: string, required = true): boolean {
    if (x === undefined) { if (required) this.err(path, 'missing required number'); return false }
    if (typeof x !== 'number' || Number.isNaN(x)) { this.err(path, 'expected number'); return false }
    return true
  }
  arr(x: unknown, path: string): x is unknown[] {
    if (!Array.isArray(x)) { this.err(path, 'expected array'); return false }
    return true
  }
}

function checkEndpoint(c: Ctx, x: unknown, path: string): void {
  if (!isObj(x)) { c.err(path, 'expected object'); return }
  c.str(x.method, `${path}.method`)
  c.str(x.path, `${path}.path`)
  c.str(x.routeKey, `${path}.routeKey`)
}

function checkEntry(c: Ctx, x: unknown, path: string): void {
  if (!isObj(x)) { c.err(path, 'expected object'); return }
  c.str(x.siteId, `${path}.siteId`)
  c.str(x.title, `${path}.title`)
  c.str(x.vulnClass, `${path}.vulnClass`)
  c.str(x.cwe, `${path}.cwe`)
  c.str(x.severity, `${path}.severity`)
  if (c.arr(x.endpoints, `${path}.endpoints`)) x.endpoints.forEach((e, i) => checkEndpoint(c, e, `${path}.endpoints[${i}]`))
  if (c.arr(x.triggerEndpoints, `${path}.triggerEndpoints`)) x.triggerEndpoints.forEach((e, i) => checkEndpoint(c, e, `${path}.triggerEndpoints[${i}]`))
  if (c.arr(x.params, `${path}.params`)) x.params.forEach((p, i) => c.str(p, `${path}.params[${i}]`))
  if (!isObj(x.oracle)) c.err(`${path}.oracle`, 'expected object')
  else {
    if (c.arr(x.oracle.kinds, `${path}.oracle.kinds`)) (x.oracle.kinds as unknown[]).forEach((k, i) => c.str(k, `${path}.oracle.kinds[${i}]`))
    if (c.arr(x.oracle.routeKeys, `${path}.oracle.routeKeys`)) (x.oracle.routeKeys as unknown[]).forEach((k, i) => c.str(k, `${path}.oracle.routeKeys[${i}]`))
  }
  if (!isObj(x.rootCause)) c.err(`${path}.rootCause`, 'expected object')
  else { c.str(x.rootCause.file, `${path}.rootCause.file`); c.str(x.rootCause.symbol, `${path}.rootCause.symbol`) }
}

export function validateGroundTruth(x: unknown): ValidationResult<GroundTruth> {
  const c = new Ctx()
  if (!isObj(x)) { c.err('groundTruth', 'expected object'); return { ok: false, errors: c.errors } }
  if (x.schemaVersion !== 1) c.err('groundTruth.schemaVersion', 'expected 1')
  c.str(x.app, 'groundTruth.app')
  c.num(x.seed, 'groundTruth.seed')
  c.str(x.seedSet, 'groundTruth.seedSet')
  if (c.arr(x.vulns, 'groundTruth.vulns')) x.vulns.forEach((e, i) => checkEntry(c, e, `groundTruth.vulns[${i}]`))
  if (c.arr(x.decoys, 'groundTruth.decoys')) x.decoys.forEach((e, i) => checkEntry(c, e, `groundTruth.decoys[${i}]`))
  if (c.arr(x.chains, 'groundTruth.chains')) {
    x.chains.forEach((ch, i) => {
      const p = `groundTruth.chains[${i}]`
      if (!isObj(ch)) { c.err(p, 'expected object'); return }
      c.str(ch.id, `${p}.id`)
      c.str(ch.severity, `${p}.severity`)
      if (c.arr(ch.siteIds, `${p}.siteIds`)) (ch.siteIds as unknown[]).forEach((s, j) => c.str(s, `${p}.siteIds[${j}]`))
    })
  }
  return c.errors.length === 0 ? { ok: true, value: x as unknown as GroundTruth, errors: [] } : { ok: false, errors: c.errors }
}

function checkFinding(c: Ctx, x: unknown, path: string): void {
  if (!isObj(x)) { c.err(path, 'expected object'); return }
  c.str(x.id, `${path}.id`)
  c.str(x.title, `${path}.title`)
  c.str(x.status, `${path}.status`)
  c.num(x.submittedAtMs, `${path}.submittedAtMs`)
  c.str(x.cwe, `${path}.cwe`, false)
  c.str(x.vulnClass, `${path}.vulnClass`, false)
  c.num(x.costUsdAtSubmit, `${path}.costUsdAtSubmit`, false)
  if (c.arr(x.endpoints, `${path}.endpoints`)) {
    x.endpoints.forEach((e, i) => {
      const p = `${path}.endpoints[${i}]`
      if (!isObj(e)) { c.err(p, 'expected object'); return }
      c.str(e.path, `${p}.path`)
      c.str(e.method, `${p}.method`, false)
    })
  }
}

export function validateFindings(x: unknown): ValidationResult<SubmittedFinding[]> {
  const c = new Ctx()
  if (!c.arr(x, 'findings')) return { ok: false, errors: c.errors }
  x.forEach((f, i) => checkFinding(c, f, `findings[${i}]`))
  return c.errors.length === 0 ? { ok: true, value: x as unknown as SubmittedFinding[], errors: [] } : { ok: false, errors: c.errors }
}

export function validateGradeInput(x: unknown): ValidationResult<GradeInput> {
  const c = new Ctx()
  if (!isObj(x)) { c.err('input', 'expected object'); return { ok: false, errors: c.errors } }
  const gt = validateGroundTruth(x.groundTruth)
  if (!gt.ok) c.errors.push(...gt.errors)
  const fs = validateFindings(x.findings)
  if (!fs.ok) c.errors.push(...fs.errors)
  c.arr(x.oracleEvents, 'input.oracleEvents')
  c.arr(x.requestLog, 'input.requestLog')
  c.str(x.mode, 'input.mode')
  if (!isObj(x.telemetry)) c.err('input.telemetry', 'expected object')
  else {
    c.num(x.telemetry.startedAtMs, 'input.telemetry.startedAtMs')
    c.num(x.telemetry.endedAtMs, 'input.telemetry.endedAtMs')
    c.num(x.telemetry.totalCostUsd, 'input.telemetry.totalCostUsd')
  }
  return c.errors.length === 0 ? { ok: true, value: x as unknown as GradeInput, errors: [] } : { ok: false, errors: c.errors }
}

// Plain-object JSON Schema for GroundTruth (informational; written to ground-truth.schema.json).
const endpointSchema = {
  type: 'object',
  required: ['method', 'path', 'routeKey'],
  properties: { method: { type: 'string' }, path: { type: 'string' }, routeKey: { type: 'string' } },
}
const entrySchema = {
  type: 'object',
  required: ['siteId', 'title', 'vulnClass', 'cwe', 'severity', 'endpoints', 'triggerEndpoints', 'params', 'oracle', 'rootCause'],
  properties: {
    siteId: { type: 'string' }, title: { type: 'string' }, vulnClass: { type: 'string' },
    cwe: { type: 'string' }, severity: { enum: ['critical', 'high', 'medium', 'low'] },
    endpoints: { type: 'array', items: endpointSchema },
    triggerEndpoints: { type: 'array', items: endpointSchema },
    params: { type: 'array', items: { type: 'string' } },
    oracle: {
      type: 'object', required: ['kinds', 'routeKeys'],
      properties: { kinds: { type: 'array', items: { type: 'string' } }, routeKeys: { type: 'array', items: { type: 'string' } } },
    },
    rootCause: { type: 'object', required: ['file', 'symbol'], properties: { file: { type: 'string' }, symbol: { type: 'string' } } },
  },
}
export const groundTruthJsonSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'GroundTruth',
  type: 'object',
  required: ['schemaVersion', 'app', 'seed', 'seedSet', 'vulns', 'decoys', 'chains'],
  properties: {
    schemaVersion: { const: 1 },
    app: { type: 'string' },
    seed: { type: 'number' },
    seedSet: { enum: ['dev', 'held-out'] },
    vulns: { type: 'array', items: entrySchema },
    decoys: { type: 'array', items: entrySchema },
    chains: {
      type: 'array',
      items: {
        type: 'object', required: ['id', 'siteIds', 'severity'],
        properties: { id: { type: 'string' }, siteIds: { type: 'array', items: { type: 'string' } }, severity: { type: 'string' } },
      },
    },
  },
} as const

export function writeSchema(targetDir?: string): string {
  const dir = targetDir ?? dirname(fileURLToPath(import.meta.url))
  const out = join(dir, 'ground-truth.schema.json')
  writeFileSync(out, JSON.stringify(groundTruthJsonSchema, null, 2) + '\n')
  return out
}
