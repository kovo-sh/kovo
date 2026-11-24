/**
 * Realism finding extraction — declared target, not every replay step.
 *
 * A confirmed finding is graded on the endpoint whose vulnerability it proves. Replay chains also
 * carry benign control/readback requests (e.g. an owner reading the invoice before and after the
 * cross-tenant write); those are baselines, not separate findings. Extracting every step made the
 * staging-concurrency suite report a decoy false positive for a scoped readback, so the harness now
 * submits only the probe-role (mutated) endpoints.
 *
 * These tests are synthetic: no fixture boots and no `Execution` run is required.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import type { Finding } from '../src/domain.ts'
import { declaredEndpointsFromReplaySpec, translateFindings } from '../scripts/benchmark-realism.ts'

const ORIGIN = 'http://127.0.0.1:4100'
const ORIGINS = { app: ORIGIN }

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f1',
    origin: ORIGIN,
    title: 'Invoice update ignores the caller tenant',
    status: 'confirmed',
    severity: 'high',
    reason: 'Deterministic differential evidence was reproduced.',
    remediation: 'Scope the write to the caller tenant.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'cross_tenant_write',
    cwe: 'CWE-639',
    ...overrides,
  }
}

function httpStep(role: 'setup' | 'control' | 'probe' | 'cleanup', method: string, pathAndQuery: string) {
  return {
    id: `${role}-${method.toLowerCase()}-${pathAndQuery.replace(/[^a-z0-9]+/gi, '-')}`.slice(0, 32),
    role,
    description: `${role} ${method} ${pathAndQuery}`,
    request: { origin: ORIGIN, method, pathAndQuery, followRedirects: false },
  }
}

function translate(overrides: { finding?: Partial<Finding>; spec: unknown }) {
  return translateFindings({
    findings: [finding(overrides.finding)],
    replaySpecs: [{ id: 's1', findingId: overrides.finding?.id ?? 'f1', spec: overrides.spec, createdAt: 1 }],
    exchanges: [],
    origins: ORIGINS,
    secrets: [],
  })
}

describe('realism finding extraction: declared probe endpoint only', () => {
  test('control GET + probe PATCH + owner readback GET submit one PATCH finding', () => {
    const spec = {
      kind: 'http_chain',
      steps: [
        httpStep('control', 'GET', '/v1/invoices/inv-beta-1'),
        httpStep('control', 'PATCH', '/v1/invoices/inv-beta-1'),
        httpStep('probe', 'PATCH', '/v1/invoices/inv-beta-1'),
        httpStep('control', 'GET', '/v1/invoices/inv-beta-1'),
      ],
    }

    const out = translate({ spec })

    assert.equal(out.findings.length, 1, 'only the mutated write is a submission')
    assert.equal(out.findings[0]?.method, 'PATCH')
    assert.equal(out.findings[0]?.endpoint, '/v1/invoices/inv-beta-1')
    assert.equal(out.findings[0]?.status, 'runtime_confirmed')
    assert.equal(out.endpointCounts.get('f1'), 1, 'SAST->live linking still sees the finding')
    assert.ok(
      !out.findings.some(entry => entry.method === 'GET'),
      'the benign owner readback must not be graded as a finding',
    )
  })

  test('a chain with two target endpoints submits both probes and no intermediate read', () => {
    const spec = {
      kind: 'http_chain',
      steps: [
        httpStep('control', 'GET', '/v1/reports/rep-beta-1'),
        httpStep('probe', 'GET', '/v1/reports/rep-beta-1'),
        httpStep('control', 'GET', '/v1/invoices/inv-beta-1'),
        httpStep('probe', 'PATCH', '/v1/invoices/inv-beta-1'),
        httpStep('control', 'GET', '/v1/invoices/inv-beta-1'),
      ],
    }

    const out = translate({ spec })

    assert.deepEqual(
      out.findings.map(entry => `${entry.method} ${entry.endpoint}`).sort(),
      ['GET /v1/reports/rep-beta-1', 'PATCH /v1/invoices/inv-beta-1'],
    )
    assert.equal(out.endpointCounts.get('f1'), 2)
  })

  test('a race burst submits its burst target, not the setup/post-check readbacks', () => {
    const spec = {
      kind: 'race_burst',
      setupSteps: [httpStep('setup', 'POST', '/v2/transfers/balance-read')],
      controlStep: httpStep('control', 'POST', '/v2/transfers'),
      burst: [
        { origin: ORIGIN, method: 'POST', pathAndQuery: '/v2/transfers', followRedirects: false },
        { origin: ORIGIN, method: 'POST', pathAndQuery: '/v2/transfers', followRedirects: false },
      ],
      postCheckStep: httpStep('control', 'POST', '/v2/transfers/balance-read'),
    }

    const out = translate({ spec })

    assert.deepEqual(
      out.findings.map(entry => `${entry.method} ${entry.endpoint}`),
      ['POST /v2/transfers'],
    )
  })

  test('cache differential submits the probe path, not control or verify readbacks', () => {
    const spec = {
      kind: 'cache_differential',
      method: 'GET',
      controlPath: '/item/1?_gcb=aaaaaaaaaaaaaaaa',
      probePath: '/item/1?_gcb=bbbbbbbbbbbbbbbb',
      verifyPath: '/item/1?_gcb=cccccccccccccccc',
    }

    const out = translate({ spec })

    assert.deepEqual(
      out.findings.map(entry => entry.endpoint),
      ['/item/1?_gcb=bbbbbbbbbbbbbbbb'],
    )
  })

  test('legacy spec without role information keeps the fallback extraction', () => {
    const legacy = {
      kind: 'http_chain',
      // No `steps`/`probePath`/... shape the extractor recognises.
      requests: [
        { method: 'GET', pathAndQuery: '/legacy/read' },
        { method: 'PUT', pathAndQuery: '/legacy/write' },
      ],
    }

    assert.deepEqual(declaredEndpointsFromReplaySpec(legacy), [])
    const out = translate({ spec: legacy })
    assert.deepEqual(
      out.findings.map(entry => `${entry.method} ${entry.endpoint}`).sort(),
      ['GET /legacy/read', 'PUT /legacy/write'],
    )
  })
})
