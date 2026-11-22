// Assert lib/types.ts taxonomy + funnel field names mirror src/domain.ts (read as text, read-only).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { failureTaxonomyBuckets } from '../lib/types.ts'
import type { BenchmarkFunnel } from '../lib/types.ts'
import { writeSchema, groundTruthJsonSchema } from '../grader/schema.ts'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..', '..', '..')

function extractArray(text: string, name: string): string[] {
  const start = text.indexOf(`export const ${name} = [`)
  assert.ok(start >= 0, `${name} not found`)
  const close = text.indexOf(']', start)
  const body = text.slice(start, close)
  return [...body.matchAll(/'([a-z_]+)'/g)].map((m) => m[1])
}

function extractFunnelFields(text: string): string[] {
  const start = text.indexOf('export interface BenchmarkFunnel {')
  assert.ok(start >= 0, 'BenchmarkFunnel not found')
  const close = text.indexOf('}', start)
  const body = text.slice(start, close)
  return [...body.matchAll(/^\s*([a-zA-Z]+):/gm)].map((m) => m[1])
}

test('failureTaxonomyBuckets matches src/domain.ts exactly and in order', () => {
  const domain = readFileSync(join(repoRoot, 'src', 'domain.ts'), 'utf8')
  const fromDomain = extractArray(domain, 'failureTaxonomyBuckets')
  assert.deepEqual([...failureTaxonomyBuckets], fromDomain)
})

test('BenchmarkFunnel field names match src/domain.ts', () => {
  const domain = readFileSync(join(repoRoot, 'src', 'domain.ts'), 'utf8')
  const fromDomain = extractFunnelFields(domain)
  // Typed sample ensures our interface has these exact fields at compile time.
  const sample: BenchmarkFunnel = {
    targetVulns: 0, surfaceDiscovered: 0, hypothesisFormed: 0, signalObserved: 0, specSubmitted: 0, zeroLlmConfirmed: 0,
  }
  assert.deepEqual(Object.keys(sample), fromDomain)
})

test('writeSchema writes ground-truth.schema.json', () => {
  const out = writeSchema()
  const written = JSON.parse(readFileSync(out, 'utf8'))
  assert.equal(written.title, 'GroundTruth')
  assert.equal(groundTruthJsonSchema.title, 'GroundTruth')
})
