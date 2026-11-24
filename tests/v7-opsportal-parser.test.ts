/**
 * v7 opsportal GraphQL parser — hang regression + bounded-parse contract.
 *
 * The measured defect: `parseSelections` in the opsportal fixture looped forever when an argument
 * value began with `$`, `[` or `{` (nothing advanced the cursor after a failed scalar scan). A probe
 * sending `{ items(first: $n) { id } }` stalled the whole benchmark cell inside the app process.
 *
 * Contract pinned here:
 *  - the exact hanging input reaches a result in well under 500 ms;
 *  - variable, list, object and escaped-string argument values parse (values stay strings; composite
 *    literals keep their source text and strings are decoded);
 *  - outputs for every case the old parser already handled are byte-identical in shape;
 *  - malformed input throws `GraphQueryParseError`, never spins;
 *  - 200 generated strings either parse or throw that bounded error, all within the time bound.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  executeGraph,
  GraphQueryParseError,
  MAX_GRAPH_QUERY_DEPTH,
  MAX_GRAPH_QUERY_STEPS,
} from '../benchmarks/realistic-bench/apps/opsportal/src/context.ts'

const TIME_BOUND_MS = 500

/** Field map that exposes arguments/values so tests can assert the parsed argument shape. */
function recordingFields(): {
  fields: Record<string, (args: Record<string, string>, parent: unknown) => unknown>
  seen: Array<Record<string, string>>
} {
  const seen: Array<Record<string, string>> = []
  const fields: Record<string, (args: Record<string, string>, parent: unknown) => unknown> = {
    items: (args) => { seen.push(args); return [{ id: 'i1' }, { id: 'i2' }] },
    hero: () => ({ label: 'hero-label', tickets: [{ subject: 's', body: 'b' }] }),
    id: (_args, parent) => (parent as { id?: string } | null)?.id,
    name: () => 'hero-label',
    label: (_args, parent) => (parent as { label?: string } | null)?.label,
    tickets: (_args, parent) => (parent as { tickets?: unknown } | null)?.tickets,
    subject: (_args, parent) => (parent as { subject?: string } | null)?.subject,
    body: (_args, parent) => (parent as { body?: string } | null)?.body,
  }
  return { fields, seen }
}

function argsOf(query: string): Record<string, string> {
  const { fields, seen } = recordingFields()
  executeGraph(query, fields, {})
  assert.equal(seen.length, 1, `expected one resolved field for ${JSON.stringify(query)}`)
  return seen[0]!
}

function timed<T>(fn: () => T): { value: T; ms: number } {
  const start = performance.now()
  const value = fn()
  return { value, ms: performance.now() - start }
}

function expectBoundedError(src: string): GraphQueryParseError {
  const start = performance.now()
  try {
    executeGraph(src, recordingFields().fields, {})
  } catch (err) {
    const ms = performance.now() - start
    assert.ok(err instanceof GraphQueryParseError, `expected GraphQueryParseError, got ${String(err)}`)
    assert.ok(ms < TIME_BOUND_MS, `bounded rejection took ${ms.toFixed(1)} ms`)
    return err
  }
  assert.fail(`expected a bounded parse error for ${JSON.stringify(src.slice(0, 80))}`)
}

test('the exact hanging input terminates under the strict time bound', () => {
  const query = '{ items(first: $n) { id } }'
  const { value, ms } = timed(() => executeGraph(query, recordingFields().fields, {}))
  assert.deepEqual(value, { items: [{ id: 'i1' }, { id: 'i2' }] })
  assert.ok(ms < TIME_BOUND_MS, `parse+execute took ${ms.toFixed(1)} ms`)
})

test('repeated hanging input stays fast and never grows the cursor unbounded', () => {
  const query = '{ items(first: $n) { id } }'
  const start = performance.now()
  for (let n = 0; n < 100; n++) executeGraph(query, recordingFields().fields, {})
  const ms = performance.now() - start
  assert.ok(ms < TIME_BOUND_MS, `100 iterations took ${ms.toFixed(1)} ms`)
})

test('variable, list and object argument values parse', () => {
  assert.deepEqual(argsOf('{ items(first: $n) { id } }'), { first: '$n' })
  assert.deepEqual(argsOf('{ items(first: [1, 2, {x: 3}], after: $cursor) { id } }'), {
    first: '[1, 2, {x: 3}]',
    after: '$cursor',
  })
  assert.deepEqual(argsOf('{ items(first: {nested: 1}, modes: [_A, _B]) { id } }'), {
    first: '{nested: 1}',
    modes: '[_A, _B]',
  })
  assert.deepEqual(argsOf('{ items(first: -12, ratio: 1.5e3, flag: true, empty: []) { id } }'), {
    first: '-12',
    ratio: '1.5e3',
    flag: 'true',
    empty: '[]',
  })
})

test('quoted strings decode escapes and keep plain values unchanged', () => {
  assert.deepEqual(argsOf('{ items(id: "acct_1") { id } }'), { id: 'acct_1' })
  assert.deepEqual(argsOf('{ items(id: "a\\"b\\\\c\\n\\t\\u0041") { id } }'), { id: 'a"b\\c\n\tA' })
  assert.deepEqual(argsOf('{ items(id: """block "quoted" text""") { id } }'), { id: 'block "quoted" text' })
})

test('nested selections, aliases, directives and variable definitions parse', () => {
  assert.deepEqual(
    executeGraph('{ hero { label tickets { subject body } } }', recordingFields().fields, {}),
    { hero: { label: 'hero-label', tickets: [{ subject: 's', body: 'b' }] } },
  )
  assert.deepEqual(
    executeGraph('{ alias: hero @include(if: true) { label } }', recordingFields().fields, {}),
    { hero: { label: 'hero-label' } },
  )
  assert.deepEqual(argsOf('query Q($n: Int = 3) { items(first: $n) { id } }'), { first: '$n' })
})

test('fragments (named spread and inline) resolve to the same shape as inline fields', () => {
  const { fields } = recordingFields()
  const expanded = executeGraph('{ hero { label tickets { subject } } }', fields, {})
  assert.deepEqual(executeGraph('{ hero { ...heroFields } } fragment heroFields on Hero { label tickets { subject } }', fields, {}), expanded)
  assert.deepEqual(executeGraph('{ hero { ... on Hero { label tickets { subject } } } }', fields, {}), expanded)
  assert.deepEqual(executeGraph('fragment F on Hero { label } { hero { ...F } }', fields, {}), { hero: { label: 'hero-label' } })
})

test('leading/trailing whitespace, comments and comma separators are ignored', () => {
  const { fields } = recordingFields()
  assert.deepEqual(
    executeGraph('  \n\t{ items ( first : 5 , other : "x y" ) # trailing comment\n { id } }  \n', fields, {}),
    { items: [{ id: 'i1' }, { id: 'i2' }] },
  )
  assert.deepEqual(executeGraph('', fields, {}), {})
  assert.deepEqual(executeGraph('   ', fields, {}), {})
})

test('previously working queries keep their exact parsed shape', () => {
  const { fields } = recordingFields()
  const cases: Array<[string, unknown]> = [
    ['{ hero { label } }', { hero: { label: 'hero-label' } }],
    ['{hero{label}}', { hero: { label: 'hero-label' } }],
    ['query Foo { hero { label } }', { hero: { label: 'hero-label' } }],
    ['mutation M { hero { label } }', { hero: { label: 'hero-label' } }],
    ['{ items { id } hero { label } }', { items: [{ id: 'i1' }, { id: 'i2' }], hero: { label: 'hero-label' } }],
    ['{ missingField }', { missingField: undefined }],
    ['{ hero { missingField } }', { hero: { missingField: undefined } }],
  ]
  for (const [query, expected] of cases) {
    assert.deepEqual(executeGraph(query, fields, {}), expected, query)
  }
})

test('malformed input throws a bounded parse error instead of spinning', () => {
  const malformed = [
    '{ items(first: ) { id } }',
    '{ items(first: [1, 2 } { id } }',
    '{ items(first: {nested: 1) { id } }',
    '{ items(first: "unterminated) { id } }',
    '{ items(first: 5 { id } }',
    '{ items(first: 5 }',
    '{ items(',
    '{ hero { ...MissingFragment } }',
    'fragment F { label } { hero { ...F } }',
    '{ hero { label }',
  ]
  for (const src of malformed) expectBoundedError(src)
})

test('recursion cap rejects deep nesting with a bounded error', () => {
  const depth = MAX_GRAPH_QUERY_DEPTH + 5
  const deep = `{ ${'hero { '.repeat(depth)}label ${'} '.repeat(depth)}}`
  const err = expectBoundedError(deep)
  assert.match(err.message, /nesting levels/)

  const allowed = `{ ${'hero { '.repeat(MAX_GRAPH_QUERY_DEPTH - 1)}label ${'} '.repeat(MAX_GRAPH_QUERY_DEPTH - 1)}}`
  assert.doesNotThrow(() => executeGraph(allowed, recordingFields().fields, {}))
})

test('iteration cap rejects oversized documents with a bounded error', () => {
  const oversized = `{${','.repeat(MAX_GRAPH_QUERY_STEPS + 10)}hero}`
  const err = expectBoundedError(oversized)
  assert.match(err.message, /parse steps/)
})

test('fuzz: 200 generated strings parse or fail bounded, never overrun the cap', () => {
  // Deterministic PRNG so failures reproduce.
  let seed = 0x5eed1e55
  const rand = (): number => {
    seed ^= seed << 13
    seed ^= seed >>> 17
    seed ^= seed << 5
    return (seed >>> 0) / 0x1_0000_0000
  }
  const alphabet = ['{', '}', '(', ')', '[', ']', '$', ':', ',', '"', '\\', '#', '@', '...', 'on', 'fragment', 'hero', 'label', 'items', 'first', ' ', '\n', '0', '_', '=']
  const inputs: string[] = ['{ items(first: $n) { id } }']
  while (inputs.length < 200) {
    let s = ''
    const len = 1 + Math.floor(rand() * 40)
    for (let n = 0; n < len; n++) s += alphabet[Math.floor(rand() * alphabet.length)]!
    inputs.push(s)
  }
  const { fields } = recordingFields()
  const start = performance.now()
  for (const src of inputs) {
    const t0 = performance.now()
    try {
      executeGraph(src, fields, {})
    } catch (err) {
      assert.ok(err instanceof GraphQueryParseError, `non-parse error for ${JSON.stringify(src)}: ${String(err)}`)
    }
    const ms = performance.now() - t0
    assert.ok(ms < TIME_BOUND_MS, `fuzz input took ${ms.toFixed(1)} ms: ${JSON.stringify(src)}`)
  }
  const total = performance.now() - start
  assert.ok(total < 200 * TIME_BOUND_MS, `fuzz total ${total.toFixed(1)} ms`)
})
