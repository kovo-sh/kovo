import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { render, markSecretBearing } from '../lib/template.ts'
import { createOracle } from '../lib/oracle.ts'

test('escapes HTML in {{ }} but not in {{{ }}}', () => {
  const ctx = { name: '<script>alert(1)</script>' }
  assert.equal(render('{{ name }}', ctx), '&lt;script&gt;alert(1)&lt;/script&gt;')
  assert.equal(render('{{{ name }}}', ctx), '<script>alert(1)</script>')
})

test('{% if %} and {% for %}', () => {
  const out = render('{% if show %}A{% endif %}{% for x in items %}[{{ x }}]{% endfor %}',
    { show: true, items: ['a', 'b'] })
  assert.equal(out, 'A[a][b]')
  assert.equal(render('{% if show %}A{% endif %}', { show: false }), '')
})

test('filters: upper/lower/money/json and property access + methods', () => {
  assert.equal(render('{{ s | upper }}', { s: 'hi' }), 'HI')
  assert.equal(render('{{ s.toUpperCase() }}', { s: 'hi' }), 'HI')
  assert.equal(render('{{ price | money }}', { price: 3.5 }), '$3.50')
  assert.equal(render('{{ a.b }}', { a: { b: 'deep' } }), 'deep')
  assert.equal(render('{{ xs.join(",") }}', { xs: ['1', '2'] }), '1,2')
})

test('markSecretBearing sets reachedSecret when traversed', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const secrets = markSecretBearing({ apiKey: 'rb_fake_123' })
  render('{{ s.apiKey }}', { s: secrets }, { oracle, inputDerived: true })
  const ev = oracle.events()
  assert.equal(ev.length, 1)
  assert.equal(ev[0]!.kind, 'template_code_exec')
  assert.equal(ev[0]!.detail.reachedSecret, true)
})

test('template_code_exec fires when source is input-derived with an expression', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  render('{{ 7 * 7 }}', {}, { oracle, inputDerived: true })
  assert.equal(oracle.events().length, 1)
  assert.equal(oracle.events()[0]!.detail.reachedSecret, false)
})

test('does NOT fire when user data is only in the context (source trusted)', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  // user content is DATA, not in the template source
  const out = render('Hello {{ user }}', { user: '{{ 7*7 }}' }, { oracle, inputDerived: false })
  assert.equal(out, 'Hello {{ 7*7 }}') // data is escaped text, never evaluated
  assert.equal(oracle.events().length, 0)
})

test('input-derived source with no expression does not fire', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  render('just plain text', {}, { oracle, inputDerived: true })
  assert.equal(oracle.events().length, 0)
})

test('source contains no eval / Function / vm', () => {
  const src = readFileSync(fileURLToPath(new URL('../lib/template.ts', import.meta.url)), 'utf8')
  assert.doesNotMatch(src, /\beval\s*\(/)
  assert.doesNotMatch(src, /new\s+Function/)
  assert.doesNotMatch(src, /node:vm/)
})
