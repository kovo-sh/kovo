import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseXml, xmlText } from '../lib/xml.ts'
import { createOracle } from '../lib/oracle.ts'

const fakeVfs = { read: (p: string) => `FILE_CONTENT_FOR(${p})` }
const fakeEgress = { fetch: (u: string) => `HTTP_CONTENT_FOR(${u})` }

test('internal entity expands (bounded)', () => {
  const xml = '<!DOCTYPE r [ <!ENTITY who "world"> ]><r><g>Hello &who;</g></r>'
  const dom = parseXml(xml)
  assert.equal(xmlText(dom, 'g'), 'Hello world')
})

test('predefined + CDATA + attributes', () => {
  const dom = parseXml('<r a="x&amp;y"><c><![CDATA[<raw> & stuff]]></c></r>')
  assert.equal(dom.attrs.a, 'x&y')
  assert.equal(xmlText(dom, 'c'), '<raw> & stuff')
})

test('external file entity: no event when resolution disabled', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const xml = '<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><r>&x;</r>'
  const dom = parseXml(xml, { oracle, vfs: fakeVfs })
  assert.equal(dom.text, '') // entity dropped, not resolved
  assert.equal(oracle.events().length, 0)
})

test('external file entity resolves + emits xxe_entity_resolved only when enabled', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const xml = '<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><r>&x;</r>'
  const dom = parseXml(xml, { oracle, resolveExternalEntities: true, vfs: fakeVfs })
  assert.match(dom.text, /FILE_CONTENT_FOR/)
  const ev = oracle.events()
  assert.equal(ev.length, 1)
  assert.equal(ev[0]!.kind, 'xxe_entity_resolved')
  assert.equal(ev[0]!.sink, 'xml:file')
  assert.equal(ev[0]!.detail.uri, 'file:///etc/passwd')
})

test('external http entity uses egress and tags xml:http', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const xml = '<!DOCTYPE r [ <!ENTITY x SYSTEM "http://169.254.169.254/latest"> ]><r>&x;</r>'
  const dom = parseXml(xml, { oracle, resolveExternalEntities: true, egress: fakeEgress })
  assert.match(dom.text, /HTTP_CONTENT_FOR/)
  assert.equal(oracle.events()[0]!.sink, 'xml:http')
})

test('billion-laughs is bounded (no hang, no throw)', () => {
  let xml = '<!DOCTYPE r [\n'
  xml += '<!ENTITY a0 "boom">\n'
  for (let i = 1; i <= 12; i++) xml += `<!ENTITY a${i} "&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};&a${i - 1};">\n`
  xml += ']><r>&a12;</r>'
  const start = Date.now()
  const dom = parseXml(xml) // internal entities only -> no event, but must terminate
  assert.ok(Date.now() - start < 2000, 'should not hang')
  assert.ok(dom.text.length <= 11_000, 'expansion bounded by budget')
})
