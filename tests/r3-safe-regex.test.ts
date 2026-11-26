/**
 * R3-H-11 regression suite for `src/server/safe-regex.ts`:
 *  - Class 1: group boundaries & alternations preserve overlapping unbounded chains
 *  - Class 2: optional/nullable bridging atoms (`?`, `{0,n}`, `*`, `(?:...)?`) are transparent
 *  - Class 3: JS empty `[]` and match-any `[^]` character classes never swallow following groups
 *  - Class 4: `i`, `u`, and unsupported/non-linear flags (+ inline modifiers `(?i:...)`) are rejected
 *  - Full H-32 bypass corpus + legitimate claim/header/jsonpath/credential corpus parity
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { describe, test } from 'node:test'

import {
  compileSafeClaimRegex,
  MAX_CLAIM_REGEX_HAYSTACK,
  runUntrustedRegex,
} from '../src/server/safe-regex.ts'
import { TranscriptStore, evaluateClaim } from '../src/server/verify-claims.ts'

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

describe('R3-H-11: safe-regex analyzer bypass classes & flag hardening', () => {
  test('Class 1: rejects overlapping unbounded runs across group boundaries and alternations', () => {
    const class1Patterns: Array<[string, string]> = [
      ['4 grouped word runs', '(\\w+)(\\w+)(\\w+)(\\w+)$'],
      ['2 grouped word runs', '(\\w+)(\\w+)$'],
      ['non-capturing grouped word runs', '(?:\\w+)(?:\\w+)(?:\\w+)$'],
      ['named capturing grouped word runs', '(?<a>\\w+)(?<b>\\w+)$'],
      ['deeply nested unquantified groups', '(((\\w+)))(((\\w+)))$'],
      ['grouped word then grouped digit overlap', '(\\w+)(\\d+)$'],
      ['grouped word with {1} wrapper', '(\\w+){1}(\\w+){1}(\\w+){1}(\\w+){1}$'],
      ['optional grouped word runs', '(\\w+)?(\\w+)?(\\w+)?(\\w+)?$'],
      ['alternation overlapping next alternation', '(?:a+|b+)(?:a+|c+)$'],
      ['alternation with one overlapping branch', '\\w+(?:-|\\\\d)\\w+$'.replace('\\\\d', '\\d')],
      ['alternation with empty nullable branch', '\\w+(?:|-)\\w+$'],
      ['empty unquantified group between runs', '\\w+()\\w+$'],
      ['grouped tail overlap', '(\\w+-?)(\\w+)$'],
      ['leading optional inside second group', '(\\w+)(?:-?\\w+)$'],
      ['grouped alternation with unbounded overlap', '(?:\\w+|[a-z]+)\\w+$'],
    ]

    const evilHaystack = `${'a'.repeat(500)}!`
    for (const [label, pattern] of class1Patterns) {
      const t0 = performance.now()
      const compiled = compileSafeClaimRegex(pattern)
      const ran = runUntrustedRegex(pattern, evilHaystack)
      const elapsed = performance.now() - t0
      assert.equal(compiled.ok, false, `Class 1 must reject ${label}: ${pattern}`)
      assert.equal(ran.ok, false, `runUntrustedRegex must reject ${label}: ${pattern}`)
      assert.equal(ran.matched, false)
      assert.ok(elapsed < 50, `Class 1 rejection slow (${elapsed.toFixed(2)}ms) for ${label}`)
    }
  })

  test('Class 2: rejects overlapping runs bridged by optional or nullable non-overlapping atoms', () => {
    const class2Patterns: Array<[string, string]> = [
      ['optional hyphen between 4 word runs', '\\w+-?\\w+-?\\w+-?\\w+$'],
      ['optional non-word between 4 word runs', '\\w+\\W?\\w+\\W?\\w+\\W?\\w+$'],
      ['optional whitespace between word runs', '\\w+\\s?\\w+$'],
      ['{0,1} hyphen between word runs', '\\w+-{0,1}\\w+$'],
      ['{0,5} hyphen between word runs', '\\w+-{0,5}\\w+$'],
      ['zero-or-more hyphen between word runs', '\\w+-*\\w+$'],
      ['zero-or-more whitespace between word runs', '\\w+\\s*\\w+$'],
      ['optional non-capturing group delimiter', '\\w+(?:-)?\\w+$'],
      ['optional multi-char group delimiter', '\\w+(?:--)?\\w+$'],
      ['optional quantified group delimiter', '\\w+(?:-{1,3})?\\w+$'],
      ['unquantified group with optional atom', '\\w+(?:-?)\\w+$'],
      ['multiple optional delimiters in a row', '\\w+-?\\.?:?\\w+$'],
      ['grouped runs bridged by \\W*', '(\\w+)\\W*(\\w+)\\W*(\\w+)$'],
      ['bounded-variable {0,3} bridge', 'a+b{0,3}a+$'],
      ['optional decimal group then overlapping digits', '\\d+(?:\\.\\d+)?\\d+$'],
      ['optional group containing non-overlapping unbounded', 'a+(?:b+)?a+$'],
      ['fixed repeat of overlapping char', '\\w+_{2}\\w+$'],
      ['word boundary assertion bridge', '\\w+\\B\\w+$'],
      ['bounded-variable overlapping chain', 'a{0,50}a{0,50}$'],
    ]

    const evilHaystack = `${'a'.repeat(500)}!`
    for (const [label, pattern] of class2Patterns) {
      const t0 = performance.now()
      const compiled = compileSafeClaimRegex(pattern)
      const ran = runUntrustedRegex(pattern, evilHaystack)
      const elapsed = performance.now() - t0
      assert.equal(compiled.ok, false, `Class 2 must reject ${label}: ${pattern}`)
      assert.equal(ran.ok, false, `runUntrustedRegex must reject ${label}: ${pattern}`)
      assert.equal(ran.matched, false)
      assert.ok(elapsed < 50, `Class 2 rejection slow (${elapsed.toFixed(2)}ms) for ${label}`)
    }

    // Multiline `^` between overlapping `[\s\S]*` runs under `m` flag is also rejected.
    assert.equal(compileSafeClaimRegex('[\\s\\S]*^[\\s\\S]*$', { flags: 'm' }).ok, false)
  })

  test('Class 3: rejects JS empty [] and match-any [^] classes including when followed by nested quantifiers', () => {
    const class3Patterns: Array<[string, string]> = [
      ['empty class before nested quantifier', '[](a+)+$'],
      ['match-any class before nested quantifier', '[^](a+)+$'],
      ['empty class before overlapping alternation', '[](?:a|aa)+$'],
      ['match-any class before overlapping alternation', '[^](?:a|aa)+$'],
      ['prefix then empty class then nested quantifier', 'a[](a+)+$'],
      ['prefix then match-any class then nested quantifier', 'a[^](a+)+$'],
      ['bare empty class', '[]'],
      ['bare match-any class', '[^]'],
      ['repeated match-any classes', '[^]+[^]+$'],
      ['empty class with trailing literal ] before nested quantifier', '[]](a+)+$'],
      ['match-any class with trailing literal ] before nested quantifier', '[^]](a+)+$'],
    ]

    const evilHaystack = `${'a'.repeat(40)}!`
    for (const [label, pattern] of class3Patterns) {
      const t0 = performance.now()
      const compiled = compileSafeClaimRegex(pattern)
      const ran = runUntrustedRegex(pattern, evilHaystack)
      const elapsed = performance.now() - t0
      assert.equal(compiled.ok, false, `Class 3 must reject ${label}: ${pattern}`)
      assert.equal(ran.ok, false, `runUntrustedRegex must reject ${label}: ${pattern}`)
      assert.equal(ran.matched, false)
      assert.ok(elapsed < 50, `Class 3 rejection slow (${elapsed.toFixed(2)}ms) for ${label}`)
    }

    // Properly escaped `\]` inside a non-empty character class remains valid and matches accurately.
    const escapedBracket = runUntrustedRegex('^[\\]]+$', ']]]')
    assert.equal(escapedBracket.ok, true)
    assert.equal(escapedBracket.matched, true)
  })

  test('Class 4: rejects i, u, and other non-linear/unsupported flags plus inline modifier groups', () => {
    const disallowedFlags = ['i', 'u', 'iu', 'mi', 'su', 'im', 'v', 'g', 'y', 'd', 'mm', 'ss', 'msu']
    for (const flags of disallowedFlags) {
      const compiled = compileSafeClaimRegex('^[a-z]+$', { flags })
      assert.equal(compiled.ok, false, `expected flag "${flags}" to be rejected`)
      const ran = runUntrustedRegex('^[a-z]+$', 'abc', { flags })
      assert.equal(ran.ok, false, `runUntrustedRegex must reject flag "${flags}"`)
    }

    // Inline modifier groups (ES2025 `(?i:...)`) must also be rejected.
    for (const inlineMod of ['(?i:abc)', '(?i:a+)+$', '(?-i:abc)', '(?m:^foo$)']) {
      const compiled = compileSafeClaimRegex(inlineMod)
      assert.equal(compiled.ok, false, `expected inline modifier "${inlineMod}" to be rejected`)
    }

    // Linear-engine-compatible flags (`''`, `'m'`, `'s'`, `'ms'`, `'sm'`) remain allowed and work accurately.
    for (const flags of ['', 'm', 's', 'ms', 'sm']) {
      const compiled = compileSafeClaimRegex('^line_[0-9]+$', { flags })
      assert.equal(compiled.ok, true, `expected linear flag "${flags}" to be accepted`)
    }
    const multilineRes = runUntrustedRegex('^target_[0-9]+$', 'header\ntarget_42\nfooter', { flags: 'm' })
    assert.equal(multilineRes.ok, true)
    assert.equal(multilineRes.matched, true)
    const dotAllRes = runUntrustedRegex('^start:.*:end$', 'start:line1\nline2:end', { flags: 's' })
    assert.equal(dotAllRes.ok, true)
    assert.equal(dotAllRes.matched, true)
  })

  test('H-32 full bypass corpus + nested alternation/nullable/stacked quantifier defenses remain intact', () => {
    const h32Corpus: string[] = [
      '(a+)+$',
      '((a+)+)+$',
      '(a?a)+$',
      '([a-z]?[a-z])+$',
      '(a?){20}a{20}',
      '(a|aa)+$',
      '((a|aa))+$',
      '(a|a)+$',
      '([a-z]|[a-z0-9])+$',
      '(a|)+$',
      '(?:)+',
      '\\w+_\\w+',
      'a+a+',
      '[a-z]+[a-z0-9]+',
      '.*a.*',
      '.*.*b',
      '(ab)\\1',
      '(?<tag>ab)\\k<tag>',
      'foo(?=bar)',
      'foo(?!bar)',
      '(?<=foo)bar',
      '(?<!foo)bar',
      'a++',
      'a+?+',
      'a+??',
      '(a?)(b?)(c?)(d?)(e?)',
      '\\b+',
      'a{200}',
      'a'.repeat(257),
      'foo\nbar',
      Array.from({ length: 18 }, (_, i) => `k${i}`).join('|'),
    ]

    const evilHaystack = `${'a'.repeat(64)}!`
    for (const pattern of h32Corpus) {
      const t0 = performance.now()
      const res = runUntrustedRegex(pattern, evilHaystack)
      const elapsed = performance.now() - t0
      assert.equal(res.ok, false, `expected H-32 corpus rejection for: ${pattern.slice(0, 40)}`)
      assert.ok(elapsed < 50, `slow rejection (${elapsed.toFixed(2)}ms) for ${pattern.slice(0, 40)}`)
    }
  })

  test('legitimate claim, header, jsonpath, credential, and repo-search regex corpus compiles and matches accurately', () => {
    const validCases: Array<{ pattern: string; yes: string; no: string }> = [
      { pattern: '^Bearer\\s+[A-Za-z0-9._-]+$', yes: 'Bearer tok_abc.123-xyz', no: 'Basic abc' },
      { pattern: '^(?:Bearer|Basic)\\s+[A-Za-z0-9+/=._-]+$', yes: 'Basic dXNlcjpwYXNz', no: 'Digest abc' },
      { pattern: '^(?:ok|ready|settled)$', yes: 'settled', no: 'pending' },
      { pattern: 'tok_[a-z0-9]+_[0-9a-f]{12}', yes: 'prefix tok_acme1_0123456789ab suffix', no: 'tok_acme1_xyz' },
      { pattern: 'tok_[a-z0-9]{8,32}', yes: 'tok_abcdef123456', no: 'tok_123' },
      {
        pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        yes: '550e8400-e29b-41d4-a716-446655440000',
        no: 'not-a-uuid',
      },
      {
        pattern: '^eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$',
        yes: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_123-abc',
        no: 'eyJonlytwo.parts',
      },
      {
        pattern: '^application/json(?:;\\s*charset=utf-8)?$',
        yes: 'application/json; charset=utf-8',
        no: 'text/html',
      },
      {
        pattern: '^https?://[a-z0-9.-]+(?::\\d+)?/[A-Za-z0-9_./-]+$',
        yes: 'https://api.example.com:8443/v1/orders',
        no: 'ftp://example.com/a',
      },
      { pattern: '^\\d+(?:\\.\\d+)?$', yes: '42.95', no: 'abc' },
      { pattern: '^v?\\d+\\.\\d+(?:\\.\\d+)?$', yes: 'v2.14.3', no: 'release-1' },
      {
        pattern: '^20\\d{2}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$',
        yes: '2026-11-25T22:05:00.123Z',
        no: '2026/11/25',
      },
      { pattern: '(?<id>[0-9]+):(?<slug>[a-z-]+)', yes: '1042:order-item', no: 'abc:123' },
      { pattern: '^(\\w+)-(\\w+)$', yes: 'tenant_a-item_1', no: 'tenant_a_item_1' },
      { pattern: '^\\w+\\s+\\w+$', yes: 'hello world', no: 'helloworld' },
      { pattern: '^\\w+(?:-|;)\\w+$', yes: 'alpha;beta', no: 'alphabeta' },
      { pattern: '^[a-z]+\\s*=\\s*[0-9]+$', yes: 'limit = 50', no: 'limit 50' },
      { pattern: 'authorize[A-Z][a-z]+\\(', yes: 'export function authorizeTenant(req)', no: 'authorize(' },
      { pattern: '^a+b{1,3}a+$', yes: 'aaabbaaa', no: 'aaaaaa' },
      { pattern: '^\\w+:{2}\\w+$', yes: 'ns::symbol', no: 'ns:symbol' },
    ]

    for (const { pattern, yes, no } of validCases) {
      const compiled = compileSafeClaimRegex(pattern)
      assert.equal(compiled.ok, true, `expected valid pattern to compile: ${pattern} (${compiled.ok ? '' : compiled.reason})`)
      const hit = runUntrustedRegex(pattern, yes)
      assert.equal(hit.ok, true)
      assert.equal(hit.matched, true, `expected "${pattern}" to match "${yes}"`)
      const miss = runUntrustedRegex(pattern, no)
      assert.equal(miss.ok, true)
      assert.equal(miss.matched, false, `expected "${pattern}" NOT to match "${no}"`)
    }

    // Haystack cap remains enforced.
    const beyondCap = `${'x'.repeat(MAX_CLAIM_REGEX_HAYSTACK + 32)}tok_acme1_0123456789ab`
    const capped = runUntrustedRegex('tok_[a-z0-9]+_[0-9a-f]{12}', beyondCap)
    assert.equal(capped.ok, true)
    assert.equal(capped.truncated, true)
    assert.equal(capped.matched, false)
  })

  test('verify-claims.ts header & jsonpath sinks reject all three R3-H-11 bypass classes rapidly', () => {
    const store = new TranscriptStore()
    const payload = `${'a'.repeat(400)}!`
    const rec = store.record({
      op: 'http',
      startedAt: 1000,
      durationMs: 4,
      request: {
        origin: 'http://127.0.0.1:4100',
        method: 'GET',
        pathAndQuery: '/api/token',
        headers: {},
        bodyBytes: 0,
        bodySha256: sha256Hex(''),
        nonce: 'n-r3-h11',
      },
      response: {
        status: 200,
        headers: {
          'x-token': payload,
          'x-auth': 'Bearer tok_valid.123',
        },
        bodyBytes: 512,
        bodySha256: sha256Hex(JSON.stringify({ token: payload, status: 'ready' })),
        mediaType: 'application/json',
      },
      body: JSON.stringify({ token: payload, status: 'ready' }),
    })

    const r3Bypasses = [
      '(\\w+)(\\w+)(\\w+)(\\w+)$',
      '\\w+-?\\w+-?\\w+-?\\w+$',
      '\\w+\\W?\\w+\\W?\\w+\\W?\\w+$',
      '\\w+-{0,3}\\w+$',
      '\\w+-*\\w+$',
      '[](a+)+$',
      '[^](a+)+$',
    ]

    for (const pattern of r3Bypasses) {
      const t0 = performance.now()
      const h = evaluateClaim(store, { kind: 'header', exchangeId: rec.exchangeId, name: 'x-token', matches: pattern }, {})
      const j = evaluateClaim(store, { kind: 'jsonpath', exchangeId: rec.exchangeId, path: '$.token', matches: pattern }, {})
      const elapsed = performance.now() - t0
      assert.equal(h.passed, false, `header sink must reject ${pattern}`)
      assert.equal(j.passed, false, `jsonpath sink must reject ${pattern}`)
      assert.ok(elapsed < 50, `sink rejection slow (${elapsed.toFixed(2)}ms) for ${pattern}`)
    }

    // Legitimate claims still pass.
    const okHeader = evaluateClaim(store, { kind: 'header', exchangeId: rec.exchangeId, name: 'x-auth', matches: '^Bearer\\s+[A-Za-z0-9._-]+$' }, {})
    assert.equal(okHeader.passed, true, okHeader.detail)
    const okJson = evaluateClaim(store, { kind: 'jsonpath', exchangeId: rec.exchangeId, path: '$.status', matches: '^(?:ok|ready|settled)$' }, {})
    assert.equal(okJson.passed, true, okJson.detail)
  })
})
