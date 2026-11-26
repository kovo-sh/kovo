/**
 * Move A Part 1 (WS-4) regression suite:
 *  - R2-H-26 / H-32: safe-regex.ts `runUntrustedRegex` chokepoint + ReDoS corpus + haystack cap
 *  - R2-C-5: markup / client-script oracle (browser attestation OR nonce + control + HTML + context)
 *  - R2-C-7 / C-6: business_logic invariant (peerDenial, resourceBound removal, repeatedTransition)
 *  - C-7: boolean differential oracle (no bare 1/0/true/false, full triangle, origin/persona/auth)
 *  - R2-H-10 / H-16: injection fingerprint oracle (no defensive strings, control parity, carrier echo-strip, family)
 *  - R2-H-12 / H-17: cross-tenant publicness guard & structured victim-secret fingerprints
 *
 * Defensive QA framing: pure in-memory differential verification fixtures only.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test } from 'node:test'

import {
  assessAuthorizationImpact,
  assessBooleanDifferential,
  assessBusinessLogicImpact,
  assessInjectionImpact,
  assessMarkupImpact,
  assessStatusOnlyDivergence,
  booleanPredicateTruth,
  findVictimDisclosedFingerprints,
  hasNonceInExecutableMarkupContext,
  isEligibleSecretFingerprint,
  matchInjectionFingerprint,
  matchStrippedInjectionFingerprint,
  type ActorIdentity,
  type BooleanDifferentialArm,
  type BooleanDifferentialRound,
  type ImpactStep,
  type StructuredSecretFingerprint,
} from '../src/server/oracle-invariants.ts'
import {
  compileSafeClaimRegex,
  MAX_CLAIM_REGEX_HAYSTACK,
  runUntrustedRegex,
} from '../src/server/safe-regex.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)

const ownerAcme: ActorIdentity = { handle: 'owner_a', role: 'owner', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const adminAcme: ActorIdentity = { handle: 'admin_a', role: 'admin', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const memberAcme: ActorIdentity = { handle: 'member_a', role: 'member', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const viewerAcme: ActorIdentity = { handle: 'viewer_a', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const ownerGlobex: ActorIdentity = { handle: 'owner_g', role: 'owner', tenant: 'globex', auth: 'cookie', sameSite: 'Lax' }
const memberGlobex: ActorIdentity = { handle: 'member_g', role: 'member', tenant: 'globex', auth: 'cookie', sameSite: 'Lax' }
const anon: ActorIdentity = { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }

function makeStep(overrides: Partial<ImpactStep> = {}): ImpactStep {
  return {
    id: overrides.id ?? 'step',
    arm: overrides.arm ?? 'probe',
    method: overrides.method ?? 'GET',
    route: overrides.route ?? '/api/items/1',
    status: overrides.status ?? 200,
    actor: overrides.actor ?? viewerAcme,
    ...overrides,
  }
}

// ===========================================================================
// 1. R2-H-26 / H-32: safe-regex.ts chokepoint & oracle-invariants wiring
// ===========================================================================

describe('R2-H-26 / H-32: runUntrustedRegex chokepoint and ReDoS defense', () => {
  test('rejects backreferences, lookarounds, overly long patterns, control chars, and ReDoS bypass classes', () => {
    const rejected: Array<[string, string]> = [
      ['backreference numeric', '(ab)\\1'],
      ['backreference named', '(?<tag>ab)\\k<tag>'],
      ['positive lookahead', 'foo(?=bar)'],
      ['negative lookahead', 'foo(?!bar)'],
      ['positive lookbehind', '(?<=foo)bar'],
      ['negative lookbehind', '(?<!foo)bar'],
      ['overly long pattern', 'a'.repeat(257)],
      ['control char newline', 'foo\nbar'],
      ['nested quantifier', '(a+)+$'],
      ['optional in repeated group', '(a?a)+$'],
      ['optional class in repeated group', '([a-z]?[a-z])+$'],
      ['repeated optional group', '(a?){20}a{20}'],
      ['overlapping quantified alternation', '(a|aa)+$'],
      ['polynomial word-underscore chain', '\\w+_\\w+'],
      ['polynomial adjacent literal quantifiers', 'a+a+'],
      ['polynomial overlapping classes', '[a-z]+[a-z0-9]+'],
      ['polynomial dot-star chain', '.*a.*'],
    ]

    const evilHaystack = `${'a'.repeat(50_000)}!`
    for (const [label, pattern] of rejected) {
      const start = performance.now()
      const res = runUntrustedRegex(pattern, evilHaystack)
      const elapsed = performance.now() - start
      assert.equal(res.ok, false, `expected rejection for ${label}: ${pattern}`)
      assert.equal(res.matched, false)
      assert.ok(elapsed < 50, `slow rejection (${elapsed.toFixed(1)} ms) for ${label}`)
    }
  })

  test('caps haystack length and matches valid credential patterns safely', () => {
    const validPattern = 'tok_[a-z0-9]+_[0-9a-f]{12}'
    assert.equal(compileSafeClaimRegex(validPattern).ok, true)

    const withinCap = runUntrustedRegex(validPattern, 'prefix tok_acme1_0123456789ab suffix')
    assert.equal(withinCap.ok, true)
    assert.equal(withinCap.matched, true)
    assert.equal(withinCap.truncated, false)

    const beyondCap = `${'x'.repeat(MAX_CLAIM_REGEX_HAYSTACK + 64)}tok_acme1_0123456789ab`
    const cappedRes = runUntrustedRegex(validPattern, beyondCap)
    assert.equal(cappedRes.ok, true)
    assert.equal(cappedRes.truncated, true)
    assert.equal(cappedRes.matched, false)
  })

  test('credentialPatternEvidence rejects ReDoS patterns rapidly and caps haystack', () => {
    const longBody = `${'a'.repeat(40_000)}!`
    const start = performance.now()
    const res = assessAuthorizationImpact({
      impactClass: 'disclosure',
      credentialPatterns: ['([a-z]?[a-z])+_end', '(a+)+_suffix'],
      steps: [
        makeStep({ id: 'c1', arm: 'control', route: '/api/admin/audit', status: 401, actor: anon, body: '' }),
        makeStep({ id: 'p1', arm: 'probe', route: '/api/admin/audit', status: 200, actor: viewerAcme, body: longBody, json: { ok: true } }),
      ],
    })
    const elapsed = performance.now() - start
    assert.equal(res.satisfied, false)
    assert.ok(elapsed < 100, `credentialPatternEvidence took ${elapsed.toFixed(1)} ms`)
  })

  test('oracle-invariants.ts contains zero dynamic new RegExp calls and zero benchmark literals', () => {
    const src = readFileSync(resolve(REPO_ROOT, 'src/server/oracle-invariants.ts'), 'utf8')
    assert.equal(/\bnew RegExp\s*\(/.test(src), false, 'oracle-invariants.ts must not invoke new RegExp directly')
    assert.equal(/rb\[cs\]_|rbc_|rbs_/.test(src), false)
  })
})

// ===========================================================================
// 2. R2-C-5: Markup / client-script oracle
// ===========================================================================

describe('R2-C-5: markup / client-script oracle', () => {
  const nonce = 'kovo_nonce_8844aabb'

  test('rejects arbitrary static script tags and generic plantedMarker echoes', () => {
    // Benign SPA HTML shell with static script tag
    const staticScript = assessMarkupImpact({
      impactClass: 'markup',
      steps: [
        makeStep({
          id: 'ctl', arm: 'control', route: '/app', pathAndQuery: '/app', status: 200,
          responseHeaders: { 'content-type': 'text/html; charset=utf-8' },
          body: '<html><head><script src="/static/bundle.js"></script></head><body>Hello</body></html>',
        }),
        makeStep({
          id: 'prb', arm: 'probe', route: '/app', pathAndQuery: '/app', status: 200,
          responseHeaders: { 'content-type': 'text/html; charset=utf-8' },
          body: '<html><head><script src="/static/bundle.js"></script></head><body>Hello</body></html>',
        }),
      ],
    })
    assert.equal(staticScript.satisfied, false, staticScript.reason)
    assert.equal(staticScript.evidence.plantedMarker, false)

    // Plain JSON create-then-echo of a 12-char title (old plantedMarker FP)
    const plantedEcho = assessMarkupImpact({
      impactClass: 'markup',
      steps: [
        makeStep({ id: 'ctl', arm: 'control', method: 'GET', route: '/api/posts', status: 200, body: '[]', json: [] }),
        makeStep({ id: 'create', arm: 'probe', method: 'POST', route: '/api/posts', status: 201, requestJson: { title: 'plainTitle123' }, json: { id: 1, title: 'plainTitle123' }, body: '{"id":1,"title":"plainTitle123"}' }),
        makeStep({ id: 'read', arm: 'probe', method: 'GET', route: '/api/posts', status: 200, responseHeaders: { 'content-type': 'application/json' }, body: '[{"id":1,"title":"plainTitle123"}]' }),
      ],
    })
    assert.equal(plantedEcho.satisfied, false, plantedEcho.reason)
    assert.equal(plantedEcho.evidence.plantedMarker, false)
  })

  test('rejects nonce in inert text, escaped markup, non-HTML media type, missing control, or control-present nonce', () => {
    assert.equal(hasNonceInExecutableMarkupContext(`<script src="/app.js"></script><p>${nonce}</p>`, nonce), false)
    assert.equal(hasNonceInExecutableMarkupContext(`&lt;script&gt;${nonce}&lt;/script&gt;`, nonce), false)
    assert.equal(hasNonceInExecutableMarkupContext(`<!-- <script>${nonce}</script> -->`, nonce), false)
    assert.equal(hasNonceInExecutableMarkupContext(`<textarea><script>${nonce}</script></textarea>`, nonce), false)

    // Non-HTML content type
    const jsonCt = assessMarkupImpact({
      impactClass: 'markup',
      probeNonces: [nonce],
      steps: [
        makeStep({ id: 'c1', arm: 'control', route: '/search', pathAndQuery: '/search?q=benign', status: 200, responseHeaders: { 'content-type': 'application/json' }, body: '{"q":"benign"}' }),
        makeStep({ id: 'p1', arm: 'probe', route: '/search', pathAndQuery: `/search?q=${nonce}`, status: 200, responseHeaders: { 'content-type': 'application/json' }, body: `{"q":"<script>${nonce}</script>"}` }),
      ],
    })
    assert.equal(jsonCt.satisfied, false, jsonCt.reason)

    // Missing same-route control
    const noControl = assessMarkupImpact({
      impactClass: 'markup',
      probeNonces: [nonce],
      steps: [
        makeStep({ id: 'p1', arm: 'probe', route: '/search', pathAndQuery: `/search?q=${nonce}`, status: 200, responseHeaders: { 'content-type': 'text/html' }, body: `<script>const x="${nonce}"</script>` }),
      ],
    })
    assert.equal(noControl.satisfied, false, noControl.reason)

    // Nonce present in control response
    const inControl = assessMarkupImpact({
      impactClass: 'markup',
      probeNonces: [nonce],
      steps: [
        makeStep({ id: 'c1', arm: 'control', route: '/search', pathAndQuery: '/search?q=benign', status: 200, responseHeaders: { 'content-type': 'text/html' }, body: `<p>${nonce}</p>` }),
        makeStep({ id: 'p1', arm: 'probe', route: '/search', pathAndQuery: `/search?q=${nonce}`, status: 200, responseHeaders: { 'content-type': 'text/html' }, body: `<script>const x="${nonce}"</script>` }),
      ],
    })
    assert.equal(inControl.satisfied, false, inControl.reason)

    // Nonce not carried in probe request
    const uncarried = assessMarkupImpact({
      impactClass: 'markup',
      probeNonces: [nonce],
      steps: [
        makeStep({ id: 'c1', arm: 'control', route: '/search', pathAndQuery: '/search?q=a', status: 200, responseHeaders: { 'content-type': 'text/html' }, body: '<p>a</p>' }),
        makeStep({ id: 'p1', arm: 'probe', route: '/search', pathAndQuery: '/search?q=b', status: 200, responseHeaders: { 'content-type': 'text/html' }, body: `<script>const x="${nonce}"</script>` }),
      ],
    })
    assert.equal(uncarried.satisfied, false, uncarried.reason)
  })

  test('confirms on host-attested browser execution OR full HTTP nonce + control + HTML + executable context', () => {
    const attested = assessMarkupImpact({
      impactClass: 'markup',
      browserExecutionAttested: true,
      steps: [makeStep({ id: 'p1', arm: 'probe', route: '/app', status: 200, body: '<div>app</div>' })],
    })
    assert.equal(attested.satisfied, true, attested.reason)
    assert.equal(attested.evidence.browserAttested, true)

    // Reflected HTTP check: nonce in request + absent in same-route control + HTML CT + executable context
    const reflected = assessMarkupImpact({
      impactClass: 'markup',
      probeNonces: [nonce],
      steps: [
        makeStep({ id: 'c1', arm: 'control', route: '/search', pathAndQuery: '/search?q=benign', status: 200, responseHeaders: { 'content-type': 'text/html; charset=utf-8' }, body: '<html><body><p>benign</p></body></html>' }),
        makeStep({ id: 'p1', arm: 'probe', route: '/search', pathAndQuery: `/search?q=${nonce}`, status: 200, responseHeaders: { 'content-type': 'text/html; charset=utf-8' }, body: `<html><body><img src=x onerror="report('${nonce}')"></body></html>` }),
      ],
    })
    assert.equal(reflected.satisfied, true, reflected.reason)
    assert.equal(reflected.evidence.nonceBound, true)
    assert.equal(reflected.evidence.htmlContentType, true)
    assert.equal(reflected.evidence.controlVerified, true)

    // Stored HTTP check: mutating step carries nonce, subsequent HTML probe renders it in <script>
    const stored = assessMarkupImpact({
      impactClass: 'markup',
      probeNonces: [nonce],
      steps: [
        makeStep({ id: 'c1', arm: 'control', method: 'GET', route: '/notes', pathAndQuery: '/notes', status: 200, responseHeaders: { 'content-type': 'text/html' }, body: '<html><body>empty</body></html>' }),
        makeStep({ id: 'w1', arm: 'probe', method: 'POST', route: '/notes', pathAndQuery: '/notes', status: 201, requestJson: { body: `marker ${nonce}` }, json: { ok: true } }),
        makeStep({ id: 'r1', arm: 'probe', method: 'GET', route: '/notes', pathAndQuery: '/notes', status: 200, responseHeaders: { 'content-type': 'text/html' }, body: `<html><body><script>var note="${nonce}";</script></body></html>` }),
      ],
    })
    assert.equal(stored.satisfied, true, stored.reason)
  })
})

// ===========================================================================
// 3. R2-C-7 / C-6: business_logic invariant
// ===========================================================================

describe('R2-C-7 / C-6: business_logic invariant hardening', () => {
  test('rejects anonymous 401, lower-role 403, resourceBound self-todo, duplicate create, and collection-prefix cross-tenant read', () => {
    // (a) Anonymous 401 + member PATCH (even with persisted delta)
    const anonControl = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'c1', arm: 'control', method: 'PATCH', route: '/api/todos/1', status: 401, actor: anon, requestJson: { status: 'done' } }),
        makeStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/todos/1', status: 200, actor: memberAcme, json: { id: '1', status: 'open' } }),
        makeStep({ id: 'p1', arm: 'probe', method: 'PATCH', route: '/api/todos/1', status: 200, actor: memberAcme, requestJson: { status: 'done' }, json: { ok: true } }),
        makeStep({ id: 'a1', arm: 'control', method: 'GET', route: '/api/todos/1', status: 200, actor: memberAcme, json: { id: '1', status: 'done' } }),
      ],
    })
    assert.equal(anonControl.satisfied, false, anonControl.reason)
    assert.equal(anonControl.evidence.boundary, false)

    // (b) Viewer 403 + admin 201 (normal RBAC working!)
    const lowerRoleControl = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'c1', arm: 'control', method: 'PATCH', route: '/api/todos/1', status: 403, actor: viewerAcme, requestJson: { status: 'done' } }),
        makeStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/todos/1', status: 200, actor: adminAcme, json: { id: '1', status: 'open' } }),
        makeStep({ id: 'p1', arm: 'probe', method: 'PATCH', route: '/api/todos/1', status: 200, actor: adminAcme, requestJson: { status: 'done' }, json: { ok: true } }),
        makeStep({ id: 'a1', arm: 'control', method: 'GET', route: '/api/todos/1', status: 200, actor: adminAcme, json: { id: '1', status: 'done' } }),
      ],
    })
    assert.equal(lowerRoleControl.satisfied, false, lowerRoleControl.reason)
    assert.equal(lowerRoleControl.evidence.boundary, false)

    // (c) Create -> read -> complete -> read on caller's own todo (resourceBound must NOT satisfy impact)
    const ownTodo = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'create', arm: 'setup', method: 'POST', route: '/api/todos', pathAndQuery: '/api/todos', status: 201, actor: memberAcme, requestJson: { title: 'buy milk' }, json: { id: 'todo-9', status: 'open' } }),
        makeStep({ id: 'before', arm: 'control', method: 'GET', route: '/api/todos/todo-9', pathAndQuery: '/api/todos/todo-9', status: 200, actor: memberAcme, json: { id: 'todo-9', status: 'open' } }),
        makeStep({ id: 'complete', arm: 'probe', method: 'POST', route: '/api/todos/todo-9/complete', pathAndQuery: '/api/todos/todo-9/complete', status: 200, actor: memberAcme, json: { ok: true } }),
        makeStep({ id: 'after', arm: 'control', method: 'GET', route: '/api/todos/todo-9', pathAndQuery: '/api/todos/todo-9', status: 200, actor: memberAcme, json: { id: 'todo-9', status: 'done' } }),
      ],
    })
    assert.equal(ownTodo.satisfied, false, ownTodo.reason)

    // (d) Duplicate collection POST create (not an existing resource ID, no intermediate readback)
    const duplicateCreate = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'p1', arm: 'probe', method: 'POST', route: '/api/orders', pathAndQuery: '/api/orders', status: 201, actor: memberAcme, requestJson: { item: 'book' }, json: { id: 'ord-1' } }),
        makeStep({ id: 'p2', arm: 'probe', method: 'POST', route: '/api/orders', pathAndQuery: '/api/orders', status: 201, actor: memberAcme, requestJson: { item: 'book' }, json: { id: 'ord-2' } }),
      ],
    })
    assert.equal(duplicateCreate.satisfied, false, duplicateCreate.reason)
    assert.equal(duplicateCreate.evidence.repeatedTransition, false)

    // (e) Foreign collection listing + own-tenant collection POST
    const collectionPrefix = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      resourceTenant: 'globex',
      steps: [
        makeStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/orders', pathAndQuery: '/api/orders', status: 200, actor: ownerGlobex, json: { items: [{ id: 'g1' }] } }),
        makeStep({ id: 'p1', arm: 'probe', method: 'POST', route: '/api/orders', pathAndQuery: '/api/orders', status: 201, actor: memberAcme, requestJson: { item: 'pen' }, json: { id: 'a1' } }),
      ],
    })
    assert.equal(collectionPrefix.satisfied, false, collectionPrefix.reason)

    // (f) Denied higher-rank peer WITHOUT persisted readback must fail
    const noPersistence = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'deny', arm: 'control', method: 'PATCH', route: '/api/orders/ord-1', status: 403, actor: adminAcme, requestJson: { status: 'approved' } }),
        makeStep({ id: 'write', arm: 'probe', method: 'PATCH', route: '/api/orders/ord-1', status: 200, actor: viewerAcme, requestJson: { status: 'approved' }, json: { ok: true } }),
      ],
    })
    assert.equal(noPersistence.satisfied, false, noPersistence.reason)
  })

  test('confirms equal-or-higher peer denial with persisted attributable delta, and verified repeated transition with intermediate readback + second delta', () => {
    const peerDenialWithPersist = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'before', arm: 'control', method: 'GET', route: '/api/orders/ord-1', status: 200, actor: adminAcme, json: { id: 'ord-1', status: 'pending' } }),
        makeStep({ id: 'deny', arm: 'control', method: 'PATCH', route: '/api/orders/ord-1', status: 403, actor: adminAcme, requestJson: { status: 'approved' } }),
        makeStep({ id: 'write', arm: 'probe', method: 'PATCH', route: '/api/orders/ord-1', status: 200, actor: viewerAcme, requestJson: { status: 'approved' }, json: { ok: true } }),
        makeStep({ id: 'after', arm: 'control', method: 'GET', route: '/api/orders/ord-1', status: 200, actor: adminAcme, json: { id: 'ord-1', status: 'approved' } }),
      ],
    })
    assert.equal(peerDenialWithPersist.satisfied, true, peerDenialWithPersist.reason)
    assert.equal(peerDenialWithPersist.evidence.boundary, true)
    assert.equal(peerDenialWithPersist.evidence.persisted, true)

    // Repeated transition on an existing resource ID with intermediate post-state readback + second delta
    const doubleRedeem = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/orders/ord-42', pathAndQuery: '/api/orders/ord-42', status: 200, actor: memberAcme, json: { id: 'ord-42', status: 'paid', refundedCents: 0 } }),
        makeStep({ id: 't1', arm: 'probe', method: 'POST', route: '/api/orders/ord-42/refund', pathAndQuery: '/api/orders/ord-42/refund', status: 200, actor: memberAcme, requestJson: { reason: 'dup' }, json: { ok: true } }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/orders/ord-42', pathAndQuery: '/api/orders/ord-42', status: 200, actor: memberAcme, json: { id: 'ord-42', status: 'refunded', refundedCents: 1000 } }),
        makeStep({ id: 't2', arm: 'probe', method: 'POST', route: '/api/orders/ord-42/refund', pathAndQuery: '/api/orders/ord-42/refund', status: 200, actor: memberAcme, requestJson: { reason: 'dup' }, json: { ok: true } }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/orders/ord-42', pathAndQuery: '/api/orders/ord-42', status: 200, actor: memberAcme, json: { id: 'ord-42', status: 'refunded', refundedCents: 2000 } }),
      ],
    })
    assert.equal(doubleRedeem.satisfied, true, doubleRedeem.reason)
    assert.equal(doubleRedeem.evidence.repeatedTransition, true)

    // Idempotent retry (no second state delta between r1 and r2) must be rejected
    const idempotentRetry = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/orders/ord-42', pathAndQuery: '/api/orders/ord-42', status: 200, actor: memberAcme, json: { id: 'ord-42', status: 'paid' } }),
        makeStep({ id: 't1', arm: 'probe', method: 'POST', route: '/api/orders/ord-42/refund', pathAndQuery: '/api/orders/ord-42/refund', status: 200, actor: memberAcme, requestJson: { reason: 'dup' }, json: { ok: true } }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/orders/ord-42', pathAndQuery: '/api/orders/ord-42', status: 200, actor: memberAcme, json: { id: 'ord-42', status: 'refunded' } }),
        makeStep({ id: 't2', arm: 'probe', method: 'POST', route: '/api/orders/ord-42/refund', pathAndQuery: '/api/orders/ord-42/refund', status: 200, actor: memberAcme, requestJson: { reason: 'dup' }, json: { ok: true } }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/orders/ord-42', pathAndQuery: '/api/orders/ord-42', status: 200, actor: memberAcme, json: { id: 'ord-42', status: 'refunded' } }),
      ],
    })
    assert.equal(idempotentRetry.satisfied, false, idempotentRetry.reason)
    assert.equal(idempotentRetry.evidence.repeatedTransition, false)
  })
})

// ===========================================================================
// 4. C-7: Boolean differential oracle
// ===========================================================================

describe('C-7: boolean differential oracle hardening', () => {
  function triangleRound(overrides: {
    baseVal?: string
    trueVal?: string
    falseVal?: string
    origin?: string
    probeOrigin?: string
    persona?: string
    probePersona?: string
    authHeader?: string
    probeAuthHeader?: string
    trueMatchesBase?: boolean
  } = {}): BooleanDifferentialRound {
    const baseVal = overrides.baseVal ?? 'widget'
    const trueVal = overrides.trueVal ?? '7919=7919'
    const falseVal = overrides.falseVal ?? '7919=7920'
    const origin = overrides.origin ?? 'https://app.example.test'
    const persona = overrides.persona ?? 'viewer_a'
    const authHeader = overrides.authHeader ?? 'Bearer tok-viewer-1'
    const baseBody = { count: 2, results: [{ id: 1 }, { id: 2 }] }
    const trueBody = overrides.trueMatchesBase === false
      ? { count: 1, results: [{ id: 1 }] }
      : baseBody
    const falseBody = { count: 0, results: [] }
    return {
      baseline: {
        status: 200, method: 'POST', origin, persona,
        pathAndQuery: '/api/search',
        requestHeaders: { authorization: authHeader },
        requestJson: { q: baseVal },
        json: baseBody,
      },
      control: {
        status: 200, method: 'POST', origin, persona,
        pathAndQuery: '/api/search',
        requestHeaders: { authorization: authHeader },
        requestJson: { q: trueVal },
        json: trueBody,
      },
      probe: {
        status: 200, method: 'POST',
        origin: overrides.probeOrigin ?? origin,
        persona: overrides.probePersona ?? persona,
        pathAndQuery: '/api/search',
        requestHeaders: { authorization: overrides.probeAuthHeader ?? authHeader },
        requestJson: { q: falseVal },
        json: falseBody,
      },
    }
  }

  test('rejects bare literals (1/0, true/false) in booleanPredicateTruth and assessBooleanDifferential', () => {
    assert.equal(booleanPredicateTruth('1'), null)
    assert.equal(booleanPredicateTruth('0'), null)
    assert.equal(booleanPredicateTruth('true'), null)
    assert.equal(booleanPredicateTruth('false'), null)
    assert.equal(booleanPredicateTruth('7919=7919'), true)
    assert.equal(booleanPredicateTruth('7919=7920'), false)

    for (const [tVal, fVal] of [['1', '0'], ['true', 'false']] as const) {
      const res = assessBooleanDifferential({
        param: 'q',
        rounds: [triangleRound({ trueVal: tVal, falseVal: fVal }), triangleRound({ trueVal: tVal, falseVal: fVal })],
      })
      assert.equal(res.satisfied, false, `bare literal ${tVal}/${fVal} must be rejected`)
    }
  })

  test('rejects missing baseline triangle, bare structural_diff where true != baseline, and origin/persona/auth mismatch', () => {
    // Missing baseline (2-arm only)
    const noBaselineRound = (r: BooleanDifferentialRound): BooleanDifferentialRound => ({ control: r.control, probe: r.probe })
    const noBaseline = assessBooleanDifferential({
      param: 'q',
      rounds: [noBaselineRound(triangleRound()), noBaselineRound(triangleRound())],
    })
    assert.equal(noBaseline.satisfied, false, noBaseline.reason)

    // True arm does not match baseline structure
    const trueMismatch = assessBooleanDifferential({
      param: 'q',
      rounds: [triangleRound({ trueMatchesBase: false }), triangleRound({ trueMatchesBase: false })],
    })
    assert.equal(trueMismatch.satisfied, false, trueMismatch.reason)
    assert.equal(trueMismatch.evidence.trueMatchesBaseline, false)

    // Different origin
    const originDiff = assessBooleanDifferential({
      param: 'q',
      rounds: [triangleRound({ probeOrigin: 'https://other.example.test' }), triangleRound({ probeOrigin: 'https://other.example.test' })],
    })
    assert.equal(originDiff.satisfied, false, originDiff.reason)
    assert.equal(originDiff.evidence.requestShapeMismatch, true)

    // Different persona
    const personaDiff = assessBooleanDifferential({
      param: 'q',
      rounds: [triangleRound({ probePersona: 'admin_a' }), triangleRound({ probePersona: 'admin_a' })],
    })
    assert.equal(personaDiff.satisfied, false, personaDiff.reason)
    assert.equal(personaDiff.evidence.requestShapeMismatch, true)

    // Different Authorization header (authDigest mismatch even with same persona label)
    const authDiff = assessBooleanDifferential({
      param: 'q',
      rounds: [triangleRound({ probeAuthHeader: 'Bearer tok-admin-9' }), triangleRound({ probeAuthHeader: 'Bearer tok-admin-9' })],
    })
    assert.equal(authDiff.satisfied, false, authDiff.reason)
    assert.equal(authDiff.evidence.requestShapeMismatch, true)
  })

  test('confirms full baseline/true/false triangle across >=2 rounds with matching origin, persona, and authDigest', () => {
    const res = assessBooleanDifferential({
      param: 'q',
      rounds: [triangleRound(), triangleRound()],
    })
    assert.equal(res.satisfied, true, res.reason)
    assert.equal(res.evidence.hasBaseline, true)
    assert.equal(res.evidence.trueMatchesBaseline, true)
    assert.equal(res.evidence.stable, true)
  })
})

// ===========================================================================
// 5. R2-H-10 / H-16: Injection fingerprint oracle
// ===========================================================================

describe('R2-H-10 / H-16: injection fingerprint hardening', () => {
  const cleanGetControl = makeStep({
    id: 'ctl', arm: 'control', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?q=books',
    status: 200, json: { results: [] }, body: '{"results":[]}',
  })

  test('rejects defensive refusal and input-validation error strings', () => {
    const defensiveBodies = [
      'Error: DOCTYPE is disallowed when the feature disallow-doctype-decl is set to true',
      'Security policy blocked external entity resolution',
      '400 Bad Request: path traversal attempt blocked',
      'PathTraversalException: invalid path',
      'ENOENT: no such file or directory',
      'Cast to ObjectId failed for value "abc"',
      'E11000 duplicate key error collection',
      'BSONTypeError: Argument passed in must be a string of 12 bytes',
      'ERROR: invalid input syntax for type uuid',
      'TemplateNotFound: index.html',
      'Rendered with Handlebars and Mustache templates',
    ]
    for (const body of defensiveBodies) {
      assert.equal(matchInjectionFingerprint(body), null, `defensive string should not match: ${body}`)
    }
  })

  test('rejects zero-control and mismatched-shape control confirmations', () => {
    const genuineProbe = makeStep({
      id: 'p1', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?q=test',
      status: 500, body: 'SQLITE_ERROR: near "test": syntax error',
    })
    const zeroControl = assessInjectionImpact({
      impactClass: 'injection',
      steps: [genuineProbe],
      injection: { family: 'sqli' },
    })
    assert.equal(zeroControl.satisfied, false, zeroControl.reason)

    const wrongRouteControl = makeStep({
      id: 'ctl-other', arm: 'control', method: 'GET', route: '/api/health', pathAndQuery: '/api/health',
      status: 200, body: '{"ok":true}',
    })
    const mismatchedRoute = assessInjectionImpact({
      impactClass: 'injection',
      steps: [wrongRouteControl, genuineProbe],
      injection: { family: 'sqli' },
    })
    assert.equal(mismatchedRoute.satisfied, false, mismatchedRoute.reason)

    const wrongQueryShapeControl = makeStep({
      id: 'ctl-shape', arm: 'control', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?page=1',
      status: 200, body: '{"results":[]}',
    })
    const mismatchedShape = assessInjectionImpact({
      impactClass: 'injection',
      steps: [wrongQueryShapeControl, genuineProbe],
      injection: { family: 'sqli' },
    })
    assert.equal(mismatchedShape.satisfied, false, mismatchedShape.reason)
  })

  test('strips echoed fingerprints across form, XML, multipart, path segment, cookie, case, HTML entity, escape, and truncated echoes', () => {
    const formControl = makeStep({ id: 'fc', arm: 'control', method: 'POST', route: '/api/submit', status: 200, requestBody: 'note=hello', body: 'ok' })
    const formEcho = makeStep({ id: 'fp', arm: 'probe', method: 'POST', route: '/api/submit', status: 400, requestBody: 'note=SQLITE_ERROR+bad', body: 'Invalid note: SQLITE_ERROR bad' })
    assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [formControl, formEcho], injection: { family: 'sqli' } }).satisfied, false)

    const xmlControl = makeStep({ id: 'xc', arm: 'control', method: 'POST', route: '/api/xml', status: 200, requestBody: '<req><item>ok</item></req>', body: '<ok/>' })
    const xmlEcho = makeStep({ id: 'xp', arm: 'probe', method: 'POST', route: '/api/xml', status: 400, requestBody: '<req><item>SAXParseException</item></req>', body: '<err>rejected: SAXParseException</err>' })
    assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [xmlControl, xmlEcho], injection: { family: 'xxe' } }).satisfied, false)

    const mpBody = '--b123\r\nContent-Disposition: form-data; name="comment"\r\n\r\nTemplateSyntaxError\r\n--b123--'
    const mpControl = makeStep({ id: 'mc', arm: 'control', method: 'POST', route: '/api/upload', status: 200, requestBody: '--b123\r\nContent-Disposition: form-data; name="comment"\r\n\r\nhello\r\n--b123--', body: 'ok' })
    const mpEcho = makeStep({ id: 'mp', arm: 'probe', method: 'POST', route: '/api/upload', status: 400, requestBody: mpBody, body: 'rejected: TemplateSyntaxError' })
    assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [mpControl, mpEcho], injection: { family: 'ssti' } }).satisfied, false)

    // Path segment echo
    const pathControl = makeStep({ id: 'pc', arm: 'control', method: 'GET', route: '/api/items/:id', pathAndQuery: '/api/items/123', status: 200, body: '{}' })
    const pathEcho = makeStep({ id: 'pp', arm: 'probe', method: 'GET', route: '/api/items/:id', pathAndQuery: '/api/items/SQLITE_ERROR', status: 400, body: 'not found: SQLITE_ERROR' })
    assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [pathControl, pathEcho], injection: { family: 'sqli' } }).satisfied, false)

    // Cookie sub-value echo
    const cookieEcho = makeStep({
      id: 'cp', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?q=books',
      requestHeaders: { cookie: 'prefs=dark; theme=PG::SyntaxError' },
      status: 400, body: 'Invalid cookie theme: PG::SyntaxError',
    })
    assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [cleanGetControl, cookieEcho], injection: { family: 'sqli' } }).satisfied, false)

    // Upper-case echo, HTML &#039; entity echo, backslash-escaped echo, and truncated echo
    const upperEcho = makeStep({ id: 'u1', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?q=sqlite_error', status: 400, body: 'REJECTED: SQLITE_ERROR' })
    const entityEcho = makeStep({ id: 'e1', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: "/api/search?q=syntax%20error%20at%20or%20near%20'x'", status: 400, body: "Bad query: syntax error at or near &#039;x&#039;" })
    const escapeEcho = makeStep({ id: 's1', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: "/api/search?q=unterminated%20quoted%20string%20'a'", status: 400, body: "Invalid: unterminated quoted string \\'a\\'" })
    const truncEcho = makeStep({ id: 't1', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?q=prefix_SQLITE_ERROR_very_long_tail_123456', status: 400, body: 'Invalid: prefix_SQLITE_ERROR...' })
    for (const step of [upperEcho, entityEcho, escapeEcho, truncEcho]) {
      assert.equal(matchStrippedInjectionFingerprint(step, 'sqli'), null, `echo should be stripped for ${step.id}`)
      assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [cleanGetControl, step], injection: { family: 'sqli' } }).satisfied, false)
      assert.equal(assessStatusOnlyDivergence([cleanGetControl, step]).fingerprint, null)
    }
  })

  test('enforces claimed-family alignment and confirms genuine non-echoed server error with same-route/same-shape control', () => {
    const genuineProbe = makeStep({
      id: 'gen', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?q=benign_input',
      status: 500, body: 'SQLITE_ERROR: near "benign_input": syntax error',
    })

    // Family mismatch: claimed xxe but error is sqli
    const wrongFamily = assessInjectionImpact({
      impactClass: 'injection',
      steps: [cleanGetControl, genuineProbe],
      injection: { family: 'xxe' },
    })
    assert.equal(wrongFamily.satisfied, false, wrongFamily.reason)

    // Matching family + same-route/same-shape control -> confirmed
    const aligned = assessInjectionImpact({
      impactClass: 'injection',
      steps: [cleanGetControl, genuineProbe],
      injection: { family: 'sqli' },
    })
    assert.equal(aligned.satisfied, true, aligned.reason)
  })
})

// ===========================================================================
// 6. R2-H-12 / H-17: Cross-tenant publicness guard & structured fingerprints
// ===========================================================================

describe('R2-H-12 / H-17: structured secret fingerprints and cross-tenant publicness guard', () => {
  test('isEligibleSecretFingerprint excludes headers.*, credential_header, and rotating CSRF/session fields', () => {
    const rejected: StructuredSecretFingerprint[] = [
      { sha256Prefix: 'a1b2c3d4e5f6', kind: 'credential_header', fieldPath: 'body.token' },
      { sha256Prefix: 'a1b2c3d4e5f6', kind: 'named_secret', fieldPath: 'headers.set-cookie' },
      { sha256Prefix: 'a1b2c3d4e5f6', kind: 'named_secret', fieldPath: 'headers.x-csrf-token' },
      { sha256Prefix: 'a1b2c3d4e5f6', kind: 'key_value', fieldPath: 'body.csrf_token' },
      { sha256Prefix: 'a1b2c3d4e5f6', kind: 'key_value', fieldPath: 'body.xsrfToken' },
      { sha256Prefix: 'a1b2c3d4e5f6', kind: 'key_value', fieldPath: 'body.session_id' },
      { sha256Prefix: 'a1b2c3d4e5f6', kind: 'key_value', fieldPath: '' },
    ]
    for (const fp of rejected) {
      assert.equal(isEligibleSecretFingerprint(fp), false, `expected ineligible: ${JSON.stringify(fp)}`)
    }
    assert.equal(isEligibleSecretFingerprint({
      sha256Prefix: 'a1b2c3d4e5f6',
      kind: 'named_secret',
      fieldPath: 'body.items[0].apiKey',
      ownerPersona: 'owner_g',
    }), true)
  })

  test('R2-H-12: rotating cookie/header or bare secretMatches cannot bypass cross-tenant publicness guard', () => {
    // Alice (globex) lists collection, Bob (acme) reads a public item with rotating XSRF cookie fingerprint
    const withBareAndHeaderFp = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        makeStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/catalog', pathAndQuery: '/api/catalog', status: 200, actor: ownerGlobex, json: { items: [{ id: 'p-1', name: 'Widget' }] } }),
        makeStep({
          id: 'p1', arm: 'probe', method: 'GET', route: '/api/catalog/p-1', pathAndQuery: '/api/catalog/p-1',
          status: 200, actor: memberAcme, json: { id: 'p-1', name: 'Widget' },
          secretMatches: ['deadbeef1234'],
          structuredSecretMatches: [
            { sha256Prefix: 'deadbeef1234', kind: 'credential_header', fieldPath: 'headers.set-cookie' },
            { sha256Prefix: 'cafebabe5678', kind: 'key_value', fieldPath: 'body.csrf_token' },
          ],
        }),
      ],
    })
    assert.equal(withBareAndHeaderFp.satisfied, false, withBareAndHeaderFp.reason)
    assert.match(withBareAndHeaderFp.reason, /publicness/i)
  })

  test('H-17: rejects rotating per-request token, self-echo on /me, and non-victim fingerprint; confirms victim-held body secret across boundary', () => {
    // (a) Rotating per-request token absent from control must NOT confirm (inverted semantics removed)
    const rotatingToken = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        makeStep({
          id: 'c1', arm: 'control', method: 'GET', route: '/api/settings', pathAndQuery: '/api/settings',
          status: 200, actor: ownerAcme, json: { theme: 'light' },
          structuredSecretMatches: [{ sha256Prefix: '111111111111', kind: 'credential_header', fieldPath: 'headers.set-cookie' }],
        }),
        makeStep({
          id: 'p1', arm: 'probe', method: 'GET', route: '/api/settings', pathAndQuery: '/api/settings',
          status: 200, actor: viewerAcme, json: { theme: 'light' },
          structuredSecretMatches: [{ sha256Prefix: '222222222222', kind: 'credential_header', fieldPath: 'headers.set-cookie' }],
        }),
      ],
    })
    assert.equal(rotatingToken.satisfied, false, rotatingToken.reason)

    // (b) Self-echo on /api/me (probe sees its own secret)
    const selfEcho = assessAuthorizationImpact({
      impactClass: 'disclosure',
      victimSecretFingerprints: [{ sha256Prefix: '333333333333', kind: 'named_secret', fieldPath: 'body.apiKey', ownerPersona: 'viewer_a' }],
      steps: [
        makeStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/me', pathAndQuery: '/api/me', status: 401, actor: anon }),
        makeStep({
          id: 'p1', arm: 'probe', method: 'GET', route: '/api/me', pathAndQuery: '/api/me',
          status: 200, actor: viewerAcme, json: { id: 'me' },
          structuredSecretMatches: [{ sha256Prefix: '333333333333', kind: 'named_secret', fieldPath: 'body.apiKey', ownerPersona: 'viewer_a' }],
        }),
      ],
    })
    assert.equal(selfEcho.satisfied, false, selfEcho.reason)

    // (c) Positive: victim-held body secret disclosed to another actor across a peer-denied boundary
    const victimDigest = '998877665544'
    const victimControl = makeStep({
      id: 'c_entitled', arm: 'control', method: 'GET', route: '/api/admin/keys', pathAndQuery: '/api/admin/keys',
      status: 200, actor: ownerAcme, json: { items: [{ id: 'k1' }] },
      structuredSecretMatches: [{ sha256Prefix: victimDigest, kind: 'named_secret', fieldPath: 'body.items[0].apiKey', ownerPersona: 'owner_a' }],
    })
    const deniedControl = makeStep({
      id: 'c_deny', arm: 'control', method: 'GET', route: '/api/admin/keys', pathAndQuery: '/api/admin/keys',
      status: 403, actor: viewerAcme,
    })
    const probeLeak = makeStep({
      id: 'p1', arm: 'probe', method: 'GET', route: '/api/admin/keys', pathAndQuery: '/api/admin/keys',
      status: 200, actor: memberAcme, json: { items: [{ id: 'k1' }] },
      structuredSecretMatches: [{ sha256Prefix: victimDigest, kind: 'named_secret', fieldPath: 'body.items[0].apiKey', ownerPersona: 'owner_a' }],
    })
    assert.equal(findVictimDisclosedFingerprints({ probe: probeLeak, controls: [victimControl, deniedControl] }).length, 1)

    const confirmed = assessAuthorizationImpact({
      impactClass: 'bfla',
      requiredRole: 'owner',
      steps: [victimControl, deniedControl, probeLeak],
    })
    assert.equal(confirmed.satisfied, true, confirmed.reason)

    // (d) Cross-tenant publicness guard passes when a genuine victim-held body secret matches across tenants
    const crossTenantSecret = assessAuthorizationImpact({
      impactClass: 'authorization',
      victimSecretFingerprints: [{ sha256Prefix: 'abcdef123456', kind: 'named_secret', fieldPath: 'body.apiKey', ownerPersona: 'owner_g', ownerTenant: 'globex' }],
      steps: [
        makeStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/vault', pathAndQuery: '/api/vault', status: 200, actor: ownerGlobex, json: { items: [{ id: 'v1' }] } }),
        makeStep({
          id: 'p1', arm: 'probe', method: 'GET', route: '/api/vault/v1', pathAndQuery: '/api/vault/v1',
          status: 200, actor: memberAcme, json: { id: 'v1', label: 'prod' },
          structuredSecretMatches: [{ sha256Prefix: 'abcdef123456', kind: 'named_secret', fieldPath: 'body.apiKey', ownerPersona: 'owner_g', ownerTenant: 'globex' }],
        }),
      ],
    })
    assert.equal(crossTenantSecret.satisfied, true, crossTenantSecret.reason)
    assert.equal(memberGlobex.tenant, 'globex')
  })
})
