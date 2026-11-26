// @kernel @fixes R4-C-1, R4-C-3, R4-C-4
/**
 * R4 WS-1 (R4-C-1, R4-C-3, R4-C-4) fast class-level guard suite for `src/server/oracle-invariants.ts`:
 *  - R4-C-1: Canonical predicate skeleton binding, empty-base standalone rejection, equal-length /
 *            same-charset discrimination, 4xx false-arm status-class rejection, and swapped-length /
 *            host-bound parity on `statusBoolean` (length-cap, charset-validator, and integer-coercion
 *            stubs reject EVERY boolean and status-boolean triangle).
 *  - R4-C-3: Shared fail-closed deletion-normalized carrier anti-reflection (per-component URL/JSON/
 *            HTML-entity decode failing closed on malformed percent-escapes, tag stripping, zero-width
 *            deletion, NFKC folding, alphanumeric core containment) — tag-stripping, zero-width-stripping,
 *            and NFKC-folding reflecting stubs reject ALL injection fingerprint classes.
 *  - R4-C-4: Business-logic refusal/bound control primitive, mandatory pre-first readback (drop
 *            no-before-read), equal-magnitude deltas, and cited-window completeness from HostFactLog
 *            seq ordering — correct add-to-cart twice, wallet deposit twice, quantity increment twice,
 *            and idempotent PUT with an uncited intermediate write ALL reject `business_logic`.
 *  - Positive controls: genuine true differential, genuine boundary/refusal double-redeem, genuine
 *            floor/cap bound crossing, and genuine non-echoed engine error still confirm cleanly.
 *
 * Defensive QA framing: pure in-memory differential verification fixtures only.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test } from 'node:test'

import {
  assessBooleanDifferential,
  assessBusinessLogicImpact,
  assessInjectionImpact,
  canonicalPredicateSkeleton,
  checkCitedWindowCompleteness,
  deletionNormalizeComparable,
  matchStrippedInjectionFingerprint,
  normalizeCarrierForAntiReflection,
  parseBooleanPredicate,
  stripRequestEchoes,
  verifyBooleanTriangleBinding,
  verifyRepeatedTransitionControl,
  type ActorIdentity,
  type BooleanDifferentialArm,
  type BooleanDifferentialRound,
  type ImpactStep,
  type InjectionFamily,
} from '../src/server/oracle-invariants.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const memberAcme: ActorIdentity = { handle: 'member_a', role: 'member', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const viewerAcme: ActorIdentity = { handle: 'viewer_a', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }

function makeStep(overrides: Partial<ImpactStep> = {}): ImpactStep {
  return {
    id: overrides.id ?? 'step',
    arm: overrides.arm ?? 'probe',
    method: overrides.method ?? 'GET',
    route: overrides.route ?? '/api/items/1',
    status: overrides.status ?? 200,
    actor: overrides.actor ?? memberAcme,
    ...overrides,
  }
}

// ===========================================================================
// 1. R4-C-1: Boolean & status-boolean validator / coercion stub guards
// ===========================================================================

describe('R4-C-1: canonicalPredicateSkeleton, empty-base rejection, and validator/coercion stubs', () => {
  type StubHandler = (paramVal: string) => { status: number; json: unknown }

  function runBooleanDiffAgainstStub(
    stub: StubHandler,
    baseVal: string,
    trueVal: string,
    falseVal: string,
    param = 'id',
  ) {
    const mkArm = (val: string): BooleanDifferentialArm => {
      const resp = stub(val)
      return {
        status: resp.status,
        method: 'GET',
        origin: 'https://app.example.test',
        persona: 'viewer_a',
        pathAndQuery: `/api/items?${param}=${encodeURIComponent(val)}`,
        json: resp.json,
      }
    }
    const round: BooleanDifferentialRound = {
      baseline: mkArm(baseVal),
      control: mkArm(trueVal),
      probe: mkArm(falseVal),
    }
    return assessBooleanDifferential({ param, rounds: [round, round] })
  }

  function runStatusBooleanAgainstStub(
    stub: StubHandler,
    baseVal: string,
    trueVal: string,
    falseVal: string,
    param = 'id',
  ) {
    const mk = (id: string, arm: 'control' | 'probe', val: string): ImpactStep => {
      const resp = stub(val)
      return makeStep({
        id,
        arm,
        method: 'GET',
        route: '/api/items',
        pathAndQuery: `/api/items?${param}=${encodeURIComponent(val)}`,
        status: resp.status,
        actor: viewerAcme,
        json: resp.json,
      })
    }
    const benign = mk('b', 'control', baseVal)
    const tautology = mk('t', 'probe', trueVal)
    const contradiction = mk('f', 'probe', falseVal)
    return assessInjectionImpact({
      impactClass: 'injection',
      steps: [benign, tautology, contradiction],
      injection: { family: 'sqli', param, statusBoolean: { benign, tautology, contradiction, param } },
    })
  }

  test('canonicalPredicateSkeleton rejects empty-base standalone/negated/parenthesised predicates and extracts exact skeleton', () => {
    // Empty-base standalone predicates (including negated & parenthesised R4-C-1 bypasses) MUST reject
    for (const emptyBase of [
      '1=1',
      '1=2',
      'NOT 1=2',
      'NOT 42=0',
      '(1=1)',
      '(42=42)',
      'NOT (42=0)',
      "'a'='a'",
      "'a'='b'",
      ' AND 1=1',
      "' AND 1=1--",
      'TRUE',
      'FALSE',
    ]) {
      assert.equal(canonicalPredicateSkeleton(emptyBase), null, `expected empty-base rejection: ${emptyBase}`)
      assert.equal(parseBooleanPredicate(emptyBase), null, `parseBooleanPredicate must reject: ${emptyBase}`)
    }

    const sTrue = canonicalPredicateSkeleton('42 AND 7919=7919')
    const sFalse = canonicalPredicateSkeleton('42 AND 7919=7920')
    assert.ok(sTrue && sFalse)
    assert.equal(sTrue.baseValue, '42')
    assert.equal(sTrue.skeleton, sFalse.skeleton)
    assert.equal(sTrue.predicatePrefix, sFalse.predicatePrefix)
    assert.equal(sTrue.rawLength, sFalse.rawLength)
    assert.equal(sTrue.operandCharClass, sFalse.operandCharClass)
    assert.equal(sTrue.clauseCharClass, sFalse.clauseCharClass)
    assert.equal(sTrue.truth, true)
    assert.equal(sFalse.truth, false)

    // Operator / negation / paren asymmetries produce distinct skeletons
    const sNeq = canonicalPredicateSkeleton('42 AND 7919!=7919')
    const sNot = canonicalPredicateSkeleton('42 AND NOT 7919=7919')
    const sParen = canonicalPredicateSkeleton('42 AND (7919=7920)')
    assert.ok(sNeq && sNot && sParen)
    assert.notEqual(sTrue.skeleton, sNeq.skeleton)
    assert.notEqual(sTrue.skeleton, sNot.skeleton)
    assert.notEqual(sTrue.skeleton, sParen.skeleton)
  })

  test('length-cap validator stub (400, 422, and 404) rejects EVERY boolean and status-boolean triangle', () => {
    for (const rejectStatus of [400, 422, 404] as const) {
      const lengthCapStub: StubHandler = (val) =>
        val.length <= 10
          ? { status: 200, json: { id: 42, name: 'Widget' } }
          : { status: rejectStatus, json: { error: 'value too long' } }

      // Asymmetric lengths around cap=10 (`42 AND 1=1` len 10 vs `42 AND 1=10` len 11)
      const shapes: Array<[string, string, string]> = [
        ['42', '42 AND 1=1', '42 AND 1=10'],
        ['42', '42 AND 1=1', '42 AND 1=1+1'],
        ['42', '42 AND 1=1', '42 AND 1=2'],
        ['42', '42 AND TRUE', '42 AND FALSE'],
      ]
      for (const [b, t, f] of shapes) {
        const diffRes = runBooleanDiffAgainstStub(lengthCapStub, b, t, f)
        assert.equal(diffRes.satisfied, false, `length-cap (${rejectStatus}) boolean diff must reject: ${t} vs ${f}`)
        const sbRes = runStatusBooleanAgainstStub(lengthCapStub, b, t, f)
        assert.equal(sbRes.satisfied, false, `length-cap (${rejectStatus}) statusBoolean must reject: ${t} vs ${f}`)
      }
    }

    // Even when a worker supplies a swapped-length second round to statusBoolean, length-cap stub fails symmetry!
    const lengthCap404: StubHandler = (val) =>
      val.length <= 10
        ? { status: 200, json: { id: 42 } }
        : { status: 404, json: { error: 'too long' } }
    const mk = (id: string, arm: 'control' | 'probe', val: string) => {
      const r = lengthCap404(val)
      return makeStep({ id, arm, method: 'GET', route: '/api/items', pathAndQuery: `/api/items?id=${encodeURIComponent(val)}`, status: r.status, actor: viewerAcme, json: r.json })
    }
    const swappedRes = assessInjectionImpact({
      impactClass: 'injection',
      steps: [
        mk('b1', 'control', '42'),
        mk('t1', 'probe', '42 AND 1=1'),
        mk('f1', 'probe', '42 AND 1=10'),
      ],
      injection: {
        family: 'sqli',
        param: 'id',
        statusBoolean: {
          benign: mk('b1', 'control', '42'),
          tautology: mk('t1', 'probe', '42 AND 1=1'),
          contradiction: mk('f1', 'probe', '42 AND 1=10'),
          swappedRound: {
            benign: mk('b2', 'control', '42'),
            tautology: mk('t2', 'probe', '42 AND 10=10'), // len 12 -> 404 on length-cap stub!
            contradiction: mk('f2', 'probe', '42 AND 1=2'), // len 10 -> 200 on length-cap stub!
          },
        },
      },
    })
    assert.equal(swappedRes.satisfied, false, 'length-cap stub must fail swapped-length symmetry')
  })

  test('charset-validator stub (400, 422, and 404) rejects EVERY boolean and status-boolean triangle', () => {
    for (const rejectStatus of [400, 422, 404] as const) {
      // Allows alphanumeric, space, single-quote, hyphen, `=`; rejects `!`, `<`, `>`, `+`, `(`, `)`, uppercase diffs
      const charsetStub: StubHandler = (val) =>
        /^[0-9a-zA-Z '=-]+$/.test(val)
          ? { status: 200, json: { id: 42, name: 'Widget' } }
          : { status: rejectStatus, json: { error: 'invalid characters' } }

      const shapes: Array<[string, string, string]> = [
        ['42', '42 AND 1=1', '42 AND 1!=1'],
        ['42', '42 AND 1=1', '42 AND 1<>1'],
        ['42', '42 AND 1=1', '42 AND (1=2)'],
        ['abc', "abc' AND 'a'='a'--", "abc' AND 'a'='!'--"],
        ['abc', "abc' AND 'a'='a'--", "abc' AND 'a'='1'--"],
        ['abc', "abc' AND 'a'='a'--", "abc' AND 'a'='A'--"],
        ['42', '42 AND 1=1', '42 AND 1=2'],
      ]
      for (const [b, t, f] of shapes) {
        const diffRes = runBooleanDiffAgainstStub(charsetStub, b, t, f)
        assert.equal(diffRes.satisfied, false, `charset-validator (${rejectStatus}) boolean diff must reject: ${t} vs ${f}`)
        const sbRes = runStatusBooleanAgainstStub(charsetStub, b, t, f)
        assert.equal(sbRes.satisfied, false, `charset-validator (${rejectStatus}) statusBoolean must reject: ${t} vs ${f}`)
      }
    }
  })

  test('integer-coercion stub (including R4-C-1 empty-base negated/parenthesised bypass) rejects EVERY boolean and status-boolean triangle', () => {
    // Integer-coercion handler: parseInt(id, 10) === 42 returns 200 record; invalid/missing returns 404 (or 200 empty)
    const parseIntStub404: StubHandler = (val) => {
      const n = Number.parseInt(val, 10)
      return n === 42
        ? { status: 200, json: { id: 42, name: 'Widget' } }
        : { status: 404, json: { error: 'not found' } }
    }
    const parseIntStub200: StubHandler = (val) => {
      const n = Number.parseInt(val, 10)
      // Coerces baseline '' and keyword-led 'NOT 42=0' both to NaN (empty), while '42=0' coerces to 42 (found)!
      return n === 42
        ? { status: 200, json: { id: 42, name: 'Widget' } }
        : { status: 200, json: { id: null, items: [] } }
    }

    const shapes: Array<[string, string, string]> = [
      // R4-C-1 empty-base negated/parenthesised coercion bypasses
      ['', 'NOT 42=0', '42=0'],
      ['', '(42=42)', '42=0'],
      ['', 'NOT (42=0)', '42=0'],
      ['', '42=42', '999=0'],
      ['', "'a'='a'", "'a'='b'"],
      // Classic mismatched base integer coercion
      ['42', '42 AND 1=1', '999 AND 1=2'],
      ['42', '42 AND 7919=7919', '9999 AND 7919=7920'],
      // Same base: integer coercion yields identical response on all 3 arms
      ['42', '42 AND 7919=7919', '42 AND 7919=7920'],
    ]
    for (const stub of [parseIntStub404, parseIntStub200]) {
      for (const [b, t, f] of shapes) {
        assert.equal(runBooleanDiffAgainstStub(stub, b, t, f).satisfied, false, `parseInt boolean diff must reject: ${b} / ${t} / ${f}`)
        assert.equal(runStatusBooleanAgainstStub(stub, b, t, f).satisfied, false, `parseInt statusBoolean must reject: ${b} / ${t} / ${f}`)
      }
    }
  })

  test('assessBooleanDifferential rejects 4xx false arm when baseline is 2xx, and statusBoolean rejects 400/422 validation statuses', () => {
    const false400Round: BooleanDifferentialRound = {
      baseline: { status: 200, method: 'GET', origin: 'https://app.example.test', persona: 'viewer_a', pathAndQuery: '/api/items?id=42', json: { id: 42 } },
      control: { status: 200, method: 'GET', origin: 'https://app.example.test', persona: 'viewer_a', pathAndQuery: '/api/items?id=42%20AND%201%3D1', json: { id: 42 } },
      probe: { status: 400, method: 'GET', origin: 'https://app.example.test', persona: 'viewer_a', pathAndQuery: '/api/items?id=42%20AND%201%3D2', json: { error: 'bad request' } },
    }
    const diff400 = assessBooleanDifferential({ param: 'id', rounds: [false400Round, false400Round] })
    assert.equal(diff400.satisfied, false)
    assert.equal(diff400.evidence.statusClassMismatch, true)

    const false422Round: BooleanDifferentialRound = {
      ...false400Round,
      probe: { ...false400Round.probe, status: 422, json: { error: 'validation failed' } },
    }
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [false422Round, false422Round] }).satisfied, false)

    // statusBoolean rejects 400 and 422 even with identical-length same-skeleton predicates
    for (const validationStatus of [400, 422, 413, 414] as const) {
      const b = makeStep({ id: 'b', arm: 'control', route: '/api/items', pathAndQuery: '/api/items?id=42', status: 200, actor: viewerAcme })
      const t = makeStep({ id: 't', arm: 'probe', route: '/api/items', pathAndQuery: '/api/items?id=42%20AND%201%3D1', status: 200, actor: viewerAcme })
      const f = makeStep({ id: 'f', arm: 'probe', route: '/api/items', pathAndQuery: '/api/items?id=42%20AND%201%3D2', status: validationStatus, actor: viewerAcme })
      const res = assessInjectionImpact({
        impactClass: 'injection',
        steps: [b, t, f],
        injection: { family: 'sqli', param: 'id', statusBoolean: { benign: b, tautology: t, contradiction: f } },
      })
      assert.equal(res.satisfied, false, `statusBoolean must reject validation status ${validationStatus}`)
    }
  })

  test('genuine true boolean differential and host-bound statusBoolean still confirm cleanly', () => {
    const genuineVulnStub: StubHandler = (val) => {
      if (val === '42' || val === '42 AND 7919=7919' || val === '42 AND 8111=8111') {
        return { status: 200, json: { count: 1, items: [{ id: 42, name: 'Widget' }] } }
      }
      return { status: 200, json: { count: 0, items: [] } }
    }
    const diffOk = runBooleanDiffAgainstStub(genuineVulnStub, '42', '42 AND 7919=7919', '42 AND 7919=7920')
    assert.equal(diffOk.satisfied, true, diffOk.reason)

    // Host-bound pair check on verifyBooleanTriangleBinding & statusBoolean
    const hostPair = { challengeId: 'bool-1', baseValue: '42', trueValue: '42 AND 7919=7919', falseValue: '42 AND 7919=7920' }
    const b = makeStep({ id: 'b', arm: 'control', route: '/api/items', pathAndQuery: '/api/items?id=42', status: 200, actor: viewerAcme })
    const t = makeStep({ id: 't', arm: 'probe', route: '/api/items', pathAndQuery: '/api/items?id=42%20AND%207919%3D7919', status: 200, actor: viewerAcme })
    const f = makeStep({ id: 'f', arm: 'probe', route: '/api/items', pathAndQuery: '/api/items?id=42%20AND%207919%3D7920', status: 404, actor: viewerAcme })
    const sbOk = assessInjectionImpact({
      impactClass: 'injection',
      steps: [b, t, f],
      injection: { family: 'sqli', param: 'id', statusBoolean: { benign: b, tautology: t, contradiction: f, hostPair } },
    })
    assert.equal(sbOk.satisfied, true, sbOk.reason)

    // Mismatched hostPair rejects
    const sbWrongPair = verifyBooleanTriangleBinding({
      baseline: { status: 200, method: 'GET', pathAndQuery: '/api/items?id=42' },
      armA: { status: 200, method: 'GET', pathAndQuery: '/api/items?id=42%20AND%201%3D1' },
      armB: { status: 404, method: 'GET', pathAndQuery: '/api/items?id=42%20AND%201%3D2' },
      param: 'id',
      hostPair,
    })
    assert.equal(sbWrongPair.ok, false)
  })
})

// ===========================================================================
// 2. R4-C-3: Deletion-normalized anti-reflection primitive
// ===========================================================================

describe('R4-C-3: deletion-normalized anti-reflection against deleting sanitizers & malformed escapes', () => {
  const cleanControl = makeStep({
    id: 'ctl', arm: 'control', method: 'GET', route: '/api/search', pathAndQuery: '/api/search?q=books',
    status: 200, json: { results: [] }, body: '{"results":[]}',
  })

  // Target-side deleting sanitizer stubs:
  const stripTags = (s: string) => s.replace(/<!--[\s\S]*?-->/g, '').replace(/<\/?[a-zA-Z][^>]*>/g, '')
  const stripZeroWidth = (s: string) => s.replace(/[\u200B-\u200F\u2060\uFEFF\u00AD]/g, '')
  const foldNfkc = (s: string) => s.normalize('NFKC')

  test('tag-stripping, zero-width-stripping, and NFKC-folding reflecting stubs reject ALL injection fingerprint classes', () => {
    const cases: Array<{ family: InjectionFamily; tagSplit: string; zwSplit: string; nfkcSplit: string }> = [
      {
        family: 'sqli',
        tagSplit: 'SQLI<b></b>TE_ERROR: near input',
        zwSplit: 'SQLI\u200BTE\uFEFF_ERROR: near input',
        nfkcSplit: '\uFF33\uFF31\uFF2C\uFF29\uFF34\uFF25_ERROR: near input',
      },
      {
        family: 'sqli',
        tagSplit: 'PG::<span class="x"></span>SyntaxError',
        zwSplit: 'PG::\u200DSyntax\u200BError',
        nfkcSplit: '\uFF30\uFF27::SyntaxError',
      },
      {
        family: 'nosqli',
        tagSplit: 'Mongo<!--pad-->ServerError',
        zwSplit: 'Mongo\u2060ServerError',
        nfkcSplit: '\uFF2D\uFF4F\uFF4E\uFF47\uFF4FServerError',
      },
      {
        family: 'ssti',
        tagSplit: 'Template<i></i>SyntaxError',
        zwSplit: 'Template\u200CSyntaxError',
        nfkcSplit: '\uFF34\uFF45\uFF4D\uFF50\uFF4C\uFF41\uFF54\uFF45SyntaxError',
      },
      {
        family: 'cmdi',
        tagSplit: '/bin/sh:<span></span> command not found',
        zwSplit: '/bin/sh:\u200B command not found',
        nfkcSplit: '/bin/sh: \uFF43\uFF4F\uFF4D\uFF4D\uFF41\uFF4E\uFF44 not found',
      },
      {
        family: 'xxe',
        tagSplit: 'SAX<br/>ParseException',
        zwSplit: 'SAX\u00ADParseException',
        nfkcSplit: '\uFF33\uFF21\uFF38ParseException',
      },
      {
        family: 'traversal',
        tagSplit: 'ro<em></em>ot:x:0:0:',
        zwSplit: 'ro\u200Bot:x:0:0:',
        nfkcSplit: '\uFF52\uFF4F\uFF4F\uFF54:x:0:0:',
      },
    ]

    for (const c of cases) {
      const variants: Array<[string, string, string]> = [
        ['tag-strip', c.tagSplit, stripTags(c.tagSplit)],
        ['zero-width', c.zwSplit, stripZeroWidth(c.zwSplit)],
        ['nfkc-fold', c.nfkcSplit, foldNfkc(c.nfkcSplit)],
      ]
      for (const [kind, sent, reflected] of variants) {
        const probe = makeStep({
          id: `${c.family}-${kind}`,
          arm: 'probe',
          method: 'GET',
          route: '/api/search',
          pathAndQuery: `/api/search?q=${encodeURIComponent(sent)}`,
          status: 400,
          body: `No results for: ${reflected}`,
        })
        assert.equal(
          matchStrippedInjectionFingerprint(probe, c.family),
          null,
          `matchStrippedInjectionFingerprint must reject ${c.family}/${kind}`,
        )
        const assess = assessInjectionImpact({
          impactClass: 'injection',
          steps: [cleanControl, probe],
          injection: { family: c.family },
        })
        assert.equal(assess.satisfied, false, `assessInjectionImpact must reject ${c.family}/${kind}`)
      }
    }
  })

  test('fails closed on malformed percent-escapes in URL/form carriers and decodes valid escapes adjacent to malformed ones', () => {
    const norm = normalizeCarrierForAntiReflection('%53%51%4C%49%54%45%5F%45%52%52%4F%52%ZZ')
    assert.equal(norm.hadMalformedPercentEscape, true)
    assert.ok(norm.alnumCore.includes('sqliteerror'))
    assert.equal(deletionNormalizeComparable('SQLI<b></b>TE\u200B_ERROR'), 'sqliteerror')

    // Query with malformed escape in a sibling parameter (`&pad=%ZZ`) + percent-encoded fingerprint in `q`
    const malformedSibling = makeStep({
      id: 'malformed-sibling',
      arm: 'probe',
      method: 'GET',
      route: '/api/search',
      pathAndQuery: '/api/search?q=%53%51%4C%49%54%45%5F%45%52%52%4F%52&pad=%ZZ',
      status: 400,
      body: 'No results for: SQLITE_ERROR',
    })
    assert.equal(matchStrippedInjectionFingerprint(malformedSibling, 'sqli'), null)
    assert.equal(stripRequestEchoes(malformedSibling).includes('sqlite_error'), false)

    // Malformed percent escape inside form-urlencoded body fails closed too
    const formControl = makeStep({ id: 'fc', arm: 'control', method: 'POST', route: '/api/submit', status: 200, requestBody: 'note=ok&pad=1', body: 'ok' })
    const malformedForm = makeStep({
      id: 'malformed-form',
      arm: 'probe',
      method: 'POST',
      route: '/api/submit',
      status: 400,
      requestBody: 'note=%53%51%4C%49%54%45%5F%45%52%52%4F%52&pad=%ZZ',
      body: 'Invalid: SQLITE_ERROR',
    })
    assert.equal(matchStrippedInjectionFingerprint(malformedForm, 'sqli'), null)
    assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [formControl, malformedForm], injection: { family: 'sqli' } }).satisfied, false)

    // Genuine non-echoed server error still confirms cleanly
    const genuine = makeStep({
      id: 'gen',
      arm: 'probe',
      method: 'GET',
      route: '/api/search',
      pathAndQuery: '/api/search?q=benign_search_term',
      status: 500,
      body: '<h1>Error</h1><p>SQLITE_ERROR: near "benign_search_term": syntax error</p>',
    })
    const fp = matchStrippedInjectionFingerprint(genuine, 'sqli')
    assert.ok(fp && fp.family === 'sqli' && fp.label === 'sqlite')
    assert.equal(assessInjectionImpact({ impactClass: 'injection', steps: [cleanControl, genuine], injection: { family: 'sqli' } }).satisfied, true)
  })
})

// ===========================================================================
// 3. R4-C-4: Business-logic refusal/bound control & cited-window completeness
// ===========================================================================

describe('R4-C-4: business_logic accumulator rejection, refusal/bound control, and cited-window completeness', () => {
  test('rejects correct add-to-cart twice, wallet deposit twice, and quantity increment twice without refusal/bound control', () => {
    // 1. Add-to-cart twice
    const addToCartTwice = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', route: '/api/carts/c-1', pathAndQuery: '/api/carts/c-1', status: 200, json: { id: 'c-1', quantity: 0, total_cents: 0 } }),
        makeStep({ id: 't1', seq: 2, arm: 'control', method: 'POST', route: '/api/carts/c-1/items', pathAndQuery: '/api/carts/c-1/items', status: 200, requestJson: { sku: 'BOOK', qty: 1 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', route: '/api/carts/c-1', pathAndQuery: '/api/carts/c-1', status: 200, json: { id: 'c-1', quantity: 1, total_cents: 1500 } }),
        makeStep({ id: 't2', seq: 4, arm: 'probe', method: 'POST', route: '/api/carts/c-1/items', pathAndQuery: '/api/carts/c-1/items', status: 200, requestJson: { sku: 'BOOK', qty: 1 }, json: { ok: true } }),
        makeStep({ id: 'r2', seq: 5, arm: 'control', method: 'GET', route: '/api/carts/c-1', pathAndQuery: '/api/carts/c-1', status: 200, json: { id: 'c-1', quantity: 2, total_cents: 3000 } }),
      ],
    })
    assert.equal(addToCartTwice.satisfied, false, addToCartTwice.reason)
    assert.equal(addToCartTwice.evidence.repeatedTransition, false)

    // 2. Wallet deposit twice (including starting from 0 where r1.balance === request.amount!)
    for (const startBalance of [0, 100]) {
      const depositTwice = assessBusinessLogicImpact({
        impactClass: 'business_logic',
        steps: [
          makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', route: '/api/wallets/w-1', pathAndQuery: '/api/wallets/w-1', status: 200, json: { id: 'w-1', balance: startBalance } }),
          makeStep({ id: 't1', seq: 2, arm: 'probe', method: 'POST', route: '/api/wallets/w-1/deposit', pathAndQuery: '/api/wallets/w-1/deposit', status: 200, requestJson: { amount: 50 }, json: { ok: true } }),
          makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', route: '/api/wallets/w-1', pathAndQuery: '/api/wallets/w-1', status: 200, json: { id: 'w-1', balance: startBalance + 50 } }),
          makeStep({ id: 't2', seq: 4, arm: 'probe', method: 'POST', route: '/api/wallets/w-1/deposit', pathAndQuery: '/api/wallets/w-1/deposit', status: 200, requestJson: { amount: 50 }, json: { ok: true } }),
          makeStep({ id: 'r2', seq: 5, arm: 'control', method: 'GET', route: '/api/wallets/w-1', pathAndQuery: '/api/wallets/w-1', status: 200, json: { id: 'w-1', balance: startBalance + 100 } }),
        ],
      })
      assert.equal(depositTwice.satisfied, false, `wallet deposit twice (start=${startBalance}) must reject`)
      assert.equal(depositTwice.evidence.repeatedTransition, false)
    }

    // 3. Quantity increment twice
    const quantityIncTwice = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', route: '/api/inventory/i-5', pathAndQuery: '/api/inventory/i-5', status: 200, json: { id: 'i-5', quantity: 10, stock: 10 } }),
        makeStep({ id: 't1', seq: 2, arm: 'control', method: 'POST', route: '/api/inventory/i-5/increment', pathAndQuery: '/api/inventory/i-5/increment', status: 200, requestJson: { delta: 1 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', route: '/api/inventory/i-5', pathAndQuery: '/api/inventory/i-5', status: 200, json: { id: 'i-5', quantity: 11, stock: 11 } }),
        makeStep({ id: 't2', seq: 4, arm: 'probe', method: 'POST', route: '/api/inventory/i-5/increment', pathAndQuery: '/api/inventory/i-5/increment', status: 200, requestJson: { delta: 1 }, json: { ok: true } }),
        makeStep({ id: 'r2', seq: 5, arm: 'control', method: 'GET', route: '/api/inventory/i-5', pathAndQuery: '/api/inventory/i-5', status: 200, json: { id: 'i-5', quantity: 12, stock: 12 } }),
      ],
    })
    assert.equal(quantityIncTwice.satisfied, false, quantityIncTwice.reason)
    assert.equal(quantityIncTwice.evidence.repeatedTransition, false)
  })

  test('rejects no-before-read branch, unequal-magnitude deltas, and idempotent PUT with an uncited intermediate write', () => {
    // 1. Missing pre-first readback (no-before-read branch dropped) even with a refusal control
    const noBeforeRead = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'balance', kind: 'floor', min: 0 }],
      steps: [
        makeStep({ id: 't1', seq: 1, arm: 'probe', method: 'POST', route: '/api/wallets/w-2/withdraw', pathAndQuery: '/api/wallets/w-2/withdraw', status: 200, requestJson: { amount: 600 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 2, arm: 'control', method: 'GET', route: '/api/wallets/w-2', pathAndQuery: '/api/wallets/w-2', status: 200, json: { id: 'w-2', balance: 400 } }),
        makeStep({ id: 't2', seq: 3, arm: 'probe', method: 'POST', route: '/api/wallets/w-2/withdraw', pathAndQuery: '/api/wallets/w-2/withdraw', status: 200, requestJson: { amount: 600 }, json: { ok: true } }),
        makeStep({ id: 'r2', seq: 4, arm: 'control', method: 'GET', route: '/api/wallets/w-2', pathAndQuery: '/api/wallets/w-2', status: 200, json: { id: 'w-2', balance: -200 } }),
      ],
    })
    assert.equal(noBeforeRead.satisfied, false, 'no-before-read must reject')

    // 2. Unequal-magnitude deltas (-600 then -700 from identical requests) rejected
    const unequalDeltas = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'balance', kind: 'floor', min: 0 }],
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', route: '/api/wallets/w-3', pathAndQuery: '/api/wallets/w-3', status: 200, json: { id: 'w-3', balance: 1000 } }),
        makeStep({ id: 't1', seq: 2, arm: 'probe', method: 'POST', route: '/api/wallets/w-3/withdraw', pathAndQuery: '/api/wallets/w-3/withdraw', status: 200, requestJson: { amount: 600 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', route: '/api/wallets/w-3', pathAndQuery: '/api/wallets/w-3', status: 200, json: { id: 'w-3', balance: 400 } }),
        makeStep({ id: 't2', seq: 4, arm: 'probe', method: 'POST', route: '/api/wallets/w-3/withdraw', pathAndQuery: '/api/wallets/w-3/withdraw', status: 200, requestJson: { amount: 600 }, json: { ok: true } }),
        makeStep({ id: 'r2', seq: 5, arm: 'control', method: 'GET', route: '/api/wallets/w-3', pathAndQuery: '/api/wallets/w-3', status: 200, json: { id: 'w-3', balance: -300 } }),
      ],
    })
    assert.equal(unequalDeltas.satisfied, false, 'unequal-magnitude deltas must reject')

    // 3. Idempotent PUT with an uncited intermediate mutating write inside HostFactLog seq window
    const r0 = makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', route: '/api/items/i-9', pathAndQuery: '/api/items/i-9', status: 200, json: { id: 'i-9', credits: 10 } })
    const t1 = makeStep({ id: 't1', seq: 2, arm: 'control', method: 'PUT', route: '/api/items/i-9', pathAndQuery: '/api/items/i-9', status: 200, requestJson: { credits: 20 }, json: { ok: true } })
    const r1 = makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', route: '/api/items/i-9', pathAndQuery: '/api/items/i-9', status: 200, json: { id: 'i-9', credits: 20 } })
    const t2 = makeStep({ id: 't2', seq: 4, arm: 'probe', method: 'PUT', route: '/api/items/i-9', pathAndQuery: '/api/items/i-9', status: 200, requestJson: { credits: 20 }, json: { ok: true } })
    const uncited = makeStep({ id: 'u-write', seq: 5, arm: 'probe', method: 'PUT', route: '/api/items/i-9', pathAndQuery: '/api/items/i-9', status: 200, requestJson: { credits: 30 }, json: { ok: true } })
    const r2 = makeStep({ id: 'r2', seq: 6, arm: 'control', method: 'GET', route: '/api/items/i-9', pathAndQuery: '/api/items/i-9', status: 200, json: { id: 'i-9', credits: 30 } })

    const completeness = checkCitedWindowCompleteness({
      citedSteps: [r0, t1, r1, t2, r2],
      allTranscriptSteps: [r0, t1, r1, t2, uncited, r2],
    })
    assert.equal(completeness.complete, false)
    assert.deepEqual(completeness.uncitedMutatingIds, ['u-write'])

    const putWithUncited = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'credits', kind: 'cap', max: 25 }],
      steps: [r0, t1, r1, t2, r2],
      allTranscriptSteps: [r0, t1, r1, t2, uncited, r2],
    })
    assert.equal(putWithUncited.satisfied, false, putWithUncited.reason)
    assert.equal(putWithUncited.evidence.citedWindowIncomplete, true)
    assert.deepEqual(putWithUncited.evidence.uncitedMutatingIds, ['u-write'])
  })

  test('confirms genuine double-redeem with refusal control or crossed bound (single_use / floor / cap) and clean window', () => {
    // 1. Refusal control (409) + equal-magnitude double-redeem
    const refusal = makeStep({ id: 'ctrl-409', seq: 1, arm: 'control', method: 'POST', route: '/api/vouchers/v-1/redeem', pathAndQuery: '/api/vouchers/v-1/redeem', status: 409, requestJson: { code: 'USED1' }, json: { error: 'already_used' } })
    const r0 = makeStep({ id: 'r0', seq: 2, arm: 'control', method: 'GET', route: '/api/vouchers/v-1', pathAndQuery: '/api/vouchers/v-1', status: 200, json: { id: 'v-1', redeemed_count: 0, discount_cents: 0 } })
    const t1 = makeStep({ id: 't1', seq: 3, arm: 'probe', method: 'POST', route: '/api/vouchers/v-1/redeem', pathAndQuery: '/api/vouchers/v-1/redeem', status: 200, requestJson: { code: 'FRESH1' }, json: { ok: true } })
    const r1 = makeStep({ id: 'r1', seq: 4, arm: 'control', method: 'GET', route: '/api/vouchers/v-1', pathAndQuery: '/api/vouchers/v-1', status: 200, json: { id: 'v-1', redeemed_count: 1, discount_cents: 1000 } })
    const t2 = makeStep({ id: 't2', seq: 5, arm: 'probe', method: 'POST', route: '/api/vouchers/v-1/redeem', pathAndQuery: '/api/vouchers/v-1/redeem', status: 200, requestJson: { code: 'FRESH1' }, json: { ok: true } })
    const r2 = makeStep({ id: 'r2', seq: 6, arm: 'control', method: 'GET', route: '/api/vouchers/v-1', pathAndQuery: '/api/vouchers/v-1', status: 200, json: { id: 'v-1', redeemed_count: 2, discount_cents: 2000 } })

    const withRefusal = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [refusal, r0, t1, r1, t2, r2],
      allTranscriptSteps: [refusal, r0, t1, r1, t2, r2],
    })
    assert.equal(withRefusal.satisfied, true, withRefusal.reason)
    assert.equal(withRefusal.evidence.repeatedTransition, true)
    assert.equal(withRefusal.evidence.refusalControl, true)

    // 2. Explicit single_use bound without refusal control
    const withSingleUse = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'redeemed_count', kind: 'single_use' }],
      steps: [r0, t1, r1, t2, r2],
      allTranscriptSteps: [r0, t1, r1, t2, r2],
    })
    assert.equal(withSingleUse.satisfied, true, withSingleUse.reason)
    assert.equal(withSingleUse.evidence.boundCrossed, true)

    // 3. Direct verifyRepeatedTransitionControl unit check: cap NOT crossed stays rejected
    const capNotCrossed = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'discount_cents', kind: 'cap', max: 5000 }],
      steps: [r0, t1, r1, t2, r2],
    })
    assert.equal(capNotCrossed.satisfied, false, 'cap bound not crossed (2000 <= 5000) must stay rejected')

    const directNoControl = verifyRepeatedTransitionControl({
      steps: [r0, t1, r1, t2, r2],
      repeated: {
        verified: true,
        changedFields: ['discount_cents'],
        invariantFields: ['discount_cents'],
        firstStep: t1,
        secondStep: t2,
        beforeFirst: r0,
        midRead: r1,
        afterSecond: r2,
        numericTransitions: [{ path: 'discount_cents', before: 0, mid: 1000, after: 2000, delta1: 1000, delta2: 1000 }],
        arrayTransitions: [],
        citedWindowIncomplete: false,
        uncitedMutatingIds: [],
      },
      boundary: false,
      oracleDeclared: false,
      invariantBounds: null,
    })
    assert.equal(directNoControl.satisfied, false)
  })

  test('oracle-invariants.ts remains free of dynamic new RegExp calls', () => {
    const src = readFileSync(resolve(REPO_ROOT, 'src/server/oracle-invariants.ts'), 'utf8')
    assert.equal(/\bnew RegExp\s*\(/.test(src), false)
  })
})
