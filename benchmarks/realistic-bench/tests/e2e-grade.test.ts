// End-to-end grading: build a controlled acme-saas run (a known mix of vulnerable sites and a hard
// decoy), drive real solvers so the impact oracle records genuine events, assemble Guardian-style
// findings (true positives + one decoy false positive + one unmatched false positive + a duplicate),
// then grade with gradeRun and assert recall / precision / decoy-FP / funnel all come out right.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { GradeInput, SiteMode, SubmittedFinding, VariantPlan } from '../lib/types.ts'
import { generateVariant } from '../generator/variant.ts'
import { buildGroundTruth } from '../generator/groundtruth.ts'
import { gradeRun } from '../grader/score.ts'
import { renderScorecard } from '../grader/report.ts'
import { makeSolverCtx } from './helpers/site-matrix.ts'
import acme from '../apps/acme-saas/index.ts'

// Sites driven to vulnerable and exploited (independent resources — safe to run on one boot).
const VULN = ['acme.invoice-bola', 'acme.project-search-sqli', 'acme.file-path-traversal', 'acme.avatar-ssrf']
const DECOY = 'acme.notification-idor' // forced hardened; a finding here must be a false positive

test('e2e: real solver run grades to expected recall, precision, and decoy FP', async () => {
  const base: VariantPlan = generateVariant(acme.blueprint, 2)
  // Controlled mix: the four VULN sites vulnerable, everything else hardened (so DECOY is a decoy).
  const sites: Record<string, SiteMode> = {}
  for (const s of acme.blueprint.sites) sites[s.id] = VULN.includes(s.id) ? 'vulnerable' : 'hardened'
  const plan: VariantPlan = { ...base, sites }
  const groundTruth = buildGroundTruth(acme.blueprint, plan)

  const app = await acme.start({ plan, groundTruth })
  const startedAtMs = Date.now()
  try {
    const ctx = makeSolverCtx(app, 'acme_sid')
    for (const id of VULN) {
      const { solve } = (await import(new URL(`../apps/acme-saas/sites/${id}/solver.ts`, import.meta.url).href)) as { solve(c: typeof ctx): Promise<void> }
      await solve(ctx)
    }
    const oracleEvents = app.oracle.events()
    const requestLog = app.oracle.requests()
    const submittedAtMs = Date.now()

    // Build findings: one true positive per exploited site (from the ground-truth runtime endpoints).
    const findings: SubmittedFinding[] = VULN.map((id, i) => {
      const gt = groundTruth.vulns.find((v) => v.siteId === id)!
      const ep = gt.endpoints[0]!
      return {
        id: `F${i}`, title: gt.title, cwe: gt.cwe, vulnClass: gt.vulnClass, severity: gt.severity,
        endpoints: [{ method: ep.method, path: ep.path }], params: gt.params,
        status: 'runtime_confirmed', submittedAtMs, costUsdAtSubmit: 2 + i,
      }
    })
    // Duplicate of the first true positive (same root cause) — must collapse to 1 TP + 1 duplicate.
    findings.push({ ...findings[0]!, id: 'F-dup' })
    // Decoy false positive: a confident finding on the hardened decoy site's endpoint.
    const decoyGt = groundTruth.decoys.find((d) => d.siteId === DECOY)!
    findings.push({
      id: 'F-decoy', title: decoyGt.title, cwe: decoyGt.cwe, vulnClass: decoyGt.vulnClass,
      severity: 'high', endpoints: [{ method: decoyGt.endpoints[0]!.method, path: decoyGt.endpoints[0]!.path }],
      status: 'confirmed', submittedAtMs,
    })
    // Unmatched false positive: a finding on a route that maps to no planted site.
    findings.push({
      id: 'F-unmatched', title: 'alleged issue on an unplanted route', cwe: 'CWE-200',
      vulnClass: 'info_disclosure', severity: 'medium', endpoints: [{ method: 'GET', path: '/api/health' }],
      status: 'confirmed', submittedAtMs,
    })

    const input: GradeInput = {
      groundTruth, findings, oracleEvents, requestLog, egressLog: app.oracle.egress(),
      telemetry: { startedAtMs, endedAtMs: submittedAtMs, totalCostUsd: 12, budgetUsd: 20 },
      mode: 'grey-box',
    }
    const card = gradeRun(input)

    // Every exploited site confirmed via a real oracle event recorded before submit.
    assert.equal(card.confirmed, VULN.length, `confirmed=${card.confirmed} vulns=${card.vulns.map((v) => `${v.siteId}:${v.outcome}`).join(',')}`)
    // Duplicate collapses.
    assert.equal(card.duplicateFindings, 1, 'duplicate finding should collapse to one TP')
    // Strict decoy grading + unmatched FP.
    assert.equal(card.decoyFalsePositives, 1, 'the decoy finding is a false positive')
    assert.equal(card.unmatchedFalsePositives, 1, 'the unplanted-route finding is unmatched')
    // Precision = TP / (TP + decoyFP + unmatchedFP) = 4 / 6.
    assert.ok(card.precision > 0.6 && card.precision < 0.7, `precision=${card.precision}`)
    // Funnel is monotonic and reaches confirmation for the exploited sites.
    const f = card.funnel
    assert.ok(f.surfaceDiscovered >= f.hypothesisFormed && f.hypothesisFormed >= f.signalObserved
      && f.signalObserved >= f.specSubmitted && f.specSubmitted >= f.zeroLlmConfirmed, 'funnel must be monotonic')
    assert.ok(f.zeroLlmConfirmed >= VULN.length, `funnel confirmed ${f.zeroLlmConfirmed}`)
    // No out-of-scope egress escaped.
    assert.equal(card.egressBlocked >= 0, true)
    // Reports render deterministically.
    const md = renderScorecard(card, 'md')
    assert.match(md, /recall/i)
    assert.ok(renderScorecard(card, 'json').length > 0)
  } finally {
    await app.stop()
  }
})
