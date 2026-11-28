/**
 * Phase 0 Non-Kernel Cleanup Regression Suite (`tests/p0-planner-skills-clean.test.ts`).
 *
 * The heuristic composite planner, grey-box dataflow synthesizer, capability-consumer frontier and
 * runtime invariant parity adapter were retired in Track B Cut 2 (World Graph + single-turn planner
 * is the one authoritative planner path). Remaining verification:
 *  4. Shared `invariant-runtime-parity.ts` entity normalization keeps `facets` as an entity noun.
 *  5. `exec-recon-planner.ts` has a neutral `HOP_CONTINUATION_DIRECTIVE`.
 *  5. `src/skills/multihop-chains.md` is crisp (~40 lines) and free of lab/oracle-schema dumps.
 *  6. `scripts/check-v8-contamination.ts` blocks structural lab-artifact regressions across
 *     `src/server/**` and `src/skills/**` while passing cleanly on the repository.
 *  7. The retired heuristic synthesizer modules stay deleted.
 */
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  formatContaminationReport,
  scanSourceTreeForContamination,
} from '../scripts/check-v8-contamination.ts'
import {
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  workerInvestigationPrompt,
} from '../src/server/agent-prompts.ts'
import { HOP_CONTINUATION_DIRECTIVE } from '../src/server/exec-recon-planner.ts'
import { inferEntityName } from '../src/server/invariant-runtime-parity.ts'
import { loadSkill } from '../src/server/skills.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

describe('Phase 0 planner, frontier, dataflow, skills & contamination cleanup', () => {
  test('4. invariant-runtime-parity keeps facets as entity noun', () => {
    assert.equal(inferEntityName('/api/v1/facets'), 'facet', 'facets must no longer be stripped by WRAPPER_SEG_RE')
    assert.equal(inferEntityName('/api/v1/things/:id'), 'thing')
  })

  test('5. exec-recon-planner, multihop-chains.md, and agent-prompts.ts are trimmed and domain-general', () => {
    const directiveLower = HOP_CONTINUATION_DIRECTIVE.toLowerCase()
    for (const forbidden of ['hops 3', 'hmac_sign', 'jwt_sign', 'await_async']) {
      assert.equal(directiveLower.includes(forbidden), false, `HOP_CONTINUATION_DIRECTIVE must stay neutral (found ${forbidden})`)
    }

    const skill = loadSkill('multihop-chains')
    assert.ok(skill, 'multihop-chains skill must load')
    const skillText = skill.content
    const skillLines = skillText.trimEnd().split('\n').length
    assert.ok(skillLines <= 50, `multihop-chains.md must be trimmed to ~40 lines, got ${skillLines}`)
    const skillLower = skillText.toLowerCase()
    for (const forbidden of ['service-meta', 'webhooks/trigger', 'hardened-twin', 'fast_lab', 'dual_tenant_abac', 'economic_conservation', 'balance_minting']) {
      assert.equal(skillLower.includes(forbidden), false, `multihop-chains.md must not include ${forbidden}`)
    }

    for (const forbidden of ['dual_tenant_abac', 'economic_conservation', 'N >= 5']) {
      assert.equal(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.includes(forbidden), false, `agent-prompts pattern must not include ${forbidden}`)
    }
    const promptJson = workerInvestigationPrompt({
      goal: 'Verify multi-hop flow',
      step: { id: 'step-1', title: 'Chain step', hypothesis: '[chain_hops=2] Test flow', category: 'broken-access-control', skills: ['multihop-chains'] },
      origins: ['https://app.example'],
      capabilityTier: 2,
      maxTurns: 10,
    })
    assert.equal(promptJson.includes('dual_tenant_abac'), false)
    assert.equal(promptJson.includes('economic_conservation'), false)
  })

  test('6. check-v8-contamination.ts blocks structural lab-artifact regressions and passes on repo', () => {
    const repoResult = scanSourceTreeForContamination(REPO_ROOT)
    assert.equal(repoResult.ok, true, formatContaminationReport(repoResult))

    const dir = mkdtempSync(join(tmpdir(), 'kovo-p0-contam-'))
    try {
      mkdirSync(join(dir, 'src', 'server'), { recursive: true })
      mkdirSync(join(dir, 'src', 'skills'), { recursive: true })
      writeFileSync(
        join(dir, 'src', 'server', 'regression.ts'),
        [
          'const a = "fast_lab"',
          'const b = "dual_org_cache_bleed"',
          'const c = "nfkc-collision"',
          'const d = "split_refund_ledger_break"',
          'const e = "billingz"',
          'const f = "whsec_12345"',
          'const g = "xfer_999"',
          'const h = "hardened_twin"',
          'const i = "rbs_secret_abc"',
        ].join('\n'),
        'utf8',
      )
      const res = scanSourceTreeForContamination(dir)
      assert.equal(res.ok, false)
      assert.equal(res.hits.length, 9, `expected 9 structural lab-artifact hits, got ${res.hits.length}`)
      for (const tok of [
        'fast_lab', 'dual_org_cache_bleed', 'nfkc-collision', 'split_refund_ledger_break',
        'billingz', 'whsec_', 'xfer_', 'hardened_twin', 'rbs_',
      ]) {
        assert.ok(
          res.hits.some(h => h.token === tok && h.category === 'structural_lab_artifact'),
          `missing contamination detection for ${tok}`,
        )
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('7. retired heuristic synthesizer modules stay deleted (World Graph planner is authoritative)', () => {
    for (const rel of ['src/server/gb-dataflow-synthesizer.ts', 'src/server/capability-consumer-frontier.ts']) {
      assert.equal(existsSync(join(REPO_ROOT, rel)), false, `${rel} must stay deleted`)
    }
  })
})
