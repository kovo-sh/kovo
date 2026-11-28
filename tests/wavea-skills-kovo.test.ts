/**
 * Wave A #1 — Skills kovo_verify-Only Contract & Prompt Stage-Agnostic Tests.
 *
 * Verifies:
 *  1. Every `src/skills/*.md` file has ZERO references to retired legacy Replay Spec
 *     fields/kinds (`assertionsJq`, `http_chain`, `race_burst`, `browser_chain`,
 *     `ws_chain`, `sql_boolean_diff`, `sql_time_diff`, `upload_probe`, `rce_proof`,
 *     `dns_takeover`, `tls_audit`, `browser_dom`, `cache_differential`, `Replay Spec`,
 *     `DeclarativeReplaySpec`, `ReplayStep`, `spaCatchallControl`).
 *  2. Every `src/skills/*.md` file has ZERO benchmark-specific persona/lab handles
 *     (`member_b`, `owner_a`, `dual_member`, `fast_lab`, `member_a`, `viewer_a`) and
 *     passes `scanSourceTreeForContamination`.
 *  3. `src/skills/multihop-chains.md` Section 1 stays <= 1200 chars for pre-injection
 *     and every `SPECIALIST_PROFILES` skill slug resolves to a real `src/skills/*.md` file.
 *  4. `src/server/agent-prompts.ts` has zero hardcoded `"Stage 1 -> Stage 2 -> Stage 3 -> Stage 4"`
 *     or `"Stages 2-4"` / `"Hops 2-4"` boilerplate, and `src/server/exec-dispatch.ts` does not
 *     tell workers to `"submit a DeclarativeReplaySpec"`.
 */
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { SPECIALIST_PROFILES } from '../src/server/agent-prompts.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  listSkills,
  selectPreInjectionSkills,
} from '../src/server/skills.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const SKILLS_DIR = join(REPO_ROOT, 'src/skills')

const RETIRED_SKILL_PATTERNS: ReadonlyArray<{ label: string; pattern: RegExp }> = [
  { label: 'assertionsJq', pattern: /\bassertionsJq\b/ },
  { label: 'DeclarativeReplaySpec / ReplaySpec / ReplayStep', pattern: /\b(?:DeclarativeReplaySpec|ReplaySpec|ReplayStep)\b/ },
  { label: 'Replay Spec / ReplayVerifier prose', pattern: /\b(?:Replay\s+Spec|ReplayVerifier)\b/i },
  { label: 'propose_finding / verify_replay_spec', pattern: /\b(?:propose_finding|verify_replay_spec)\b/ },
  { label: 'kind: http_chain / http_chain', pattern: /\bhttp_chain\b/ },
  { label: 'kind: race_burst / bare race_burst', pattern: /(?<!prove_)\brace_burst\b/ },
  { label: 'kind: browser_chain / browser_chain', pattern: /\bbrowser_chain\b/ },
  { label: 'kind: ws_chain / ws_chain', pattern: /\bws_chain\b/ },
  { label: 'retired legacy spec kinds', pattern: /\b(?:sql_boolean_diff|sql_time_diff|upload_probe|rce_proof|dns_takeover|tls_audit|browser_dom|cache_differential|auth_protocol_proof)\b/ },
  { label: 'spaCatchallControl', pattern: /\bspaCatchallControl\b/ },
]

const BENCHMARK_PERSONA_LITERALS: ReadonlyArray<{ label: string; pattern: RegExp }> = [
  { label: 'member_a', pattern: /\bmember_a\b/ },
  { label: 'member_b', pattern: /\bmember_b\b/ },
  { label: 'owner_a', pattern: /\bowner_a\b/ },
  { label: 'owner_b', pattern: /\bowner_b\b/ },
  { label: 'viewer_a', pattern: /\bviewer_a\b/ },
  { label: 'viewer_b', pattern: /\bviewer_b\b/ },
  { label: 'dual_member', pattern: /\bdual_member\b/ },
  { label: 'fast_lab', pattern: /\bfast_lab\b/ },
]

test('all src/skills/*.md have zero retired Replay Spec fields/kinds and zero benchmark persona handles', () => {
  const files = readdirSync(SKILLS_DIR).filter(f => f.endsWith('.md')).sort()
  assert.ok(files.length >= 43, `expected >= 43 skill markdown files, got ${files.length}`)

  for (const file of files) {
    const content = readFileSync(join(SKILLS_DIR, file), 'utf8')
    for (const { label, pattern } of RETIRED_SKILL_PATTERNS) {
      assert.equal(
        pattern.test(content),
        false,
        `src/skills/${file} still references retired Replay Spec token (${label})`,
      )
    }
    for (const { label, pattern } of BENCHMARK_PERSONA_LITERALS) {
      assert.equal(
        pattern.test(content),
        false,
        `src/skills/${file} leaks benchmark persona/lab literal (${label})`,
      )
    }
    assert.equal(/\bctx\.race\b/.test(content), false, `src/skills/${file} must not reference nonexistent ctx.race`)
  }

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination hits: ${JSON.stringify(scan.hits)}`)
})

test('SPECIALIST_PROFILES slugs and multihop-chains.md Section 1 budget remain intact', () => {
  clearSkillsCache()
  const known = new Set(listSkills().map(s => s.name))
  for (const [profileId, cfg] of Object.entries(SPECIALIST_PROFILES)) {
    for (const slug of cfg.skills) {
      assert.ok(known.has(slug), `SPECIALIST_PROFILES[${profileId}] missing skill ${slug}`)
    }
  }

  const multihop = readFileSync(join(SKILLS_DIR, 'multihop-chains.md'), 'utf8')
  const section2Idx = multihop.indexOf('\n## 2.')
  assert.ok(section2Idx > 0, 'multihop-chains.md must have Section 2 heading')
  assert.ok(section2Idx <= 1200, `multihop-chains.md Section 1 is ${section2Idx} chars (must be <= 1200)`)
  assert.ok(multihop.includes('actor_low'), 'multihop-chains.md must use generic actor_low placeholder')

  const preInjected = selectPreInjectionSkills({ profileSkills: ['bola-idor-race'], lane: 'chain', limit: 2 })
  const mh = preInjected.find(s => s.name === MULTIHOP_CHAINS_SKILL)
  assert.ok(mh, 'multihop-chains must be pre-injected on chain lane')
  assert.ok(mh!.excerpt.length <= 1200)
  assert.ok(mh!.excerpt.includes('ctx.seal_capability'))
  assert.ok(mh!.excerpt.includes('ctx.prove_composite'))
  assert.ok(mh!.excerpt.includes('CompositeProofReceipt'))
})

test('agent-prompts.ts and exec-dispatch.ts avoid hardcoded 4-stage count boilerplate and DeclarativeReplaySpec directives', () => {
  const prompts = readFileSync(join(REPO_ROOT, 'src/server/agent-prompts.ts'), 'utf8')
  const dispatch = readFileSync(join(REPO_ROOT, 'src/server/exec-dispatch.ts'), 'utf8')

  assert.equal(prompts.includes('Stage 1 -> Stage 2 -> Stage 3 -> Stage 4'), false)
  assert.equal(prompts.includes('Stages 2-4'), false)
  assert.equal(prompts.includes('Hops 2-4'), false)
  assert.ok(prompts.includes('N-hop causal chain'))
  assert.equal(dispatch.includes('submit a DeclarativeReplaySpec'), false)
})
