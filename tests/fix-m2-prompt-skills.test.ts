/**
 * Regression tests for M2 prompt, skill, and `kovo_verify` tool-schema friction fixes:
 *  1. `kovo_verify` tool schema & description make `script` unmistakably primary & required
 *     (unless `scriptPath` is given) and mark `runtime` / `timeoutMs` / `title` clearly
 *     secondary optional fields so models never emit metadata-only calls.
 *  2. Zero stale `seal_capability({ regex: ... })` recommendations in `agent-prompts.ts` or
 *     `src/skills/*.md`; structured selectors (`jsonPath`, `header`, `cookie`, `value`) only.
 *  3. `ctx.chain(...)` is promoted as the preferred one-shot multi-hop builder across prompts
 *     and skills without violating Move O1 prompt budgets, and prompts remind workers that
 *     `kovo_verify` auto-persists confirmed findings (prefer over legacy `propose_chain_finding`).
 */
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  kovoVerifyHelperGuidance,
  proposeChainFindingDescription,
  workerInvestigationPrompt,
  workerSessionInstructions,
} from '../src/server/agent-prompts.ts'
import { buildWorkerTools } from '../src/server/agent-session.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SKILLS_DIR = join(REPO_ROOT, 'src/skills')
const PROMPTS_PATH = join(REPO_ROOT, 'src/server/agent-prompts.ts')

test('1. kovo_verify schema puts script first as primary and warns against metadata-only calls', async () => {
  const tools = buildWorkerTools(
    { kovo_verify: async () => ({ confirmed: false, reason: 'stub', detail: '', attempts: [] }) },
    value => value,
    AbortSignal.timeout(5_000),
    64 * 1024,
    () => {},
  )
  const gv = tools.find(t => t.name === 'kovo_verify')
  assert.ok(gv, 'kovo_verify tool must be registered')

  const params = gv.parameters as {
    properties: Record<string, { description?: string; minLength?: number }>
  }
  const propKeys = Object.keys(params.properties)
  assert.equal(propKeys[0], 'script', 'script must be the first parameter in kovo_verify schema')
  assert.equal(params.properties.script?.minLength, 1)
  assert.match(params.properties.script?.description ?? '', /REQUIRED/i)
  assert.match(params.properties.script?.description ?? '', /scriptPath/i)

  assert.match(params.properties.runtime?.description ?? '', /Optional secondary/i)
  assert.match(params.properties.runtime?.description ?? '', /without `script`/i)
  assert.match(params.properties.timeoutMs?.description ?? '', /Optional secondary/i)
  assert.match(params.properties.timeoutMs?.description ?? '', /without `script`/i)
  assert.match(params.properties.title?.description ?? '', /Optional secondary/i)

  assert.match(gv.description, /REQUIRED: pass `script` inline/i)
  assert.match(gv.description, /NEVER send `\{ runtime, timeoutMs, title \}` without `script`/i)

  // Metadata-only calls fail cleanly with explicit script-required error.
  const execCtx = { abortSignal: new AbortController().signal } as Parameters<typeof gv.execute>[2]
  const res = await gv.execute({ runtime: 'ts', timeoutMs: 30_000, title: 'metadata only' }, {} as never, execCtx) as {
    isError?: boolean
    output?: readonly { type: string; text?: string }[]
  }
  assert.equal(res.isError, true)
  const errText = (res.output ?? []).map(p => p.text ?? '').join('\n')
  assert.match(errText, /`script` is REQUIRED/i)
  assert.match(errText, /do not send metadata-only/i)
})

test('2. No stale seal_capability regex recommendations in agent-prompts.ts or src/skills/*.md', () => {
  const prompts = readFileSync(PROMPTS_PATH, 'utf8')
  const guidance = kovoVerifyHelperGuidance()
  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  const multihopSkill = readFileSync(join(SKILLS_DIR, 'multihop-chains.md'), 'utf8')

  for (const [label, text] of [
    ['agent-prompts.ts', prompts],
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['kovoVerifyHelperGuidance()', guidance],
    ['workerSessionInstructions', sysPrompt],
    ['multihop-chains.md', multihopSkill],
  ] as const) {
    assert.equal(/SSE\/non-JSON:\s*`?regex`?/i.test(text), false, `${label} still recommends SSE/non-JSON regex`)
    assert.equal(/extract capabilities with\s+`?regex`?/i.test(text), false, `${label} still instructs extracting with regex`)
    assert.equal(/jsonPath\s*\|\s*header\s*\|\s*cookie\s*\|\s*regex\s*\|\s*value/i.test(text), false, `${label} still lists regex as a seal_capability selector`)
    assert.equal(/seal_capability\s*\([^)]*\bregex\s*:/i.test(text), false, `${label} has seal_capability({ regex: ... }) snippet`)
  }

  // Must explicitly forbid regex and name structured selectors.
  for (const text of [KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN, guidance, multihopSkill]) {
    assert.match(text, /NEVER.*`?regex`?/i)
    assert.match(text, /jsonPath/)
    assert.match(text, /header/)
    assert.match(text, /cookie/)
    assert.match(text, /value/)
  }

  for (const file of readdirSync(SKILLS_DIR)) {
    if (!file.endsWith('.md')) continue
    const content = readFileSync(join(SKILLS_DIR, file), 'utf8')
    assert.equal(
      /seal_capability\s*\([^)]*\bregex\s*:/i.test(content),
      false,
      `${file} must not contain seal_capability({ regex: ... })`,
    )
  }
})

test('3. ctx.chain builder and kovo_verify auto-persistence are promoted without contamination', () => {
  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  const multihopSkill = readFileSync(join(SKILLS_DIR, 'multihop-chains.md'), 'utf8')
  const proposeDesc = proposeChainFindingDescription(true)

  for (const [label, text] of [
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
    ['multihop-chains.md', multihopSkill],
  ] as const) {
    assert.ok(text.includes('ctx.chain'), `${label} must promote ctx.chain`)
  }

  assert.ok(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.includes('ch.hop('))
  assert.ok(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.includes('ch.prove('))
  assert.ok(multihopSkill.includes('chain.hop('))
  assert.ok(multihopSkill.includes('chain.prove('))

  const inv = JSON.parse(workerInvestigationPrompt({
    goal: 'Verify multi-hop workflow',
    step: {
      id: 'step-m2-chain',
      title: 'Clean-session chain · Stage 1 -> Stage 2 -> Terminal',
      hypothesis: 'Stage 1 -> Stage 2 -> Terminal verification',
      category: 'broken-access-control',
      skills: ['multihop-chains'],
    },
    origins: ['https://app.example.invalid'],
    capabilityTier: 2,
    maxTurns: 10,
  })) as { multiHopDirectives?: { compositeCallSignature?: string; singleScriptConsolidation?: string } }
  assert.match(inv.multiHopDirectives?.compositeCallSignature ?? '', /ctx\.chain/)
  assert.match(inv.multiHopDirectives?.singleScriptConsolidation ?? '', /ctx\.chain/)

  assert.match(sysPrompt, /auto-persists confirmed findings/i)
  assert.match(KOVO_VERIFY_TOOL_DESCRIPTION, /auto-persists/i)
  assert.match(proposeDesc, /auto-persists confirmed findings without `assertionsJq`/i)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination detected: ${JSON.stringify(scan.hits)}`)
})
