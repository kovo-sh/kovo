// @kernel
/**
 * Behavioral regression tests for the AST-verified `Kernel-cosmetic:` exemption across:
 *   - `scripts/lib/kernel-cosmetic-ast.ts`
 *   - `scripts/check-kernel-review.ts`
 *   - `scripts/check-contract-change.ts` (parity-gate + tunable constant rules)
 *   - `scripts/check-fix-provenance.ts`
 *   - `AGENTS.md` Claude Opus default & `Kernel-cosmetic:` policy
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { verifyCosmeticTsChange } from '../scripts/lib/kernel-cosmetic-ast.ts'
import { checkKernelReviewRepo, formatKernelReviewReport } from '../scripts/check-kernel-review.ts'
import { checkGitRepo, formatContractChangeReport } from '../scripts/check-contract-change.ts'
import { runFixProvenanceCheck } from '../scripts/check-fix-provenance.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const CHECK_KERNEL_REVIEW_TS = join(REPO_ROOT, 'scripts/check-kernel-review.ts')
const CHECK_CONTRACT_TS = join(REPO_ROOT, 'scripts/check-contract-change.ts')
const CHECK_PROVENANCE_TS = join(REPO_ROOT, 'scripts/check-fix-provenance.ts')

function initTempGitRepo(t: { after: (fn: () => void) => void }, prefix: string): {
  repo: string
  git: (...args: string[]) => string
} {
  const repo = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(repo, { recursive: true, force: true }))
  const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '-b', 'main')
  git('config', 'user.email', 'cosmetic-gate-test@example.invalid')
  git('config', 'user.name', 'Cosmetic Gate Tester')
  return { repo, git }
}

const BASE_KERNEL_SOURCE = [
  '/**',
  ' * Kovo Hunter oracle invariant helper.',
  ' */',
  'export const MAX_ORACLE_HOPS = 5',
  '',
  "export type OracleFamily = 'authz' | 'injection'",
  '',
  'const ALLOWED_HEADERS = new Set(["x-kovo-proof"])',
  'const SIGNATURE_RE = /^sig:[a-f0-9]+$/',
  '',
  'export function verifyOracleInvariant(input: { status: number; header: string; family: OracleFamily }): boolean {',
  '  // Guard Kovo Hunter status threshold',
  '  if (input.status !== 200) {',
  "    throw new Error('Kovo Hunter oracle rejected non-200 response')",
  '  }',
  "  if (input.header === 'Kovo Hunter') {",
  '    return false',
  '  }',
  "  if (input.header.includes('Kovo Hunter')) {",
  '    return false',
  '  }',
  '  if (!ALLOWED_HEADERS.has(input.header)) {',
  '    return false',
  '  }',
  '  const re = new RegExp("^kovo-hunter$")',
  '  if (re.test(input.header) || SIGNATURE_RE.test(input.header)) {',
  '    return true',
  '  }',
  '  const meta = { oracleFamily: input.family, reason: "Kovo Hunter verified proof" }',
  '  return meta.oracleFamily === "authz"',
  '}',
  '',
].join('\n')

const COSMETIC_KERNEL_SOURCE = [
  '/**',
  ' * Kovo oracle invariant helper (reformatted JSDoc comment).',
  ' */',
  'export const MAX_ORACLE_HOPS = 5',
  '',
  "export type OracleFamily = 'authz' | 'injection'",
  '',
  'const ALLOWED_HEADERS = new Set(["x-kovo-proof"])',
  'const SIGNATURE_RE = /^sig:[a-f0-9]+$/',
  '',
  'export function verifyOracleInvariant(input: { status: number; header: string; family: OracleFamily }): boolean {',
  '  // Guard Kovo status threshold',
  '  if (input.status !== 200) {',
  '    throw new Error("Kovo oracle rejected non-200 response")',
  '  }',
  "  if (input.header === 'Kovo Hunter') {",
  '    return false',
  '  }',
  "  if (input.header.includes('Kovo Hunter')) {",
  '    return false',
  '  }',
  '  if (!ALLOWED_HEADERS.has(input.header)) {',
  '    return false',
  '  }',
  '  const re = new RegExp("^kovo-hunter$")',
  '  if (re.test(input.header) || SIGNATURE_RE.test(input.header)) {',
  '    return true',
  '  }',
  '  const meta = { oracleFamily: input.family, reason: "Kovo verified proof" }',
  '  return meta.oracleFamily === "authz"',
  '}',
  '',
].join('\n')

test('Kernel-cosmetic: comment & brand-copy kernel diff PASSES all 3 gates WITH trailer and FAILS WITHOUT trailer', (t) => {
  const { repo, git } = initTempGitRepo(t, 'r3-cosmetic-pass-')
  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'plans'), { recursive: true })
  mkdirSync(join(repo, 'tests/parity/corpus'), { recursive: true })

  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), BASE_KERNEL_SOURCE)
  writeFileSync(join(repo, 'plans/ROADMAP.md'), '# Roadmap\n`R3-05`\n')
  writeFileSync(
    join(repo, 'tests/parity/corpus/sample-fp.json'),
    JSON.stringify({
      id: 'sample-fp',
      side: 'fp',
      expected: { confirmed: false },
      covers: { files: ['src/server/oracle-invariants.ts'], classes: ['authz'] },
    }) + '\n',
  )
  git('add', '.')
  git('commit', '-m', 'init')

  // Apply pure cosmetic comment + error/reason brand copy diff WITHOUT Kernel-cosmetic trailer -> all 3 MUST FAIL!
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), COSMETIC_KERNEL_SOURCE)
  git('add', 'src/server/oracle-invariants.ts')
  git('commit', '-m', 'chore(brand): rename comments and error copy in oracle-invariants')

  const krNoTrailer = checkKernelReviewRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(krNoTrailer.ok, false, 'check-kernel-review must FAIL without Kernel-cosmetic trailer')

  const ccNoTrailer = checkGitRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(ccNoTrailer.ok, false, 'check-contract-change parity-gate must FAIL without Kernel-cosmetic trailer')

  const fpNoTrailer = runFixProvenanceCheck({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(fpNoTrailer.ok, false, 'check-fix-provenance must FAIL without Kernel-cosmetic trailer')

  // Amend WITH Kernel-cosmetic trailer -> all 3 gates MUST PASS!
  git(
    'commit',
    '--amend',
    '-m',
    'chore(brand): rename comments and error copy in oracle-invariants\n\nKernel-cosmetic: pure brand copy and comment rename',
  )

  const krPass = checkKernelReviewRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(krPass.ok, true, `check-kernel-review expected PASS, violations=${krPass.violations.join('; ')}`)
  assert.ok(krPass.cosmeticOverride)
  const krReport = formatKernelReviewReport(krPass)
  assert.match(krReport, /PASS \(cosmetic\/non-behavioral kernel diff verified by AST; 1 file\(s\)\)/)

  const krCli = spawnSync(process.execPath, [CHECK_KERNEL_REVIEW_TS, '--root', repo, '--base', 'HEAD~1'], {
    encoding: 'utf8',
  })
  assert.equal(krCli.status, 0, `check-kernel-review CLI failed: ${krCli.stderr}`)
  assert.match(krCli.stdout, /PASS \(cosmetic\/non-behavioral kernel diff verified by AST; 1 file\(s\)\)/)

  const ccPass = checkGitRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(ccPass.ok, true, `check-contract-change expected PASS: ${ccPass.committed.parity?.reason}`)
  assert.equal(ccPass.committed.parity?.cosmeticVerified, true)
  assert.match(
    formatContractChangeReport(ccPass),
    /PASS \(cosmetic\/non-behavioral kernel diff verified by AST; 1 file\(s\)\)/,
  )

  const ccCli = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], {
    encoding: 'utf8',
  })
  assert.equal(ccCli.status, 0, `check-contract-change CLI failed: ${ccCli.stderr}`)

  const fpPass = runFixProvenanceCheck({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(fpPass.ok, true, `check-fix-provenance expected PASS: ${fpPass.commits[0]?.violations.join('; ')}`)
  assert.equal(fpPass.commits[0]?.cosmeticVerified, true)

  const fpCli = spawnSync(process.execPath, [CHECK_PROVENANCE_TS, '--root', repo, '--base', 'HEAD~1'], {
    encoding: 'utf8',
  })
  assert.equal(fpCli.status, 0, `check-fix-provenance CLI failed: ${fpCli.stderr}`)
})

test('Kernel-cosmetic: changing an if condition, regex, numeric threshold, or comparison string FAILS CLOSED across all 3 gates', (t) => {
  const forbiddenMutations: Array<{ label: string; mutate: (src: string) => string }> = [
    {
      label: 'if condition operator (!== -> ===)',
      mutate: s => s.replace('if (input.status !== 200)', 'if (input.status === 200)'),
    },
    {
      label: 'numeric threshold (200 -> 201)',
      mutate: s => s.replace('if (input.status !== 200)', 'if (input.status !== 201)'),
    },
    {
      label: 'tunable constant MAX_ORACLE_HOPS (5 -> 10)',
      mutate: s => s.replace('export const MAX_ORACLE_HOPS = 5', 'export const MAX_ORACLE_HOPS = 10'),
    },
    {
      label: 'regex literal change',
      mutate: s => s.replace('const SIGNATURE_RE = /^sig:[a-f0-9]+$/', 'const SIGNATURE_RE = /^sig:[a-z0-9]+$/'),
    },
    {
      label: 'new RegExp string argument change',
      mutate: s => s.replace('new RegExp("^kovo-hunter$")', 'new RegExp("^kovo$")'),
    },
    {
      label: 'comparison string literal (===)',
      mutate: s => s.replace("if (input.header === 'Kovo Hunter')", "if (input.header === 'Kovo')"),
    },
    {
      label: '.includes() string literal',
      mutate: s => s.replace("if (input.header.includes('Kovo Hunter'))", "if (input.header.includes('Kovo'))"),
    },
    {
      label: 'Set entry string literal',
      mutate: s => s.replace('new Set(["x-kovo-proof"])', 'new Set(["x-other-proof"])'),
    },
    {
      label: 'union type literal',
      mutate: s => s.replace("export type OracleFamily = 'authz' | 'injection'", "export type OracleFamily = 'authz' | 'xss'"),
    },
    {
      label: 'const -> let declaration kind',
      mutate: s => s.replace('const meta = {', 'let meta = {'),
    },
  ]

  // 1. Direct AST unit verification on all forbidden mutations.
  for (const m of forbiddenMutations) {
    const mutated = m.mutate(BASE_KERNEL_SOURCE)
    assert.notEqual(mutated, BASE_KERNEL_SOURCE, `mutation "${m.label}" did not change source`)
    const astRes = verifyCosmeticTsChange('src/server/oracle-invariants.ts', BASE_KERNEL_SOURCE, mutated)
    assert.equal(astRes.ok, false, `AST verifier MUST fail closed for: ${m.label}`)
  }

  // 2. End-to-end git repo test across all 3 gates for core forbidden mutations WITH Kernel-cosmetic trailer.
  const { repo, git } = initTempGitRepo(t, 'r3-cosmetic-fail-closed-')
  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'plans'), { recursive: true })
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), BASE_KERNEL_SOURCE)
  writeFileSync(join(repo, 'plans/ROADMAP.md'), '# Roadmap\n`R3-05`\n')
  git('add', '.')
  git('commit', '-m', 'init')
  const baseSha = git('rev-parse', 'HEAD')

  for (const idx of [0, 1, 2, 3, 4, 5, 6]) {
    const m = forbiddenMutations[idx]!
    git('reset', '--hard', baseSha)
    writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), m.mutate(BASE_KERNEL_SOURCE))
    git('add', 'src/server/oracle-invariants.ts')
    git(
      'commit',
      '-m',
      `chore: smuggle ${m.label}\n\nKernel-cosmetic: attempting false cosmetic claim`,
    )

    const kr = checkKernelReviewRepo({ rootDir: repo, baseRef: baseSha })
    assert.equal(kr.ok, false, `check-kernel-review MUST FAIL CLOSED on "${m.label}" with Kernel-cosmetic`)
    assert.match(kr.violations.join('\n'), /oracle-invariants\.ts/)

    const cc = checkGitRepo({ rootDir: repo, baseRef: baseSha })
    assert.equal(cc.ok, false, `check-contract-change MUST FAIL CLOSED on "${m.label}" with Kernel-cosmetic`)

    const fp = runFixProvenanceCheck({ rootDir: repo, baseRef: baseSha })
    assert.equal(fp.ok, false, `check-fix-provenance MUST FAIL CLOSED on "${m.label}" with Kernel-cosmetic`)
    assert.match(fp.commits[0]?.violations.join('\n') ?? '', /invalid_kernel_cosmetic/)
  }
})

test('AGENTS.md sets Claude Opus (claude-opus-5-5-high) as default kernel reviewer and documents Kernel-cosmetic:', () => {
  const agentsMd = readFileSync(join(REPO_ROOT, 'AGENTS.md'), 'utf8')
  assert.match(agentsMd, /claude-opus-5-5-high/)
  assert.match(agentsMd, /Kernel-cosmetic:/)
  assert.match(agentsMd, /kernel-cosmetic-ast\.ts/)
})
