// Truth loading + endpoint matching + precision/recall grading.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  ClaimResult,
  GradeResult,
  SubmittedFinding,
  Truth,
  TruthChain,
  TruthDecoy,
  TruthFinding,
} from './types.ts'

const SUITE_ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..')

/** Load `<suite>/fixtures/<name>/truth.json`. Truth is never served by any fixture. */
export function loadTruth(fixture: string): Truth {
  const path = join(SUITE_ROOT, 'fixtures', fixture, 'truth.json')
  return JSON.parse(readFileSync(path, 'utf8')) as Truth
}

const FAMILIES: Record<string, string[]> = {
  object_authz: ['bola', 'idor', 'cross_tenant_read', 'cross_tenant_write', 'authz_bypass', 'broken_object_authz'],
  function_authz: ['bfla', 'broken_function_authz', 'privilege_escalation', 'mass_assignment'],
  auth: ['auth_bypass', 'jwt_forgery', 'broken_auth', 'session_fixation', 'token_forgery'],
  xss: ['xss', 'stored_xss', 'reflected_xss', 'dom_xss'],
  sqli: ['sqli', 'blind_sqli', 'sql_injection', 'nosql_injection'],
  redirect: ['open_redirect', 'redirect'],
  race: ['race_double_spend', 'race_condition', 'toctou'],
  workflow: ['price_tampering', 'workflow_skip', 'business_logic', 'mass_assignment_price'],
  ssrf: ['ssrf', 'ssrf_internal_fetch', 'ssrf_callback'],
  xxe: ['xxe', 'xxe_callback', 'xxe_entity_resolved'],
  webhook: ['webhook_forgery', 'webhook_replay'],
  history: ['git_history_regression', 'sast_regression', 'removed_authz_check'],
}

function familyOf(cls: string | undefined): string | null {
  if (!cls) return null
  const lower = cls.toLowerCase()
  for (const [family, members] of Object.entries(FAMILIES)) {
    if (members.includes(lower)) return family
  }
  return lower
}

export function classesCompatible(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return true
  if (a.toLowerCase() === b.toLowerCase()) return true
  const fa = familyOf(a)
  const fb = familyOf(b)
  return fa !== null && fa === fb
}

function normalizeEndpoint(endpoint: string): string[] {
  const noQuery = endpoint.split('?')[0]
  const pathOnly = noQuery.replace(/^[a-z]+:\/\/[^/]+/i, '')
  return pathOnly.split('/').filter(Boolean)
}

/** Compare a submitted endpoint against a truth/decoy pattern (`:param` and `*` wildcards). */
export function endpointMatches(pattern: string, submitted: string): boolean {
  const want = normalizeEndpoint(pattern)
  const got = normalizeEndpoint(submitted)
  for (let i = 0; i < want.length; i++) {
    const part = want[i]
    if (part === '*') return true
    if (i >= got.length) return false
    if (!part.startsWith(':') && part !== got[i]) return false
  }
  return want.length === got.length
}

function methodMatches(pattern: string | undefined, submitted: string | undefined): boolean {
  if (!pattern || !submitted) return true
  return pattern.toUpperCase() === submitted.toUpperCase()
}

function originMatches(pattern: string | undefined, submitted: string | undefined): boolean {
  if (!pattern || !submitted) return true
  return pattern.toLowerCase() === submitted.toLowerCase()
}

const IGNORED_STATUSES = new Set(['ruled_out', 'false_positive', 'informational'])

export function gradeFindings(truth: Truth, submitted: SubmittedFinding[]): GradeResult {
  const claims: ClaimResult[] = []
  const usedTruth = new Set<string>()
  const usedDecoys = new Set<string>()
  let ignored = 0

  for (const finding of submitted) {
    if (!finding || typeof finding.endpoint !== 'string' || finding.status && IGNORED_STATUSES.has(finding.status)) {
      ignored++
      claims.push({ finding, kind: 'ignored', reason: 'ignored_status_or_missing_endpoint' })
      continue
    }

    const decoy = truth.decoys.find(
      (entry) =>
        endpointMatches(entry.endpoint, finding.endpoint) &&
        methodMatches(entry.method, finding.method) &&
        originMatches(entry.origin, finding.origin) &&
        classesCompatible(entry.vulnClass, finding.vulnClass),
    )
    if (decoy) {
      claims.push({
        finding,
        kind: 'decoy_false_positive',
        matched: decoy,
        reason: usedDecoys.has(decoy.id) ? `duplicate claim on decoy ${decoy.id}` : decoy.reason,
      })
      usedDecoys.add(decoy.id)
      continue
    }

    const match = truth.findings.find(
      (entry) =>
        endpointMatches(entry.endpoint, finding.endpoint) &&
        methodMatches(entry.method, finding.method) &&
        originMatches(entry.origin, finding.origin) &&
        classesCompatible(entry.vulnClass, finding.vulnClass),
    )
    if (match) {
      const duplicate = usedTruth.has(match.id)
      usedTruth.add(match.id)
      claims.push({
        finding,
        kind: 'true_positive',
        matched: match,
        reason: duplicate ? 'duplicate_report_of_true_positive' : 'matched_ground_truth',
      })
      continue
    }

    claims.push({
      finding,
      kind: 'unmatched_false_positive',
      reason: 'no truth or decoy entry matches endpoint/method/class',
    })
  }

  const truePositives = new Set(
    claims.filter((c) => c.kind === 'true_positive').map((c) => (c.matched as TruthFinding).id),
  ).size
  const falsePositives =
    new Set(claims.filter((c) => c.kind === 'decoy_false_positive').map((c) => (c.matched as TruthDecoy).id)).size +
    claims.filter((c) => c.kind === 'unmatched_false_positive').length

  const chains: Array<TruthChain & { covered: number; complete: boolean }> = truth.chains.map((chain) => {
    const covered = chain.members.filter((id) => usedTruth.has(id)).length
    return { ...chain, covered, complete: covered === chain.members.length }
  })

  return {
    fixture: truth.fixture,
    submitted: submitted.length,
    ignored,
    truePositives,
    falsePositives,
    precision: truePositives + falsePositives === 0 ? 1 : truePositives / (truePositives + falsePositives),
    recall: truth.findings.length === 0 ? 1 : truePositives / truth.findings.length,
    missed: truth.findings.filter((entry) => !usedTruth.has(entry.id)),
    chains: chains.map(({ id, title, covered, complete }) => ({
      id,
      title,
      total: truth.chains.find((c) => c.id === id)?.members.length ?? 0,
      covered,
      complete,
    })),
    claims,
  }
}

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`
}

export function renderGrade(result: GradeResult): string {
  const lines: string[] = []
  lines.push(`realism-suite grade — ${result.fixture}`)
  lines.push(
    `submitted=${result.submitted} tp=${result.truePositives} fp=${result.falsePositives} ` +
      `precision=${pct(result.precision)} recall=${pct(result.recall)} ignored=${result.ignored}`,
  )
  for (const claim of result.claims) {
    const where = claim.matched ? ` (${claim.matched.id})` : ''
    lines.push(`  [${claim.kind}] ${claim.finding.method ?? 'ANY'} ${claim.finding.endpoint}${where} — ${claim.reason}`)
  }
  if (result.missed.length > 0) {
    lines.push('missed:')
    for (const entry of result.missed) lines.push(`  - ${entry.id}: ${entry.method ?? 'ANY'} ${entry.endpoint}`)
  }
  if (result.chains.length > 0) {
    lines.push('chains:')
    for (const chain of result.chains) {
      lines.push(`  - ${chain.id}: ${chain.covered}/${chain.total}${chain.complete ? ' complete' : ''}`)
    }
  }
  return lines.join('\n')
}
