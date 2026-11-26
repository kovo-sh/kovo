// Route/path matching, CWE-family + vulnClass-alias compatibility, and finding->entry matching.
// Pure, no I/O. See CONTRACTS.md "Grading".
import type { GroundTruthEntry, SubmittedFinding } from '../lib/types.ts'

// ---------------------------------------------------------------------------------------------
// CWE family + vulnClass alias tables
// ---------------------------------------------------------------------------------------------
const familyCwes: Record<string, number[]> = {
  authz: [639, 284, 285, 862, 863, 566],
  sqli: [89, 564, 943],
  xss: [79, 80, 83],
  ssrf: [918],
  xxe: [611, 776],
  traversal: [22, 23, 35, 73],
  command: [77, 78, 88],
  ssti: [1336, 94, 95],
  auth: [287, 306, 288, 290],
  token: [345, 347, 327, 1270],
  csrf: [352],
  redirect: [601],
  mass_assign: [915],
  race: [362, 367],
  logic: [840, 841],
  cache: [524, 525, 444, 349],
  disclosure: [200, 359, 522, 532],
  rate: [307, 799],
  webhook: [],
}

const classFamily: Record<string, string> = {
  idor: 'authz', bola: 'authz', bfla: 'authz', graphql_bola: 'authz',
  mass_assignment: 'mass_assign', auth_bypass: 'auth', oauth: 'auth', jwt: 'token',
  csrf: 'csrf', sqli: 'sqli', ssti: 'ssti', ssrf: 'ssrf', xxe: 'xxe',
  xss_stored: 'xss', xss_reflected: 'xss', path_traversal: 'traversal',
  command_injection: 'command', cache_poisoning: 'cache', cache_deception: 'cache',
  race_condition: 'race', business_logic: 'logic', workflow_bypass: 'logic',
  open_redirect: 'redirect', webhook_forgery: 'webhook', info_disclosure: 'disclosure',
  rate_limit_bypass: 'rate',
}

const cweToFamily = new Map<number, string>()
for (const [fam, nums] of Object.entries(familyCwes)) {
  for (const n of nums) cweToFamily.set(n, fam)
}

function cweNumber(cwe: string | undefined): number | null {
  if (!cwe) return null
  const m = /(\d+)/.exec(cwe)
  return m ? Number(m[1]) : null
}

function familiesOf(vulnClass: string | undefined, cwe: string | undefined): Set<string> {
  const out = new Set<string>()
  if (vulnClass && classFamily[vulnClass]) out.add(classFamily[vulnClass])
  const n = cweNumber(cwe)
  if (n != null && cweToFamily.has(n)) out.add(cweToFamily.get(n) as string)
  return out
}

/** True when a finding's vulnClass/CWE is compatible with the entry (same class, same CWE, or same family). */
export function classCompatible(
  finding: { vulnClass?: string; cwe?: string },
  entry: Pick<GroundTruthEntry, 'vulnClass' | 'cwe'>,
): boolean {
  const vulnClass = finding.vulnClass?.trim()
  const cwe = finding.cwe?.trim()
  if (!vulnClass && !cwe) return false // fail-closed: never wildcard-match a classless finding by endpoint alone
  if (vulnClass === 'unmatched_classless') return false
  if (vulnClass && vulnClass === entry.vulnClass) return true
  const fc = cweNumber(cwe)
  const ec = cweNumber(entry.cwe)
  if (fc != null && ec != null && fc === ec) return true
  const ff = familiesOf(vulnClass, cwe)
  const ef = familiesOf(entry.vulnClass, entry.cwe)
  for (const f of ff) if (ef.has(f)) return true
  return false
}

// ---------------------------------------------------------------------------------------------
// Close-sibling class pairs (explicit allowlist, see CONTRACTS.md "Grading")
// ---------------------------------------------------------------------------------------------
// A grader must never invent tolerance: an incompatible label is only forgiven when it is one of
// the documented sibling *taxonomy* pairs below AND the claim is runtime-confirmed on a planted
// vulnerable entry with the same endpoint. Everything else stays a false positive.
const cweClassKey = new Map<number, string>([
  [639, 'bola'], [284, 'bfla'], [285, 'bfla'], [862, 'bfla'], [863, 'bfla'], [566, 'bfla'], [269, 'bfla'],
  [915, 'mass_assignment'],
  [472, 'business_logic'], [840, 'business_logic'], [841, 'business_logic'],
  [362, 'race_condition'], [367, 'race_condition'],
  [200, 'info_disclosure'], [359, 'info_disclosure'], [522, 'info_disclosure'], [532, 'info_disclosure'],
])

/** Canonical taxonomy key for a claim/entry label (vulnClass first, else its CWE). */
export function classKey(label: { vulnClass?: string; cwe?: string }): string | null {
  if (label.vulnClass) return label.vulnClass
  const n = cweNumber(label.cwe)
  return n != null ? cweClassKey.get(n) ?? null : null
}

/** Documented sibling pairs. Symmetric; both directions are accepted. */
export const siblingClassPairs: ReadonlyArray<readonly [string, string]> = [
  // object vs function-level authorization (and their GraphQL spelling)
  ['bola', 'idor'], ['bola', 'bfla'], ['idor', 'bfla'],
  ['bola', 'graphql_bola'], ['idor', 'graphql_bola'], ['bfla', 'graphql_bola'],
  // privileged-field writes can be reported as function-level authz
  ['mass_assignment', 'bfla'],
  // protected-field overpost can be reported as business logic
  ['mass_assignment', 'business_logic'],
  // invariant / double-spend logic vs. concurrency framing
  ['business_logic', 'race_condition'],
  // a role-gated data read can be reported as missing function-level authz
  ['info_disclosure', 'bfla'],
]

const siblingPairKeys = new Set(siblingClassPairs.map(([a, b]) => (a < b ? `${a}|${b}` : `${b}|${a}`)))

/** True when the two labels are a documented close-sibling taxonomy pair. */
export function siblingClassPair(
  finding: { vulnClass?: string; cwe?: string },
  entry: Pick<GroundTruthEntry, 'vulnClass' | 'cwe'>,
): boolean {
  const a = classKey(finding)
  const b = classKey(entry)
  if (!a || !b || a === b) return false
  return siblingPairKeys.has(a < b ? `${a}|${b}` : `${b}|${a}`)
}

// ---------------------------------------------------------------------------------------------
// Path / endpoint matching
// ---------------------------------------------------------------------------------------------
/** Strip http://127.0.0.1:PORT origin and query/hash, collapse trailing slash. */
export function normalizePath(path: string): string {
  let p = path.trim()
  p = p.replace(/^https?:\/\/[^/]+/i, '')
  const q = p.search(/[?#]/)
  if (q >= 0) p = p.slice(0, q)
  if (!p.startsWith('/')) p = '/' + p
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
  return p
}

function segs(p: string): string[] {
  return normalizePath(p).split('/').filter((s) => s.length > 0)
}

function isTemplatedSeg(s: string): boolean {
  return (
    s.startsWith(':') ||
    (s.startsWith('{') && s.endsWith('}')) ||
    (s.startsWith('<') && s.endsWith('>'))
  )
}

/** A finding endpoint path matches an entry route pattern. Entry `:param` and finding template
 *  segments ({id}/:id/<id>) act as single-segment wildcards. */
export function endpointMatches(
  findingEndpoint: { method?: string; path: string },
  entryEndpoint: { method?: string; path: string },
): boolean {
  if (findingEndpoint.method && entryEndpoint.method) {
    if (findingEndpoint.method.toUpperCase() !== entryEndpoint.method.toUpperCase()) return false
  }
  const a = segs(findingEndpoint.path)
  const b = segs(entryEndpoint.path)
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    const fs = a[i]
    const es = b[i]
    if (isTemplatedSeg(es) || isTemplatedSeg(fs)) continue
    if (fs !== es) return false
  }
  return true
}

/** True when any finding endpoint matches any of the entry's entry- or trigger-endpoints. */
export function findingHitsEntry(finding: SubmittedFinding, entry: GroundTruthEntry): boolean {
  const targets = [...entry.endpoints, ...entry.triggerEndpoints]
  for (const fe of finding.endpoints) {
    for (const te of targets) {
      if (endpointMatches(fe, te)) return true
    }
  }
  return false
}

function paramOverlap(finding: SubmittedFinding, entry: GroundTruthEntry): number {
  if (!finding.params || finding.params.length === 0) return 0
  const ep = new Set(entry.params.map((p) => p.toLowerCase()))
  let n = 0
  for (const p of finding.params) if (ep.has(p.toLowerCase())) n++
  return n
}

export interface GradeEntry {
  entry: GroundTruthEntry
  isDecoy: boolean
}

export interface MatchResult {
  entry: GroundTruthEntry
  isDecoy: boolean
  paramOverlap: number
  exactClass: boolean
}

/** Best class-compatible endpoint/param match for a finding. Ties prefer a vuln over a decoy. */
export function matchFindingToEntries(
  finding: SubmittedFinding,
  entries: GradeEntry[],
): MatchResult | null {
  const cands: MatchResult[] = []
  for (const ge of entries) {
    if (!classCompatible(finding, ge.entry)) continue
    if (!findingHitsEntry(finding, ge.entry)) continue
    const exactClass = !!finding.vulnClass && finding.vulnClass === ge.entry.vulnClass
    cands.push({ entry: ge.entry, isDecoy: ge.isDecoy, paramOverlap: paramOverlap(finding, ge.entry), exactClass })
  }
  if (cands.length === 0) return null
  cands.sort((x, y) => {
    if (x.exactClass !== y.exactClass) return x.exactClass ? -1 : 1
    if (x.paramOverlap !== y.paramOverlap) return y.paramOverlap - x.paramOverlap
    if (x.isDecoy !== y.isDecoy) return x.isDecoy ? 1 : -1 // prefer vuln on tie
    return 0
  })
  return cands[0]
}
