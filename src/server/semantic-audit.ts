import { createHash, randomUUID } from 'node:crypto'
import { z } from 'zod'
import {
  type CodeLocation,
  type Finding,
  type OwaspCategory,
  type SpecialistProfile,
} from '../domain.ts'
import { type CodeAuditSuspectData, type HostTier, classifyHostTier } from './agent-session.ts'
import { isProfileHealthy, resolveProfilePoolForRole, type ResolvedModelProfile } from './model-settings.ts'
import { providerPool, type UsageCallback } from './provider.ts'
import { type NamedSecret, redact } from './redact.ts'
import type { Assignment, Run, Store } from './store.ts'
import type {
  CallGraphResult,
  SastFinding,
  SastSeverity,
  WorkerBackend,
  WorkerSession,
} from './worker-backend.ts'

// ============================================================================
// Constants & Security Guardrails
// ============================================================================

export const MAX_AUDIT_SUSPECTS_CEILING = 80
export const DEFAULT_AUDIT_SUSPECTS_BUDGET = 40
export const MAX_DYNAMIC_RULES_PER_STAGE = 24
export const MAX_GIT_COMMITS_TO_MINE = 200
export const MAX_VARIANT_MATCHES_PER_FINDING = 40
export const MAX_REGEX_LENGTH = 256

const SAFE_REPO_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}(?:\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}){0,3}$/
const SAFE_GIT_REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$/
const SAFE_RULE_ID_RE = /^[a-z0-9][a-z0-9._-]{2,96}$/i
const SECURITY_COMMIT_RE = /\b(?:fix(?:e[sd])?|patch|vuln(?:erability)?|cve-\d{4}-\d+|cwe-\d+|auth(?:z|entication)?|perm(?:ission)?|idor|bola|bfla|csrf|xsrf|xss|sqli|sql\s*injection|ssrf|xxe|ssti|rce|bypass|sanitiz(?:e|er|ation)|escap(?:e|ing)|tenant|ownership|rbac|acl|jwt|oauth|redirect|traversal|prototype\s*pollution|mass\s*assignment|race)\b/i

// ============================================================================
// Zod Schemas & TypeScript Interfaces
// ============================================================================

export const auditSinkKindSchema = z.enum([
  'api_route',
  'server_action',
  'webhook',
  'db_query',
  'outbound_fetch',
  'redirect',
  'postmessage_iframe',
  'upload_storage',
  'auth_config',
  'other',
])
export type AuditSinkKind = z.infer<typeof auditSinkKindSchema>

export const projectSecuritySpecSourceSchema = z.object({
  name: z.string().trim().min(1).max(120),
  kind: z.enum(['http_param', 'http_header', 'http_body', 'cookie', 'server_action_arg', 'graphql_arg', 'webhook_payload', 'ws_message', 'env_or_file']),
  patterns: z.array(z.string().trim().min(1).max(200)).min(1).max(16),
  framework: z.string().trim().max(64).optional(),
})

export const projectSecuritySpecGuardSchema = z.object({
  name: z.string().trim().min(1).max(120),
  kind: z.enum(['auth_middleware', 'session_check', 'tenant_scope', 'ownership_check', 'role_check', 'csrf_check', 'webhook_signature']),
  patterns: z.array(z.string().trim().min(1).max(200)).min(1).max(16),
  enforces: z.string().trim().min(1).max(240),
  file: z.string().trim().max(300).optional(),
})

export const projectSecuritySpecSanitizerSchema = z.object({
  name: z.string().trim().min(1).max(120),
  protectsAgainst: z.array(z.string().trim().min(1).max(64)).min(1).max(8),
  patterns: z.array(z.string().trim().min(1).max(200)).min(1).max(16),
})

export const projectSecuritySpecSinkSchema = z.object({
  name: z.string().trim().min(1).max(120),
  sinkKind: auditSinkKindSchema,
  cwe: z.string().trim().regex(/^CWE-\d{1,5}$/).optional(),
  patterns: z.array(z.string().trim().min(1).max(200)).min(1).max(16),
  severity: z.enum(['critical', 'high', 'medium', 'low']).default('high'),
})

export const projectSecuritySpecInvariantSchema = z.object({
  id: z.string().trim().min(1).max(80),
  description: z.string().trim().min(1).max(400),
  appliesTo: z.string().trim().min(1).max(160),
  requiredGuard: z.string().trim().min(1).max(160),
  cwe: z.string().trim().regex(/^CWE-\d{1,5}$/).default('CWE-862'),
  severity: z.enum(['critical', 'high', 'medium', 'low']).default('high'),
})

export const projectSecuritySpecSchema = z.object({
  repo: z.string().trim().min(1).max(200),
  languages: z.array(z.string().trim().min(1).max(40)).max(16).default([]),
  frameworks: z.array(z.string().trim().min(1).max(64)).max(16).default([]),
  ormLibraries: z.array(z.string().trim().min(1).max(64)).max(16).default([]),
  authLibraries: z.array(z.string().trim().min(1).max(64)).max(16).default([]),
  sources: z.array(projectSecuritySpecSourceSchema).max(40).default([]),
  authTenantGuards: z.array(projectSecuritySpecGuardSchema).max(40).default([]),
  sanitizers: z.array(projectSecuritySpecSanitizerSchema).max(40).default([]),
  sinks: z.array(projectSecuritySpecSinkSchema).max(40).default([]),
  businessInvariants: z.array(projectSecuritySpecInvariantSchema).max(32).default([]),
  generatedAt: z.number().int().nonnegative(),
  usedLlm: z.boolean().default(false),
})
export type ProjectSecuritySpec = z.output<typeof projectSecuritySpecSchema>

export const dynamicRuleSpecSchema = z.object({
  id: z.string().trim().regex(SAFE_RULE_ID_RE),
  engine: z.enum(['opengrep', 'ast-grep']),
  languages: z.array(z.string().trim().regex(/^[a-z0-9_-]{1,32}$/i)).min(1).max(6),
  severity: z.enum(['critical', 'high', 'medium', 'low']).default('high'),
  cwe: z.string().trim().regex(/^CWE-\d{1,5}$/).optional(),
  sinkKind: auditSinkKindSchema.default('other'),
  message: z.string().trim().min(3).max(400),
  mode: z.enum(['pattern', 'taint']).default('pattern'),
  patterns: z.array(z.string().trim().min(3).max(1000)).max(8).optional(),
  excludePatterns: z.array(z.string().trim().min(3).max(500)).max(6).optional(),
  taintSources: z.array(z.string().trim().min(3).max(500)).max(8).optional(),
  taintSinks: z.array(z.string().trim().min(3).max(500)).max(8).optional(),
  taintSanitizers: z.array(z.string().trim().min(3).max(500)).max(8).optional(),
  metavariableRegex: z.record(
    z.string().regex(/^\$[A-Z0-9_]{1,32}$/),
    z.string().min(1).max(MAX_REGEX_LENGTH),
  ).optional(),
})
export type DynamicRuleSpec = z.output<typeof dynamicRuleSpecSchema>

export interface ValidatedDynamicRule {
  spec: DynamicRuleSpec
  yaml: string
  sha256: string
}

export interface CallGraphNode {
  id: string
  file: string
  line: number
  endLine?: number
  symbol: string
  kind: 'entrypoint' | 'function' | 'middleware' | 'sink' | 'guard' | 'sanitizer'
  httpMethod?: string
  routePath?: string
  sinkKind?: AuditSinkKind
  guards: string[]
  sanitizers: string[]
  calls: string[]
}

export interface CallGraphEdge {
  fromId: string
  toId: string
  file: string
  line: number
}

export interface CallGraphIndex {
  repo: string
  filesScanned: number
  nodes: CallGraphNode[]
  edges: CallGraphEdge[]
  analyzerSource: 'worker_analyzer' | 'offline_script_fallback'
}

export interface SinkBackwardPath {
  entrypointId: string
  entrypointSymbol: string
  entrypointFile: string
  entrypointLine: number
  routeOrAction: string
  httpMethod?: string
  sinkId: string
  sinkSymbol: string
  sinkFile: string
  sinkLine: number
  sinkKind: AuditSinkKind
  callChain: string[]
  dominatingGuards: string[]
  partialGuards: string[]
  dominatingSanitizers: string[]
  /** Missing authorization/tenant guard on an auth-sensitive route. */
  isAuthUnguarded: boolean
  /** Missing input sanitizer on an injection-capable sink. */
  isInjectionUnsanitized: boolean
  /** Either independent finding above (aggregate, backwards-compatible). */
  isUnguardedPath: boolean
}

export interface SemanticAuditSuspect {
  id: string
  fingerprint: string
  stage: 'stage1_dynamic_rule' | 'stage2_backward_taint' | 'stage3_git_miner' | 'stage3_variant_sweep'
  origin: string
  repo: string
  file: string
  line: number
  endLine?: number
  routeOrAction: string
  httpMethod?: string
  authCheck: string
  ownershipCheck: string
  sinkKind: AuditSinkKind
  cwe?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  priorityScore: number
  recommendedTier: 1 | 2 | 3
  specialistProfile: SpecialistProfile
  hypothesis: string
  sourceToSinkTrace?: string
  invariantId?: string
  ruleId?: string
  /** Param names parsed from the enclosing route template (`:id`, `{order_id}`, `<int:id>`). */
  paramNames?: string[]
  /** Symbol of the resolved enclosing HTTP entrypoint. */
  entrypointSymbol?: string
  /** Phase-0 live endpoint that this suspect reconciles to (when discovered). */
  reconciledEndpoint?: string
  data: CodeAuditSuspectData
}

export interface GitSecurityCommitSignal {
  commitSha: string
  subject: string
  committedAt?: string
  matchedKeywords: string[]
  touchedFiles: string[]
  removedChecksOrGuards: string[]
  /** Exact removed-guard locations parsed from `git show --unified=3`. */
  removedGuardLocations?: Array<{ file: string; line: number; snippet: string }>
  candidatePatterns: Array<{
    file: string
    line: number
    snippet: string
    reason: string
  }>
}

const REMOVED_GUARD_RE = /\b(?:auth|authorize|authenticate|require[A-Z_]|require\s*\(|session|permission|ownership|tenant(?:Id|_id)?|org(?:Id|_id)?|csrf|xsrf|sanitiz|escape|validate|validateOrThrow|allowlist|whitelist|isAdmin|role|roles|acl|rbac|policy|req\.user|currentUser)\b/i

/** Parse `git show --unified=3` output for removed authorization/sanitizer lines. */
export function extractRemovedGuardsFromDiff(
  diff: string,
  maxResults = 12,
): Array<{ file: string; line: number; snippet: string }> {
  const out: Array<{ file: string; line: number; snippet: string }> = []
  let currentFile = ''
  let newLine = 0
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('+++ b/')) {
      currentFile = raw.slice(6).trim()
      continue
    }
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
    if (hunk) {
      newLine = Number(hunk[1])
      continue
    }
    if (raw.startsWith('-') && !raw.startsWith('---')) {
      const snippet = raw.slice(1).trim()
      if (snippet && REMOVED_GUARD_RE.test(snippet) && currentFile && !/^\s*(?:#|\/\/|\*)/.test(snippet)) {
        out.push({ file: currentFile, line: Math.max(1, newLine), snippet: snippet.slice(0, 240) })
        if (out.length >= maxResults) return out
      }
      continue
    }
    if (!raw.startsWith('-')) newLine += 1
  }
  return out
}

export interface GitHistoryMiningResult {
  repo: string
  available: boolean
  reason?: string
  commitsScanned: number
  securityCommits: GitSecurityCommitSignal[]
  suspects: SemanticAuditSuspect[]
}

export interface VariantSweepQuery {
  id: string
  engine: 'opengrep' | 'ast-grep'
  description: string
  rule: ValidatedDynamicRule
  callGraphSymbol?: string
}

export interface VariantSweepResult {
  findingId: string
  repo: string
  queriesExecuted: number
  rejectedQueries: Array<{ id: string; reason: string }>
  rawMatches: SastFinding[]
  newSuspects: SemanticAuditSuspect[]
  durationMs: number
}

export interface SemanticAuditLlmCall {
  (prompt: { systemPrompt: string; userPrompt: string }): Promise<string>
}

export interface SemanticAuditContext {
  run: Pick<Run, 'id' | 'projectId' | 'goal' | 'goalRevision' | 'scopeRevision' | 'capabilityTier' | 'budgetUsd' | 'spentUsd' | 'budgetRequests' | 'spentRequests'>
  approvedOrigins: readonly string[]
  reposDir: string
  mountedRepos: readonly string[]
  backend: WorkerBackend
  session?: WorkerSession
  modelProfiles?: readonly ResolvedModelProfile[]
  llmCall?: SemanticAuditLlmCall
  hostTiers?: Record<string, HostTier>
  secrets?: readonly NamedSecret[]
  storage?: Store
  assignment?: Assignment
  onUsage?: UsageCallback
  /** Live Phase-0 endpoints for reconciling code-derived routes to runnable HTTP targets. */
  liveEndpoints?: ReadonlyArray<{ method: string; path: string }>
  signal: AbortSignal
}

export interface SemanticAuditPipelineOptions {
  suspectBudget?: number
  enableStage1Llm?: boolean
  enableStage3GitMiner?: boolean
  gitMaxCommits?: number
  gitDiffBase?: string
  persistToStore?: boolean
}

export interface SemanticAuditPipelineResult {
  specsByRepo: Record<string, ProjectSecuritySpec>
  dynamicRulesCount: number
  rejectedDynamicRules: Array<{ ruleId: string; reason: string }>
  callGraphsByRepo: Record<string, { filesScanned: number; nodes: number; edges: number; source: CallGraphIndex['analyzerSource'] }>
  backwardPathsEvaluated: number
  gitMiningByRepo: Record<string, GitHistoryMiningResult>
  allSuspectsCount: number
  rankedSuspects: SemanticAuditSuspect[]
  persistedFactIds: string[]
  persistedEndpointIds: string[]
  durationMs: number
}

// ============================================================================
// Validation & Sanitization Layer
// ============================================================================

export function normalizeRepoIdentifier(raw: string): string {
  const clean = raw.trim().replace(/^\/repos\//, '').replace(/\/+$/, '')
  if (!clean || /[\0\r\n\\]/.test(clean) || clean.startsWith('/') || clean.split('/').includes('..') || !SAFE_REPO_ID_RE.test(clean)) {
    throw new Error(`Invalid repository identifier: ${raw}`)
  }
  return clean
}

export function validateSafeRegex(pattern: string): { ok: true } | { ok: false; reason: string } {
  if (!pattern || typeof pattern !== 'string') return { ok: false, reason: 'Regex pattern must be non-empty.' }
  if (pattern.length > MAX_REGEX_LENGTH) return { ok: false, reason: `Regex exceeds ${MAX_REGEX_LENGTH} character limit.` }
  if (/[\0\r\n]/.test(pattern)) return { ok: false, reason: 'Regex contains forbidden control characters.' }
  if (/\\[1-9]/.test(pattern)) return { ok: false, reason: 'Regex backreferences are not allowed.' }
  if (/\(\?<[=!]/.test(pattern)) return { ok: false, reason: 'Regex lookbehinds are not allowed.' }
  if (/\([^)]*[+*][^)]*\)\s*[+*{]/.test(pattern) || /(\.\*|\.\+){2,}/.test(pattern)) {
    return { ok: false, reason: 'Regex risks catastrophic backtracking (ReDoS).' }
  }
  try {
    new RegExp(pattern)
  } catch {
    return { ok: false, reason: 'Invalid regular expression syntax.' }
  }
  return { ok: true }
}

const FORBIDDEN_RULE_TEXT_RE = /(?:^|\n)\s*(?:fix|fix-regex|paths|metadata)\s*:|https?:\/\/|\x00/i
const YAML_ANCHOR_ALIAS_RE = /(?:^|\s)[&*][a-zA-Z0-9_-]+/
const YAML_TAG_RE = /!![a-zA-Z0-9_:-]+/
const TRIVIAL_WILDCARD_RE = /^(?:\$[A-Z0-9_]+|\.{3}|\$\$\$|\*+|\.\*|\.\+)$/

function checkPatternSafety(p: string): string | null {
  if (!p || p.length < 3) return 'Pattern too short.'
  if (TRIVIAL_WILDCARD_RE.test(p.trim())) return `Overly broad wildcard pattern "${p.trim()}" rejected.`
  if (FORBIDDEN_RULE_TEXT_RE.test(p)) return 'Pattern contains forbidden directive or URL.'
  if (YAML_TAG_RE.test(p)) return 'Custom YAML tags (!!) are not allowed.'
  if (/(?:^|\s)&[a-zA-Z_][a-zA-Z0-9_-]*\b|\*[a-zA-Z_][a-zA-Z0-9_-]*\b/.test(p) && !p.includes('SELECT *') && !p.includes('* FROM')) {
    return 'YAML anchors/aliases (&/*) are not allowed.'
  }
  return null
}

function serializeOpengrepRule(spec: DynamicRuleSpec): string {
  const ogSev = spec.severity === 'critical' || spec.severity === 'high' ? 'ERROR' : spec.severity === 'medium' ? 'WARNING' : 'INFO'
  const lines: string[] = [
    'rules:',
    `  - id: ${JSON.stringify(spec.id)}`,
    `    languages: [${spec.languages.map(l => JSON.stringify(l)).join(', ')}]`,
    `    severity: ${ogSev}`,
    `    message: ${JSON.stringify(spec.message)}`,
    '    metadata:',
    `      sinkKind: ${JSON.stringify(spec.sinkKind)}`,
  ]
  if (spec.cwe) lines.push(`      cwe: ${JSON.stringify(spec.cwe)}`)

  if (spec.mode === 'taint' && spec.taintSources?.length && spec.taintSinks?.length) {
    lines.push('    mode: taint')
    lines.push('    pattern-sources:')
    for (const s of spec.taintSources) lines.push(`      - pattern: ${JSON.stringify(s)}`)
    if (spec.taintSanitizers?.length) {
      lines.push('    pattern-sanitizers:')
      for (const sn of spec.taintSanitizers) lines.push(`      - pattern: ${JSON.stringify(sn)}`)
    }
    lines.push('    pattern-sinks:')
    for (const sk of spec.taintSinks) lines.push(`      - pattern: ${JSON.stringify(sk)}`)
  } else {
    const patterns = spec.patterns ?? []
    if (spec.excludePatterns?.length || (spec.metavariableRegex && Object.keys(spec.metavariableRegex).length > 0)) {
      lines.push('    patterns:')
      if (patterns.length === 1) {
        lines.push(`      - pattern: ${JSON.stringify(patterns[0])}`)
      } else {
        lines.push('      - pattern-either:')
        for (const p of patterns) lines.push(`          - pattern: ${JSON.stringify(p)}`)
      }
      for (const ex of spec.excludePatterns ?? []) {
        lines.push(`      - pattern-not: ${JSON.stringify(ex)}`)
      }
      for (const [mvar, re] of Object.entries(spec.metavariableRegex ?? {})) {
        lines.push('      - metavariable-regex:')
        lines.push(`          metavariable: ${JSON.stringify(mvar)}`)
        lines.push(`          regex: ${JSON.stringify(re)}`)
      }
    } else if (patterns.length === 1) {
      lines.push(`    pattern: ${JSON.stringify(patterns[0])}`)
    } else {
      lines.push('    pattern-either:')
      for (const p of patterns) lines.push(`      - pattern: ${JSON.stringify(p)}`)
    }
  }
  return lines.join('\n') + '\n'
}

function serializeAstGrepRule(spec: DynamicRuleSpec): string {
  const sgLangMap: Record<string, string> = {
    typescript: 'typescript', ts: 'typescript', tsx: 'tsx',
    javascript: 'javascript', js: 'javascript', jsx: 'jsx',
    python: 'python', py: 'python', go: 'go', java: 'java',
  }
  const lang = sgLangMap[spec.languages[0].toLowerCase()] ?? spec.languages[0].toLowerCase()
  const sgSev = spec.severity === 'critical' || spec.severity === 'high' ? 'error' : spec.severity === 'medium' ? 'warning' : 'info'
  const patterns = spec.patterns ?? []
  const lines: string[] = [
    `id: ${JSON.stringify(spec.id)}`,
    `language: ${JSON.stringify(lang)}`,
    `severity: ${sgSev}`,
    `message: ${JSON.stringify(spec.message)}`,
    'rule:',
  ]
  if (patterns.length === 1) {
    lines.push(`  pattern: ${JSON.stringify(patterns[0])}`)
  } else {
    lines.push('  any:')
    for (const p of patterns) lines.push(`    - pattern: ${JSON.stringify(p)}`)
  }
  if (spec.excludePatterns?.length) {
    lines.push('  not:')
    lines.push('    any:')
    for (const ex of spec.excludePatterns) lines.push(`      - pattern: ${JSON.stringify(ex)}`)
  }
  return lines.join('\n') + '\n'
}

export function validateAndSerializeDynamicRule(
  raw: unknown,
): { ok: true; value: ValidatedDynamicRule } | { ok: false; reason: string } {
  const parsed = dynamicRuleSpecSchema.safeParse(raw)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    return { ok: false, reason: `${issue?.path.join('.') || 'rule'}: ${issue?.message ?? 'invalid schema'}` }
  }
  const spec = parsed.data

  if (FORBIDDEN_RULE_TEXT_RE.test(spec.id) || FORBIDDEN_RULE_TEXT_RE.test(spec.message)) {
    return { ok: false, reason: 'Rule metadata contains forbidden directives or URLs.' }
  }

  if (spec.mode === 'taint') {
    if (spec.engine !== 'opengrep') return { ok: false, reason: 'Taint mode is only supported for opengrep.' }
    if (!spec.taintSources?.length || !spec.taintSinks?.length) {
      return { ok: false, reason: 'Taint rules require non-empty taintSources and taintSinks.' }
    }
    for (const p of [...spec.taintSources, ...spec.taintSinks, ...(spec.taintSanitizers ?? [])]) {
      const err = checkPatternSafety(p)
      if (err) return { ok: false, reason: err }
    }
  } else {
    if (!spec.patterns?.length) {
      return { ok: false, reason: 'Pattern rules require at least one pattern.' }
    }
    for (const p of [...spec.patterns, ...(spec.excludePatterns ?? [])]) {
      const err = checkPatternSafety(p)
      if (err) return { ok: false, reason: err }
    }
  }

  for (const [mvar, re] of Object.entries(spec.metavariableRegex ?? {})) {
    const check = validateSafeRegex(re)
    if (!check.ok) return { ok: false, reason: `metavariableRegex.${mvar}: ${check.reason}` }
  }

  const yaml = spec.engine === 'opengrep' ? serializeOpengrepRule(spec) : serializeAstGrepRule(spec)
  if (Buffer.byteLength(yaml, 'utf8') > 16 * 1024) {
    return { ok: false, reason: 'Serialized rule YAML exceeds 16 KiB limit.' }
  }
  const sha256 = createHash('sha256').update(yaml).digest('hex')
  return { ok: true, value: { spec, yaml, sha256 } }
}

export function validateRawRuleYaml(yamlText: string, engine: 'opengrep' | 'ast-grep'): { ok: boolean; reason?: string } {
  if (!yamlText || Buffer.byteLength(yamlText, 'utf8') > 16 * 1024) {
    return { ok: false, reason: 'Rule YAML must be non-empty and <= 16 KiB.' }
  }
  if (yamlText.includes('\0')) return { ok: false, reason: 'Rule YAML contains null bytes.' }
  if (YAML_ANCHOR_ALIAS_RE.test(yamlText)) return { ok: false, reason: 'YAML anchors/aliases are not allowed.' }
  if (YAML_TAG_RE.test(yamlText)) return { ok: false, reason: 'YAML custom tags (!!) are not allowed.' }
  if (/(?:^|\n)\s*(?:fix|fix-regex)\s*:/i.test(yamlText)) return { ok: false, reason: 'fix/fix-regex directives are forbidden.' }
  for (const m of yamlText.matchAll(/(?:pattern-regex|regex)\s*:\s*["']?([^\n"']+)["']?/g)) {
    const chk = validateSafeRegex(m[1].trim())
    if (!chk.ok) return { ok: false, reason: chk.reason }
  }
  if (engine === 'opengrep') {
    if (!/(?:^|\n)rules\s*:/.test(yamlText) || !/(?:^|\n)\s*-\s*id\s*:/.test(yamlText)) {
      return { ok: false, reason: 'Opengrep YAML must declare rules: and - id:.' }
    }
  } else {
    if (!/(?:^|\n)id\s*:/.test(yamlText) || !/(?:^|\n)rule\s*:/.test(yamlText)) {
      return { ok: false, reason: 'ast-grep YAML must declare id: and rule:.' }
    }
  }
  return { ok: true }
}

export function sanitizeGitDiffBase(ref?: string): string | undefined {
  if (ref === undefined) return undefined
  const clean = ref.trim()
  if (!clean) return undefined
  if (clean.startsWith('-') || clean.includes('..') || clean.includes('@{') || /[~^:\s\\*?\[\x00-\x1f]/.test(clean) || !SAFE_GIT_REF_RE.test(clean)) {
    throw new Error(`Unsafe git diff base ref rejected: ${ref}`)
  }
  return clean
}

// ============================================================================
// Stage 1: IRIS-Style ProjectSecuritySpec + Dynamic Rule Generation
// ============================================================================

export interface RepoContextSummary {
  repo: string
  filesScanned: number
  languages: string[]
  frameworks: string[]
  ormLibraries: string[]
  authLibraries: string[]
  snippets: Array<{ file: string; excerpt: string }>
}

export function createReasoningLlmCall(
  profiles: readonly ResolvedModelProfile[],
  options: { signal?: AbortSignal; secrets?: readonly NamedSecret[]; onUsage?: UsageCallback } = {},
): SemanticAuditLlmCall | undefined {
  const routed = resolveProfilePoolForRole('reasoning', profiles)
  if (routed.length === 0) return undefined
  return async ({ systemPrompt, userPrompt }) => {
    const now = Date.now()
    const primary = routed.find(p => isProfileHealthy(p, now)) ?? routed[0]
    const effectiveThinking = primary?.thinkingLevel === 'off' ? 'off' : 'high'
    const { models, model } = providerPool(routed, 'semantic-audit', {
      signal: options.signal,
      secrets: options.secrets,
      onUsage: options.onUsage,
      maxCalls: 4,
      thinkingLevel: effectiveThinking,
      roleAffinity: 'reasoning',
      firstEventTimeoutMs: 45_000,
      idleTimeoutMs: 45_000,
      totalTimeoutMs: 90_000,
    })
    const stream = models.stream(model, {
      systemPrompt: redact(systemPrompt, options.secrets),
      messages: [{ role: 'user', content: redact(userPrompt, options.secrets), timestamp: Date.now() }],
      tools: [],
    })
    let out = ''
    for await (const ev of stream) {
      if (ev.type === 'text_delta' && typeof ev.delta === 'string') out += ev.delta
    }
    const res = await stream.result()
    if (!out && Array.isArray(res.content)) {
      out = res.content
        .filter((p): p is { type: 'text'; text: string } => p.type === 'text' && typeof p.text === 'string')
        .map(p => p.text)
        .join('')
    }
    return out.trim()
  }
}

export async function collectRepoContextForSpec(
  session: WorkerSession,
  repo: string,
  signal: AbortSignal,
): Promise<RepoContextSummary> {
  const cleanRepo = normalizeRepoIdentifier(repo)
  const code = `
import fs from 'node:fs';
import path from 'node:path';
const repoRoot = path.resolve('/repos', ${JSON.stringify(cleanRepo)});
const skip = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__', 'vendor', 'target']);
const exts = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.php', '.rb', '.json']);
const files = [];
function walk(d) {
  if (files.length >= 400) return;
  let ents = [];
  try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (files.length >= 400) break;
    if (skip.has(e.name)) continue;
    const full = path.join(d, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) walk(full);
    else if (exts.has(path.extname(e.name).toLowerCase())) files.push(full);
  }
}
walk(repoRoot);
// Security relevance: routes/controllers/middleware/auth/DB/GraphQL first, docs/config last.
const relevance = (f) => {
  const rel = path.relative(repoRoot, f).toLowerCase();
  let score = 0;
  if (/(route|router|controller|handler|endpoint|api)/.test(rel)) score += 8;
  if (/(middleware|auth|session|login|jwt|oauth|permission|rbac|acl)/.test(rel)) score += 7;
  if (/(db|database|orm|query|repository|model|schema|migration)/.test(rel)) score += 5;
  if (/(graphql|resolver|trpc)/.test(rel)) score += 6;
  if (/(server|app|main|index)\\./.test(rel)) score += 3;
  if (/(test|spec|mock|fixture)/.test(rel)) score -= 7;
  if (/(readme|license|changelog|docs?\\/)/.test(rel)) score -= 8;
  return score;
};
files.sort((a, b) => relevance(b) - relevance(a) || a.localeCompare(b));
const langs = new Set();
const snippets = [];
let total = 0;
for (const f of files) {
  const rel = path.relative(repoRoot, f);
  const ext = path.extname(f).toLowerCase();
  if (['.ts','.tsx'].includes(ext)) langs.add('typescript');
  else if (['.js','.jsx','.mjs','.cjs'].includes(ext)) langs.add('javascript');
  else if (ext === '.py') langs.add('python');
  else if (ext === '.go') langs.add('go');
  else if (ext === '.java') langs.add('java');
  else if (ext === '.php') langs.add('php');
  else if (ext === '.rb') langs.add('ruby');
  if (snippets.length < 40 && total < 44000) {
    try {
      const st = fs.lstatSync(f);
      if (st.size <= 128 * 1024) {
        const txt = fs.readFileSync(f, 'utf8').slice(0, 1800);
        snippets.push({ file: rel, excerpt: txt });
        total += txt.length;
      }
    } catch {}
  }
}
process.stdout.write(JSON.stringify({ filesScanned: files.length, languages: [...langs], snippets }));
`
  try {
    const res = await session.runScript({ runtime: 'node', code, timeoutMs: 20_000 }, signal)
    const parsed = JSON.parse(res.stdout || '{}') as {
      filesScanned?: number
      languages?: string[]
      snippets?: Array<{ file: string; excerpt: string }>
    }
    const snippets = Array.isArray(parsed.snippets) ? parsed.snippets : []
    const combined = snippets.map(s => `${s.file}\n${s.excerpt}`).join('\n')
    const frameworks: string[] = []
    const ormLibraries: string[] = []
    const authLibraries: string[] = []
    if (/next\/server|NextResponse|__NEXT_DATA__|next\.config/i.test(combined)) frameworks.push('nextjs')
    if (/\bexpress\b|app\.(?:get|post|put|delete)\(/i.test(combined)) frameworks.push('express')
    if (/\bfastify\b/i.test(combined)) frameworks.push('fastify')
    if (/@Controller|@Injectable|NestFactory/i.test(combined)) frameworks.push('nestjs')
    if (/\bFastAPI\b|APIRouter/i.test(combined)) frameworks.push('fastapi')
    if (/\bFlask\b|render_template_string/i.test(combined)) frameworks.push('flask')
    if (/\bdjango\b/i.test(combined)) frameworks.push('django')
    if (/prisma|\$queryRawUnsafe/i.test(combined)) ormLibraries.push('prisma')
    if (/drizzle-orm/i.test(combined)) ormLibraries.push('drizzle')
    if (/\bsequelize\b/i.test(combined)) ormLibraries.push('sequelize')
    if (/\btypeorm\b/i.test(combined)) ormLibraries.push('typeorm')
    if (/sqlalchemy/i.test(combined)) ormLibraries.push('sqlalchemy')
    if (/next-auth|NextAuth/i.test(combined)) authLibraries.push('nextauth')
    if (/@clerk/i.test(combined)) authLibraries.push('clerk')
    if (/jsonwebtoken|PyJWT|jwt\.verify/i.test(combined)) authLibraries.push('jwt')
    if (/passport/i.test(combined)) authLibraries.push('passport')

    return {
      repo: cleanRepo,
      filesScanned: Number(parsed.filesScanned ?? snippets.length),
      languages: Array.isArray(parsed.languages) && parsed.languages.length ? parsed.languages : ['typescript'],
      frameworks,
      ormLibraries,
      authLibraries,
      snippets,
    }
  } catch {
    return {
      repo: cleanRepo,
      filesScanned: 0,
      languages: ['typescript'],
      frameworks: [],
      ormLibraries: [],
      authLibraries: [],
      snippets: [],
    }
  }
}

export function inferProjectSecuritySpecDeterministic(
  repo: string,
  context: RepoContextSummary,
): { spec: ProjectSecuritySpec; candidateRules: DynamicRuleSpec[] } {
  const combined = context.snippets.map(s => s.excerpt).join('\n')
  const sources: ProjectSecuritySpec['sources'] = [
    { name: 'HTTP Request Params/Body', kind: 'http_param', patterns: ['req.query', 'req.body', 'req.params', 'request.args', 'request.json'] },
  ]
  const authTenantGuards: ProjectSecuritySpec['authTenantGuards'] = []
  const sanitizers: ProjectSecuritySpec['sanitizers'] = [
    { name: 'Numeric Coercion', protectsAgainst: ['sqli', 'idor'], patterns: ['parseInt', 'Number', 'int'] },
  ]
  const sinks: ProjectSecuritySpec['sinks'] = [
    { name: 'Raw SQL Query', sinkKind: 'db_query', cwe: 'CWE-89', patterns: ['db.query', 'db.execute', '$queryRawUnsafe', '$executeRawUnsafe'], severity: 'critical' },
    { name: 'Outbound HTTP Fetch', sinkKind: 'outbound_fetch', cwe: 'CWE-918', patterns: ['fetch(', 'axios.get', 'requests.get'], severity: 'high' },
  ]
  const businessInvariants: ProjectSecuritySpec['businessInvariants'] = []
  const candidateRules: DynamicRuleSpec[] = []

  // Detect custom auth / tenant guard helper functions exported in repo
  const guardMatches = new Set<string>()
  for (const m of combined.matchAll(/\b(?:export\s+(?:async\s+)?function|function|const)\s+((?:require|check|assert|verify|ensure)[A-Z][A-Za-z0-9_]{2,48})/g)) {
    guardMatches.add(m[1])
  }
  for (const g of guardMatches) {
    const isTenant = /org|tenant|owner|member/i.test(g)
    authTenantGuards.push({
      name: g,
      kind: isTenant ? 'tenant_scope' : 'auth_middleware',
      patterns: [g],
      enforces: isTenant ? `Tenant/org isolation via ${g}` : `Authentication check via ${g}`,
    })
  }
  if (authTenantGuards.length === 0) {
    authTenantGuards.push({
      name: 'Session/Auth Guard',
      kind: 'session_check',
      patterns: ['requireAuth', 'requireSession', 'getServerSession'],
      enforces: 'Authenticated user session',
    })
  }

  // Detect custom DB / ORM wrapper functions (e.g., customDb.unsafeExec, prisma.$queryRawUnsafe, runUnsafe)
  const customSinkCalls = new Set<string>()
  for (const m of combined.matchAll(/\b([a-zA-Z_$][A-Za-z0-9_$]*\.(?:unsafeExec|rawExec|queryRaw|execSql|\$queryRawUnsafe|\$executeRawUnsafe))\s*\(/g)) {
    customSinkCalls.add(m[1])
  }
  const ogLangs = context.languages.filter(l => ['javascript', 'typescript', 'python', 'go', 'java', 'php', 'ruby'].includes(l))
  const effectiveLangs = ogLangs.length ? ogLangs : ['typescript', 'javascript']

  for (const call of customSinkCalls) {
    const parts = call.split('.')
    const method = parts[parts.length - 1]
    sinks.push({
      name: `Custom DB Sink (${call})`,
      sinkKind: 'db_query',
      cwe: 'CWE-89',
      patterns: [call],
      severity: 'critical',
    })
    const ruleId = `guardian.dynamic.custom-sink-${method.replace(/[^a-z0-9]/gi, '').toLowerCase()}`
    candidateRules.push({
      id: ruleId,
      engine: 'opengrep',
      languages: effectiveLangs.filter(l => l === 'typescript' || l === 'javascript').length ? ['typescript', 'javascript'] : effectiveLangs.slice(0, 2),
      severity: 'critical',
      cwe: 'CWE-89',
      sinkKind: 'db_query',
      message: `Dynamic rule: potential SQL injection via ${call}(...)`,
      mode: 'pattern',
      patterns: [`$OBJ.${method}($QUERY, ...)`, `$OBJ.${method}($QUERY)`],
    })
  }

  if (authTenantGuards.length > 0) {
    businessInvariants.push({
      id: 'inv-tenant-guard',
      description: `All privileged API routes and DB mutations must be dominated by ${authTenantGuards[0].name}.`,
      appliesTo: 'api_route,db_query,server_action',
      requiredGuard: authTenantGuards[0].name,
      cwe: 'CWE-862',
      severity: 'high',
    })
  }

  const spec = projectSecuritySpecSchema.parse({
    repo,
    languages: context.languages,
    frameworks: context.frameworks,
    ormLibraries: context.ormLibraries,
    authLibraries: context.authLibraries,
    sources,
    authTenantGuards,
    sanitizers,
    sinks,
    businessInvariants,
    generatedAt: Date.now(),
    usedLlm: false,
  })

  return { spec, candidateRules }
}

function stripJsonFences(raw: string): string {
  const trimmed = raw.trim()
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fence) return fence[1].trim()
  const start = trimmed.indexOf('{')
  const end = trimmed.lastIndexOf('}')
  if (start >= 0 && end > start) return trimmed.slice(start, end + 1)
  return trimmed
}

export async function extractProjectSecuritySpecAndRules(
  ctx: SemanticAuditContext,
  repo: string,
  session: WorkerSession,
  options: { enableLlm?: boolean } = {},
): Promise<{
  spec: ProjectSecuritySpec
  rules: ValidatedDynamicRule[]
  rejectedRules: Array<{ ruleId: string; reason: string }>
}> {
  const context = await collectRepoContextForSpec(session, repo, ctx.signal)
  const deterministic = inferProjectSecuritySpecDeterministic(context.repo, context)
  let spec = deterministic.spec
  const rawRuleCandidates: unknown[] = [...deterministic.candidateRules]

  const llmCall = options.enableLlm !== false
    ? (ctx.llmCall ?? (ctx.modelProfiles?.length
      ? createReasoningLlmCall(ctx.modelProfiles, { signal: ctx.signal, secrets: ctx.secrets, onUsage: ctx.onUsage })
      : undefined))
    : undefined

  if (llmCall && context.snippets.length > 0) {
    try {
      const snippetText = context.snippets
        .slice(0, 16)
        .map(s => `### ${s.file}\n${s.excerpt.slice(0, 900)}`)
        .join('\n\n')
      const systemPrompt = [
        'You are a white-box security architect extracting a ProjectSecuritySpec and targeted Opengrep/ast-grep dynamic rules.',
        'Output ONLY valid JSON matching { "spec": { ... }, "dynamicRules": [ ... ] }.',
        'Never emit fix: directives, YAML anchors (&/*), URLs, or wildcard-only patterns like $X.',
      ].join(' ')
      const userPrompt = [
        `Repository: ${context.repo}`,
        `Languages: ${context.languages.join(', ')}`,
        `Detected frameworks: ${context.frameworks.join(', ') || 'unknown'}`,
        'Excerpts:',
        snippetText,
      ].join('\n')

      const rawResp = await llmCall({ systemPrompt, userPrompt })
      const parsedJson = JSON.parse(stripJsonFences(rawResp)) as { spec?: Record<string, unknown>; dynamicRules?: unknown[] }
      if (parsedJson.spec && typeof parsedJson.spec === 'object') {
        const merged = projectSecuritySpecSchema.safeParse({
          ...deterministic.spec,
          ...parsedJson.spec,
          repo: context.repo,
          generatedAt: Date.now(),
          usedLlm: true,
        })
        if (merged.success) spec = merged.data
      }
      if (Array.isArray(parsedJson.dynamicRules)) {
        rawRuleCandidates.push(...parsedJson.dynamicRules)
      }
    } catch {
      // Deterministic baseline remains active on LLM failure/malformed JSON
    }
  }

  const rules: ValidatedDynamicRule[] = []
  const rejectedRules: Array<{ ruleId: string; reason: string }> = []
  const seenRuleIds = new Set<string>()
  for (const cand of rawRuleCandidates) {
    if (rules.length >= MAX_DYNAMIC_RULES_PER_STAGE) break
    const res = validateAndSerializeDynamicRule(cand)
    if (!res.ok) {
      const id = (cand && typeof cand === 'object' && typeof (cand as { id?: unknown }).id === 'string')
        ? (cand as { id: string }).id
        : 'invalid-rule'
      rejectedRules.push({ ruleId: id, reason: res.reason })
      continue
    }
    if (seenRuleIds.has(res.value.spec.id)) continue
    seenRuleIds.add(res.value.spec.id)
    rules.push(res.value)
  }

  return { spec, rules, rejectedRules }
}

export async function runValidatedDynamicRulesInWorker(
  session: WorkerSession,
  repo: string,
  rules: readonly ValidatedDynamicRule[],
  signal: AbortSignal,
  secrets: readonly NamedSecret[] = [],
): Promise<SastFinding[]> {
  if (rules.length === 0) return []
  const cleanRepo = normalizeRepoIdentifier(repo)
  const ogRules = rules.filter(r => r.spec.engine === 'opengrep')
  const sgRules = rules.filter(r => r.spec.engine === 'ast-grep')

  const buildScript = (
    engine: 'opengrep' | 'ast-grep',
    engineRules: ReadonlyArray<ValidatedDynamicRule>,
  ): string => {
    const items = engineRules.map(r => ({
      id: r.spec.id,
      cwe: r.spec.cwe,
      yaml: r.yaml,
    }))
    if (engine === 'opengrep') {
      return `
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
const repoRoot = path.resolve('/repos', ${JSON.stringify(cleanRepo)});
const rules = ${JSON.stringify(items)};
const findings = [];
const tmpFiles = [];
try {
  fs.mkdirSync('/tmp/.config', { recursive: true });
  fs.mkdirSync('/tmp/.cache', { recursive: true });
  for (const rule of rules) {
    const p = '/tmp/guardian-dyn-og-' + randomUUID() + '.yaml';
    tmpFiles.push(p);
    fs.writeFileSync(p, rule.yaml, { mode: 0o600 });
    try {
      const out = execFileSync('opengrep', ['scan', '--config', p, '--json', '--no-git-ignore', '--quiet', repoRoot], {
        encoding: 'utf8', timeout: 45000, maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env, HOME: '/tmp', XDG_CONFIG_HOME: '/tmp/.config', XDG_CACHE_HOME: '/tmp/.cache', OPENGREP_SEND_METRICS: 'off' }
      });
      const parsed = JSON.parse(out || '{}');
      for (const r of parsed.results || []) {
        const sevRaw = String(r.extra?.severity || '').toLowerCase();
        const severity = sevRaw === 'error' ? 'high' : sevRaw === 'warning' ? 'medium' : 'info';
        findings.push({
          engine: 'opengrep', ruleId: String(r.check_id || rule.id), severity,
          file: path.relative(repoRoot, r.path || ''), line: Number(r.start?.line || 1),
          endLine: r.end?.line ? Number(r.end.line) : undefined,
          message: String(r.extra?.message || 'Dynamic rule match').slice(0, 400),
          maskedPreview: String(r.extra?.lines || '').trim().slice(0, 240),
          cwe: rule.cwe || undefined,
        });
      }
    } catch {}
  }
} finally {
  for (const f of tmpFiles) { try { fs.unlinkSync(f); } catch {} }
}
process.stdout.write(JSON.stringify(findings));
`
    }
    return `
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
const repoRoot = path.resolve('/repos', ${JSON.stringify(cleanRepo)});
const rules = ${JSON.stringify(items)};
const findings = [];
const tmpFiles = [];
try {
  for (const rule of rules) {
    const p = '/tmp/guardian-dyn-sg-' + randomUUID() + '.yaml';
    tmpFiles.push(p);
    fs.writeFileSync(p, rule.yaml, { mode: 0o600 });
    try {
      const out = execFileSync('ast-grep', ['scan', '--rule', p, '--json=compact', repoRoot], {
        encoding: 'utf8', timeout: 45000, maxBuffer: 4 * 1024 * 1024
      });
      const arr = JSON.parse(out || '[]');
      for (const m of Array.isArray(arr) ? arr : []) {
        findings.push({
          engine: 'ast-grep', ruleId: String(m.ruleId || rule.id), severity: 'high',
          file: path.relative(repoRoot, m.file || ''), line: Number(m.range?.start?.line || 0) + 1,
          endLine: m.range?.end?.line !== undefined ? Number(m.range.end.line) + 1 : undefined,
          message: String(m.message || 'Dynamic ast-grep match').slice(0, 400),
          maskedPreview: String(m.text || '').trim().replace(/\\s+/g, ' ').slice(0, 240),
          cwe: rule.cwe || undefined,
        });
      }
    } catch {}
  }
} finally {
  for (const f of tmpFiles) { try { fs.unlinkSync(f); } catch {} }
}
process.stdout.write(JSON.stringify(findings));
`
  }

  const runOne = async (engine: 'opengrep' | 'ast-grep', engineRules: ReadonlyArray<ValidatedDynamicRule>): Promise<SastFinding[]> => {
    if (engineRules.length === 0) return []
    try {
      // Reuse the warm session; each engine runs independently (never short-circuited by grep).
      const res = await session.runScript({ runtime: 'node', code: buildScript(engine, engineRules), timeoutMs: 60_000 }, signal)
      const raw = JSON.parse(res.stdout || '[]') as SastFinding[]
      return (Array.isArray(raw) ? raw : []).map(f => ({
        ...f,
        message: redact(f.message, secrets),
        maskedPreview: redact(f.maskedPreview, secrets),
      }))
    } catch {
      return []
    }
  }

  // opengrep and ast-grep rules run on the same warm worker session; the session
  // protocol is single-flight, so execute engines sequentially but never gate one on
  // literal grep results. Both always run for the requested rule set.
  const ogFindings = await runOne('opengrep', ogRules)
  const sgFindings = await runOne('ast-grep', sgRules)
  return [...ogFindings, ...sgFindings]
}

// ============================================================================
// Stage 2: Atlantis/RepoAudit-Style Backward Traversal & Path Dominance
// ============================================================================

export async function buildRepoCallGraph(
  session: WorkerSession,
  repo: string,
  spec: ProjectSecuritySpec,
  signal: AbortSignal,
): Promise<CallGraphIndex> {
  const cleanRepo = normalizeRepoIdentifier(repo)
  const customGuardPatterns = spec.authTenantGuards.flatMap(g => g.patterns).slice(0, 40)
  const customSanitizerPatterns = spec.sanitizers.flatMap(s => s.patterns).slice(0, 40)
  const customSinkPatterns = spec.sinks.flatMap(sk =>
    sk.patterns.map(p => ({ pattern: p, sinkKind: sk.sinkKind })),
  ).slice(0, 40)

  // Prefer dedicated worker op: 'call_graph' or analyze('call-graph')
  if (typeof session.callGraph === 'function') {
    try {
      const res: CallGraphResult = await session.callGraph({
        repo: cleanRepo,
        maxDepth: 6,
        customGuardPatterns,
        customSanitizerPatterns,
        customSinkPatterns,
      }, signal)
      return {
        repo: cleanRepo,
        filesScanned: res.filesScanned,
        nodes: res.nodes as CallGraphNode[],
        edges: res.edges,
        analyzerSource: 'worker_analyzer',
      }
    } catch {
      // fall through to analyze / runScript fallback
    }
  }

  try {
    const analyzed = await session.analyze('call-graph', {
      repo: cleanRepo,
      maxDepth: 6,
      customGuardPatterns,
      customSanitizerPatterns,
      customSinkPatterns,
    }, signal)
    if (Array.isArray(analyzed.nodes) && Array.isArray(analyzed.edges)) {
      return {
        repo: cleanRepo,
        filesScanned: Number(analyzed.filesScanned ?? 0),
        nodes: analyzed.nodes as CallGraphNode[],
        edges: analyzed.edges as CallGraphEdge[],
        analyzerSource: 'worker_analyzer',
      }
    }
  } catch {
    // fall back to embedded script indexer inside --network none container
  }

  const fallbackCode = `
import fs from 'node:fs';
import path from 'node:path';
const repoRoot = path.resolve('/repos', ${JSON.stringify(cleanRepo)});
const skip = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv']);
const exts = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.php', '.rb']);
const files = [];
function walk(d) {
  if (files.length >= 400) return;
  let ents = [];
  try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (skip.has(e.name)) continue;
    const full = path.join(d, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) walk(full);
    else if (exts.has(path.extname(e.name).toLowerCase())) files.push(full);
  }
}
walk(repoRoot);
const guardPats = ${JSON.stringify(customGuardPatterns)};
const sanPats = ${JSON.stringify(customSanitizerPatterns)};
const sinkPats = ${JSON.stringify(customSinkPatterns)};
const nodes = [];
const edges = [];
const bySym = new Map();
for (const f of files) {
  let txt = '';
  try { txt = fs.readFileSync(f, 'utf8'); } catch { continue; }
  const rel = path.relative(repoRoot, f);
  const lines = txt.split('\\n');
  for (let i = 0; i < lines.length; i += 1) {
    const l = lines[i];
    const fnM = l.match(/(?:export\\s+)?(?:async\\s+)?function\\s+([A-Za-z0-9_]+)\\s*\\(|def\\s+([A-Za-z0-9_]+)\\s*\\(/);
    const rtM = l.match(/\\.(get|post|put|patch|delete)\\s*\\(\\s*["']([^"']+)["']/);
    const sym = fnM ? (fnM[1] || fnM[2]) : rtM ? (rtM[1].toUpperCase() + ' ' + rtM[2]) : null;
    if (!sym) continue;
    const block = lines.slice(i, Math.min(lines.length, i + 25)).join('\\n');
    const guards = guardPats.filter(p => block.includes(p));
    const sanitizers = sanPats.filter(p => block.includes(p));
    const sinkHit = sinkPats.find(sp => block.includes(sp.pattern));
    const calls = [...block.matchAll(/\\b([A-Za-z_][A-Za-z0-9_]*)\\s*\\(/g)].map(m => m[1]).filter(c => c !== sym);
    const node = {
      id: rel + ':' + (i + 1) + ':' + sym,
      file: rel, line: i + 1, symbol: sym,
      kind: rtM ? 'entrypoint' : sinkHit ? 'sink' : 'function',
      ...(rtM ? { httpMethod: rtM[1].toUpperCase(), routePath: rtM[2] } : {}),
      ...(sinkHit ? { sinkKind: sinkHit.sinkKind } : {}),
      guards, sanitizers, calls: [...new Set(calls)].slice(0, 30)
    };
    nodes.push(node);
    if (!bySym.has(sym)) bySym.set(sym, []);
    bySym.get(sym).push(node);
  }
}
for (const caller of nodes) {
  for (const c of caller.calls) {
    for (const callee of (bySym.get(c) || []).slice(0, 3)) {
      if (callee.id !== caller.id) edges.push({ fromId: caller.id, toId: callee.id, file: caller.file, line: caller.line });
    }
  }
}
process.stdout.write(JSON.stringify({ filesScanned: files.length, nodes, edges }));
`
  try {
    const res = await session.runScript({ runtime: 'node', code: fallbackCode, timeoutMs: 25_000 }, signal)
    const parsed = JSON.parse(res.stdout || '{}') as { filesScanned?: number; nodes?: CallGraphNode[]; edges?: CallGraphEdge[] }
    return {
      repo: cleanRepo,
      filesScanned: Number(parsed.filesScanned ?? 0),
      nodes: Array.isArray(parsed.nodes) ? parsed.nodes : [],
      edges: Array.isArray(parsed.edges) ? parsed.edges : [],
      analyzerSource: 'offline_script_fallback',
    }
  } catch {
    return {
      repo: cleanRepo,
      filesScanned: 0,
      nodes: [],
      edges: [],
      analyzerSource: 'offline_script_fallback',
    }
  }
}

export function analyzeSinkBackwardPaths(
  graph: CallGraphIndex,
  spec: ProjectSecuritySpec,
): SinkBackwardPath[] {
  const nodeById = new Map<string, CallGraphNode>(graph.nodes.map(n => [n.id, n]))
  const callersOf = new Map<string, CallGraphNode[]>()
  for (const edge of graph.edges) {
    const caller = nodeById.get(edge.fromId)
    if (!caller) continue
    const list = callersOf.get(edge.toId) ?? []
    list.push(caller)
    callersOf.set(edge.toId, list)
  }

  const sinkNodes = graph.nodes.filter(n => {
    if (n.kind === 'sink' || n.sinkKind !== undefined) return true
    return spec.sinks.some(s => s.patterns.some(p => n.calls.includes(p) || n.symbol.includes(p)))
  })

  const rawPaths: Array<{ ep: CallGraphNode; sink: CallGraphNode; chain: CallGraphNode[] }> = []
  for (const sink of sinkNodes) {
    const maxDepth = 12
    const dfs = (cur: CallGraphNode, visited: Set<string>, chainRev: CallGraphNode[]) => {
      if (rawPaths.length >= 400) return
      const callers = callersOf.get(cur.id) ?? []
      if (cur.kind === 'entrypoint' || (callers.length === 0 && chainRev.length > 1)) {
        rawPaths.push({ ep: cur, sink, chain: [...chainRev].reverse() })
        if (cur.kind === 'entrypoint') return
      }
      if (chainRev.length >= maxDepth) return
      for (const caller of callers) {
        if (visited.has(caller.id)) continue
        visited.add(caller.id)
        chainRev.push(caller)
        dfs(caller, visited, chainRev)
        chainRev.pop()
        visited.delete(caller.id)
      }
    }
    const vis = new Set<string>([sink.id])
    dfs(sink, vis, [sink])
  }

  const grouped = new Map<string, Array<{ ep: CallGraphNode; sink: CallGraphNode; chain: CallGraphNode[] }>>()
  for (const p of rawPaths) {
    const key = `${p.ep.id}::${p.sink.id}`
    const arr = grouped.get(key) ?? []
    arr.push(p)
    grouped.set(key, arr)
  }

  const results: SinkBackwardPath[] = []
  for (const group of grouped.values()) {
    const { ep, sink, chain } = group[0]
    const guardSets = group.map(g => new Set(g.chain.flatMap(n => n.guards)))
    const sanSets = group.map(g => new Set(g.chain.flatMap(n => n.sanitizers)))
    const allGuards = [...new Set(guardSets.flatMap(s => [...s]))]
    const dominatingGuards = allGuards.filter(g => guardSets.every(s => s.has(g)))
    const partialGuards = allGuards.filter(g => !dominatingGuards.includes(g))
    const allSanitizers = [...new Set(sanSets.flatMap(s => [...s]))]
    const dominatingSanitizers = allSanitizers.filter(sn => sanSets.every(s => s.has(sn)))

    const sinkKind: AuditSinkKind = sink.sinkKind ?? 'other'
    const authSensitive = ['api_route', 'server_action', 'webhook', 'auth_config', 'db_query'].includes(sinkKind)
    const injectionSink = ['db_query', 'outbound_fetch', 'redirect', 'postmessage_iframe', 'upload_storage', 'other'].includes(sinkKind)
    const isAuthUnguarded = authSensitive && dominatingGuards.length === 0
    const isInjectionUnsanitized = injectionSink && dominatingSanitizers.length === 0
    const isUnguardedPath = isAuthUnguarded || isInjectionUnsanitized

    results.push({
      entrypointId: ep.id,
      entrypointSymbol: ep.symbol,
      entrypointFile: ep.file,
      entrypointLine: ep.line,
      routeOrAction: ep.routePath ?? ep.symbol,
      ...(ep.httpMethod ? { httpMethod: ep.httpMethod } : {}),
      sinkId: sink.id,
      sinkSymbol: sink.symbol,
      sinkFile: sink.file,
      sinkLine: sink.line,
      sinkKind,
      callChain: chain.map(n => n.symbol),
      dominatingGuards,
      partialGuards,
      dominatingSanitizers,
      isAuthUnguarded,
      isInjectionUnsanitized,
      isUnguardedPath,
    })
  }

  return results
}

export interface ResolvedEntrypoint {
  routePath: string
  httpMethod?: string
  symbol: string
  file: string
  line: number
  paramNames: string[]
  matchedBy: 'range' | 'nearest' | 'none'
  reconciledEndpoint?: string
}

const ROUTE_PARAM_RE = /(?::([A-Za-z_][A-Za-z0-9_]*)|[{<]([A-Za-z_][A-Za-z0-9_]*)[}>])/g

/** Extract parameter names from any common route-template syntax. */
export function routeTemplateParamNames(routePath: string): string[] {
  const names: string[] = []
  for (const match of routePath.matchAll(ROUTE_PARAM_RE)) {
    const name = match[1] ?? match[2]
    if (name && !names.includes(name)) names.push(name)
  }
  return names
}

/** Normalize Next.js app-router paths and route-template syntax for reconciliation. */
export function normalizeReconRoute(routePath: string): string {
  let path = routePath.trim()
  path = path.replace(/^[a-z]+:\/\/[^/]+/i, '')
  path = path.replace(/^(?:\.?\/)?(?:src\/)?app\//, '/')
  path = path.split('/').filter(seg => !/^\(.*\)$/.test(seg)).join('/')
  path = path.replace(/\[\[?(?:\.\.\.)?([^\]]+)\]\]?/g, ':$1')
  path = path.replace(/[{<]([A-Za-z_][A-Za-z0-9_]*)[}>]/g, ':$1')
  path = path.replace(/\/+/g, '/')
  if (!path.startsWith('/')) path = `/${path}`
  return path.length > 1 ? path.replace(/\/$/, '') : '/'
}

function routeSegmentsMatch(left: string, right: string): boolean {
  const a = left.split('/')
  const b = right.split('/')
  if (a.length !== b.length) return false
  return a.every((seg, i) => {
    const other = b[i]
    if (seg === other) return true
    return seg.startsWith(':') && other.startsWith(':')
  })
}

/** Reconcile a code-derived route template with live Phase-0 endpoints. */
export function reconcileSuspectWithEndpoints(
  httpMethod: string | undefined,
  routePath: string,
  endpoints: ReadonlyArray<{ method: string; path: string }> | undefined,
): string | undefined {
  if (!endpoints?.length) return undefined
  const target = normalizeReconRoute(routePath)
  const method = httpMethod?.toUpperCase()
  for (const endpoint of endpoints) {
    if (method && endpoint.method.toUpperCase() !== method && endpoint.method.toUpperCase() !== 'ANY') continue
    const candidate = normalizeReconRoute(endpoint.path)
    if (candidate === target || routeSegmentsMatch(candidate, target)) return `${endpoint.method.toUpperCase()} ${endpoint.path}`
  }
  return undefined
}

/**
 * Map a `file:line` SAST suspect backwards to its enclosing HTTP entrypoint.
 * Resolution order: containing function span -> nearest preceding entrypoint in
 * the same file -> none (caller keeps the raw file target).
 */
export function resolveSuspectEntrypoint(
  graph: CallGraphIndex | undefined,
  target: { file: string; line: number },
  liveEndpoints?: ReadonlyArray<{ method: string; path: string }>,
): ResolvedEntrypoint | null {
  if (!graph) return null
  const entrypoints = graph.nodes.filter(n => n.kind === 'entrypoint' && n.routePath)
  const inFile = entrypoints.filter(n => n.file === target.file)
  const sorted = [...inFile].sort((a, b) => a.line - b.line)
  let best: { node: CallGraphNode; matchedBy: 'range' | 'nearest' } | null = null
  for (const node of sorted) {
    const end = node.endLine ?? node.line
    if (target.line >= node.line && target.line <= end) {
      best = { node, matchedBy: 'range' }
      break
    }
    if (node.line <= target.line) best = { node, matchedBy: 'nearest' }
  }
  if (!best) {
    // Sink may live in a helper file; follow one reverse call-graph hop to a route.
    const nodeById = new Map(graph.nodes.map(n => [n.id, n]))
    const callerIds = graph.edges.filter(e => inFile.some(n => n.id === e.toId) || e.toId.startsWith(`${target.file}:`)).map(e => e.fromId)
    const caller = callerIds.map(id => nodeById.get(id)).find(n => n?.kind === 'entrypoint' && n.routePath)
    if (!caller) return null
    best = { node: caller, matchedBy: 'nearest' }
  }
  const routePath = best.node.routePath ?? best.node.symbol
  const reconciled = reconcileSuspectWithEndpoints(best.node.httpMethod, routePath, liveEndpoints)
  return {
    routePath,
    ...(best.node.httpMethod ? { httpMethod: best.node.httpMethod } : {}),
    symbol: best.node.symbol,
    file: best.node.file,
    line: best.node.line,
    paramNames: routeTemplateParamNames(routePath),
    matchedBy: best.matchedBy,
    ...(reconciled ? { reconciledEndpoint: reconciled } : {}),
  }
}


function mapSinkToSpecialist(sinkKind: AuditSinkKind, cwe?: string): SpecialistProfile {
  if (sinkKind === 'postmessage_iframe') return 'client-browser-dom-specialist'
  if (sinkKind === 'webhook' || sinkKind === 'auth_config' || cwe === 'CWE-287' || cwe === 'CWE-347') {
    return 'auth-session-oauth-specialist'
  }
  if (sinkKind === 'api_route' || sinkKind === 'server_action' || cwe === 'CWE-862' || cwe === 'CWE-639') {
    return 'bola-bfla-specialist'
  }
  if (sinkKind === 'db_query' || sinkKind === 'outbound_fetch' || sinkKind === 'upload_storage' || sinkKind === 'redirect') {
    return 'injection-parser-specialist'
  }
  return 'injection-parser-specialist'
}

function inferSinkKindFromFinding(f: SastFinding): AuditSinkKind {
  const hay = `${f.ruleId} ${f.message} ${f.cwe ?? ''}`.toLowerCase()
  if (hay.includes('sql') || hay.includes('cwe-89') || hay.includes('query')) return 'db_query'
  if (hay.includes('ssrf') || hay.includes('cwe-918') || hay.includes('fetch')) return 'outbound_fetch'
  if (hay.includes('redirect') || hay.includes('cwe-601')) return 'redirect'
  if (hay.includes('xss') || hay.includes('innerhtml') || hay.includes('postmessage')) return 'postmessage_iframe'
  if (hay.includes('traversal') || hay.includes('upload') || hay.includes('cwe-22')) return 'upload_storage'
  if (hay.includes('jwt') || hay.includes('auth') || hay.includes('cors')) return 'auth_config'
  if (hay.includes('webhook')) return 'webhook'
  return 'api_route'
}

function computePriorityScore(params: {
  severity: 'critical' | 'high' | 'medium' | 'low'
  isUnguarded: boolean
  hasPartialGuards: boolean
  sinkKind: AuditSinkKind
  origin: string
  hostTiers?: Record<string, HostTier>
  corroborated?: boolean
}): number {
  const base = params.severity === 'critical' ? 35 : params.severity === 'high' ? 26 : params.severity === 'medium' ? 16 : 8
  let score = base
  if (params.isUnguarded) score += 28
  if (params.hasPartialGuards) score += 15
  if (['db_query', 'server_action', 'webhook', 'outbound_fetch', 'auth_config'].includes(params.sinkKind)) score += 12
  const tier = params.hostTiers?.[params.origin] ?? classifyHostTier(params.origin)
  if (tier === 'crown_jewel') score += 10
  else if (tier === 'low_value_static') score -= 20
  if (params.corroborated) score += 8
  return Math.max(0, Math.min(100, score))
}

function makeSuspectFingerprint(origin: string, repo: string, file: string, line: number, sinkKind: string, routeOrAction: string): string {
  return createHash('sha256')
    .update(`${origin}|${repo}|${file}|${line}|${sinkKind}|${routeOrAction}`)
    .digest('hex')
    .slice(0, 24)
}

function pickApprovedOrigin(approvedOrigins: readonly string[], hint: string): string | null {
  if (approvedOrigins.length === 0) return null
  const lower = hint.toLowerCase()
  const match = approvedOrigins.find(o => {
    try {
      const host = new URL(o).hostname.toLowerCase()
      return lower.includes(host)
    } catch {
      return false
    }
  })
  return match ?? approvedOrigins[0]
}

export function scoreAndBuildSuspects(params: {
  repo: string
  approvedOrigins: readonly string[]
  spec: ProjectSecuritySpec
  dynamicFindings: readonly SastFinding[]
  backwardPaths: readonly SinkBackwardPath[]
  hostTiers?: Record<string, HostTier>
  callGraph?: CallGraphIndex
  liveEndpoints?: ReadonlyArray<{ method: string; path: string }>
}): SemanticAuditSuspect[] {
  const suspects: SemanticAuditSuspect[] = []
  if (params.approvedOrigins.length === 0) return suspects

  const backwardByFile = new Set(params.backwardPaths.map(bp => `${bp.sinkFile}:${bp.sinkLine}`))

  for (const f of params.dynamicFindings) {
    const origin = pickApprovedOrigin(params.approvedOrigins, `${params.repo} ${f.file}`)
    if (!origin) continue
    const sinkKind = inferSinkKindFromFinding(f)
    const sev: SemanticAuditSuspect['severity'] = f.severity === 'info' ? 'low' : f.severity
    const corroborated = backwardByFile.has(`${f.file}:${f.line}`)
    const resolved = resolveSuspectEntrypoint(params.callGraph, { file: f.file, line: f.line }, params.liveEndpoints)
    const priorityScore = computePriorityScore({
      severity: sev,
      isUnguarded: true,
      hasPartialGuards: false,
      sinkKind,
      origin,
      hostTiers: params.hostTiers,
      corroborated,
    })
    const routeOrAction = resolved?.routePath ?? f.file
    const fingerprint = makeSuspectFingerprint(origin, params.repo, f.file, f.line, sinkKind, routeOrAction)
    const hypothesis = `${f.message}${f.maskedPreview ? ` (${f.maskedPreview})` : ''}${resolved && resolved.matchedBy !== 'none' ? ` [entrypoint ${resolved.httpMethod ?? 'ANY'} ${resolved.routePath}${resolved.paramNames.length ? ` params: ${resolved.paramNames.join(', ')}` : ''}]` : ''}`
    const data: CodeAuditSuspectData = {
      subkind: 'code_audit_suspect',
      repo: params.repo,
      file: f.file,
      line: Math.max(1, f.line),
      routeOrAction,
      authCheck: 'unknown',
      ownershipCheck: 'unknown',
      sinkKind,
      hypothesis,
      recommendedTier: sinkKind === 'db_query' || sinkKind === 'outbound_fetch' ? 1 : 2,
    }
    suspects.push({
      id: randomUUID(),
      fingerprint,
      stage: 'stage1_dynamic_rule',
      origin,
      repo: params.repo,
      file: f.file,
      line: Math.max(1, f.line),
      ...(f.endLine ? { endLine: f.endLine } : {}),
      routeOrAction,
      ...(resolved?.httpMethod ? { httpMethod: resolved.httpMethod } : {}),
      ...(resolved ? { paramNames: resolved.paramNames, entrypointSymbol: resolved.symbol } : {}),
      ...(resolved?.reconciledEndpoint ? { reconciledEndpoint: resolved.reconciledEndpoint } : {}),
      authCheck: data.authCheck,
      ownershipCheck: data.ownershipCheck,
      sinkKind,
      ...(f.cwe ? { cwe: f.cwe } : {}),
      severity: sev,
      priorityScore,
      recommendedTier: data.recommendedTier,
      specialistProfile: mapSinkToSpecialist(sinkKind, f.cwe),
      hypothesis,
      ruleId: f.ruleId,
      data,
    })
  }

  for (const bp of params.backwardPaths) {
    if (!bp.isUnguardedPath && bp.partialGuards.length === 0) continue
    const origin = pickApprovedOrigin(params.approvedOrigins, `${params.repo} ${bp.routeOrAction}`)
    if (!origin) continue
    const sev: SemanticAuditSuspect['severity'] = bp.isUnguardedPath
      ? (bp.sinkKind === 'db_query' || bp.sinkKind === 'other' ? 'critical' : 'high')
      : 'medium'
    const priorityScore = computePriorityScore({
      severity: sev,
      isUnguarded: bp.isUnguardedPath,
      hasPartialGuards: bp.partialGuards.length > 0,
      sinkKind: bp.sinkKind,
      origin,
      hostTiers: params.hostTiers,
    })
    const authCheck = bp.dominatingGuards.length
      ? `present (${bp.dominatingGuards.join(', ')})`
      : bp.partialGuards.length
        ? `partial (${bp.partialGuards.join(', ')})`
        : 'missing'
    const ownershipCheck = bp.dominatingGuards.some(g => /org|tenant|owner|member/i.test(g))
      ? 'present'
      : 'missing'
    const trace = bp.callChain.join(' -> ')
    const missingControls = [
      bp.isAuthUnguarded ? 'auth/tenant guard' : null,
      bp.isInjectionUnsanitized ? 'input sanitizer' : null,
    ].filter((value): value is string => value !== null)
    const hypothesis = `Backward taint path ${trace} reaches ${bp.sinkKind} sink without dominating ${missingControls.join(' or ') || 'control'}.`
    const fingerprint = makeSuspectFingerprint(origin, params.repo, bp.sinkFile, bp.sinkLine, bp.sinkKind, bp.routeOrAction)
    const reconciled = reconcileSuspectWithEndpoints(bp.httpMethod, bp.routeOrAction, params.liveEndpoints)
    const data: CodeAuditSuspectData = {
      subkind: 'code_audit_suspect',
      repo: params.repo,
      file: bp.sinkFile,
      line: Math.max(1, bp.sinkLine),
      routeOrAction: bp.routeOrAction,
      authCheck,
      ownershipCheck,
      sinkKind: bp.sinkKind,
      hypothesis,
      recommendedTier: ownershipCheck === 'missing' ? 2 : 1,
    }
    suspects.push({
      id: randomUUID(),
      fingerprint,
      stage: 'stage2_backward_taint',
      origin,
      repo: params.repo,
      file: bp.sinkFile,
      line: Math.max(1, bp.sinkLine),
      routeOrAction: bp.routeOrAction,
      ...(bp.httpMethod ? { httpMethod: bp.httpMethod } : {}),
      paramNames: routeTemplateParamNames(bp.routeOrAction),
      entrypointSymbol: bp.entrypointSymbol,
      ...(reconciled ? { reconciledEndpoint: reconciled } : {}),
      authCheck,
      ownershipCheck,
      sinkKind: bp.sinkKind,
      severity: sev,
      priorityScore,
      recommendedTier: data.recommendedTier,
      specialistProfile: mapSinkToSpecialist(bp.sinkKind),
      hypothesis,
      sourceToSinkTrace: trace,
      data,
    })
  }

  return suspects
}

const SEV_ORDER: Record<SemanticAuditSuspect['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

export function rankAndBudgetAuditSuspects(
  suspects: readonly SemanticAuditSuspect[],
  options: { budgetCap?: number; hostTiers?: Record<string, HostTier> } = {},
): SemanticAuditSuspect[] {
  const rawCap = options.budgetCap ?? DEFAULT_AUDIT_SUSPECTS_BUDGET
  const cap = Math.max(1, Math.min(Math.round(rawCap), MAX_AUDIT_SUSPECTS_CEILING))
  const byFp = new Map<string, SemanticAuditSuspect>()
  for (const s of suspects) {
    const existing = byFp.get(s.fingerprint)
    if (!existing || s.priorityScore > existing.priorityScore) {
      byFp.set(s.fingerprint, s)
    }
  }
  const unique = [...byFp.values()]
  unique.sort((a, b) =>
    (b.priorityScore - a.priorityScore) ||
    (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) ||
    a.file.localeCompare(b.file) ||
    (a.line - b.line))
  return unique.slice(0, cap)
}

// ============================================================================
// Stage 3: Big Sleep / Aardvark-Style Git-History Miner & Variant Sweep
// ============================================================================

export async function mineGitSecurityHistory(
  ctx: SemanticAuditContext,
  repo: string,
  session: WorkerSession,
  _spec: ProjectSecuritySpec,
  options: { maxCommits?: number; diffBase?: string } = {},
): Promise<GitHistoryMiningResult> {
  const cleanRepo = normalizeRepoIdentifier(repo)
  const maxCommits = Math.max(1, Math.min(options.maxCommits ?? MAX_GIT_COMMITS_TO_MINE, MAX_GIT_COMMITS_TO_MINE))
  const safeDiffBase = sanitizeGitDiffBase(options.diffBase)
  const rangeArg = safeDiffBase ? `${safeDiffBase}..HEAD` : undefined

  const script = `
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
const repoRoot = path.resolve('/repos', ${JSON.stringify(cleanRepo)});
const gitDir = path.join(repoRoot, '.git');
if (!fs.existsSync(gitDir)) {
  process.stdout.write(JSON.stringify({ available: false, reason: 'No .git directory in mounted repository.' }));
  process.exit(0);
}
const baseArgs = ['-C', repoRoot, '-c', 'safe.directory=*', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null'];
try {
  execFileSync('git', [...baseArgs, 'rev-parse', '--git-dir'], { encoding: 'utf8', timeout: 5000 });
} catch {
  process.stdout.write(JSON.stringify({ available: false, reason: 'Invalid git repository.' }));
  process.exit(0);
}
const logArgs = [...baseArgs, 'log', '-n', String(${maxCommits}), '--no-merges', '--pretty=format:===COMMIT===%H%x09%aI%x09%s', '--name-only'];
if (${JSON.stringify(rangeArg ?? null)}) logArgs.push(${JSON.stringify(rangeArg ?? '')});
let logOut = '';
try {
  logOut = execFileSync('git', logArgs, { encoding: 'utf8', timeout: 10000, maxBuffer: 2 * 1024 * 1024 });
} catch (err) {
  process.stdout.write(JSON.stringify({ available: false, reason: 'git log failed' }));
  process.exit(0);
}
const commits = [];
for (const block of logOut.split('===COMMIT===').slice(1)) {
  const lines = block.trim().split('\\n');
  const [sha, committedAt, ...subjParts] = (lines[0] || '').split('\\t');
  const subject = subjParts.join('\\t');
  const touchedFiles = lines.slice(1).map(s => s.trim()).filter(Boolean).slice(0, 40);
  commits.push({ sha, committedAt, subject, touchedFiles });
}
// Inspect real unified diffs for removed guards/sanitizers (bounded to first 30 commits).
for (let i = 0; i < Math.min(commits.length, 30); i += 1) {
  try {
    commits[i].diff = execFileSync('git', [...baseArgs, 'show', '--unified=3', '--no-color', '--format=', commits[i].sha], {
      encoding: 'utf8', timeout: 8000, maxBuffer: 1024 * 1024,
    }).slice(0, 30000);
  } catch { commits[i].diff = ''; }
}
process.stdout.write(JSON.stringify({ available: true, commits }));
`

  let parsed: { available?: boolean; reason?: string; commits?: Array<{ sha: string; committedAt?: string; subject: string; touchedFiles: string[]; diff?: string }> } = {}
  try {
    const res = await session.runScript({ runtime: 'node', code: script, timeoutMs: 20_000 }, ctx.signal)
    parsed = JSON.parse(res.stdout || '{}')
  } catch {
    return {
      repo: cleanRepo,
      available: false,
      reason: 'Git history worker invocation failed.',
      commitsScanned: 0,
      securityCommits: [],
      suspects: [],
    }
  }

  if (!parsed.available) {
    return {
      repo: cleanRepo,
      available: false,
      reason: parsed.reason ?? 'No git history available.',
      commitsScanned: 0,
      securityCommits: [],
      suspects: [],
    }
  }

  const commits = parsed.commits ?? []
  const securityCommits: GitSecurityCommitSignal[] = []
  const suspects: SemanticAuditSuspect[] = []
  const origin = ctx.approvedOrigins[0]

  for (const c of commits) {
    const kwMatch = c.subject.match(SECURITY_COMMIT_RE)
    if (!kwMatch) continue
    const matchedKeywords = [...new Set(c.subject.match(new RegExp(SECURITY_COMMIT_RE.source, 'gi')) ?? [])].map(k => k.toLowerCase())
    const removedGuards = c.diff ? extractRemovedGuardsFromDiff(c.diff) : []
    const redactedRemoved = removedGuards.map(g => ({
      ...g,
      snippet: redact(g.snippet, ctx.secrets),
    }))
    const signalEntry: GitSecurityCommitSignal = {
      commitSha: c.sha,
      subject: redact(c.subject, ctx.secrets),
      committedAt: c.committedAt,
      matchedKeywords,
      touchedFiles: c.touchedFiles,
      removedChecksOrGuards: redactedRemoved.map(g => `${g.file}:${g.line} ${g.snippet}`),
      ...(redactedRemoved.length ? { removedGuardLocations: redactedRemoved } : {}),
      candidatePatterns: (redactedRemoved.length > 0
        ? redactedRemoved.slice(0, 4)
        : c.touchedFiles.slice(0, 4).map(f => ({ file: f, line: 1, snippet: redact(c.subject, ctx.secrets), reason: 'touched file' }))
      ).map(g => ({
        file: g.file,
        line: g.line,
        snippet: g.snippet,
        reason: `Historical security fix commit (${matchedKeywords.join(', ')})${redactedRemoved.length ? ' removed guard/sanitizer' : ''}`,
      })),
    }
    securityCommits.push(signalEntry)

    const target = redactedRemoved[0]
      ?? (c.touchedFiles.length > 0 ? { file: c.touchedFiles[0], line: 1, snippet: '' } : null)
    if (origin && target) {
      const targetFile = target.file
      const targetLine = Math.max(1, target.line)
      const sinkKind: AuditSinkKind = /idor|bola|bfla|tenant|ownership|auth/i.test(c.subject) || REMOVED_GUARD_RE.test(target.snippet)
        ? 'api_route'
        : 'db_query'
      const hypothesis = redactedRemoved.length > 0
        ? `Historical security fix (${c.sha.slice(0, 8)}: "${redact(c.subject, ctx.secrets)}") removed a guard/sanitizer at ${targetFile}:${targetLine} ("${redact(target.snippet, ctx.secrets).slice(0, 120)}"); audit sibling routes/handlers for an incomplete patch or regression.`
        : `Historical security fix (${c.sha.slice(0, 8)}: "${redact(c.subject, ctx.secrets)}") touched ${targetFile}; audit sibling routes/handlers for incomplete patch or regression.`
      const fp = makeSuspectFingerprint(origin, cleanRepo, targetFile, targetLine, sinkKind, targetFile)
      suspects.push({
        id: randomUUID(),
        fingerprint: fp,
        stage: 'stage3_git_miner',
        origin,
        repo: cleanRepo,
        file: targetFile,
        line: targetLine,
        routeOrAction: targetFile,
        authCheck: 'unknown (historical security patch)',
        ownershipCheck: 'unknown',
        sinkKind,
        severity: 'high',
        priorityScore: computePriorityScore({
          severity: 'high',
          isUnguarded: true,
          hasPartialGuards: false,
          sinkKind,
          origin,
          hostTiers: ctx.hostTiers,
        }),
        recommendedTier: sinkKind === 'api_route' ? 2 : 1,
        specialistProfile: mapSinkToSpecialist(sinkKind),
        hypothesis,
        data: {
          subkind: 'code_audit_suspect',
          repo: cleanRepo,
          file: targetFile,
          line: targetLine,
          routeOrAction: targetFile,
          authCheck: 'unknown (historical security patch)',
          ownershipCheck: 'unknown',
          sinkKind,
          hypothesis,
          recommendedTier: sinkKind === 'api_route' ? 2 : 1,
        },
      })
    }
  }

  return {
    repo: cleanRepo,
    available: true,
    commitsScanned: commits.length,
    securityCommits,
    suspects,
  }
}

export async function generateVariantSweepQueries(
  ctx: SemanticAuditContext,
  finding: Pick<Finding, 'id' | 'origin' | 'title' | 'cwe' | 'category' | 'severity' | 'status' | 'codeLocations'>,
  codeLocation: CodeLocation,
  snippet: string,
  spec?: ProjectSecuritySpec,
): Promise<{ queries: VariantSweepQuery[]; rejected: Array<{ id: string; reason: string }> }> {
  const candidates: DynamicRuleSpec[] = []
  const rejected: Array<{ id: string; reason: string }> = []

  // Deterministic structural sibling pattern extraction from the confirmed vulnerable snippet
  const callMatch = snippet.match(/\b([A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafeExec|exec|execSync|fetch|redirect))\s*\(/)
  const ext = codeLocation.file.split('.').pop()?.toLowerCase() ?? 'ts'
  const langs = ext === 'py' ? ['python'] : ext === 'go' ? ['go'] : ext === 'java' ? ['java'] : ['typescript', 'javascript']

  if (callMatch) {
    const methodPart = callMatch[1].split('.').pop()!.trim()
    candidates.push({
      id: `guardian.variant.${finding.id.slice(0, 12)}.${methodPart.replace(/[^a-z0-9]/gi, '').toLowerCase()}`,
      engine: 'opengrep',
      languages: langs,
      severity: finding.severity === 'informational' ? 'medium' : finding.severity,
      ...(finding.cwe ? { cwe: finding.cwe } : {}),
      sinkKind: spec?.sinks[0]?.sinkKind ?? 'db_query',
      message: `Variant sweep for ${finding.title}: sibling ${methodPart}(...) sink`,
      mode: 'pattern',
      patterns: [
        `$OBJ.${methodPart}($ARG + $OTHER, ...)`,
        `$OBJ.${methodPart}(\`...\${$X}...\`, ...)`,
        `$OBJ.${methodPart}($REQ.$FIELD, ...)`,
        `$OBJ.${methodPart}($INPUT[$$KEY], ...)`,
      ],
    })
  } else {
    candidates.push({
      id: `guardian.variant.${finding.id.slice(0, 12)}.sink`,
      engine: 'opengrep',
      languages: langs,
      severity: finding.severity === 'informational' ? 'medium' : finding.severity,
      ...(finding.cwe ? { cwe: finding.cwe } : {}),
      sinkKind: 'db_query',
      message: `Variant sweep for ${finding.title}: sibling unsafe query/sink call`,
      mode: 'pattern',
      patterns: ['$DB.query($SQL + $X, ...)', '$DB.query(`...${$X}...`, ...)'],
    })
  }

  // Optional reasoning LLM query synthesis
  const llmCall = ctx.llmCall ?? (ctx.modelProfiles?.length
    ? createReasoningLlmCall(ctx.modelProfiles, { signal: ctx.signal, secrets: ctx.secrets, onUsage: ctx.onUsage })
    : undefined)
  if (llmCall) {
    try {
      const resp = await llmCall({
        systemPrompt: 'Synthesize 1-3 safe Opengrep/ast-grep JSON DynamicRuleSpec objects in {"rules": [...]} to find sibling variants of the confirmed bug.',
        userPrompt: `Finding: ${finding.title} (${finding.cwe ?? finding.category})\nFile: ${codeLocation.file}:${codeLocation.startLine}\nSnippet:\n${redact(snippet, ctx.secrets)}`,
      })
      const parsed = JSON.parse(stripJsonFences(resp)) as { rules?: unknown[] }
      if (Array.isArray(parsed.rules)) {
        for (const r of parsed.rules.slice(0, 4)) candidates.push(r as DynamicRuleSpec)
      }
    } catch {
      // keep deterministic query
    }
  }

  const queries: VariantSweepQuery[] = []
  for (const cand of candidates) {
    const val = validateAndSerializeDynamicRule(cand)
    if (!val.ok) {
      rejected.push({ id: String((cand as { id?: unknown }).id ?? 'variant'), reason: val.reason })
      continue
    }
    queries.push({
      id: val.value.spec.id,
      engine: val.value.spec.engine,
      description: val.value.spec.message,
      rule: val.value,
    })
  }

  return { queries, rejected }
}

export async function runVariantSweepForFinding(
  ctx: SemanticAuditContext,
  params: {
    finding: Pick<Finding, 'id' | 'origin' | 'title' | 'cwe' | 'category' | 'severity' | 'status' | 'codeLocations'>
    mountedRepos?: readonly string[]
    spec?: ProjectSecuritySpec
    maxMatches?: number
  },
): Promise<VariantSweepResult> {
  const startedAt = Date.now()
  const { finding } = params
  if (finding.status !== 'confirmed' && finding.status !== 'static_verified') {
    throw new Error(`Variant sweep only runs on confirmed or static_verified findings (got "${finding.status}").`)
  }
  const locs = finding.codeLocations ?? []
  if (locs.length === 0) {
    return {
      findingId: finding.id,
      repo: '',
      queriesExecuted: 0,
      rejectedQueries: [],
      rawMatches: [],
      newSuspects: [],
      durationMs: Date.now() - startedAt,
    }
  }

  const primaryLoc = locs[0]
  const cleanRepo = normalizeRepoIdentifier(primaryLoc.repo)
  const ownedSession = !ctx.session
  const session = ctx.session ?? await ctx.backend.openSession(ctx.assignment?.id ?? randomUUID(), ctx.signal, { reposDir: ctx.reposDir })

  try {
    // Read bounded snippet inside --network none container
    let snippet = primaryLoc.snippet ?? ''
    if (!snippet) {
      const readCode = `
import fs from 'node:fs';
import path from 'node:path';
const repoRoot = path.resolve('/repos', ${JSON.stringify(cleanRepo)});
const target = path.resolve(repoRoot, ${JSON.stringify(primaryLoc.file)});
if (!target.startsWith(repoRoot + '/')) process.exit(1);
const lines = fs.readFileSync(target, 'utf8').split('\\n');
const s = Math.max(0, ${primaryLoc.startLine} - 4);
const e = Math.min(lines.length, ${primaryLoc.endLine} + 4);
process.stdout.write(lines.slice(s, e).join('\\n').slice(0, 2000));
`
      try {
        const sr = await session.runScript({ runtime: 'node', code: readCode, timeoutMs: 10_000 }, ctx.signal)
        snippet = sr.stdout
      } catch {
        snippet = ''
      }
    }

    const { queries, rejected } = await generateVariantSweepQueries(ctx, finding, primaryLoc, snippet, params.spec)
    const targetRepos = (params.mountedRepos?.length ? params.mountedRepos : ctx.mountedRepos)
      .map(r => { try { return normalizeRepoIdentifier(r) } catch { return null } })
      .filter((r): r is string => Boolean(r))
    const reposToScan = targetRepos.length ? targetRepos : [cleanRepo]

    const allMatches: SastFinding[] = []
    for (const rName of reposToScan) {
      const hits = await runValidatedDynamicRulesInWorker(session, rName, queries.map(q => q.rule), ctx.signal, ctx.secrets)
      allMatches.push(...hits)
    }

    const overlapsOriginal = (m: SastFinding) => locs.some(l =>
      m.file === l.file && m.line >= l.startLine - 1 && m.line <= l.endLine + 1,
    )
    const maxOut = Math.max(1, Math.min(params.maxMatches ?? MAX_VARIANT_MATCHES_PER_FINDING, MAX_VARIANT_MATCHES_PER_FINDING))
    const siblingMatches = allMatches.filter(m => !overlapsOriginal(m)).slice(0, maxOut)

    const newSuspects: SemanticAuditSuspect[] = siblingMatches.map(m => {
      const sinkKind = inferSinkKindFromFinding(m)
      const sev: SemanticAuditSuspect['severity'] = m.severity === 'info' ? 'low' : m.severity
      const hypothesis = `Variant sweep sibling of confirmed finding ${finding.id} (${finding.title}) at ${m.file}:${m.line}: ${m.message}`
      const fp = makeSuspectFingerprint(finding.origin, cleanRepo, m.file, m.line, sinkKind, m.file)
      return {
        id: randomUUID(),
        fingerprint: fp,
        stage: 'stage3_variant_sweep',
        origin: finding.origin,
        repo: cleanRepo,
        file: m.file,
        line: Math.max(1, m.line),
        ...(m.endLine ? { endLine: m.endLine } : {}),
        routeOrAction: m.file,
        authCheck: 'unknown (variant sweep sibling)',
        ownershipCheck: 'unknown',
        sinkKind,
        ...(m.cwe ?? finding.cwe ? { cwe: m.cwe ?? finding.cwe ?? undefined } : {}),
        severity: sev,
        priorityScore: computePriorityScore({
          severity: sev,
          isUnguarded: true,
          hasPartialGuards: false,
          sinkKind,
          origin: finding.origin,
          hostTiers: ctx.hostTiers,
          corroborated: true,
        }),
        recommendedTier: 1,
        specialistProfile: mapSinkToSpecialist(sinkKind, m.cwe ?? finding.cwe ?? undefined),
        hypothesis,
        ruleId: m.ruleId,
        data: {
          subkind: 'code_audit_suspect',
          repo: cleanRepo,
          file: m.file,
          line: Math.max(1, m.line),
          routeOrAction: m.file,
          authCheck: 'unknown (variant sweep sibling)',
          ownershipCheck: 'unknown',
          sinkKind,
          hypothesis,
          recommendedTier: 1,
        },
      }
    })

    if (ctx.storage && ctx.assignment && newSuspects.length > 0) {
      for (const s of newSuspects) {
        ctx.storage.addFact(ctx.run as Run, ctx.assignment, {
          kind: 'code_audit_suspect',
          origin: s.origin,
          summary: s.hypothesis,
          data: s.data as unknown as Record<string, unknown>,
          secrets: ctx.secrets,
        })
      }
    }

    return {
      findingId: finding.id,
      repo: cleanRepo,
      queriesExecuted: queries.length,
      rejectedQueries: rejected,
      rawMatches: siblingMatches,
      newSuspects,
      durationMs: Date.now() - startedAt,
    }
  } finally {
    if (ownedSession) {
      await session.close().catch(() => undefined)
    }
  }
}

// ============================================================================
// Store Persistence, ChainStep Conversion & Top-Level Pipeline
// ============================================================================

export function persistSemanticAuditOutputs(
  storage: Store,
  run: Pick<Run, 'id' | 'scopeRevision'>,
  assignment: Assignment,
  specsByRepo: Record<string, ProjectSecuritySpec>,
  suspects: readonly SemanticAuditSuspect[],
): { factIds: string[]; endpointIds: string[] } {
  const factIds: string[] = []
  const endpointIds: string[] = []

  for (const s of suspects) {
    if (s.routeOrAction.startsWith('/')) {
      const ep = storage.upsertEndpoint({
        runId: run.id,
        scopeRevision: run.scopeRevision,
        origin: s.origin,
        method: s.httpMethod ?? 'GET',
        pathTemplate: s.routeOrAction,
        source: 'repo_ast',
        framework: specsByRepo[s.repo]?.frameworks[0] ?? null,
        authRequirement: s.authCheck,
        ownershipGuard: s.ownershipCheck,
        sinkKinds: [s.sinkKind],
        riskScore: s.priorityScore,
        codeLocation: {
          repo: s.repo,
          file: s.file,
          startLine: s.line,
          endLine: s.endLine ?? s.line,
        },
      })
      endpointIds.push(ep.id)
    }
    const fact = storage.addFact(run as Run, assignment, {
      kind: 'code_audit_suspect',
      origin: s.origin,
      summary: `[${s.stage}] ${s.file}:${s.line} (${s.sinkKind}) — ${s.hypothesis}`,
      data: s.data as unknown as Record<string, unknown>,
    })
    factIds.push(fact.id)
  }

  return { factIds, endpointIds }
}

function sinkToCategoryAndSkills(sinkKind: AuditSinkKind): { category: OwaspCategory; skills: string[] } {
  switch (sinkKind) {
    case 'server_action':
    case 'api_route':
      return { category: 'broken-access-control', skills: ['source-first-audit', 'bola-idor-race'] }
    case 'webhook':
    case 'auth_config':
      return { category: 'auth-identity', skills: ['source-first-audit', 'jwt-oauth-saml'] }
    case 'outbound_fetch':
    case 'redirect':
      return { category: 'ssrf-redirects', skills: ['source-first-audit', 'oob-ssrf-browser-chain'] }
    case 'postmessage_iframe':
      return { category: 'cors-client-side', skills: ['cross-host-chaining', 'xss-dom-prototype'] }
    case 'upload_storage':
      return { category: 'upload-storage', skills: ['source-first-audit'] }
    case 'db_query':
      return { category: 'injection-input', skills: ['source-first-audit', 'sqli-parser-injection'] }
    default:
      return { category: 'broken-access-control', skills: ['source-first-audit'] }
  }
}

/**
 * Stable identity for a code-audit suspect: the same (repo, file, line, sinkKind)
 * location must not be queued twice, even when it is produced by multiple
 * semantic-audit stages or repeated worker passes.
 */
export function codeAuditSuspectLocationKey(input: {
  id?: string
  repo?: unknown
  file?: unknown
  line?: unknown
  sinkKind?: unknown
}): string {
  const repo = typeof input.repo === 'string' ? input.repo : ''
  const file = typeof input.file === 'string' ? input.file : ''
  if (!file) return `id:${input.id ?? ''}`
  const line = typeof input.line === 'number' && Number.isFinite(input.line) ? input.line : 0
  const sinkKind = typeof input.sinkKind === 'string' ? input.sinkKind : ''
  return `${repo}|${file}|${line}|${sinkKind}`
}

export function dedupeCodeAuditSuspects<T extends { id: string; data: unknown }>(suspects: readonly T[]): T[] {
  const seen = new Set<string>()
  const out: T[] = []
  for (const suspect of suspects) {
    const data = (suspect.data && typeof suspect.data === 'object' ? suspect.data : {}) as Record<string, unknown>
    const key = codeAuditSuspectLocationKey({ ...data, id: suspect.id })
    if (seen.has(key)) continue
    seen.add(key)
    out.push(suspect)
  }
  return out
}

export function toChainStepInputs(
  run: Pick<Run, 'candidates' | 'approved'>,
  suspects: readonly SemanticAuditSuspect[],
  hostTiers?: Record<string, HostTier>,
  persistedFactIds?: readonly string[],
): Array<Parameters<Store['addChainStep']>[1]> {
  const out: Array<Parameters<Store['addChainStep']>[1]> = []
  const seenLocations = new Set<string>()
  for (let index = 0; index < suspects.length; index += 1) {
    const s = suspects[index]
    const asset = run.candidates.find(c => c.origin === s.origin && run.approved.includes(c.id))
    if (!asset) continue
    const locationKey = codeAuditSuspectLocationKey(s)
    if (seenLocations.has(locationKey)) continue
    seenLocations.add(locationKey)
    const { category, skills } = sinkToCategoryAndSkills(s.sinkKind)
    const isCrown = (hostTiers?.[s.origin] ?? classifyHostTier(s.origin)) === 'crown_jewel'
    const priority = Math.min(100, Math.max(20, s.priorityScore + (isCrown ? 5 : 0)))
    const factId = persistedFactIds?.[index]
    out.push({
      title: `Semantic audit · ${s.routeOrAction.slice(0, 80)} (${s.file}:${s.line})`,
      hypothesis: s.hypothesis,
      category,
      priority,
      targetAssetIds: [asset.id],
      skills,
      sourceOrigins: [s.origin],
      specialistProfile: s.specialistProfile,
      ...(factId ? { dependsOnFactIds: [factId] } : {}),
    })
  }
  return out
}

export async function runThreeStageSemanticAudit(
  ctx: SemanticAuditContext,
  options: SemanticAuditPipelineOptions = {},
): Promise<SemanticAuditPipelineResult> {
  const startedAt = Date.now()
  const ownedSession = !ctx.session
  const session = ctx.session ?? await ctx.backend.openSession(ctx.assignment?.id ?? randomUUID(), ctx.signal, { reposDir: ctx.reposDir })

  const specsByRepo: Record<string, ProjectSecuritySpec> = {}
  const rejectedDynamicRules: Array<{ ruleId: string; reason: string }> = []
  const callGraphsByRepo: SemanticAuditPipelineResult['callGraphsByRepo'] = {}
  const gitMiningByRepo: Record<string, GitHistoryMiningResult> = {}
  let dynamicRulesCount = 0
  let backwardPathsEvaluated = 0
  const allSuspects: SemanticAuditSuspect[] = []

  try {
    for (const rawRepo of ctx.mountedRepos) {
      let cleanRepo: string
      try {
        cleanRepo = normalizeRepoIdentifier(rawRepo)
      } catch {
        continue
      }

      // Stage 1: IRIS-style Spec + Dynamic Rule Scan
      const stage1 = await extractProjectSecuritySpecAndRules(ctx, cleanRepo, session, {
        enableLlm: options.enableStage1Llm
          ?? (ctx.modelProfiles?.length ? process.env.GUARDIAN_STAGE1_LLM !== '0' : false),
      })
      specsByRepo[cleanRepo] = stage1.spec
      dynamicRulesCount += stage1.rules.length
      rejectedDynamicRules.push(...stage1.rejectedRules)

      const dynamicFindings = await runValidatedDynamicRulesInWorker(
        session,
        cleanRepo,
        stage1.rules,
        ctx.signal,
        ctx.secrets,
      )

      // Stage 2: Atlantis/RepoAudit-style Call-Graph Backward Traversal & Path Dominance
      const graph = await buildRepoCallGraph(session, cleanRepo, stage1.spec, ctx.signal)
      callGraphsByRepo[cleanRepo] = {
        filesScanned: graph.filesScanned,
        nodes: graph.nodes.length,
        edges: graph.edges.length,
        source: graph.analyzerSource,
      }
      const backwardPaths = analyzeSinkBackwardPaths(graph, stage1.spec)
      backwardPathsEvaluated += backwardPaths.length

      allSuspects.push(...scoreAndBuildSuspects({
        repo: cleanRepo,
        approvedOrigins: ctx.approvedOrigins,
        spec: stage1.spec,
        dynamicFindings,
        backwardPaths,
        hostTiers: ctx.hostTiers,
        callGraph: graph,
        ...(ctx.liveEndpoints ? { liveEndpoints: ctx.liveEndpoints } : {}),
      }))

      // Stage 3: Big Sleep/Aardvark-style Git Security Miner
      if (options.enableStage3GitMiner !== false) {
        const gitRes = await mineGitSecurityHistory(ctx, cleanRepo, session, stage1.spec, {
          maxCommits: options.gitMaxCommits,
          diffBase: options.gitDiffBase,
        })
        gitMiningByRepo[cleanRepo] = gitRes
        allSuspects.push(...gitRes.suspects)
      }
    }

    const rankedSuspects = rankAndBudgetAuditSuspects(allSuspects, {
      budgetCap: options.suspectBudget,
      hostTiers: ctx.hostTiers,
    })

    let persistedFactIds: string[] = []
    let persistedEndpointIds: string[] = []
    if (options.persistToStore !== false && ctx.storage && ctx.assignment) {
      const persisted = persistSemanticAuditOutputs(
        ctx.storage,
        ctx.run,
        ctx.assignment,
        specsByRepo,
        rankedSuspects,
      )
      persistedFactIds = persisted.factIds
      persistedEndpointIds = persisted.endpointIds
    }

    return {
      specsByRepo,
      dynamicRulesCount,
      rejectedDynamicRules,
      callGraphsByRepo,
      backwardPathsEvaluated,
      gitMiningByRepo,
      allSuspectsCount: allSuspects.length,
      rankedSuspects,
      persistedFactIds,
      persistedEndpointIds,
      durationMs: Date.now() - startedAt,
    }
  } finally {
    if (ownedSession) {
      await session.close().catch(() => undefined)
    }
  }
}
