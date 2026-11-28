/**
 * Track A3 — Tier-2 Same-Model Skeptic Policy Judge (fail-closed).
 *
 * Tier-1 universal primitives (`v8-oracle-families.ts`) decide deterministically from host-signed
 * facts. When they cannot decide a terminal-impact claim, this judge evaluates a strictly masked
 * view of the cited host-signed exchanges plus (optionally) AST comment-stripped, path-confined
 * `/repos:ro` source slices and a host-verified refusal control.
 *
 * Invariants:
 *  - Untrusted response text NEVER reaches the judge: response bodies are reduced to a structural
 *    key/type tree, numeric deltas, and SHA-256 hashes (`maskHostSignedExchangesForPolicyJudge`).
 *  - Every cited exchange must carry a valid host signature; any missing/invalid signature rejects.
 *  - Without verified repo slices AND without a host-verified refusal control, a positive judgment
 *    is clamped to `needs_review` (`downgradedNoRepoRule`), never `confirmed`.
 *  - Without an injected skeptic (`--no-llm`), the judge never auto-confirms.
 */
import { lstatSync, readFileSync, realpathSync } from 'node:fs'
import { extname, isAbsolute, relative, resolve } from 'node:path'
import ts from 'typescript'
import { sha256Hex, verifyHostRecordSignature, type HostTranscriptEntry } from './composite-receipt.ts'
import { normalizeGuardPath } from './v8-oracle-families.ts'
export type { CompiledVerifyFixPredicate } from './verify-fix-predicate.ts'

export type PolicyJudgeVerdict = 'confirmed' | 'needs_review' | 'rejected'
export type RefusalControlKind = 'serial_4xx' | 'clean_session_403' | 'boundary_flip_403_200'

/** Structural JSON shape with every string leaf replaced by type/length/hash (never raw text). */
export type JsonKeySchemaNode =
  | { type: 'object'; keys: Record<string, JsonKeySchemaNode>; truncated?: boolean }
  | { type: 'array'; length: number; items: JsonKeySchemaNode[] }
  | { type: 'string'; length: number; sha256: string }
  | { type: 'number' | 'boolean' | 'null' }

export interface MaskedNumericDelta { path: string; previousExchangeId: string; delta: number }

export interface MaskedHostFact {
  exchangeId: string
  hostSignature: string | null
  /** `true` when verified against the host signing key, `false` when missing/invalid, `null` when no key was supplied. */
  signatureVerified: boolean | null
  timestampMs: number | null
  method: string
  route: string
  status: number | null
  principalId: string | null
  principalRole: string | null
  principalTenants: string[]
  jsonKeySchema: JsonKeySchemaNode | null
  numericDeltas: MaskedNumericDelta[]
  bodySha256: string | null
  maskedValueHashes: string[]
}

export interface RefusalControlClaim {
  kind: RefusalControlKind
  /** Host-signed refusal-control exchanges (serial replay, clean/peer session, or denied control). */
  controlExchangeIds: readonly string[]
  /** Host-signed probe exchange the control is contrasted against. */
  probeExchangeId: string
}

export interface VerifiedRefusalControl {
  kind: RefusalControlKind
  controlExchangeIds: string[]
  probeExchangeId: string
  controlStatuses: number[]
  probeStatus: number
  route: string
}

export interface PolicyJudgeRepoSliceRequest { relPath: string; startLine?: number; endLine?: number }
export interface ConfinedRepoSlice { relPath: string; startLine: number; endLine: number; sha256: string; code: string }

export interface PolicyJudgeLlmRequest {
  role: 'same_model_skeptic'
  vulnClass: string
  facts: MaskedHostFact[]
  repoSlices: ConfinedRepoSlice[]
  refusalControl: VerifiedRefusalControl | null
  instructions: string
}
export interface PolicyJudgeLlmResponse { verdict: string; rationale?: string }
/** Injected same-model skeptic. Receives ONLY masked facts, comment-stripped slices, and verified refusal metadata. */
export type PolicyJudgeLlmCall = (request: PolicyJudgeLlmRequest) => PolicyJudgeLlmResponse

/** Host-configured Tier-2 options (never worker-supplied). */
export interface PolicyJudgeOptions {
  repoRoot?: string
  repoSlices?: readonly PolicyJudgeRepoSliceRequest[]
  refusalControl?: RefusalControlClaim
  llmCall?: PolicyJudgeLlmCall
  /** Defaults to `true`: without a signing key every exchange is treated as unverifiable. */
  requireSignedExchanges?: boolean
}

export interface PolicyJudgeInput extends PolicyJudgeOptions {
  vulnClass: string
  exchanges: readonly HostTranscriptEntry[]
  /** Exchanges the claim cites; defaults to every supplied exchange. */
  citedExchangeIds?: readonly string[]
  signingKey?: string
}

export interface PolicyJudgeDecision {
  tier: 2
  verdict: PolicyJudgeVerdict
  confirmed: boolean
  downgradedNoRepoRule: boolean
  mode: 'llm_skeptic' | 'deterministic_no_llm'
  reason: string
  signaturesVerified: boolean
  citedExchangeIds: string[]
  maskedFacts: MaskedHostFact[]
  verifiedRefusalControl: VerifiedRefusalControl | null
  verifiedRepoSlices: Omit<ConfinedRepoSlice, 'code'>[]
  rejectedRepoSlices: { relPath: string; reason: string }[]
  llmVerdict: PolicyJudgeVerdict | null
}

/* ───────────────────────── Masked host-signed facts ───────────────────────── */

const SAFE_KEY_RE = /^[A-Za-z_$][\w$.-]{0,63}$/
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor'])
const SAFE_SEG_RE = /^[A-Za-z0-9_.:{}-]{1,48}$/
const SAFE_TOKEN_RE = /^[A-Za-z0-9_.:@-]{1,64}$/
const MAX_SCHEMA_DEPTH = 6, MAX_SCHEMA_KEYS = 64, MAX_ARRAY_ITEMS = 3, MAX_VALUE_HASHES = 64
const shortHash = (value: string): string => sha256Hex(value).slice(0, 16)
const maskKey = (key: string): string => (SAFE_KEY_RE.test(key) && !FORBIDDEN_KEYS.has(key) ? key : `key:${shortHash(key)}`)
const maskToken = (value: string | null | undefined): string | null => {
  const v = typeof value === 'string' ? value.trim() : ''
  return !v ? null : SAFE_TOKEN_RE.test(v) ? v : `tok:${shortHash(v)}`
}
/** Path-only route with every non-structural segment replaced by a hash (query strings never survive). */
function maskRoute(raw: string | null | undefined): string {
  const path = normalizeGuardPath(raw)
  if (!path) return ''
  return path === '/' ? '/' : `/${path.slice(1).split('/').map(seg => (SAFE_SEG_RE.test(seg) ? seg : `~${shortHash(seg).slice(0, 8)}`)).join('/')}`
}

function parseResponseJson(entry: HostTranscriptEntry): unknown {
  if (entry.step.json !== undefined) return entry.step.json
  const body = entry.step.body?.trim()
  if (!body || !/^[[{]/.test(body)) return undefined
  try { return JSON.parse(body) } catch { return undefined }
}

function buildJsonKeySchema(value: unknown, depth: number, hashes: Set<string>, numbers: Map<string, number>, path: string): JsonKeySchemaNode {
  if (value === null || value === undefined) return { type: 'null' }
  if (typeof value === 'string') { const sha = shortHash(value); hashes.add(sha); return { type: 'string', length: value.length, sha256: sha } }
  if (typeof value === 'number') { if (Number.isFinite(value)) numbers.set(path, value); return { type: 'number' } }
  if (typeof value === 'boolean') return { type: 'boolean' }
  if (depth >= MAX_SCHEMA_DEPTH) return { type: 'null' }
  if (Array.isArray(value)) {
    return { type: 'array', length: value.length, items: value.slice(0, MAX_ARRAY_ITEMS).map((v, i) => buildJsonKeySchema(v, depth + 1, hashes, numbers, `${path}[${i}]`)) }
  }
  const entries = Object.entries(value as Record<string, unknown>)
  const keys: Record<string, JsonKeySchemaNode> = Object.create(null)
  for (const [k, v] of entries.slice(0, MAX_SCHEMA_KEYS)) { const mk = maskKey(k); keys[mk] = buildJsonKeySchema(v, depth + 1, hashes, numbers, `${path}.${mk}`) }
  return entries.length > MAX_SCHEMA_KEYS ? { type: 'object', keys, truncated: true } : { type: 'object', keys }
}

function principalTenantsOf(entry: HostTranscriptEntry): string[] {
  const raw = [entry.actorTenant, entry.step.actor?.tenant, ...(entry.step.actor?.tenants ?? [])]
  return [...new Set(raw.map(maskToken).filter((t): t is string => Boolean(t)))].sort()
}

function signatureStatus(entry: HostTranscriptEntry, signingKey: string | undefined): boolean | null {
  if (!entry.hostSignature) return false
  return signingKey ? verifyHostRecordSignature(entry, signingKey) : null
}

/**
 * Build masked, injection-proof facts from host-signed exchanges. Response free text is reduced to
 * a structural key/type tree + hashes; numeric leaves become deltas against the previous exchange
 * (chronological) that carried the same masked path.
 */
export function maskHostSignedExchangesForPolicyJudge(entries: readonly HostTranscriptEntry[], options: { signingKey?: string } = {}): MaskedHostFact[] {
  const ordered = [...entries].sort((a, b) => (a.timestampMs ?? a.seq ?? 0) - (b.timestampMs ?? b.seq ?? 0))
  const lastNumeric = new Map<string, { exchangeId: string; value: number }>()
  return ordered.map(entry => {
    const hashes = new Set<string>(), numbers = new Map<string, number>()
    const json = parseResponseJson(entry)
    const jsonKeySchema = json === undefined ? null : buildJsonKeySchema(json, 0, hashes, numbers, '$')
    if (json === undefined && typeof entry.step.body === 'string' && entry.step.body.length > 0) hashes.add(shortHash(entry.step.body))
    const numericDeltas: MaskedNumericDelta[] = []
    for (const [path, value] of numbers) {
      const prev = lastNumeric.get(path)
      if (prev) numericDeltas.push({ path, previousExchangeId: prev.exchangeId, delta: Number((value - prev.value).toFixed(6)) })
      lastNumeric.set(path, { exchangeId: entry.exchangeId, value })
    }
    const body = typeof entry.step.body === 'string' ? entry.step.body : json !== undefined ? JSON.stringify(json) : null
    return {
      exchangeId: entry.exchangeId,
      hostSignature: entry.hostSignature ?? null,
      signatureVerified: signatureStatus(entry, options.signingKey),
      timestampMs: Number.isFinite(entry.timestampMs) ? entry.timestampMs! : null,
      method: (entry.step.method || 'GET').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10),
      route: maskRoute(entry.step.route ?? entry.step.pathAndQuery),
      status: typeof entry.step.status === 'number' ? entry.step.status : null,
      principalId: maskToken(entry.actorPersona ?? entry.step.actor?.handle),
      principalRole: maskToken(entry.actorRoleLabel ?? entry.actorPrivilege ?? entry.step.actor?.role),
      principalTenants: principalTenantsOf(entry),
      jsonKeySchema,
      numericDeltas,
      bodySha256: body === null ? null : sha256Hex(body),
      maskedValueHashes: [...hashes].sort().slice(0, MAX_VALUE_HASHES),
    }
  })
}

/* ───────────────────── AST comment stripping & repo confinement ───────────────────── */

const JS_FAMILY_EXT = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'])
const MAX_SLICE_FILE_BYTES = 512 * 1024, MAX_SLICE_LINES = 400
const SCRIPT_KINDS: Readonly<Record<string, ts.ScriptKind>> = {
  '.ts': ts.ScriptKind.TS, '.mts': ts.ScriptKind.TS, '.cts': ts.ScriptKind.TS,
  '.tsx': ts.ScriptKind.TSX, '.js': ts.ScriptKind.JS, '.mjs': ts.ScriptKind.JS, '.cjs': ts.ScriptKind.JS,
  '.jsx': ts.ScriptKind.JSX,
}

/**
 * Strip every `//`, `/* *\/`, and JSDoc comment using the TypeScript AST parser (string, template,
 * regex, and JSX literals are preserved verbatim). Multi-line comments preserve newlines so line
 * numbers stay stable; single-line block comments become a space so adjacent tokens never merge.
 */
export function stripSourceCommentsAst(code: string, filePath: string): string {
  const kind = SCRIPT_KINDS[extname(filePath).toLowerCase()] ?? ts.ScriptKind.TS
  const sf = ts.createSourceFile(filePath, code, ts.ScriptTarget.Latest, true, kind)
  const ranges: { pos: number; end: number }[] = []
  const seen = new Set<number>()
  const add = (list: readonly ts.CommentRange[] | undefined): void => {
    for (const r of list ?? []) { if (!seen.has(r.pos)) { seen.add(r.pos); ranges.push({ pos: r.pos, end: r.end }) } }
  }
  const visit = (node: ts.Node): void => {
    add(ts.getLeadingCommentRanges(code, node.pos))
    add(ts.getTrailingCommentRanges(code, node.end))
    if (node.kind === ts.SyntaxKind.EndOfFileToken) return
    for (const child of node.getChildren(sf)) visit(child)
  }
  visit(sf)
  if (!ranges.length) return code
  ranges.sort((a, b) => a.pos - b.pos)
  let out = '', cursor = 0
  for (const r of ranges) {
    if (r.pos < cursor) continue
    out += code.slice(cursor, r.pos)
    const text = code.slice(r.pos, r.end)
    out += text.includes('\n') ? text.replace(/[^\n]/g, '') : (text.startsWith('/*') ? ' ' : '')
    cursor = r.end
  }
  return out + code.slice(cursor)
}

/** Resolve `relPath` strictly inside `repoRoot` (rejects `..`, absolute escapes, NUL bytes, and symlink escapes). */
export function assertConfinedRepoPath(repoRoot: string, relPath: string): string {
  if (typeof repoRoot !== 'string' || !repoRoot.trim()) throw new Error('repo_root_missing')
  if (typeof relPath !== 'string' || !relPath.trim()) throw new Error('repo_path_empty')
  if (relPath.includes('\0')) throw new Error('repo_path_nul_byte')
  if (isAbsolute(relPath) || /^[A-Za-z]:[\\/]/.test(relPath) || relPath.startsWith('\\')) throw new Error('repo_path_absolute')
  if (relPath.split(/[\\/]+/).some(seg => seg === '..')) throw new Error('repo_path_traversal')
  const rootReal = realpathSync(repoRoot)
  const candidate = resolve(rootReal, relPath)
  const within = (p: string): boolean => { const rel = relative(rootReal, p); return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel) }
  if (!within(candidate)) throw new Error('repo_path_escape')
  const real = realpathSync(candidate)
  if (!within(real)) throw new Error('repo_path_symlink_escape')
  if (!lstatSync(real).isFile()) throw new Error('repo_path_not_file')
  return real
}

/** Load a confined, comment-stripped, line-bounded source slice from the read-only repo mount. */
export function loadConfinedRepoSlice(repoRoot: string, relPath: string, startLine?: number, endLine?: number): ConfinedRepoSlice {
  const abs = assertConfinedRepoPath(repoRoot, relPath)
  if (!JS_FAMILY_EXT.has(extname(abs).toLowerCase())) throw new Error('unsupported_source_language')
  if (lstatSync(abs).size > MAX_SLICE_FILE_BYTES) throw new Error('repo_file_too_large')
  const lines = stripSourceCommentsAst(readFileSync(abs, 'utf8'), abs).split('\n')
  const safeStart = startLine !== undefined && Number.isFinite(startLine) ? Math.trunc(startLine) : 1
  const safeEnd = endLine !== undefined && Number.isFinite(endLine) ? Math.trunc(endLine) : lines.length
  const start = Math.max(1, safeStart)
  const end = Math.min(lines.length, safeEnd, start + MAX_SLICE_LINES - 1)
  if (end < start) throw new Error('repo_slice_empty_range')
  const code = lines.slice(start - 1, end).join('\n')
  if (!code.trim()) throw new Error('repo_slice_empty_after_strip')
  const normalizedRelPath = relative(realpathSync(repoRoot), abs).replace(/\\/g, '/')
  return { relPath: normalizedRelPath, startLine: start, endLine: end, sha256: sha256Hex(code), code }
}

/* ─────────────────────────── Refusal-control verification ─────────────────────────── */

const REFUSAL_CONTROL_KINDS = new Set<RefusalControlKind>(['serial_4xx', 'clean_session_403', 'boundary_flip_403_200'])
const isOk = (s: number | null | undefined): s is number => typeof s === 'number' && s >= 200 && s < 300
const routeOf = (e: HostTranscriptEntry): string => normalizeGuardPath(e.step.route ?? e.step.pathAndQuery)
const methodOf = (e: HostTranscriptEntry): string => (e.step.method || 'GET').trim().toUpperCase()
const actorOf = (e: HostTranscriptEntry): string => (e.actorPersona ?? e.step.actor?.handle ?? '').trim().toLowerCase()

function refusalControlError(kind: RefusalControlKind, controls: HostTranscriptEntry[], probe: HostTranscriptEntry): string | null {
  if (!REFUSAL_CONTROL_KINDS.has(kind)) return 'refusal_control_kind_invalid'
  if (!isOk(probe.step.status)) return 'refusal_probe_not_accepted'
  const probeRoute = routeOf(probe)
  if (!probeRoute) return 'refusal_probe_route_missing'
  const probeMethod = methodOf(probe)
  if (controls.some(c => c.exchangeId === probe.exchangeId)) return 'refusal_control_reuses_probe'
  if (controls.some(c => routeOf(c) !== probeRoute)) return 'refusal_control_route_mismatch'
  if (controls.some(c => methodOf(c) !== probeMethod)) return 'refusal_control_method_mismatch'
  if (kind === 'serial_4xx') return controls.every(c => c.step.status === 400 || c.step.status === 409) ? null : 'serial_control_not_4xx'
  if (!controls.every(c => c.step.status === 403)) return 'refusal_control_not_403'
  if (kind === 'clean_session_403') {
    const probeActor = actorOf(probe)
    return controls.every(c => c.cleanSession === true || !actorOf(c) || actorOf(c) !== probeActor) ? null : 'control_not_clean_or_peer_session'
  }
  const probeActor = actorOf(probe)
  if (!probeActor || !Number.isFinite(probe.timestampMs)) return 'boundary_flip_not_same_principal_or_ordered'
  return controls.every(c => Number.isFinite(c.timestampMs) && c.timestampMs! <= probe.timestampMs! && actorOf(c) === probeActor) ? null : 'boundary_flip_not_same_principal_or_ordered'
}

function verifyRefusalControl(claim: RefusalControlClaim, byId: ReadonlyMap<string, HostTranscriptEntry>): { ok: true; value: VerifiedRefusalControl } | { ok: false; reason: string } {
  if (!claim || !REFUSAL_CONTROL_KINDS.has(claim.kind)) return { ok: false, reason: 'refusal_control_kind_invalid' }
  if (!Array.isArray(claim.controlExchangeIds) || !claim.controlExchangeIds.length || typeof claim.probeExchangeId !== 'string' || !claim.probeExchangeId) {
    return { ok: false, reason: 'refusal_control_exchange_missing' }
  }
  const controls = claim.controlExchangeIds.map(id => byId.get(id))
  const probe = byId.get(claim.probeExchangeId)
  if (controls.some(c => !c) || !probe) return { ok: false, reason: 'refusal_control_exchange_missing' }
  const present = controls as HostTranscriptEntry[]
  const err = refusalControlError(claim.kind, present, probe)
  if (err) return { ok: false, reason: err }
  return { ok: true, value: { kind: claim.kind, controlExchangeIds: present.map(c => c.exchangeId), probeExchangeId: probe.exchangeId, controlStatuses: present.map(c => c.step.status!), probeStatus: probe.step.status!, route: maskRoute(probe.step.route ?? probe.step.pathAndQuery) } }
}

/* ─────────────────────────────── Judge evaluation ─────────────────────────────── */

const SKEPTIC_INSTRUCTIONS = 'You are a skeptical verifier. Using ONLY the masked host-signed facts, comment-stripped source slices, and verified refusal-control metadata, answer with verdict "confirmed" only if the policy violation is proven; otherwise "needs_review" or "rejected".'

function loadRequestedSlices(input: PolicyJudgeInput): { slices: ConfinedRepoSlice[]; rejected: { relPath: string; reason: string }[] } {
  const slices: ConfinedRepoSlice[] = [], rejected: { relPath: string; reason: string }[] = []
  for (const req of input.repoSlices ?? []) {
    const relPath = typeof req?.relPath === 'string' ? req.relPath : ''
    if (!input.repoRoot) { rejected.push({ relPath, reason: 'repo_root_missing' }); continue }
    try { slices.push(loadConfinedRepoSlice(input.repoRoot, relPath, req.startLine, req.endLine)) } catch (err) { rejected.push({ relPath, reason: err instanceof Error ? err.message : String(err) }) }
  }
  return { slices, rejected }
}

function normalizeLlmVerdict(raw: unknown): PolicyJudgeVerdict {
  const v = typeof raw === 'string' ? raw.trim().toLowerCase() : ''
  return v === 'confirmed' || v === 'rejected' ? v : 'needs_review'
}

function signatureFailure(cited: readonly (HostTranscriptEntry | undefined)[], input: PolicyJudgeInput): string | null {
  if (!cited.length) return 'no_cited_exchanges'
  if (cited.some(e => !e)) return 'cited_exchange_missing_from_host_transcript'
  if (cited.some(e => !e!.hostSignature)) return 'missing_host_signature'
  if (input.signingKey) return cited.some(e => !verifyHostRecordSignature(e!, input.signingKey!)) ? 'invalid_host_signature' : null
  return input.requireSignedExchanges === false ? null : 'host_signing_key_unavailable'
}

/**
 * Tier-2 fail-closed policy judgment. See module header for the binding invariants; the
 * decision table is: bad signatures → `rejected`; skeptic `rejected` → `rejected`; skeptic
 * `confirmed` with verified repo slices or refusal control → `confirmed`; skeptic `confirmed`
 * otherwise → `needs_review` (no-repo rule); no skeptic → `needs_review` with structural evidence.
 */
export function evaluatePolicyJudge(input: PolicyJudgeInput): PolicyJudgeDecision {
  const byId = new Map(input.exchanges.map(e => [e.exchangeId, e] as const))
  const rcClaim = input.refusalControl
  const refusalIds = rcClaim ? [...(Array.isArray(rcClaim.controlExchangeIds) ? rcClaim.controlExchangeIds : []), ...(typeof rcClaim.probeExchangeId === 'string' && rcClaim.probeExchangeId ? [rcClaim.probeExchangeId] : [])] : []
  const citedIds = [...new Set([...(input.citedExchangeIds ?? input.exchanges.map(e => e.exchangeId)), ...refusalIds])]
  const cited = citedIds.map(id => byId.get(id))
  const present = cited.filter((e): e is HostTranscriptEntry => Boolean(e))
  const maskedFacts = maskHostSignedExchangesForPolicyJudge(present, { signingKey: input.signingKey })
  const mode = input.llmCall ? 'llm_skeptic' as const : 'deterministic_no_llm' as const
  const sigErr = signatureFailure(cited, input)
  if (sigErr) {
    return {
      tier: 2, verdict: 'rejected', confirmed: false, downgradedNoRepoRule: false, mode,
      reason: `policy_judge_fail_closed: ${sigErr}`, signaturesVerified: false, citedExchangeIds: citedIds,
      maskedFacts, verifiedRefusalControl: null, verifiedRepoSlices: [], rejectedRepoSlices: [], llmVerdict: null,
    }
  }
  const signaturesVerified = Boolean(input.signingKey)
  const { slices, rejected: rejectedRepoSlices } = loadRequestedSlices(input)
  const refusal = rcClaim && signaturesVerified ? verifyRefusalControl(rcClaim, byId) : rcClaim ? { ok: false as const, reason: 'host_signing_key_unavailable' } : null
  const verifiedRefusalControl = refusal?.ok ? refusal.value : null
  const base = { tier: 2 as const, mode, citedExchangeIds: citedIds, maskedFacts, verifiedRefusalControl, verifiedRepoSlices: slices.map(({ code: _code, ...meta }) => meta), rejectedRepoSlices }
  const decide = (verdict: PolicyJudgeVerdict, reason: string, extra: { signaturesVerified: boolean; llmVerdict?: PolicyJudgeVerdict | null; downgradedNoRepoRule?: boolean }): PolicyJudgeDecision => ({
    ...base, verdict, confirmed: verdict === 'confirmed', reason, signaturesVerified: extra.signaturesVerified, llmVerdict: extra.llmVerdict ?? null, downgradedNoRepoRule: extra.downgradedNoRepoRule ?? false,
  })
  const hasProof = slices.length > 0 || verifiedRefusalControl !== null
  const refusalNote = refusal && !refusal.ok ? ` (refusal control unverified: ${refusal.reason})` : ''
  if (!input.llmCall) {
    const structural = hasProof || present.some(e => isOk(e.step.status))
    return structural
      ? decide('needs_review', `deterministic_no_llm: structural evidence present; operator review required${refusalNote}`, { signaturesVerified })
      : decide('rejected', 'deterministic_no_llm: no structural evidence of policy violation', { signaturesVerified })
  }
  let llmVerdict: PolicyJudgeVerdict
  try {
    llmVerdict = normalizeLlmVerdict(input.llmCall({ role: 'same_model_skeptic', vulnClass: maskToken(input.vulnClass) ?? 'unknown', facts: maskedFacts, repoSlices: slices, refusalControl: verifiedRefusalControl, instructions: SKEPTIC_INSTRUCTIONS })?.verdict)
  } catch (err) {
    return decide('needs_review', `llm_skeptic_error: ${(err instanceof Error ? err.message : String(err)).slice(0, 160)}`, { signaturesVerified })
  }
  if (llmVerdict !== 'confirmed') return decide(llmVerdict, `llm_skeptic_${llmVerdict}${refusalNote}`, { signaturesVerified, llmVerdict })
  if (!signaturesVerified) return decide('needs_review', 'llm_skeptic_confirmed: signatures not cryptographically verified; operator review required', { signaturesVerified, llmVerdict })
  if (!hasProof) return decide('needs_review', `no_repo_rule: positive judgment without verified repo slices or refusal control${refusalNote}`, { signaturesVerified, llmVerdict, downgradedNoRepoRule: true })
  return decide('confirmed', verifiedRefusalControl ? `llm_skeptic_confirmed with host-verified refusal control (${verifiedRefusalControl.kind})` : 'llm_skeptic_confirmed with confined repo-source proof', { signaturesVerified, llmVerdict })
}
