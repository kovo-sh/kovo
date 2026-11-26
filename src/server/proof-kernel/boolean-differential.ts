/**
 * Proof Kernel — Single Concept Module for Boolean-Pair Binding & Differential Verification (`R3-17`).
 *
 * Consolidates ALL shared boolean-differential primitives into one concept-owned module:
 *   - Single `stepToBooleanArm()` converter (replaces the verbatim `impactStepToBooleanArm` /
 *     `stepToBooleanArm` clone across `oracle-invariants.ts` and `proof-receipt.ts`).
 *   - Single equal-length & character-multiset helper (`sortedCharMultiset` / `hasEqualLengthAndCharMultiset`).
 *   - Single canonical predicate skeleton parser (`parseBooleanPredicate` / `canonicalPredicateSkeleton` /
 *     `booleanPredicateTruth` / `stripBooleanPredicateSuffix`).
 *   - Single handler-side base-parity core (`verifyBooleanArmBaseParityCore`, wrapped by
 *     `verify-support.ts::verifyBooleanArmBaseParity` for defense-in-depth).
 *   - Single kernel triangle binding & multi-round structural differential verifier
 *     (`verifyBooleanTriangleBinding`, `verifyStampedBooleanPairRound`, `assessBooleanDifferential`).
 */

import { createHash } from 'node:crypto'
import { flattenJson, isBooleanDifferentialEchoOnly } from './reflection.ts'
import type { ImpactAssessment, ImpactStep } from '../oracle-invariants.ts'
import type {
  BooleanPairArm,
  BooleanPairStyle,
  HostMintedBooleanPairChallenge,
  HostMintedOracle,
  ReceiptTranscriptEntry,
} from '../proof-receipt.ts'

export interface HostBooleanPairBinding {
  challengeId?: string
  baseValue: string
  trueValue: string
  falseValue: string
}

export interface BooleanDifferentialArm {
  status: number | null
  method?: string
  origin?: string | null
  persona?: string | null
  authDigest?: string | null
  pathAndQuery?: string
  requestJson?: unknown
  requestBody?: string
  requestHeaders?: Record<string, string> | null
  json?: unknown
  body?: string
}

export interface BooleanDifferentialRound {
  baseline?: BooleanDifferentialArm
  control: BooleanDifferentialArm
  probe: BooleanDifferentialArm
  hostPair?: HostBooleanPairBinding | null
}

export interface BooleanDifferentialAssessment extends ImpactAssessment {
  evidence: {
    rounds: number
    stable: boolean
    controlStable: boolean
    probeStable: boolean
    requestShapeMismatch: boolean
    serverErrors: boolean
    echoedOnly: boolean
    predicateContrast: boolean
    changedPaths: string[]
    echoPaths: string[]
    hasBaseline?: boolean
    baselineStable?: boolean
    trueMatchesBaseline?: boolean
    baseBindingMismatch?: boolean
    statusClassMismatch?: boolean
  }
}

export interface ParsedBooleanPredicate {
  baseValue: string
  predicateClause: string
  predicatePrefix: string
  skeleton: string
  quoteDelimiter: '' | "'" | '"'
  combinator: 'AND' | 'OR' | '&&' | '||' | ''
  comparisonKind: 'numeric' | 'string' | 'unclosed_string' | 'literal'
  operator: string
  arithmeticOp: '+' | '-' | null
  negated: boolean
  operands: readonly string[]
  rawLength: number
  operandCharClass: string
  clauseCharClass: string
  leadingOperand: string | null
  truth: boolean
}

export type CanonicalPredicateSkeleton = ParsedBooleanPredicate

export interface BooleanTriangleBindingResult {
  ok: boolean
  param: string | null
  baseValue: string | null
  trueArm: 'armA' | 'armB' | null
  code: 'ok' | 'param' | 'shape' | 'predicate' | 'base_binding' | 'skeleton'
  reason: string
  pathSegmentIndex: number | null
  skeleton?: string | null
  trueArmLength?: number
  falseArmLength?: number
}

export interface HostMintedBooleanPairLike {
  readonly baseValue: string
  readonly trueValue: string
  readonly falseValue: string
  readonly style?: BooleanPairStyle
}

export interface StampedBooleanPairRoundInput {
  baseline?: ReceiptTranscriptEntry
  armA: ReceiptTranscriptEntry
  armB: ReceiptTranscriptEntry
  param: string
  requireBaseline: boolean
  requireArmATrue?: boolean
  oracle: HostMintedOracle
  targetOrigin: string
  runId?: string
  extractParam: (entry: ReceiptTranscriptEntry, param: string) => string | null
  normalizeOrigin: (origin: string) => string
  exactPathnameOf: (pathAndQuery: string) => string
}

export const BOOLEAN_VOLATILE_HEADERS = new Set([
  'authorization', 'cookie', 'proxy-authorization', 'x-request-id', 'x-correlation-id',
  'x-trace-id', 'traceparent', 'tracestate', 'date', 'set-cookie',
])
const AUTH_SHAPE_HEADERS = new Set(['authorization', 'cookie', 'proxy-authorization', 'x-api-key'])
const UUID_TEXT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_PREDICATE_INPUT_LEN = 4096
const TRAILING_NUMERIC_PRED_RE = /(\bNOT\s+)?(\(\s*)?(\d{1,12})(\s*)(==|=|!=|<>)(\s*)(\d{1,12})(?:(\s*)([+-])(\s*)(\d{1,12}))?\s*$/i
const TRAILING_STRING_PRED_RE = /(\bNOT\s+)?(\(\s*)?(['"])([^'"]{0,64})\3(\s*)(==|=|!=|<>)(\s*)(['"])([^'"]{0,64})\8\s*$/i
const TRAILING_UNCLOSED_STRING_PRED_RE = /(\bNOT\s+)?(\(\s*)?(['"])([^'"]{0,64})\3(\s*)(==|=|!=|<>)(\s*)\3([^'"]{0,64})$/i
const TRAILING_LITERAL_PRED_RE = /(\bNOT\s+)?(\(\s*)?(TRUE|FALSE)\s*$/i
const TRAILING_INLINE_COMMENT_RE = /\/\*[^*]{0,128}\*\/\s*$/
const STANDALONE_EMPTY_BASE_PRED_RE = /^\s*(?:['")]*\s*(?:AND|OR|&&|\|\|)\s*)?(?:NOT\s+)?\(?\s*(?:\d+\s*(?:==|=|!=|<>)\s*\d+(?:\s*[+-]\s*\d+)?|['"][^'"]*['"]\s*(?:==|=|!=|<>)\s*['"][^'"]*['"]?|(?:TRUE|FALSE))\s*\)?\s*(?:--[^\r\n]*|#[^\r\n]*|\/\*[\s\S]*?\*\/)?\s*$/i

/** Single canonical character-multiset helper (`R4-C-1` / `R3-17`). */
export function sortedCharMultiset(value: string): string {
  return [...value].sort().join('')
}

/** Single canonical equal-length + non-identical + identical-character-multiset invariant check. */
export function hasEqualLengthAndCharMultiset(a: string, b: string): boolean {
  return a.length === b.length && a !== b && sortedCharMultiset(a) === sortedCharMultiset(b)
}

/** Single shared `ImpactStep -> BooleanDifferentialArm` adapter (replaces verbatim clone). */
export function stepToBooleanArm(step: ImpactStep): BooleanDifferentialArm {
  return {
    status: step.status,
    method: step.method,
    persona: step.actor.handle ?? null,
    pathAndQuery: step.pathAndQuery ?? step.route,
    ...(step.requestJson !== undefined ? { requestJson: step.requestJson } : {}),
    ...(step.requestBody !== undefined ? { requestBody: step.requestBody } : {}),
    requestHeaders: step.requestHeaders ?? null,
    ...(step.json !== undefined ? { json: step.json } : {}),
    ...(step.body !== undefined ? { body: step.body } : {}),
  }
}

function charClassSignature(text: string): string {
  let hasLower = false, hasUpper = false, hasDigit = false, hasNonAscii = false
  const nonAlnum: string[] = []
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i)
    if (code >= 97 && code <= 122) hasLower = true
    else if (code >= 65 && code <= 90) hasUpper = true
    else if (code >= 48 && code <= 57) hasDigit = true
    else {
      if (code > 127) hasNonAscii = true
      nonAlnum.push(text[i]!)
    }
  }
  nonAlnum.sort()
  return `${hasLower ? 'L' : ''}${hasUpper ? 'U' : ''}${hasDigit ? 'D' : ''}${hasNonAscii ? 'N' : ''}|${nonAlnum.join('')}`
}

function stripTrailingSeparators(text: string): { rest: string; stripped: boolean } {
  let rest = text
  let stripped = false
  for (let i = 0; i < 4; i += 1) {
    const trimmed = rest.replace(/[ \t\r\n]+$/, '')
    if (trimmed.length !== rest.length) { rest = trimmed; stripped = true }
    const commentMatch = TRAILING_INLINE_COMMENT_RE.exec(rest)
    if (commentMatch) { rest = rest.slice(0, commentMatch.index); stripped = true; continue }
    break
  }
  return { rest, stripped }
}

interface MatchedTrailingComparison {
  matchIndex: number
  truth: boolean
  isLiteralOnly: boolean
  leadingOperand: string | null
  negated: boolean
  comparisonKind: ParsedBooleanPredicate['comparisonKind']
  operator: string
  arithmeticOp: '+' | '-' | null
  operands: string[]
  leadPrefix: string
  comparisonSkeleton: string
}

function matchTrailingComparison(expr: string): MatchedTrailingComparison | null {
  const numMatch = TRAILING_NUMERIC_PRED_RE.exec(expr)
  if (numMatch) {
    const negated = Boolean(numMatch[1])
    const leftStr = numMatch[3]!, ws1 = numMatch[4] ?? '', operator = numMatch[5]!, ws2 = numMatch[6] ?? ''
    const rightStr = numMatch[7]!, ws3 = numMatch[8] ?? '', arith = (numMatch[9] as '+' | '-' | undefined) ?? null
    const ws4 = numMatch[10] ?? '', deltaStr = numMatch[11]
    let right = Number(rightStr)
    if (arith && deltaStr) right += arith === '-' ? -Number(deltaStr) : Number(deltaStr)
    const rawTruth = operator === '!=' || operator === '<>' ? Number(leftStr) !== right : Number(leftStr) === right
    return {
      matchIndex: numMatch.index, truth: negated ? !rawTruth : rawTruth, isLiteralOnly: false, leadingOperand: leftStr,
      negated, comparisonKind: 'numeric', operator, arithmeticOp: arith,
      operands: deltaStr ? [leftStr, rightStr, deltaStr] : [leftStr, rightStr],
      leadPrefix: `${numMatch[1] ?? ''}${numMatch[2] ?? ''}`,
      comparisonSkeleton: arith && deltaStr
        ? `<NUM>${ws1}${operator}${ws2}<NUM>${ws3}${arith}${ws4}<NUM>`
        : `<NUM>${ws1}${operator}${ws2}<NUM>`,
    }
  }
  const strMatch = TRAILING_STRING_PRED_RE.exec(expr)
  if (strMatch) {
    const negated = Boolean(strMatch[1]), q1 = strMatch[3]!, leftStr = strMatch[4]!
    const ws1 = strMatch[5] ?? '', operator = strMatch[6]!, ws2 = strMatch[7] ?? '', q2 = strMatch[8]!, rightStr = strMatch[9]!
    const rawTruth = operator === '!=' || operator === '<>' ? leftStr !== rightStr : leftStr === rightStr
    return {
      matchIndex: strMatch.index, truth: negated ? !rawTruth : rawTruth, isLiteralOnly: false, leadingOperand: null,
      negated, comparisonKind: 'string', operator, arithmeticOp: null, operands: [leftStr, rightStr],
      leadPrefix: `${strMatch[1] ?? ''}${strMatch[2] ?? ''}`,
      comparisonSkeleton: `${q1}<STR>${q1}${ws1}${operator}${ws2}${q2}<STR>${q2}`,
    }
  }
  const unclosedMatch = TRAILING_UNCLOSED_STRING_PRED_RE.exec(expr)
  if (unclosedMatch) {
    const negated = Boolean(unclosedMatch[1]), q1 = unclosedMatch[3]!, leftStr = unclosedMatch[4]!
    const ws1 = unclosedMatch[5] ?? '', operator = unclosedMatch[6]!, ws2 = unclosedMatch[7] ?? '', rightStr = unclosedMatch[8]!
    const rawTruth = operator === '!=' || operator === '<>' ? leftStr !== rightStr : leftStr === rightStr
    return {
      matchIndex: unclosedMatch.index, truth: negated ? !rawTruth : rawTruth, isLiteralOnly: false, leadingOperand: null,
      negated, comparisonKind: 'unclosed_string', operator, arithmeticOp: null, operands: [leftStr, rightStr],
      leadPrefix: `${unclosedMatch[1] ?? ''}${unclosedMatch[2] ?? ''}`,
      comparisonSkeleton: `${q1}<STR>${q1}${ws1}${operator}${ws2}${q1}<STR>`,
    }
  }
  const litMatch = TRAILING_LITERAL_PRED_RE.exec(expr)
  if (litMatch) {
    const negated = Boolean(litMatch[1]), litStr = litMatch[3]!
    const rawTruth = litStr.toLowerCase() === 'true'
    return {
      matchIndex: litMatch.index, truth: negated ? !rawTruth : rawTruth, isLiteralOnly: true, leadingOperand: null,
      negated, comparisonKind: 'literal', operator: '', arithmeticOp: null, operands: [litStr],
      leadPrefix: `${litMatch[1] ?? ''}${litMatch[2] ?? ''}`, comparisonSkeleton: '<BOOL>',
    }
  }
  return null
}

function parseBooleanPredicateCore(
  text: string,
  allowCompoundCheck: boolean,
  allowStandalone = false,
  fullRaw?: string,
): ParsedBooleanPredicate | null {
  if (!text || text.length > MAX_PREDICATE_INPUT_LEN) return null
  let expr = text.replace(/[ \t\r\n]+$/, '')
  if (expr.endsWith(';')) expr = expr.slice(0, -1).replace(/[ \t\r\n]+$/, '')
  for (let i = 0; i < 3 && expr.endsWith(')'); i += 1) expr = expr.slice(0, -1).replace(/[ \t\r\n]+$/, '')

  const matched = matchTrailingComparison(expr)
  if (!matched) return null

  const prefix = expr.slice(0, matched.matchIndex)
  const rawSource = fullRaw ?? text
  const trailingSuffix = rawSource.slice(expr.length)

  if (prefix.trim() === '') {
    if (!allowStandalone || matched.isLiteralOnly || prefix.length > 0) return null
    return {
      baseValue: '', predicateClause: rawSource, predicatePrefix: matched.leadPrefix,
      skeleton: `${matched.leadPrefix}${matched.comparisonSkeleton}${trailingSuffix}`,
      quoteDelimiter: '', combinator: '', comparisonKind: matched.comparisonKind,
      operator: matched.operator, arithmeticOp: matched.arithmeticOp, negated: matched.negated,
      operands: matched.operands, rawLength: rawSource.length,
      operandCharClass: charClassSignature(matched.operands.join('')),
      clauseCharClass: charClassSignature(rawSource),
      leadingOperand: matched.leadingOperand, truth: matched.truth,
    }
  }

  const afterComb = stripTrailingSeparators(prefix)
  const combMatch = /(AND|OR|&&|\|\|)$/i.exec(afterComb.rest)
  if (!combMatch) return null
  const combText = combMatch[1]!.toUpperCase() as 'AND' | 'OR' | '&&' | '||'
  const isWordComb = combText === 'AND' || combText === 'OR'
  if (isWordComb && !afterComb.stripped && !expr.slice(matched.matchIndex).startsWith('(')) return null

  const beforeComb = stripTrailingSeparators(afterComb.rest.slice(0, combMatch.index))
  let base = beforeComb.rest
  let hadParen = false
  for (let i = 0; i < 2 && base.endsWith(')'); i += 1) { base = base.slice(0, -1); hadParen = true }
  let quoteDelimiter: '' | "'" | '"' = ''
  if (base.endsWith("'") || base.endsWith('"')) {
    quoteDelimiter = base.slice(-1) as "'" | '"'
    base = base.slice(0, -1)
  }
  if (base.length === 0) return null
  if (isWordComb && !beforeComb.stripped && !hadParen && quoteDelimiter === '') return null
  if (allowCompoundCheck && parseBooleanPredicateCore(base, false, true) !== null) return null

  const predicateClause = rawSource.slice(base.length)
  const predicatePrefix = `${expr.slice(base.length, matched.matchIndex)}${matched.leadPrefix}`
  return {
    baseValue: base, predicateClause, predicatePrefix,
    skeleton: `${predicatePrefix}${matched.comparisonSkeleton}${trailingSuffix}`,
    quoteDelimiter, combinator: combText, comparisonKind: matched.comparisonKind,
    operator: matched.operator, arithmeticOp: matched.arithmeticOp, negated: matched.negated,
    operands: matched.operands, rawLength: rawSource.length,
    operandCharClass: charClassSignature(matched.operands.join('')),
    clauseCharClass: charClassSignature(predicateClause),
    leadingOperand: null, truth: matched.truth,
  }
}

/** Parse an explicit non-empty-base boolean predicate clause and its canonical structural skeleton. */
export function parseBooleanPredicate(raw: string | null): ParsedBooleanPredicate | null {
  if (raw === null || raw.length === 0 || raw.length > MAX_PREDICATE_INPUT_LEN) return null
  const direct = parseBooleanPredicateCore(raw, true, false, raw)
  if (direct) return direct
  const blockComment = TRAILING_INLINE_COMMENT_RE.exec(raw)
  if (blockComment) {
    const parsed = parseBooleanPredicateCore(raw.slice(0, blockComment.index), true, false, raw)
    if (parsed) return parsed
  }
  for (const marker of ['--', '#'] as const) {
    let searchFrom = raw.length
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const idx = raw.lastIndexOf(marker, searchFrom - 1)
      if (idx < 0) break
      const parsed = parseBooleanPredicateCore(raw.slice(0, idx), true, false, raw)
      if (parsed) return parsed
      searchFrom = idx
    }
  }
  return null
}

/** Single shared canonical predicate skeleton parser (`R4-C-1` / `R3-17`). */
export function canonicalPredicateSkeleton(raw: string | null): CanonicalPredicateSkeleton | null {
  return parseBooleanPredicate(raw)
}

export function decodedText(value: string): string {
  try { return decodeURIComponent(value) } catch { return value }
}

/** Parse a standalone or attached boolean predicate (used by `booleanPredicateTruth` in `oracle-invariants.ts`). */
export function parseStandaloneBooleanPredicate(raw: string): ParsedBooleanPredicate | null {
  return parseBooleanPredicateCore(raw, true, true, raw)
}

/** Strip a trailing boolean predicate suffix via `canonicalPredicateSkeleton`. */
export function stripBooleanPredicateSuffix(raw: string): {
  baseValue: string
  predicateTruth: boolean | null
  predicateText: string | null
  skeleton: string | null
} {
  const parsed = canonicalPredicateSkeleton(raw)
  if (!parsed) return { baseValue: raw, predicateTruth: null, predicateText: null, skeleton: null }
  return { baseValue: parsed.baseValue, predicateTruth: parsed.truth, predicateText: parsed.predicateClause, skeleton: parsed.skeleton }
}

/**
 * Core boolean arm base-parity, canonical-skeleton, and equal-length/multiset verifier (`R4-C-1` / `R3-17`).
 * Wrapped by `verify-support.ts::verifyBooleanArmBaseParity` for handler-side defense-in-depth.
 */
export function verifyBooleanArmBaseParityCore(input: {
  controlValue: string
  variantValue: string
  baselineValue?: string
  hostPair?: HostMintedBooleanPairLike
}): { ok: true; sharedBase: string | null; controlTruth: boolean | null; variantTruth: boolean | null } | { ok: false; reason: string } {
  if (input.hostPair) {
    const pair = input.hostPair
    if (pair.baseValue.trim().length === 0) return { ok: false, reason: 'host-minted boolean pair has an empty base value' }
    if (!hasEqualLengthAndCharMultiset(pair.trueValue, pair.falseValue)) {
      return { ok: false, reason: 'host-minted boolean pair violates equal-length and identical character-multiset invariants' }
    }
    if (input.baselineValue !== undefined && input.baselineValue !== pair.baseValue) {
      return { ok: false, reason: `baseline value "${input.baselineValue}" does not match host-minted base "${pair.baseValue}"` }
    }
    const ctlIsTrue = input.controlValue === pair.trueValue && input.variantValue === pair.falseValue
    const ctlIsFalse = input.controlValue === pair.falseValue && input.variantValue === pair.trueValue
    if (!ctlIsTrue && !ctlIsFalse) return { ok: false, reason: 'control and variant arms do not match the host-minted boolean pair' }
    return { ok: true, sharedBase: pair.baseValue, controlTruth: ctlIsTrue, variantTruth: ctlIsFalse }
  }

  const ctl = stripBooleanPredicateSuffix(input.controlValue)
  const vr = stripBooleanPredicateSuffix(input.variantValue)
  const base = input.baselineValue !== undefined ? stripBooleanPredicateSuffix(input.baselineValue) : null
  if ((base && base.predicateTruth !== null) || (input.baselineValue !== undefined && STANDALONE_EMPTY_BASE_PRED_RE.test(input.baselineValue))) {
    return { ok: false, reason: 'baseline arm must carry a benign non-predicate base value' }
  }
  if ((ctl.predicateTruth === null && STANDALONE_EMPTY_BASE_PRED_RE.test(input.controlValue)) ||
      (vr.predicateTruth === null && STANDALONE_EMPTY_BASE_PRED_RE.test(input.variantValue))) {
    return { ok: false, reason: 'empty-base or standalone boolean predicates are forbidden' }
  }
  if (ctl.predicateTruth !== null && vr.predicateTruth !== null) {
    if (ctl.predicateTruth === vr.predicateTruth) return { ok: false, reason: 'boolean differential arms must carry opposite explicit boolean predicates' }
    if (ctl.baseValue !== vr.baseValue) return { ok: false, reason: `boolean predicate arms have mismatched base values ("${ctl.baseValue}" vs "${vr.baseValue}"); arms must share the identical base value` }
    if (input.baselineValue !== undefined && input.baselineValue !== ctl.baseValue) return { ok: false, reason: `baseline value "${input.baselineValue}" does not match boolean arm base "${ctl.baseValue}"` }
    if (ctl.skeleton !== vr.skeleton) return { ok: false, reason: 'boolean predicate arms must share the exact canonical predicate skeleton' }
    if (!hasEqualLengthAndCharMultiset(input.controlValue, input.variantValue)) {
      return { ok: false, reason: 'boolean predicate arms must have identical byte length and character multiset' }
    }
    return { ok: true, sharedBase: ctl.baseValue, controlTruth: ctl.predicateTruth, variantTruth: vr.predicateTruth }
  }
  if (ctl.predicateTruth !== null || vr.predicateTruth !== null) {
    const predArm = ctl.predicateTruth !== null ? ctl : vr
    const benignVal = ctl.predicateTruth !== null ? input.variantValue : input.controlValue
    if (predArm.baseValue !== benignVal) return { ok: false, reason: `boolean predicate arm base "${predArm.baseValue}" does not match benign arm value "${benignVal}"` }
    if (input.baselineValue !== undefined && input.baselineValue !== benignVal) return { ok: false, reason: `baseline value "${input.baselineValue}" does not match shared base "${benignVal}"` }
    return { ok: true, sharedBase: benignVal, controlTruth: ctl.predicateTruth, variantTruth: vr.predicateTruth }
  }
  return { ok: true, sharedBase: input.baselineValue ?? null, controlTruth: null, variantTruth: null }
}

function leafClassOf(value: string, param?: string | null): string {
  if (value === '') return 'empty'
  if (UUID_TEXT_RE.test(value)) return 'uuid'
  if (/^-?\d+$/.test(value)) {
    const n = Number(value)
    return n === 0 ? 'num:zero' : n === 1 ? 'num:one' : n > 0 ? 'num:many' : 'num:negative'
  }
  if (/^(?:true|false)$/i.test(value)) return `bool:${value.toLowerCase()}`
  if (param && value.toLowerCase().includes(param.toLowerCase())) return 'predicate'
  if (/^[A-Za-z0-9_+/=-]{16,}$/.test(value)) return 'token'
  return value.length <= 32 ? 'short' : 'long'
}

function structuralSignature(value: unknown, param?: string | null): Map<string, string> {
  const out = new Map<string, string>()
  const walk = (node: unknown, path: string, depth: number): void => {
    if (depth > 6 || out.size >= 256) return
    const key = path || '$'
    if (node === null || node === undefined) { out.set(key, 'null'); return }
    if (Array.isArray(node)) {
      out.set(`${key}[]`, node.length === 0 ? 'len:0' : node.length === 1 ? 'len:1' : node.length <= 3 ? 'len:few' : 'len:many')
      for (let i = 0; i < Math.min(node.length, 8); i += 1) walk(node[i], `${key}[${i}]`, depth + 1)
      return
    }
    if (typeof node === 'object') {
      for (const [childKey, child] of Object.entries(node as Record<string, unknown>).slice(0, 64)) {
        walk(child, path ? `${path}.${childKey}` : childKey, depth + 1)
      }
      return
    }
    out.set(key, leafClassOf(String(node), param))
  }
  walk(value, '', 0)
  if (out.size === 0) out.set('$', 'empty')
  return out
}

function bodySignature(arm: BooleanDifferentialArm, param?: string | null): Map<string, string> {
  const signature = arm.json !== undefined
    ? structuralSignature(arm.json, param)
    : (() => {
        const text = String(arm.body ?? '')
        const out = new Map<string, string>()
        out.set('body.length', text.length === 0 ? 'len:0' : text.length < 64 ? 'len:small' : text.length < 1024 ? 'len:medium' : 'len:large')
        const lines = text.split('\n').length
        out.set('body.lines', lines <= 1 ? 'len:1' : lines <= 8 ? 'len:few' : 'len:many')
        const tags = (text.match(/<\s*[A-Za-z][^>]*>/g) ?? []).length
        out.set('body.tags', tags === 0 ? 'tags:0' : tags <= 2 ? 'tags:few' : tags <= 8 ? 'tags:many' : 'tags:lots')
        return out
      })()
  signature.set('$status', arm.status === null ? 'none' : `${Math.floor(arm.status / 100)}xx`)
  return signature
}

function rawTextBodyOf(arm: BooleanDifferentialArm): string | undefined {
  if (typeof arm.requestBody === 'string' && arm.requestBody.length > 0) return arm.requestBody
  if (typeof arm.requestJson === 'string' && arm.requestJson.length > 0) return arm.requestJson
  return undefined
}

function findXmlTagRange(text: string, tagName: string, fromIndex = 0): { openEnd: number; closeStart: number; closeEnd: number } | null {
  const lower = text.toLowerCase(), needle = `<${tagName.toLowerCase()}`, closeNeedle = `</${tagName.toLowerCase()}>`
  let pos = fromIndex
  while (pos < lower.length) {
    const start = lower.indexOf(needle, pos)
    if (start < 0) return null
    const after = lower[start + needle.length]
    if (after !== '>' && after !== ' ' && after !== '\t' && after !== '\n' && after !== '\r' && after !== '/') {
      pos = start + needle.length; continue
    }
    const openEnd = lower.indexOf('>', start + needle.length)
    if (openEnd < 0) return null
    if (lower[openEnd - 1] === '/') { pos = openEnd + 1; continue }
    const closeStart = lower.indexOf(closeNeedle, openEnd + 1)
    if (closeStart < 0) return null
    return { openEnd: openEnd + 1, closeStart, closeEnd: closeStart + closeNeedle.length }
  }
  return null
}

function decodeBasicXmlEntities(value: string): string {
  return value.replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&apos;|&#0*39;|&#x0*27;/gi, "'").replace(/&amp;/gi, '&')
}

function extractBooleanParamValue(arm: BooleanDifferentialArm, param: string): string | null {
  if (arm.pathAndQuery) {
    try { const v = new URL(arm.pathAndQuery, 'http://kovo.invalid').searchParams.get(param); if (v !== null) return v } catch { /* ignore */ }
  }
  if (arm.requestJson && typeof arm.requestJson === 'object') {
    const wanted = param.split('.').pop() ?? param
    const walk = (node: unknown): string | null => {
      if (!node || typeof node !== 'object') return null
      if (Array.isArray(node)) { for (const item of node) { const h = walk(item); if (h !== null) return h }; return null }
      for (const [k, child] of Object.entries(node as Record<string, unknown>)) {
        if (k === param || k === wanted) return child === undefined || child === null ? null : String(child)
        const h = walk(child); if (h !== null) return h
      }
      return null
    }
    const hit = walk(arm.requestJson)
    if (hit !== null) return hit
  }
  const rawBody = rawTextBodyOf(arm)
  if (rawBody && rawBody.trim()) {
    const trimmed = rawBody.trim().slice(0, 64 * 1024), wanted = param.split('.').pop() ?? param
    if (trimmed.startsWith('<')) {
      const range = findXmlTagRange(trimmed, wanted)
      if (range) return decodeBasicXmlEntities(trimmed.slice(range.openEnd, range.closeStart))
    }
    if (trimmed.includes('=')) {
      try {
        const sp = new URLSearchParams(trimmed)
        if (sp.has(param)) return sp.get(param)
        if (wanted !== param && sp.has(wanted)) return sp.get(wanted)
      } catch { /* ignore */ }
    }
  }
  if (arm.requestHeaders) {
    const wanted = param.toLowerCase()
    for (const [k, v] of Object.entries(arm.requestHeaders)) if (k.toLowerCase() === wanted) return v
  }
  return null
}

function maskJsonParam(value: unknown, param: string): unknown {
  const wanted = param.split('.').pop() ?? param
  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(walk)
    if (!node || typeof node !== 'object') return node
    const out: Record<string, unknown> = {}
    for (const [k, child] of Object.entries(node as Record<string, unknown>)) {
      out[k] = k === param || k === wanted ? '{{injected}}' : walk(child)
    }
    return out
  }
  return walk(value)
}

function maskTextBodyParam(rawBody: string | undefined, param: string): string | null {
  if (!rawBody || !rawBody.trim()) return null
  const trimmed = rawBody.trim().slice(0, 64 * 1024), wanted = param.split('.').pop() ?? param
  if (trimmed.startsWith('<')) {
    let out = '', cursor = 0
    while (cursor < trimmed.length) {
      const range = findXmlTagRange(trimmed, wanted, cursor)
      if (!range) { out += trimmed.slice(cursor); break }
      out += trimmed.slice(cursor, range.openEnd) + '{{injected}}' + trimmed.slice(range.closeStart, range.closeEnd)
      cursor = range.closeEnd
    }
    return out
  }
  if (trimmed.includes('=')) {
    try {
      const sp = new URLSearchParams(trimmed)
      if (sp.has(param)) sp.set(param, '{{injected}}')
      else if (wanted !== param && sp.has(wanted)) sp.set(wanted, '{{injected}}')
      return [...sp.entries()].map(([k, v]) => `${k}=${v}`).sort().join('&')
    } catch { /* ignore */ }
  }
  return trimmed
}

function maskedPath(pathAndQuery: string | undefined, param: string, maskSegmentIndex?: number | null): string {
  if (!pathAndQuery) return ''
  try {
    const url = new URL(pathAndQuery, 'http://kovo.invalid')
    if (url.searchParams.has(param)) url.searchParams.set(param, '{{injected}}')
    let pathname = url.pathname
    if (maskSegmentIndex !== undefined && maskSegmentIndex !== null && maskSegmentIndex >= 0) {
      const segs = pathname.split('/')
      if (maskSegmentIndex < segs.length) { segs[maskSegmentIndex] = '{{injected}}'; pathname = segs.join('/') }
    }
    return `${pathname}?${[...url.searchParams.entries()].map(([k, v]) => `${k}=${v}`).sort().join('&')}`
  } catch { return pathAndQuery }
}

function requestShape(arm: BooleanDifferentialArm, param: string, maskSegmentIndex?: number | null): string {
  const excluded = param ? param.toLowerCase() : null
  let authDigest = typeof arm.authDigest === 'string' && arm.authDigest.trim().length > 0 ? arm.authDigest.trim().toLowerCase() : ''
  if (!authDigest) {
    const pairs: string[] = []
    for (const [k, v] of Object.entries(arm.requestHeaders ?? {})) {
      const lk = k.toLowerCase()
      if (!AUTH_SHAPE_HEADERS.has(lk) || (excluded && lk === excluded)) continue
      pairs.push(`${lk}=${v}`)
    }
    if (pairs.length > 0) { pairs.sort(); authDigest = createHash('sha256').update(pairs.join('\n')).digest('hex').slice(0, 16) }
  }
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(arm.requestHeaders ?? {})) {
    const lk = k.toLowerCase()
    if (BOOLEAN_VOLATILE_HEADERS.has(lk)) continue
    headers[lk] = excluded && lk === excluded ? '{{injected}}' : v
  }
  const rawBody = rawTextBodyOf(arm)
  return JSON.stringify({
    origin: (arm.origin ?? '').trim().toLowerCase(),
    persona: (arm.persona ?? '').trim().toLowerCase(),
    authDigest,
    method: (arm.method ?? '').toUpperCase(),
    path: maskedPath(arm.pathAndQuery, param, maskSegmentIndex),
    json: arm.requestJson === undefined || typeof arm.requestJson === 'string' ? null : maskJsonParam(arm.requestJson, param),
    body: rawBody === undefined ? null : maskTextBodyParam(rawBody, param),
    headers,
  })
}

function collectArmParams(arm: BooleanDifferentialArm): Map<string, string> {
  const out = new Map<string, string>()
  if (arm.pathAndQuery) {
    try { for (const [k, v] of new URL(arm.pathAndQuery, 'http://kovo.invalid').searchParams.entries()) if (!out.has(k)) out.set(k, v) } catch { /* ignore */ }
  }
  if (arm.requestJson && typeof arm.requestJson === 'object') {
    for (const [path, v] of flattenJson(arm.requestJson)) { const leaf = path.split('.').pop() ?? path; if (!out.has(leaf)) out.set(leaf, v) }
  }
  const rawBody = rawTextBodyOf(arm)
  if (rawBody && rawBody.trim() && !rawBody.trim().startsWith('<') && rawBody.includes('=')) {
    try { for (const [k, v] of new URLSearchParams(rawBody.trim().slice(0, 64 * 1024))) if (!out.has(k)) out.set(k, v) } catch { /* ignore */ }
  }
  for (const [k, v] of Object.entries(arm.requestHeaders ?? {})) {
    const lk = k.toLowerCase()
    if (!BOOLEAN_VOLATILE_HEADERS.has(lk) && !out.has(lk)) out.set(lk, v)
  }
  return out
}

function deriveUniqueBooleanParam(baseline: BooleanDifferentialArm, armA: BooleanDifferentialArm, armB: BooleanDifferentialArm): string | null {
  const bMap = collectArmParams(baseline), aMap = collectArmParams(armA), cMap = collectArmParams(armB)
  const differing: string[] = []
  for (const key of new Set([...bMap.keys(), ...aMap.keys(), ...cMap.keys()])) {
    if (bMap.get(key) !== aMap.get(key) || bMap.get(key) !== cMap.get(key) || aMap.get(key) !== cMap.get(key)) differing.push(key)
  }
  return differing.length === 1 ? differing[0]! : null
}

function extractDifferingPathSegment(
  baseline: BooleanDifferentialArm, armA: BooleanDifferentialArm, armB: BooleanDifferentialArm,
): { segmentIndex: number; baseVal: string; valA: string; valB: string } | null {
  if (!baseline.pathAndQuery || !armA.pathAndQuery || !armB.pathAndQuery) return null
  try {
    const bSegs = new URL(baseline.pathAndQuery, 'http://kovo.invalid').pathname.split('/')
    const aSegs = new URL(armA.pathAndQuery, 'http://kovo.invalid').pathname.split('/')
    const cSegs = new URL(armB.pathAndQuery, 'http://kovo.invalid').pathname.split('/')
    if (bSegs.length !== aSegs.length || bSegs.length !== cSegs.length) return null
    const diffs: number[] = []
    for (let i = 0; i < bSegs.length; i += 1) {
      if (bSegs[i] !== aSegs[i] || bSegs[i] !== cSegs[i] || aSegs[i] !== cSegs[i]) diffs.push(i)
    }
    if (diffs.length !== 1) return null
    const idx = diffs[0]!
    return { segmentIndex: idx, baseVal: decodedText(bSegs[idx]!), valA: decodedText(aSegs[idx]!), valB: decodedText(cSegs[idx]!) }
  } catch { return null }
}

function resolveTriangleValues(input: {
  baseline: BooleanDifferentialArm; armA: BooleanDifferentialArm; armB: BooleanDifferentialArm; param?: string | null; requireNamedParam?: boolean
}): { param: string; baselineVal: string | null; valA: string | null; valB: string | null; pathSegmentIndex: number | null } {
  const explicitParam = input.param?.trim() || ''
  let param = explicitParam || (input.requireNamedParam ? '' : (deriveUniqueBooleanParam(input.baseline, input.armA, input.armB) ?? ''))
  let baselineVal = param ? extractBooleanParamValue(input.baseline, param) : null
  let valA = param ? extractBooleanParamValue(input.armA, param) : null
  let valB = param ? extractBooleanParamValue(input.armB, param) : null
  let pathSegmentIndex: number | null = null
  if (baselineVal === null && valA === null && valB === null) {
    const pathDiff = extractDifferingPathSegment(input.baseline, input.armA, input.armB)
    if (pathDiff && (param !== '' || !input.requireNamedParam)) {
      pathSegmentIndex = pathDiff.segmentIndex
      baselineVal = pathDiff.baseVal; valA = pathDiff.valA; valB = pathDiff.valB
      if (!param) param = `$path[${pathDiff.segmentIndex}]`
    }
  }
  return { param, baselineVal, valA, valB, pathSegmentIndex }
}

/** Shared kernel-side boolean triangle base-binding & skeleton verifier (`R4-C-1` / `R3-C-4` / `R3-17`). */
export function verifyBooleanTriangleBinding(input: {
  baseline: BooleanDifferentialArm
  armA: BooleanDifferentialArm
  armB: BooleanDifferentialArm
  param?: string | null
  requireNamedParam?: boolean
  hostPair?: HostBooleanPairBinding | null
  allowUnequalLength?: boolean
}): BooleanTriangleBindingResult {
  const fail = (code: BooleanTriangleBindingResult['code'], reason: string, param: string | null = null, pathSegmentIndex: number | null = null): BooleanTriangleBindingResult => ({
    ok: false, param, baseValue: null, trueArm: null, code, reason, pathSegmentIndex, skeleton: null,
  })
  const { param, baselineVal, valA, valB, pathSegmentIndex } = resolveTriangleValues(input)
  if (!param) return fail('param', 'A boolean differential must name a single injected parameter.')
  const baseShape = requestShape(input.baseline, param, pathSegmentIndex)
  if (baseShape !== requestShape(input.armA, param, pathSegmentIndex) || baseShape !== requestShape(input.armB, param, pathSegmentIndex)) {
    return fail('shape', 'The baseline, true-variant, and false-variant arms differ beyond the injected parameter (origin, persona, auth, or request shape mismatch).', param, pathSegmentIndex)
  }
  if (baselineVal === null || valA === null || valB === null) {
    return fail('base_binding', `The named injected parameter "${param}" must be present in the baseline, true-variant, and false-variant arms.`, param, pathSegmentIndex)
  }
  if (baselineVal.trim() === '') {
    return fail('base_binding', `The baseline arm for "${param}" must carry a non-empty benign value; empty-base predicates are rejected.`, param, pathSegmentIndex)
  }
  if (canonicalPredicateSkeleton(baselineVal) !== null || parseBooleanPredicateCore(baselineVal, true, true, baselineVal) !== null) {
    return fail('predicate', 'The baseline arm must carry a benign non-predicate value, not an injected boolean expression.', param, pathSegmentIndex)
  }
  if (input.hostPair) {
    const pair = input.hostPair
    if (baselineVal !== pair.baseValue) return fail('base_binding', `The baseline value for "${param}" does not match the host-minted boolean pair base value.`, param, pathSegmentIndex)
    if (!((valA === pair.trueValue && valB === pair.falseValue) || (valA === pair.falseValue && valB === pair.trueValue))) {
      return fail('base_binding', `The true and false arm values for "${param}" do not match the host-minted boolean pair byte-for-byte.`, param, pathSegmentIndex)
    }
  }
  const parsedA = canonicalPredicateSkeleton(valA)
  const parsedB = canonicalPredicateSkeleton(valB)
  if (!parsedA || !parsedB || parsedA.truth === parsedB.truth) {
    return fail('predicate', 'The true and false variant arms must carry opposite, explicit non-empty-base boolean predicate expressions on the named parameter; standalone empty-base predicates and bare literals (1/0, true/false) are rejected.', param, pathSegmentIndex)
  }
  const trueParsed = parsedA.truth ? parsedA : parsedB
  const falseParsed = parsedA.truth ? parsedB : parsedA
  if (trueParsed.baseValue === '' || falseParsed.baseValue === '') return fail('base_binding', `Empty-base boolean predicates on "${param}" are rejected.`, param, pathSegmentIndex)
  if (trueParsed.baseValue !== falseParsed.baseValue) return fail('base_binding', `The true and false arms do not share a byte-identical base value for "${param}" once the predicate clause is stripped (integer-coercion/base-value mismatch).`, param, pathSegmentIndex)
  if (trueParsed.baseValue !== baselineVal) return fail('base_binding', `The stripped base value for "${param}" in the true/false arms does not equal the baseline arm's value (base-value binding mismatch).`, param, pathSegmentIndex)
  if (trueParsed.quoteDelimiter !== falseParsed.quoteDelimiter) return fail('base_binding', `The true and false arms use mismatched quote breakout delimiters on "${param}".`, param, pathSegmentIndex)
  if (trueParsed.predicatePrefix !== falseParsed.predicatePrefix || trueParsed.skeleton !== falseParsed.skeleton) {
    return fail('skeleton', `The true and false arms on "${param}" do not share the same canonical predicate skeleton (validator/operator asymmetry rejected).`, param, pathSegmentIndex)
  }
  if (trueParsed.clauseCharClass !== falseParsed.clauseCharClass || trueParsed.operandCharClass !== falseParsed.operandCharClass) {
    return fail('skeleton', `The true and false arms on "${param}" use differing character classes or symbol multisets (charset-validator asymmetry rejected).`, param, pathSegmentIndex)
  }
  if (!input.allowUnequalLength) {
    const operandLengthsMatch = trueParsed.operands.length === falseParsed.operands.length &&
      trueParsed.operands.every((op, idx) => op.length === falseParsed.operands[idx]!.length)
    if (trueParsed.rawLength !== falseParsed.rawLength || !operandLengthsMatch) {
      return fail('skeleton', `The true and false arms on "${param}" have unequal lengths (${trueParsed.rawLength} vs ${falseParsed.rawLength}); length-asymmetric predicate pairs are rejected.`, param, pathSegmentIndex)
    }
  }
  return {
    ok: true, param, baseValue: baselineVal, trueArm: parsedA.truth ? 'armA' : 'armB',
    code: 'ok', reason: '', pathSegmentIndex, skeleton: trueParsed.skeleton,
    trueArmLength: trueParsed.rawLength, falseArmLength: falseParsed.rawLength,
  }
}

/** Single stamped host-minted boolean-pair round verifier (`R4-C-1` / `R3-16` / `R3-17`). */
export function verifyStampedBooleanPairRound(
  input: StampedBooleanPairRoundInput,
): { ok: true; challenge: HostMintedBooleanPairChallenge } | { ok: false; reason: string } {
  if (!input.runId) return { ok: false, reason: 'hostBooleanPair verification requires a host runId (zero wildcard fallback).' }
  const stampA = input.armA.hostBooleanPair
  const stampB = input.armB.hostBooleanPair
  if (!stampA || !stampB) {
    return { ok: false, reason: 'missing host-minted hostBooleanPair stamp on true/false arms; worker-chosen boolean predicate pairs are rejected.' }
  }
  const bindFor = (e: ReceiptTranscriptEntry, arm: BooleanPairArm) => ({
    runId: input.runId!,
    origin: e.origin ? input.normalizeOrigin(e.origin) : input.targetOrigin,
    method: e.step.method,
    route: input.exactPathnameOf(e.step.pathAndQuery ?? e.step.route ?? '/'),
    param: input.param,
    armRole: arm,
    exchangeId: e.exchangeId,
  })
  const verifiedA = input.oracle.verifyBooleanPair(stampA, bindFor(input.armA, stampA.arm))
  const verifiedB = input.oracle.verifyBooleanPair(stampB, bindFor(input.armB, stampB.arm))
  if (!verifiedA || !verifiedB) {
    return { ok: false, reason: 'hostBooleanPair stamp failed HostMintedOracle verification (unminted challengeId, mismatched values, unequal length, or mismatched character multiset).' }
  }
  if (verifiedA.challengeId !== verifiedB.challengeId) {
    return { ok: false, reason: `paired true/false arms cite different hostBooleanPair challengeIds (${verifiedA.challengeId} vs ${verifiedB.challengeId}).` }
  }
  if (verifiedA.param && verifiedA.param !== input.param) {
    return { ok: false, reason: `hostBooleanPair param (${verifiedA.param}) does not match target param (${input.param}).` }
  }
  const aIsTrue = stampA.arm === 'true' && stampB.arm === 'false'
  const aIsFalse = stampA.arm === 'false' && stampB.arm === 'true'
  if (input.requireArmATrue ? !aIsTrue : (!aIsTrue && !aIsFalse)) {
    return { ok: false, reason: `paired arms must carry opposing host-minted true/false stamps (got ${stampA.arm} and ${stampB.arm}).` }
  }
  if (input.requireBaseline || input.baseline) {
    if (!input.baseline?.hostBooleanPair) return { ok: false, reason: 'baseline arm is missing its host-minted hostBooleanPair stamp.' }
    const verifiedBase = input.oracle.verifyBooleanPair(input.baseline.hostBooleanPair, bindFor(input.baseline, 'baseline'))
    if (!verifiedBase || verifiedBase.challengeId !== verifiedA.challengeId || input.baseline.hostBooleanPair.arm !== 'baseline') {
      return { ok: false, reason: 'baseline arm hostBooleanPair stamp does not match the round challengeId/baseline role.' }
    }
    if (input.extractParam(input.baseline, input.param) !== input.baseline.hostBooleanPair.mintedValue) {
      return { ok: false, reason: `baseline request param "${input.param}" does not equal host-minted baseValue byte for byte.` }
    }
  }
  if (input.extractParam(input.armA, input.param) !== stampA.mintedValue) {
    return { ok: false, reason: `arm "${input.armA.exchangeId}" param "${input.param}" does not equal host-minted value byte for byte.` }
  }
  if (input.extractParam(input.armB, input.param) !== stampB.mintedValue) {
    return { ok: false, reason: `arm "${input.armB.exchangeId}" param "${input.param}" does not equal host-minted value byte for byte.` }
  }
  return { ok: true, challenge: verifiedA }
}

function differentialPaths(control: BooleanDifferentialArm, probe: BooleanDifferentialArm, param: string): { changed: string[]; echoed: string[] } {
  const controlRaw = control.json !== undefined ? flattenJson(control.json) : new Map([['body.text', String(control.body ?? '')]])
  const probeRaw = probe.json !== undefined ? flattenJson(probe.json) : new Map([['body.text', String(probe.body ?? '')]])
  const controlSig = bodySignature(control, param), probeSig = bodySignature(probe, param)
  const paths = new Set([...controlRaw.keys(), ...probeRaw.keys(), ...controlSig.keys(), ...probeSig.keys()])
  const injected = [extractBooleanParamValue(probe, param) ?? '', extractBooleanParamValue(control, param) ?? ''].filter(Boolean)
  const changed: string[] = [], echoed: string[] = []
  for (const path of paths) {
    if ((controlSig.get(path) ?? '') === (probeSig.get(path) ?? '')) continue
    changed.push(path)
    const leaf = path.split('.').pop() ?? path
    if (isBooleanDifferentialEchoOnly(controlRaw.get(path) ?? '', probeRaw.get(path) ?? '', leaf, param, injected)) {
      echoed.push(path)
    }
  }
  return { changed, echoed }
}

function signatureMapKey(map: Map<string, string>): string {
  return [...map.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('|')
}

/** Paired multi-round baseline/true/false boolean-differential oracle (`C-7` / `R4-C-1` / `R3-17`). */
export function assessBooleanDifferential(input: {
  rounds: readonly BooleanDifferentialRound[]
  param?: string | null
  baseline?: BooleanDifferentialArm
  hostPair?: HostBooleanPairBinding | null
}): BooleanDifferentialAssessment {
  const param = input.param?.trim() || ''
  const evidence: BooleanDifferentialAssessment['evidence'] = {
    rounds: input.rounds.length, stable: false, controlStable: false, probeStable: false,
    requestShapeMismatch: false, serverErrors: false, echoedOnly: false, predicateContrast: false,
    changedPaths: [], echoPaths: [], hasBaseline: false, baselineStable: false,
    trueMatchesBaseline: false, baseBindingMismatch: false, statusClassMismatch: false,
  }
  const reject = (reason: string): BooleanDifferentialAssessment => ({ required: true, satisfied: false, reason, evidence })
  if (!param) return reject('A boolean differential must name the injected parameter.')
  if (input.rounds.length < 2) return reject('A boolean differential needs at least two paired baseline/true/false triangle rounds.')

  const triangles: Array<{ baseline: BooleanDifferentialArm; trueArm: BooleanDifferentialArm; falseArm: BooleanDifferentialArm }> = []
  for (const round of input.rounds) {
    const baseline = round.baseline ?? input.baseline
    if (!baseline) return reject('A boolean differential requires a full baseline / true-variant / false-variant triangle in every round; bare two-arm structural_diff alone cannot confirm.')
    if ((baseline.status ?? 0) >= 500 || (round.control.status ?? 0) >= 500 || (round.probe.status ?? 0) >= 500) {
      evidence.serverErrors = true
      return reject('A boolean differential arm returned a server error (5xx); error behaviour is not proof.')
    }
    const binding = verifyBooleanTriangleBinding({
      baseline, armA: round.control, armB: round.probe, param, requireNamedParam: true,
      hostPair: round.hostPair ?? input.hostPair ?? null,
    })
    if (!binding.ok) {
      if (binding.code === 'shape') evidence.requestShapeMismatch = true
      if (binding.code === 'base_binding') evidence.baseBindingMismatch = true
      return reject(binding.reason)
    }
    const trueArm = binding.trueArm === 'armA' ? round.control : round.probe
    const falseArm = binding.trueArm === 'armA' ? round.probe : round.control
    const baseClass = baseline.status === null ? null : Math.floor(baseline.status / 100)
    const trueClass = trueArm.status === null ? null : Math.floor(trueArm.status / 100)
    const falseClass = falseArm.status === null ? null : Math.floor(falseArm.status / 100)
    if (baseClass === null || trueClass === null || falseClass === null || trueClass !== baseClass || falseClass !== baseClass) {
      evidence.statusClassMismatch = true
      return reject(`Boolean differential arms must remain in the baseline HTTP status class (${baseline.status ?? 'none'} vs true=${trueArm.status ?? 'none'} / false=${falseArm.status ?? 'none'}); 4xx validator/error divergences are rejected.`)
    }
    triangles.push({ baseline, trueArm, falseArm })
  }
  evidence.hasBaseline = true
  evidence.predicateContrast = true

  const baselineSignatures = triangles.map(tri => signatureMapKey(bodySignature(tri.baseline, param)))
  const trueSignatures = triangles.map(tri => signatureMapKey(bodySignature(tri.trueArm, param)))
  const falseSignatures = triangles.map(tri => signatureMapKey(bodySignature(tri.falseArm, param)))
  const controlSignatures = input.rounds.map(round => signatureMapKey(bodySignature(round.control, param)))
  const probeSignatures = input.rounds.map(round => signatureMapKey(bodySignature(round.probe, param)))
  evidence.baselineStable = new Set(baselineSignatures).size === 1
  evidence.controlStable = new Set(controlSignatures).size === 1
  evidence.probeStable = new Set(probeSignatures).size === 1
  if (!evidence.baselineStable || !evidence.controlStable || !evidence.probeStable) {
    return reject('The baseline, true-variant, or false-variant response structure was unstable across rounds; a moving baseline is not a differential.')
  }
  evidence.trueMatchesBaseline = triangles.every((_, idx) => trueSignatures[idx] === baselineSignatures[idx])
  if (!evidence.trueMatchesBaseline) {
    return reject('The true-predicate variant did not match the benign baseline response structure; a bare structural_diff without true=baseline equivalence is not boolean evaluation.')
  }

  const roundDiffs = triangles.map(tri => differentialPaths(tri.trueArm, tri.falseArm, param))
  const structural = roundDiffs.map(diff => diff.echoed.length === diff.changed.length ? '' : [...diff.changed].filter(path => !diff.echoed.includes(path)).sort().join(','))
  evidence.echoPaths = [...new Set(roundDiffs.flatMap(diff => diff.echoed))]
  evidence.changedPaths = [...new Set(structural.flatMap(value => value ? value.split(',') : []))]
  if (roundDiffs.every(diff => diff.changed.length > 0 && diff.echoed.length === diff.changed.length)) {
    evidence.echoedOnly = true
    return reject('The only difference was the injected predicate echoed back (or a rotating nonce); no structural response change.')
  }
  if (structural.some(value => value === '')) {
    return reject('At least one round showed no structural response change between true and false variants; a boolean differential must reproduce every round.')
  }
  if (new Set(structural).size !== 1 || new Set(falseSignatures).size !== 1) {
    return reject('The structural response difference was unstable across rounds; the boolean differential must be identical each round.')
  }
  evidence.stable = true
  return {
    required: true,
    satisfied: true,
    reason: `Full baseline/true/false triangle reproduced across ${input.rounds.length} rounds (true matched baseline; false diverged in ${evidence.changedPaths.slice(0, 6).join(', ')}) after token stripping, with matching origin/persona/auth and no 5xx.`,
    evidence,
  }
}
