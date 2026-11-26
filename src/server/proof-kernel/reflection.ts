/**
 * Proof Kernel — Single Fail-Closed Reflection & Carrier Normalization Stage (`R3-17`).
 *
 * Concept-owned authority for ALL request-carrier decoding, malformed-escape fail-closed
 * rejection, and anti-reflection / echo predicates across the confirmation kernel:
 *   - Single canonical carrier normalizer: `normalizeRequestCarrier()` (replaces the prior
 *     dual `normalizeRequestCarrier` + `normalizeCarrierForAntiReflection` + signed-URL
 *     carrier wrapper).
 *   - Explicit fail-closed malformed-input rejection mode (`malformedMode: 'reject' | 'flag'`,
 *     plus `strictJson` validation); malformed URL/JSON/encoding NEVER silently passes as
 *     non-echoed.
 *   - All oracle echo predicates (injection fingerprint stripping, evaluated-expression
 *     anti-reflection, signed-URL echo & traversal differential, and boolean-differential
 *     echo classification) live strictly in this module.
 *
 * Pure leaf module (zero runtime imports from other `src/server/*` modules).
 */

export interface RequestCarrierInput {
  pathAndQuery?: string | null
  requestBody?: string | null
  requestJson?: unknown
  requestHeaders?: Readonly<Record<string, string>> | null
}

export interface NormalizeCarrierOptions {
  /** Whether to percent-decode raw string fragments (default: true). */
  decodePercent?: boolean
  /**
   * Fail-closed malformed-input handling:
   * - `'flag'` (default): marks `malformedEscape: true` + `malformedReason` so every echo/reflection
   *   predicate fails closed (treats malformed carrier as reflected/rejected).
   * - `'reject'`: immediately throws `MalformedCarrierError`.
   */
  malformedMode?: 'flag' | 'reject'
  /** When true, malformed JSON syntax in a JSON-shaped body also triggers `malformedEscape`. */
  strictJson?: boolean
}

export interface NormalizedRequestCarrier {
  /** Raw concatenated carrier text (bounded). */
  readonly raw: string
  /** True when any malformed URL percent-escape, malformed JSON unicode escape, or strict-JSON error was observed. */
  readonly malformedEscape: boolean
  /** Compatibility alias for `malformedEscape` on single-fragment callers (`R4-C-3`). */
  readonly hadMalformedPercentEscape: boolean
  /** Machine-readable malformed-input reason, or null when clean. */
  readonly malformedReason: string | null
  /** True when a JSON-shaped request body failed `JSON.parse`. */
  readonly malformedJson: boolean
  /** Per-component raw + decoded input values (excluding pure transport headers). */
  readonly inputComponents: string[]
  /** Transport-level header values (Host, User-Agent, Accept, etc.). */
  readonly transportHeaderComponents: string[]
  /** Joined decoded input components for containment checks. */
  readonly combinedDecoded: string
  /** Deletion-normalized comparable text of the primary/combined carrier (whitespace-collapsed, lowercase). */
  readonly comparable: string
  /** Alphanumeric core (`[a-z0-9]+`) of the primary/combined carrier after full deletion normalization. */
  readonly alnumCore: string
  /** Per-component deletion-normalized comparable strings. */
  readonly comparables: string[]
  /** Per-component deletion-normalized alphanumeric cores. */
  readonly alnumCores: string[]
  /** Normalized parameter map extracted from query, JSON leaves, and form body (`body:<key>`). */
  readonly params: Record<string, string>
}

export class MalformedCarrierError extends Error {
  readonly reason: string
  constructor(reason: string) {
    super(`Malformed request carrier (${reason}); anti-reflection fails closed.`)
    this.name = 'MalformedCarrierError'
    this.reason = reason
  }
}

export interface ReflectionEchoStepInput {
  pathAndQuery?: string
  requestJson?: unknown
  requestBody?: string
  requestHeaders?: Record<string, string> | null
  json?: unknown
  body?: string
}

export interface ExpressionChallengeShape {
  readonly operandA: number
  readonly operandB: number
  readonly operator: '*' | '+'
  readonly expectedOutput: string
}

export interface SignedUrlResponseInput {
  responseBody?: string | null
  responseJson?: unknown
  responseHeaders?: Record<string, string> | null
}

const TRANSPORT_HEADER_NAME_RE = /^(?:host|content-length|content-type|accept|accept-encoding|accept-language|connection|user-agent|date|cache-control|pragma|upgrade-insecure-requests|sec-fetch-[a-z-]+)$/i
const SIGNED_URL_SIG_PARAM_RE = /^(?:x-goog-signature|x-amz-signature|signature|sig)$/i
const SIGNED_URL_INLINE_RE = /https?:\/\/[^\s"'<>\\]+/gi
const NONCE_LIKE_RUN_RE = /[A-Za-z0-9_-]{16,}/g

function isHexDigitCode(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102)
}

/** Shared bounded JSON flattener (`depth <= 6`, `<= 256` leaves). */
export function flattenJson(value: unknown, prefix = '', depth = 0, out = new Map<string, string>()): Map<string, string> {
  if (out.size >= 256 || depth > 6) return out
  if (value === null || value === undefined) return out
  if (Array.isArray(value)) {
    for (let i = 0; i < Math.min(value.length, 16); i += 1) flattenJson(value[i], `${prefix}[${i}]`, depth + 1, out)
    return out
  }
  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      flattenJson(child, prefix ? `${prefix}.${key}` : key, depth + 1, out)
    }
    return out
  }
  out.set(prefix, String(value))
  return out
}

/** Strip HTML comments (`<!-- ... -->`) in linear O(n) time. */
export function stripHtmlComments(html: string): string {
  let out = ''
  let pos = 0
  while (pos < html.length) {
    const start = html.indexOf('<!--', pos)
    if (start < 0) {
      out += html.slice(pos)
      break
    }
    out += html.slice(pos, start)
    const end = html.indexOf('-->', start + 4)
    if (end < 0) break
    pos = end + 3
  }
  return out
}

/** Decode HTML named and numeric (decimal + hex) entities (up to 2 passes). */
export function decodeHtmlAndNumericEntities(input: string): string {
  if (!input.includes('&')) return input
  let out = input
  for (let pass = 0; pass < 2; pass += 1) {
    const next = out
      .replace(/&#0*(\d{1,7});/g, (full, num) => {
        const code = Number(num)
        if (!Number.isInteger(code) || code < 1 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return full
        try { return String.fromCodePoint(code) } catch { return full }
      })
      .replace(/&#x0*([0-9a-f]{1,6});/gi, (full, hex) => {
        const code = Number.parseInt(hex, 16)
        if (!Number.isInteger(code) || code < 1 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return full
        try { return String.fromCodePoint(code) } catch { return full }
      })
      .replace(/&nbsp;/gi, ' ')
      .replace(/&quot;/gi, '"')
      .replace(/&apos;/gi, "'")
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&amp;/gi, '&')
    if (next === out) break
    out = next
  }
  return out
}

/**
 * Linear per-escape URL percent decoder (`R4-C-3` / `R4-C-2`):
 * decodes every valid `%XX` run even if a malformed `%ZZ` / truncated `%2` appears elsewhere,
 * and reports `malformedReason` so callers fail closed.
 */
function decodePercentSafe(
  raw: string,
  options: { plusAsSpace: boolean; strictBarePercent: boolean },
): { decoded: string; malformedReason: string | null } {
  const bounded = raw.slice(0, 64 * 1024)
  let current = options.plusAsSpace ? bounded.replace(/\+/g, ' ') : bounded
  let malformedReason: string | null = null

  for (let pass = 0; pass < 3; pass += 1) {
    if (!current.includes('%')) break
    let out = ''
    let changed = false
    let i = 0
    const hasValidHexPercent = /%[0-9a-fA-F]{2}/.test(current)
    while (i < current.length) {
      if (current[i] !== '%') {
        out += current[i]!
        i += 1
        continue
      }
      if (i + 2 >= current.length ||
          !isHexDigitCode(current.charCodeAt(i + 1)) ||
          !isHexDigitCode(current.charCodeAt(i + 2))) {
        const looksMalformedToken = i + 1 < current.length && (
          /[g-zG-Z]/.test(current[i + 1]!) ||
          (isHexDigitCode(current.charCodeAt(i + 1)) && (i + 2 >= current.length || !isHexDigitCode(current.charCodeAt(i + 2))))
        )
        const truncatedAtEnd = i + 1 >= current.length
        if (pass === 0 && (options.strictBarePercent || hasValidHexPercent || looksMalformedToken || truncatedAtEnd)) {
          malformedReason ??= 'malformed_percent_escape'
        } else if (pass >= 1 && (looksMalformedToken || truncatedAtEnd)) {
          malformedReason ??= 'malformed_percent_escape'
        }
        out += '%'
        i += 1
        continue
      }
      let runEnd = i
      while (runEnd + 2 < current.length &&
          current[runEnd] === '%' &&
          isHexDigitCode(current.charCodeAt(runEnd + 1)) &&
          isHexDigitCode(current.charCodeAt(runEnd + 2))) {
        runEnd += 3
      }
      const run = current.slice(i, runEnd)
      try {
        const dec = decodeURIComponent(run)
        out += dec
        if (dec !== run) changed = true
      } catch {
        malformedReason ??= 'invalid_utf8_percent_escape'
        for (let k = i; k < runEnd; k += 3) {
          const byte = Number.parseInt(current.slice(k + 1, k + 3), 16)
          if (byte >= 0x09 && byte <= 0x7e) {
            out += String.fromCharCode(byte)
            changed = true
          } else {
            out += current.slice(k, k + 3)
          }
        }
      }
      i = runEnd
    }
    current = out
    if (!changed) break
  }

  return { decoded: current, malformedReason }
}

function decodeUnicodeAndBackslashEscapes(raw: string): { decoded: string; malformedReason: string | null } {
  if (!raw.includes('\\')) return { decoded: raw, malformedReason: null }
  const malformedReason = /\\u(?![0-9a-fA-F]{4}|\{[0-9a-fA-F]{1,6}\})/.test(raw)
    ? 'malformed_unicode_escape'
    : null
  const decoded = raw
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (full, hex: string) => {
      const code = Number.parseInt(hex, 16)
      if (!Number.isInteger(code) || code < 1 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return full
      try { return String.fromCodePoint(code) } catch { return full }
    })
    .replace(/\\u([0-9a-f]{4})/gi, (_full, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (_full, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\(["'\\/])/g, '$1')
    .replace(/\\[nrt]/g, ' ')
  return { decoded, malformedReason }
}

function stripZeroWidthAndInvisible(input: string): string {
  return input
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]/g, '')
    .replace(/\p{Cf}/gu, '')
}

function stripMarkupTagsLinear(input: string): string {
  let current = input
  for (let pass = 0; pass < 3; pass += 1) {
    const withoutComments = stripHtmlComments(current)
    let out = ''
    let i = 0
    while (i < withoutComments.length) {
      const ch = withoutComments[i]!
      if (ch === '<') {
        const next = withoutComments[i + 1] ?? ''
        const isTagStart = (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') ||
          next === '/' || next === '!' || next === '?'
        if (isTagStart) {
          let closeIdx = -1
          const limit = Math.min(withoutComments.length, i + 512)
          for (let j = i + 1; j < limit; j += 1) {
            if (withoutComments[j] === '>') {
              closeIdx = j
              break
            }
            if (withoutComments[j] === '<') break
          }
          if (closeIdx > i) {
            i = closeIdx + 1
            continue
          }
        }
      }
      out += ch
      i += 1
    }
    if (out === current) break
    current = out
  }
  return current
}

function normalizeFragment(
  value: string,
  options: { decodePercent: boolean; plusAsSpace: boolean; strictBarePercent: boolean },
): { decoded: string; comparable: string; alnumCore: string; malformedReason: string | null } {
  const bounded = value.slice(0, 64 * 1024)
  const uni = decodeUnicodeAndBackslashEscapes(bounded)
  const pct = options.decodePercent
    ? decodePercentSafe(uni.decoded, { plusAsSpace: options.plusAsSpace, strictBarePercent: options.strictBarePercent })
    : { decoded: uni.decoded, malformedReason: null }
  const entitiesDecoded = decodeHtmlAndNumericEntities(pct.decoded)
  const folded = entitiesDecoded.normalize('NFKC')
  const noInvisible = stripZeroWidthAndInvisible(folded)
  const noTags = stripMarkupTagsLinear(noInvisible)
  const comparable = noTags.replace(/\s+/g, ' ').trim().toLowerCase()
  const alnumCore = comparable.replace(/[^a-z0-9]/g, '')
  return {
    decoded: entitiesDecoded,
    comparable,
    alnumCore,
    malformedReason: uni.malformedReason ?? pct.malformedReason,
  }
}

function collectJsonLeavesWithPaths(
  value: unknown,
  outLeaves: string[],
  outParams: Record<string, string>,
  prefix = '',
  depth = 0,
): void {
  if (depth > 8 || outLeaves.length >= 256 || value === null || value === undefined) return
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    const s = String(value)
    outLeaves.push(s)
    if (prefix) outParams[`body:${prefix}`] = s
    else outParams['body:$'] = s
    return
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < Math.min(value.length, 64); i += 1) {
      collectJsonLeavesWithPaths(value[i], outLeaves, outParams, `${prefix}[${i}]`, depth + 1)
    }
    return
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      outLeaves.push(k)
      collectJsonLeavesWithPaths(v, outLeaves, outParams, prefix ? `${prefix}.${k}` : k, depth + 1)
    }
  }
}

function finalizeCarrier(carrier: NormalizedRequestCarrier, options?: NormalizeCarrierOptions): NormalizedRequestCarrier {
  if (options?.malformedMode === 'reject' && carrier.malformedEscape) {
    throw new MalformedCarrierError(carrier.malformedReason ?? 'malformed_carrier')
  }
  return carrier
}

function extractBodyTextFromInput(input: RequestCarrierInput): string {
  if (typeof input.requestBody === 'string') return input.requestBody
  if (typeof input.requestJson === 'string') return input.requestJson
  if (input.requestJson !== undefined) {
    try { return JSON.stringify(input.requestJson) } catch { return '' }
  }
  return ''
}

/**
 * THE single canonical fail-closed request carrier normalizer (`R3-17`, merging `R4-C-2`, `R4-C-3`, `R4-C-6`).
 *
 * Accepts either a structured HTTP `RequestCarrierInput` (`pathAndQuery`, `requestBody`,
 * `requestJson`, `requestHeaders`) or a raw string fragment. Decodes URL percent escapes
 * per-component, JSON unicode/hex/backslash escapes, HTML named & numeric entities, NFKC folds,
 * strips invisible/zero-width/bidi characters and markup tags, and flags (or throws on, under
 * `malformedMode: 'reject'`) any malformed percent, unicode, or strict-JSON encoding.
 */
export function normalizeRequestCarrier(
  input: RequestCarrierInput | string,
  options?: NormalizeCarrierOptions,
): NormalizedRequestCarrier {
  const decodePercent = options?.decodePercent !== false
  if (typeof input === 'string') {
    const frag = normalizeFragment(input, { decodePercent, plusAsSpace: false, strictBarePercent: true })
    const malformedEscape = frag.malformedReason !== null
    return finalizeCarrier({
      raw: input.slice(0, 64 * 1024),
      malformedEscape,
      hadMalformedPercentEscape: malformedEscape,
      malformedReason: frag.malformedReason,
      malformedJson: false,
      inputComponents: input ? [input, ...(frag.decoded !== input ? [frag.decoded] : [])] : [],
      transportHeaderComponents: [],
      combinedDecoded: frag.decoded,
      comparable: frag.comparable,
      alnumCore: frag.alnumCore,
      comparables: frag.comparable ? [frag.comparable] : [],
      alnumCores: frag.alnumCore ? [frag.alnumCore] : [],
      params: {},
    }, options)
  }

  const inputComponents: string[] = []
  const transportHeaderComponents: string[] = []
  const comparables: string[] = []
  const alnumCores: string[] = []
  const params: Record<string, string> = {}
  let malformedReason: string | null = null
  let malformedJson = false

  const pushInput = (raw: string, opts: { plusAsSpace: boolean; strictBarePercent: boolean; decodePct?: boolean }): string => {
    if (!raw) return ''
    inputComponents.push(raw)
    const frag = normalizeFragment(raw, {
      decodePercent: opts.decodePct ?? decodePercent,
      plusAsSpace: opts.plusAsSpace,
      strictBarePercent: opts.strictBarePercent,
    })
    if (frag.malformedReason) malformedReason ??= frag.malformedReason
    if (frag.decoded !== raw) inputComponents.push(frag.decoded)
    if (frag.comparable) comparables.push(frag.comparable)
    if (frag.alnumCore) alnumCores.push(frag.alnumCore)
    return frag.decoded
  }

  const pq = input.pathAndQuery ?? ''
  if (pq) {
    const hashIdx = pq.indexOf('#')
    const withoutHash = hashIdx >= 0 ? pq.slice(0, hashIdx) : pq
    const qIdx = withoutHash.indexOf('?')
    const rawPath = qIdx >= 0 ? withoutHash.slice(0, qIdx) : withoutHash
    const rawQuery = qIdx >= 0 ? withoutHash.slice(qIdx + 1) : ''
    for (const seg of rawPath.split('/')) {
      if (seg) pushInput(seg, { plusAsSpace: false, strictBarePercent: true })
    }
    if (rawQuery) {
      for (const pair of rawQuery.split('&')) {
        if (!pair) continue
        const eq = pair.indexOf('=')
        const rawKey = eq >= 0 ? pair.slice(0, eq) : pair
        const rawVal = eq >= 0 ? pair.slice(eq + 1) : ''
        const decKey = pushInput(rawKey, { plusAsSpace: true, strictBarePercent: true })
        const decVal = eq >= 0 ? pushInput(rawVal, { plusAsSpace: true, strictBarePercent: true }) : ''
        if (decKey) params[decKey] = decVal
      }
    }
  }

  let contentType = ''
  const headerLines: string[] = []
  for (const [k, v] of Object.entries(input.requestHeaders ?? {})) {
    const lk = k.trim().toLowerCase()
    const sv = String(v ?? '')
    headerLines.push(`${k}:${sv}`)
    if (lk === 'content-type') contentType = sv.toLowerCase()
    if (TRANSPORT_HEADER_NAME_RE.test(lk)) {
      if (sv) transportHeaderComponents.push(sv)
    } else if (sv) {
      pushInput(sv, { plusAsSpace: false, strictBarePercent: false })
    }
  }

  const rawBody = extractBodyTextFromInput(input)
  if (rawBody) {
    const trimmed = rawBody.trim()
    const isForm = contentType.includes('application/x-www-form-urlencoded')
      || (!contentType.includes('json') && !trimmed.startsWith('{') && !trimmed.startsWith('[') && !trimmed.startsWith('<') && !trimmed.startsWith('--') && trimmed.includes('=') && !trimmed.includes('\n'))
    const looksJson = contentType.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[') || trimmed.startsWith('"')
    if (isForm) {
      for (const pair of rawBody.split('&')) {
        if (!pair) continue
        const eq = pair.indexOf('=')
        const rk = eq >= 0 ? pair.slice(0, eq) : pair
        const rv = eq >= 0 ? pair.slice(eq + 1) : ''
        const dk = pushInput(rk, { plusAsSpace: true, strictBarePercent: true })
        const dv = eq >= 0 ? pushInput(rv, { plusAsSpace: true, strictBarePercent: true }) : ''
        if (dk) params[`body:${dk}`] = dv
      }
    } else if (looksJson) {
      const rawUni = decodeUnicodeAndBackslashEscapes(rawBody)
      if (rawUni.malformedReason) {
        malformedReason ??= rawUni.malformedReason
      } else if (rawUni.decoded !== rawBody) {
        inputComponents.push(rawUni.decoded)
      }
      try {
        const parsed = JSON.parse(rawBody)
        const leaves: string[] = []
        collectJsonLeavesWithPaths(parsed, leaves, params)
        for (const leaf of leaves) pushInput(leaf, { plusAsSpace: false, strictBarePercent: false })
        pushInput(rawBody, { plusAsSpace: false, strictBarePercent: false, decodePct: false })
      } catch {
        malformedJson = true
        if (options?.strictJson) malformedReason ??= 'malformed_json_body'
        pushInput(rawBody, { plusAsSpace: false, strictBarePercent: false })
      }
    } else {
      params['body:$'] = rawBody
      pushInput(rawBody, { plusAsSpace: false, strictBarePercent: false })
    }
  } else if (input.requestJson !== undefined && typeof input.requestJson !== 'string') {
    const leaves: string[] = []
    collectJsonLeavesWithPaths(input.requestJson, leaves, params)
    for (const leaf of leaves) pushInput(leaf, { plusAsSpace: false, strictBarePercent: false })
  }

  const combinedDecoded = inputComponents.join('\n')
  const combinedComparable = comparables.join(' ').replace(/\s+/g, ' ').trim()
  const combinedAlnum = alnumCores.join('')
  const rawConcat = `${pq}\n${headerLines.join('\n')}\n${rawBody}`.slice(0, 64 * 1024)

  return finalizeCarrier({
    raw: rawConcat,
    malformedEscape: malformedReason !== null,
    hadMalformedPercentEscape: malformedReason !== null,
    malformedReason,
    malformedJson,
    inputComponents,
    transportHeaderComponents,
    combinedDecoded,
    comparable: combinedComparable,
    alnumCore: combinedAlnum,
    comparables,
    alnumCores,
    params,
  }, options)
}

/** Convenience deletion-normalized alphanumeric core helper backed by `normalizeRequestCarrier`. */
export function deletionNormalizeComparable(value: string): string {
  return normalizeRequestCarrier(value).alnumCore
}

/**
 * Canonicalize response/request text for echo comparison while preserving HTML tag boundaries
 * on error pages so server error fingerprints stay matchable.
 */
export function normalizeEchoComparable(value: string): string {
  const uni = decodeUnicodeAndBackslashEscapes(value.slice(0, 64 * 1024))
  const pct = decodePercentSafe(uni.decoded, { plusAsSpace: false, strictBarePercent: false })
  const entitiesDecoded = decodeHtmlAndNumericEntities(pct.decoded)
  const folded = entitiesDecoded.normalize('NFKC')
  return stripZeroWidthAndInvisible(folded).replace(/\s+/g, ' ').trim().toLowerCase()
}

function safeJsonText(value: unknown): string {
  try { return JSON.stringify(value) ?? '' } catch { return '' }
}

function stepResponseText(step: ReflectionEchoStepInput): string {
  const json = step.json === undefined ? '' : safeJsonText(step.json)
  return `${step.body ?? ''}\n${json}`.slice(0, 32 * 1024)
}

function tokenizeNonJsonRequestBody(rawBody: string, add: (val: string | null | undefined) => void): void {
  const bounded = rawBody.slice(0, 32 * 1024)
  add(bounded)
  const trimmed = bounded.trim()
  if (!trimmed) return

  if (trimmed.startsWith('--') && /\r?\n\r?\n/.test(trimmed)) {
    const firstNewline = trimmed.search(/\r?\n/)
    const boundary = firstNewline > 2 ? trimmed.slice(0, firstNewline).trim() : null
    if (boundary && boundary.length <= 128) {
      for (const part of trimmed.split(boundary)) {
        const sepIdx = part.search(/\r?\n\r?\n/)
        if (sepIdx >= 0) {
          const headerPart = part.slice(0, sepIdx)
          const bodyPart = part.slice(sepIdx).replace(/^\r?\n\r?\n/, '').replace(/\r?\n$/, '')
          add(bodyPart)
          for (const m of headerPart.matchAll(/(?:name|filename)="([^"]{1,512})"/gi)) add(m[1])
        }
      }
    }
  }

  if (trimmed.startsWith('<')) {
    for (const m of trimmed.matchAll(/<!\[CDATA\[([\s\S]{1,4096}?)\]\]>/g)) add(m[1])
    for (const m of trimmed.matchAll(/>([^<]{1,4096})</g)) {
      const text = decodeHtmlAndNumericEntities(m[1]!.trim())
      if (text) add(text)
    }
    for (const m of trimmed.matchAll(/=\s*(?:"([^"]{1,1024})"|'([^']{1,1024})')/g)) {
      const attr = decodeHtmlAndNumericEntities((m[1] ?? m[2] ?? '').trim())
      if (attr) add(attr)
    }
  }

  if (trimmed.includes('=')) {
    try {
      for (const [k, v] of new URLSearchParams(trimmed).entries()) { add(k); add(v) }
    } catch { /* fallback to per-component split below */ }
    const formValues: string[] = []
    for (const pair of trimmed.split('&')) {
      const eq = pair.indexOf('=')
      if (eq >= 0) {
        const rk = pair.slice(0, eq), rv = pair.slice(eq + 1)
        const decVal = decodePercentSafe(rv, { plusAsSpace: true, strictBarePercent: false }).decoded
        add(decodePercentSafe(rk, { plusAsSpace: true, strictBarePercent: false }).decoded)
        add(rv); add(rv.replace(/\+/g, ' ')); add(decVal)
        if (decVal) formValues.push(decVal)
      }
    }
    if (formValues.length > 1) add(formValues.join(''))
  }
}

/** Extract all request-side tokens across path, query, JSON, form/XML/multipart, headers, and cookies. */
export function extractRequestEchoTokens(step: ReflectionEchoStepInput): string[] {
  const tokens = new Set<string>()
  const add = (value: string | null | undefined): void => {
    if (!value) return
    const trimmed = value.trim()
    if (trimmed.length < 4) return
    tokens.add(trimmed)
    const dec = decodePercentSafe(trimmed, { plusAsSpace: false, strictBarePercent: false }).decoded
    if (dec.length >= 4) tokens.add(dec)
  }

  if (step.pathAndQuery) {
    add(step.pathAndQuery)
    const qIdx = step.pathAndQuery.indexOf('?')
    const rawPath = qIdx >= 0 ? step.pathAndQuery.slice(0, qIdx) : step.pathAndQuery
    for (const seg of rawPath.split('/').filter(Boolean)) { add(seg); add(seg.replace(/\+/g, ' ')) }
    if (qIdx >= 0) {
      const queryValues: string[] = []
      for (const pair of step.pathAndQuery.slice(qIdx + 1).split('&')) {
        if (!pair) continue
        const eq = pair.indexOf('=')
        if (eq >= 0) {
          const rk = pair.slice(0, eq), rv = pair.slice(eq + 1)
          const decVal = decodePercentSafe(rv, { plusAsSpace: true, strictBarePercent: false }).decoded
          add(decodePercentSafe(rk, { plusAsSpace: true, strictBarePercent: false }).decoded)
          add(rv); add(rv.replace(/\+/g, ' ')); add(decVal)
          if (decVal) queryValues.push(decVal)
        } else {
          const dec = decodePercentSafe(pair, { plusAsSpace: true, strictBarePercent: false }).decoded
          add(pair); add(dec)
          if (dec) queryValues.push(dec)
        }
      }
      if (queryValues.length > 1) add(queryValues.join(''))
    }
    try {
      for (const [k, v] of new URL(step.pathAndQuery, 'http://kovo.invalid').searchParams.entries()) { add(k); add(v) }
    } catch { /* raw per-component extraction above already captured segments & query */ }
  }

  if (step.requestJson !== undefined) {
    if (typeof step.requestJson === 'string') {
      tokenizeNonJsonRequestBody(step.requestJson, add)
    } else {
      const jsonValues: string[] = []
      for (const value of flattenJson(step.requestJson).values()) {
        add(value)
        if (value) jsonValues.push(value)
      }
      if (jsonValues.length > 1) add(jsonValues.join(''))
    }
  }
  if (typeof step.requestBody === 'string' && step.requestBody.length > 0) {
    tokenizeNonJsonRequestBody(step.requestBody, add)
  }
  for (const [headerName, headerVal] of Object.entries(step.requestHeaders ?? {})) {
    add(headerVal)
    if (headerName.toLowerCase() === 'cookie') {
      for (const pair of headerVal.split(';')) {
        const tp = pair.trim()
        add(tp)
        const eq = tp.indexOf('=')
        if (eq >= 0) {
          const val = tp.slice(eq + 1).trim()
          add(val); add(val.replace(/\+/g, ' '))
        }
      }
    }
  }
  return [...tokens].sort((a, b) => b.length - a.length)
}

/** True when `step`'s request carrier has any malformed percent or JSON unicode escape (fail-closed). */
export function hasMalformedRequestCarrier(step: ReflectionEchoStepInput): boolean {
  return normalizeRequestCarrier({
    pathAndQuery: step.pathAndQuery ?? null,
    requestBody: step.requestBody ?? null,
    requestJson: step.requestJson,
    requestHeaders: step.requestHeaders ?? null,
  }).malformedEscape
}

/**
 * Strip echoed request carrier tokens from `step`'s response before fingerprint matching (`R4-C-3` / `H-16`).
 * Uses the single canonical carrier normalizer for deletion-normalized anti-reflection.
 */
export function stripRequestEchoes(step: ReflectionEchoStepInput): string {
  let text = stepResponseText(step)
  const rawTokens = extractRequestEchoTokens(step)
  for (const token of rawTokens) {
    const escapedJson = JSON.stringify(token).slice(1, -1)
    const escapedHtml = token.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;').replaceAll("'", '&#39;')
    const escapedHtml039 = token.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;').replaceAll("'", '&#039;')
    const safeDecoded = decodePercentSafe(token, { plusAsSpace: false, strictBarePercent: false }).decoded
    for (const variant of new Set([token, safeDecoded, encodeURIComponent(token), escapedJson, escapedHtml, escapedHtml039])) {
      if (variant.length >= 4) text = text.split(variant).join(' ')
    }
  }
  let normalized = normalizeEchoComparable(text)
  const normalizedTokenSet = new Set<string>()
  for (const rawTok of rawTokens) {
    const basic = normalizeEchoComparable(rawTok)
    if (basic.length >= 4) normalizedTokenSet.add(basic)
    const deleted = normalizeRequestCarrier(rawTok).comparable
    if (deleted.length >= 4) normalizedTokenSet.add(deleted)
  }
  for (const normToken of [...normalizedTokenSet].sort((a, b) => b.length - a.length)) {
    if (normalized.includes(normToken)) normalized = normalized.split(normToken).join(' ')
  }
  return normalized
}

export interface RequestReflectionIndex {
  readonly malformedEscape: boolean
  readonly normalizedRequestTokens: readonly string[]
  readonly requestAlnumCores: readonly string[]
}

/** Build a reusable per-step anti-reflection containment index (backed by `normalizeRequestCarrier`). */
export function buildRequestReflectionIndex(step: ReflectionEchoStepInput): RequestReflectionIndex {
  const malformedEscape = hasMalformedRequestCarrier(step)
  const rawTokens = extractRequestEchoTokens(step)
  const normalizedRequestTokens: string[] = []
  const requestAlnumCores: string[] = []
  for (const rawTok of rawTokens) {
    const basic = normalizeEchoComparable(rawTok)
    if (basic.length >= 4) normalizedRequestTokens.push(basic)
    const norm = normalizeRequestCarrier(rawTok)
    if (norm.comparable.length >= 4) normalizedRequestTokens.push(norm.comparable)
    if (norm.alnumCore.length >= 4) requestAlnumCores.push(norm.alnumCore)
  }
  return { malformedEscape, normalizedRequestTokens, requestAlnumCores }
}

/**
 * Containment anti-reflection predicate: returns true (reflected / fail-closed) if `matchedText`
 * or its deletion-normalized alphanumeric core can be reconstructed from any request carrier,
 * OR if the request carrier contained a malformed escape.
 */
export function isMatchEchoedFromRequest(index: RequestReflectionIndex, matchedText: string): boolean {
  if (index.malformedEscape) return true
  const normMatch = normalizeEchoComparable(matchedText)
  if (normMatch.length >= 4 && index.normalizedRequestTokens.some(tok => tok.includes(normMatch))) return true
  const coreMatch = deletionNormalizeComparable(matchedText)
  if (coreMatch.length >= 4 && index.requestAlnumCores.some(core => core.includes(coreMatch))) return true
  return false
}

function maskExpressionOperands(text: string, challenge: ExpressionChallengeShape): string {
  const a = String(challenge.operandA)
  const b = String(challenge.operandB)
  if (!a || !b) return text
  let out = ''
  let cursor = 0
  let searchFrom = 0
  while (searchFrom <= text.length - a.length) {
    const pos = text.indexOf(a, searchFrom)
    if (pos === -1) break
    let i = pos + a.length
    while (i < text.length && /\s/.test(text[i]!)) i += 1
    let opMatched = false
    if (challenge.operator === '+') {
      if (text[i] === '+') { i += 1; opMatched = true }
    } else if (text[i] === '\\' && text[i + 1] === '*') {
      i += 2; opMatched = true
    } else if (text[i] === '*') {
      i += 1; opMatched = true
    }
    if (opMatched) {
      while (i < text.length && /\s/.test(text[i]!)) i += 1
      if (text.startsWith(b, i)) {
        out += text.slice(cursor, pos) + ' '
        cursor = i + b.length
        searchFrom = cursor
        continue
      }
    }
    searchFrom = pos + 1
  }
  return cursor === 0 ? text : out + text.slice(cursor)
}

function isOrderedSubsequence(needle: string, haystack: string): boolean {
  if (!needle) return false
  let j = 0
  for (let i = 0; i < haystack.length && j < needle.length; i += 1) {
    if (haystack[i] === needle[j]) j += 1
  }
  return j === needle.length
}

function stripInertSanitizerChars(value: string): string {
  return stripMarkupTagsLinear(stripZeroWidthAndInvisible(decodeHtmlAndNumericEntities(value).normalize('NFKC')))
}

/**
 * Anti-reflection predicate for host-minted evaluated-expression challenges (`R4-C-2`):
 * fails closed (returns true) on malformed carrier escapes, direct output presence, deletion-normalized
 * presence, or ordered digit-subsequence presence after masking the legitimate operands.
 */
export function carrierReflectsExpressionOutput(
  carrier: NormalizedRequestCarrier,
  challenge: ExpressionChallengeShape,
): boolean {
  if (carrier.malformedEscape) return true
  const expected = challenge.expectedOutput
  const expectedDigits = expected.replace(/[^0-9]/g, '')
  if (!expected || !expectedDigits) return true
  for (const comp of carrier.inputComponents) {
    if (comp.includes(expected)) return true
    const cleaned = stripInertSanitizerChars(comp)
    if (cleaned.includes(expected)) return true
    if (cleaned.replace(/[^0-9]/g, '').includes(expectedDigits)) return true
    const maskedDigits = maskExpressionOperands(cleaned, challenge).replace(/[^0-9]/g, '')
    if (isOrderedSubsequence(expectedDigits, maskedDigits)) return true
  }
  const joinedCleaned = stripInertSanitizerChars(carrier.combinedDecoded)
  if (joinedCleaned.includes(expected) || joinedCleaned.replace(/[^0-9]/g, '').includes(expectedDigits)) return true
  for (const th of carrier.transportHeaderComponents) {
    if (th.includes(expected) || stripInertSanitizerChars(th).includes(expected)) return true
  }
  return false
}

/** Extract signed URL and signature needles from an HTTP response for anti-reflection checks. */
export function extractSignedUrlNeedlesFromResponse(exchange: SignedUrlResponseInput): string[] {
  const haystacks: string[] = []
  if (typeof exchange.responseBody === 'string' && exchange.responseBody) haystacks.push(exchange.responseBody)
  if (exchange.responseJson !== undefined) {
    const s = safeJsonText(exchange.responseJson)
    if (s) haystacks.push(s)
  }
  for (const v of Object.values(exchange.responseHeaders ?? {})) {
    if (v) haystacks.push(v)
  }
  const needles = new Set<string>()
  for (const text of haystacks) {
    SIGNED_URL_INLINE_RE.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = SIGNED_URL_INLINE_RE.exec(text)) !== null) {
      const rawUrl = m[0].replace(/[),.;]+$/, '')
      if (rawUrl.length >= 24) needles.add(rawUrl)
      try {
        const parsed = new URL(rawUrl)
        for (const [k, v] of parsed.searchParams.entries()) {
          if (SIGNED_URL_SIG_PARAM_RE.test(k) && v.length >= 16) {
            needles.add(v)
            const dec = decodePercentSafe(v, { plusAsSpace: false, strictBarePercent: false }).decoded
            if (dec.length >= 16) needles.add(dec)
          }
        }
      } catch { /* ignore malformed URL */ }
    }
  }
  return [...needles]
}

/**
 * Single canonical signed-URL / cryptographic-signature anti-reflection predicate (`R4-C-6` / `R3-17`).
 * Replaces both `carrierEchoesSignedUrlNeedle` and `isSignatureOrUrlEchoedFromCarrier`.
 * Fails closed whenever `carrier.malformedEscape` is true.
 */
export function carrierEchoesSignedUrlNeedles(
  carrier: NormalizedRequestCarrier,
  needles: readonly string[],
): boolean {
  if (carrier.malformedEscape) return true
  const expanded: string[] = []
  for (const needle of needles) {
    if (needle.length < 16) continue
    expanded.push(needle)
    const dec = decodePercentSafe(needle, { plusAsSpace: false, strictBarePercent: false })
    if (!dec.malformedReason && dec.decoded !== needle && dec.decoded.length >= 16) {
      expanded.push(dec.decoded)
    }
  }
  if (expanded.length === 0) return false
  const allComponents = [...carrier.inputComponents, ...carrier.transportHeaderComponents, carrier.combinedDecoded]
  for (const needle of expanded) {
    const normNeedle = normalizeRequestCarrier(needle, { decodePercent: false })
    const cleanedNeedle = stripInertSanitizerChars(needle)
    if (carrier.raw.includes(needle)) return true
    if (normNeedle.comparable.length >= 16 && carrier.comparables.some(c => c.includes(normNeedle.comparable))) return true
    if (normNeedle.alnumCore.length >= 16 && carrier.alnumCores.some(c => c.includes(normNeedle.alnumCore))) return true
    for (const comp of allComponents) {
      if (!comp) continue
      if (comp.includes(needle) || stripInertSanitizerChars(comp).includes(cleanedNeedle)) return true
    }
  }
  return false
}

/**
 * Shared traversal/path-separator differential check over two normalized carriers (`R4-C-6` / `R3-17`).
 * - `'single_param'` (default for `assessSignedUrlMintDifferential`): verifies exactly 1 parameter differs
 *   and introduces `..` or a path separator (`/` or `\`).
 * - `'any_component'` (defense-in-depth in `verifySignedUrlMintPair`): verifies any newly introduced
 *   input component carries `..`, `/`, or `\`.
 */
export function hasTraversalOrSeparatorDifferential(
  ctlCarrier: NormalizedRequestCarrier,
  prbCarrier: NormalizedRequestCarrier,
  mode: 'single_param' | 'any_component' = 'single_param',
): boolean {
  if (mode === 'any_component') {
    const ctlSet = new Set(ctlCarrier.inputComponents.map(c => c.toLowerCase()))
    const sepOrTravRe = /(?:\.\.|[\\/])/
    return prbCarrier.inputComponents.some(comp => !ctlSet.has(comp.toLowerCase()) && sepOrTravRe.test(comp))
  }
  const allKeys = [...new Set([...Object.keys(ctlCarrier.params), ...Object.keys(prbCarrier.params)])]
  if (allKeys.length === 0) return false
  const diffKeys = allKeys.filter(k => (ctlCarrier.params[k] ?? '') !== (prbCarrier.params[k] ?? ''))
  if (diffKeys.length !== 1) return false
  const soleKey = diffKeys[0]!
  const ctlVal = ctlCarrier.params[soleKey] ?? ''
  const prbVal = prbCarrier.params[soleKey] ?? ''
  const prbNorm = normalizeRequestCarrier(prbVal, { decodePercent: true }).comparable
  if (prbVal.includes('..') || prbNorm.includes('..')) return true
  const ctlHasSep = /[\\/]/.test(ctlVal)
  const prbHasSep = /[\\/]/.test(prbVal) || /[\\/]/.test(prbNorm)
  if (!ctlHasSep && prbHasSep) return true
  return ctlVal.length > 0 && prbVal.startsWith(ctlVal) && /[\\/]/.test(prbVal.slice(ctlVal.length))
}

function looksVolatileValue(text: string): boolean {
  return /(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9_-]{8,}/.test(text) || /[0-9a-f]{12,}/i.test(text)
}

function stripInjectedAndNonces(text: string, injected: readonly string[]): string {
  let out = text
  for (const value of injected) {
    if (value) out = out.split(value).join('')
  }
  return out.replace(NONCE_LIKE_RUN_RE, '').trim()
}

/**
 * Boolean-differential anti-reflection predicate (`R3-17`):
 * returns true when a differing response field is merely the echoed injected predicate or a
 * volatile rotating nonce rather than a structural response delta.
 */
export function isBooleanDifferentialEchoOnly(
  controlRaw: string,
  probeRaw: string,
  leaf: string,
  param: string,
  injectedValues: readonly string[],
): boolean {
  const lowerLeaf = leaf.toLowerCase()
  const lowerParam = param.toLowerCase()
  return lowerLeaf === lowerParam ||
    lowerLeaf.endsWith(lowerParam) ||
    (probeRaw !== controlRaw && stripInjectedAndNonces(probeRaw, injectedValues) === stripInjectedAndNonces(controlRaw, injectedValues)) ||
    (probeRaw !== controlRaw && looksVolatileValue(probeRaw) && (controlRaw === '' || looksVolatileValue(controlRaw))) ||
    (probeRaw.includes(param) && controlRaw.includes(param))
}
