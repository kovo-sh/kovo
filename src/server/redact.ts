import { createHash } from 'node:crypto'

export interface NamedSecret {
  value: string
  placeholder: string
}

export const SENSITIVE_HTTP_HEADER_RE = /^(?:authorization|proxy-authorization|www-authenticate|proxy-authenticate|cookie|set-cookie|set-cookie2|x-forwarded-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-refresh-token|x-session-token|x-session-id|x-csrf-token|x-xsrf-token|csrf-token|xsrf-token|x-amz-security-token|x-forwarded-authorization|private-token|x-vault-token)$/i

const SECRET_KEY_CORE = '(?:[A-Za-z0-9_-]*(?:password|passwd|api[_-]?key|signing[_-]?key|private[_-]?key|encryption[_-]?key|master[_-]?key|hmac[_-]?key|jwt[_-]?key|secret[_-]?key(?:[_-]?base)?|secret[_-]?access[_-]?key|token|secret|session[_-]?(?:id|key|cookie)|service[_-]?role[_-]?key)|authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)'

const credentialPatterns = [
  /\b(?:sk-or-v1-[A-Za-z0-9_-]+|sk-ant-[A-Za-z0-9_-]+|sk-proj-[A-Za-z0-9_-]+|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|(?:AKIA|ASIA)[0-9A-Z]{16}|(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}|whsec_[0-9A-Za-z]{16,}|xox[baprs]-[0-9A-Za-z-]{10,}|glpat-[0-9A-Za-z_-]{16,}|SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}|AIza[0-9A-Za-z_-]{35}|npm_[0-9A-Za-z]{20,}|pypi-[0-9A-Za-z_-]{20,}|hf_[0-9A-Za-z]{20,})\b/g,
  /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g,
  /(?<!")\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)\s*:\s*[^\n\r"]+/gi,
  /\bBearer\s+[a-z0-9._~+/=-]{8,}/gi,
  new RegExp(
    `("${SECRET_KEY_CORE}"\\s*:\\s*)(?:(null|\\{|\\[|"")|"(?:\\\\.|[^"\\\\])*"|-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?|true|false)|(?<![A-Za-z0-9_-])${SECRET_KEY_CORE}["']?\\s*[:=]\\s*(?:"(?:\\\\.|[^"\\\\])*"|'[^']*'|[^\\s&,;}"']+)`,
    'gi',
  ),
]

const PEM_BEGIN_PREFIX = '-----BEGIN '
const PEM_END_PREFIX = '-----END '
const PEM_SUFFIX = 'PRIVATE KEY-----'
const PEM_SUFFIX_LABEL = 'PRIVATE KEY'

/**
 * Strictly linear O(n) `indexOf`-based scanner for `-----BEGIN ... PRIVATE KEY-----` ...
 * `-----END ... PRIVATE KEY-----` blocks (R2-H-27). Never backtracks on unclosed BEGIN markers.
 */
function findPemMarker(text: string, prefix: string, fromIndex: number): { start: number; end: number } | null {
  let pos = fromIndex
  while (pos < text.length) {
    const idx = text.indexOf(prefix, pos)
    if (idx === -1) return null
    let cursor = idx + prefix.length
    while (cursor < text.length) {
      const ch = text.charCodeAt(cursor)
      if (ch === 45 /* '-' */ || ch === 10 /* '\n' */) break
      cursor += 1
    }
    if (
      cursor < text.length &&
      text.charCodeAt(cursor) === 45 &&
      cursor - (idx + prefix.length) >= PEM_SUFFIX_LABEL.length &&
      text.startsWith(PEM_SUFFIX, cursor - PEM_SUFFIX_LABEL.length)
    ) {
      return { start: idx, end: cursor + 5 }
    }
    pos = cursor > idx + prefix.length ? cursor : idx + prefix.length
  }
  return null
}

function findPemPrivateKeySpans(text: string, maxSpans = Infinity): Array<{ start: number; end: number }> {
  if (!text.includes(PEM_BEGIN_PREFIX) || !text.includes(PEM_END_PREFIX)) return []
  const spans: Array<{ start: number; end: number }> = []
  let pos = 0
  while (spans.length < maxSpans && pos < text.length) {
    const begin = findPemMarker(text, PEM_BEGIN_PREFIX, pos)
    if (!begin) break
    const end = findPemMarker(text, PEM_END_PREFIX, begin.end)
    if (!end) break
    spans.push({ start: begin.start, end: end.end })
    pos = end.end
  }
  return spans
}

function redactPemPrivateKeys(text: string): string {
  const spans = findPemPrivateKeySpans(text)
  if (spans.length === 0) return text
  const parts: string[] = []
  let cursor = 0
  for (const span of spans) {
    parts.push(text.slice(cursor, span.start), '[redacted]')
    cursor = span.end
  }
  parts.push(text.slice(cursor))
  return parts.join('')
}

function htmlEscapeBasic(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function jsonUnicodeEscape(value: string): string {
  return value.replace(/[<>&'"=\\/+]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)
}

function collectEncodingForms(value: string, minEncodedLength: number, forms: Set<string>, allowCookieSubValue: boolean): void {
  forms.add(value)
  const add = (candidate: string, floor = minEncodedLength) => {
    if (candidate && candidate !== value && candidate.length >= floor) forms.add(candidate)
  }
  const encoded = encodeURIComponent(value)
  if (encoded !== value) {
    add(encoded, Math.max(6, minEncodedLength))
    const lowerEncoded = encoded.replace(/%[0-9A-F]{2}/g, m => m.toLowerCase())
    add(lowerEncoded, Math.max(6, minEncodedLength))
    if (encoded.includes('%20')) {
      add(encoded.replaceAll('%20', '+'), Math.max(6, minEncodedLength))
      add(lowerEncoded.replaceAll('%20', '+'), Math.max(6, minEncodedLength))
    }
    // Double URL-encoding (upper & lower hex) catches double-encoded reflection/redirect channels.
    const doubleEncoded = encodeURIComponent(encoded)
    add(doubleEncoded, Math.max(8, minEncodedLength))
    const lowerDoubleEncoded = doubleEncoded.replace(/%[0-9A-F]{2}/g, m => m.toLowerCase())
    add(lowerDoubleEncoded, Math.max(8, minEncodedLength))
  }
  const buf = Buffer.from(value, 'utf8')
  const b64 = buf.toString('base64')
  add(b64)
  add(b64.replace(/=+$/, ''))
  const b64UrlEnc = encodeURIComponent(b64)
  if (b64UrlEnc !== b64) add(b64UrlEnc)
  const b64url = buf.toString('base64url')
  add(b64url)
  // Hex encoding (lower + upper) for secrets >= 6 bytes to avoid colliding with short hex words.
  if (buf.length >= 6) {
    const hexLower = buf.toString('hex')
    add(hexLower, Math.max(12, minEncodedLength * 2))
    add(hexLower.toUpperCase(), Math.max(12, minEncodedLength * 2))
  }
  const jsonEscaped = JSON.stringify(value).slice(1, -1)
  add(jsonEscaped)
  if (/[<>&'"=\\/+]/.test(value)) {
    add(jsonUnicodeEscape(value), Math.max(6, minEncodedLength))
  }
  if (value.includes('/')) {
    add(value.replaceAll('/', '\\/'))
    add(jsonEscaped.replaceAll('/', '\\/'))
  }
  if (/[&<>"']/.test(value)) {
    const htmlEsc = htmlEscapeBasic(value)
    add(htmlEsc)
    if (value.includes("'")) add(htmlEsc.replaceAll('&#39;', '&#x27;'))
  }
  // Cookie value-only stripping: if a registered secret is a `name=value` cookie pair,
  // also scrub the bare value (and its encoded forms) when echoed without the cookie name.
  if (allowCookieSubValue) {
    const eqIdx = value.indexOf('=')
    if (eqIdx > 0 && eqIdx < value.length - 1) {
      const cookieName = value.slice(0, eqIdx)
      const cookieVal = value.slice(eqIdx + 1)
      if (/^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$/.test(cookieName) && !cookieVal.includes(';') && cookieVal.length >= Math.max(6, minEncodedLength)) {
        collectEncodingForms(cookieVal, Math.max(6, minEncodedLength), forms, false)
      }
    }
  }
}

const MAX_VARIANT_CACHE_ENTRIES = 8_192
const MAX_VARIANT_CACHE_VALUE_LENGTH = 1_024
const variantCache = new Map<string, readonly string[]>()

function computeEncodingVariants(value: string, minEncodedLength: number): readonly string[] {
  const forms = new Set<string>()
  collectEncodingForms(value, minEncodedLength, forms, true)
  return [...forms]
}

function getCachedEncodingVariants(value: string, minEncodedLength = 4): readonly string[] {
  if (value.length > MAX_VARIANT_CACHE_VALUE_LENGTH) {
    return computeEncodingVariants(value, minEncodedLength)
  }
  const cacheKey = `${minEncodedLength}\u0000${value}`
  const cached = variantCache.get(cacheKey)
  if (cached) return cached
  const computed = computeEncodingVariants(value, minEncodedLength)
  if (variantCache.size >= MAX_VARIANT_CACHE_ENTRIES) {
    const oldestKey = variantCache.keys().next().value
    if (oldestKey !== undefined) variantCache.delete(oldestKey)
  }
  variantCache.set(cacheKey, computed)
  return computed
}

/**
 * Generates exact encoded variants of a registered secret for zero-heuristic scrubbing (M-14):
 * raw, URL-encoded (uppercase/lowercase/form + double URL-encoded), base64 (padded/unpadded/URL-encoded),
 * base64url, hex (lower/upper), JSON-escaped, JSON `\uXXXX` unicode-escaped, PHP slash-escaped (`\/`),
 * HTML-entity-encoded, and cookie value-only stripped forms.
 */
export function buildSecretEncodingVariants(value: string, minEncodedLength = 4): string[] {
  return [...getCachedEncodingVariants(value, minEncodedLength)]
}

export const DEFAULT_MAX_EXACT_SECRETS = 5_000
export const MAX_SECRET_VARIANT_INPUT_CHARS = 8_192
export const MAX_EXACT_SECRET_CHARS = 16_384
const MAX_REDACT_INPUT_BYTES = 4_194_304
const MAX_BODY_SCAN_BYTES = 2_097_152
const AC_PREFIX_DEPTH = 16
const AC_BUCKET_SPLIT_THRESHOLD = 8
const AC_MAX_SPLIT_DEPTH = 256
const MAX_MATCHER_LRU_ENTRIES = 32

export interface SecretMatcherOptions {
  minLength?: number
  maxSecrets?: number
  variantMinLengthFloor?: number
}

interface MatchSpan {
  start: number
  end: number
  placeholder: string
}

/**
 * Compiled multi-needle matcher backed by an adaptive-depth prefix Aho-Corasick trie.
 * Compiles variants + automaton once per secret set and scrubs arbitrary strings in linear O(n + matches) time.
 */
export class SecretMatcher {
  readonly secretCount: number
  readonly needleCount: number
  readonly minNeedleLength: number
  readonly dedupedSecrets: readonly NamedSecret[]
  private readonly needles: readonly string[]
  private readonly placeholders: readonly string[]
  private readonly primarySecretIdx: readonly number[]
  private readonly sharedSecretIndices: ReadonlyMap<number, readonly number[]>
  private readonly onlyChar: readonly number[]
  private readonly onlyChild: readonly number[]
  private readonly branch: ReadonlyArray<Map<number, number> | undefined>
  private readonly bucket: ReadonlyArray<number[] | undefined>
  private readonly depth: readonly number[]
  private readonly fail: Int32Array
  private readonly dict: Int32Array

  constructor(
    dedupedSecrets: readonly NamedSecret[],
    needles: readonly string[],
    placeholders: readonly string[],
    primarySecretIdx: readonly number[],
    sharedSecretIndices: ReadonlyMap<number, readonly number[]>,
    minNeedleLength: number,
  ) {
    this.dedupedSecrets = dedupedSecrets
    this.secretCount = dedupedSecrets.length
    this.needles = needles
    this.needleCount = needles.length
    this.placeholders = placeholders
    this.primarySecretIdx = primarySecretIdx
    this.sharedSecretIndices = sharedSecretIndices
    this.minNeedleLength = minNeedleLength

    const onlyChar: number[] = [-1]
    const onlyChild: number[] = [-1]
    const branch: Array<Map<number, number> | undefined> = [undefined]
    const bucket: Array<number[] | undefined> = [undefined]
    const depth: number[] = [0]

    const getNext = (state: number, ch: number): number | undefined => {
      const oc = onlyChar[state]!
      if (oc === ch) return onlyChild[state]!
      const map = branch[state]
      return map ? map.get(ch) : undefined
    }

    const addEdge = (state: number, ch: number, nxt: number): void => {
      const oc = onlyChar[state]!
      if (oc === -1) {
        onlyChar[state] = ch
        onlyChild[state] = nxt
      } else if (oc >= 0) {
        const map = new Map<number, number>()
        map.set(oc, onlyChild[state]!)
        map.set(ch, nxt)
        onlyChar[state] = -2
        onlyChild[state] = -1
        branch[state] = map
      } else {
        branch[state]!.set(ch, nxt)
      }
    }

    const newNode = (d: number): number => {
      const id = onlyChar.length
      onlyChar.push(-1)
      onlyChild.push(-1)
      branch.push(undefined)
      bucket.push(undefined)
      depth.push(d)
      return id
    }

    for (let ni = 0; ni < needles.length; ni += 1) {
      const w = needles[ni]!
      const lim = Math.min(w.length, AC_PREFIX_DEPTH)
      let cur = 0
      for (let i = 0; i < lim; i += 1) {
        const ch = w.charCodeAt(i)
        let nxt = getNext(cur, ch)
        if (nxt === undefined) {
          nxt = newNode(i + 1)
          addEdge(cur, ch, nxt)
        }
        cur = nxt
      }
      const b = bucket[cur]
      if (!b) bucket[cur] = [ni]
      else b.push(ni)
    }

    // Adaptively split oversized buckets (e.g. thousands of tokens sharing a long prefix)
    // so worst-case matching remains linear in text length.
    for (let st = 0; st < bucket.length; st += 1) {
      const b = bucket[st]
      if (!b || b.length <= AC_BUCKET_SPLIT_THRESHOLD) continue
      const d = depth[st]!
      if (d >= AC_MAX_SPLIT_DEPTH) continue
      const stay: number[] = []
      for (const ni of b) {
        const w = needles[ni]!
        if (w.length <= d) {
          stay.push(ni)
          continue
        }
        const ch = w.charCodeAt(d)
        let nxt = getNext(st, ch)
        if (nxt === undefined) {
          nxt = newNode(d + 1)
          addEdge(st, ch, nxt)
        }
        const nb = bucket[nxt]
        if (!nb) bucket[nxt] = [ni]
        else nb.push(ni)
      }
      bucket[st] = stay.length > 0 ? stay : undefined
    }

    const fail = new Int32Array(onlyChar.length)
    const dict = new Int32Array(onlyChar.length).fill(-1)
    const queue: number[] = []
    if (onlyChar[0]! >= 0) {
      const child = onlyChild[0]!
      fail[child] = 0
      queue.push(child)
    } else if (onlyChar[0] === -2) {
      for (const child of branch[0]!.values()) {
        fail[child] = 0
        queue.push(child)
      }
    }

    for (let qi = 0; qi < queue.length; qi += 1) {
      const u = queue[qi]!
      const fu = fail[u]!
      dict[u] = bucket[fu] ? fu : dict[fu]!
      const oc = onlyChar[u]!
      if (oc >= 0) {
        const v = onlyChild[u]!
        let f = fu
        while (f !== 0 && getNext(f, oc) === undefined) f = fail[f]!
        fail[v] = getNext(f, oc) ?? 0
        queue.push(v)
      } else if (oc === -2) {
        for (const [ch, v] of branch[u]!) {
          let f = fu
          while (f !== 0 && getNext(f, ch) === undefined) f = fail[f]!
          fail[v] = getNext(f, ch) ?? 0
          queue.push(v)
        }
      }
    }

    this.onlyChar = onlyChar
    this.onlyChild = onlyChild
    this.branch = branch
    this.bucket = bucket
    this.depth = depth
    this.fail = fail
    this.dict = dict
  }

  private step(state: number, ch: number): number {
    const oc = this.onlyChar[state]!
    if (oc === ch) return this.onlyChild[state]!
    if (oc === -2) {
      const hit = this.branch[state]!.get(ch)
      if (hit !== undefined) return hit
    }
    let s = state
    while (s !== 0) {
      s = this.fail[s]!
      const soc = this.onlyChar[s]!
      if (soc === ch) return this.onlyChild[s]!
      if (soc === -2) {
        const hit = this.branch[s]!.get(ch)
        if (hit !== undefined) return hit
      }
    }
    return 0
  }

  /** Replaces all exact & encoded secret variants in longest-first order in a single linear pass. */
  redact(text: string): string {
    if (!text || this.needleCount === 0 || text.length < this.minNeedleLength) return text
    const candidates: MatchSpan[] = []
    let state = 0
    for (let i = 0; i < text.length; i += 1) {
      state = this.step(state, text.charCodeAt(i))
      let d = this.bucket[state] ? state : this.dict[state]!
      while (d !== -1) {
        const b = this.bucket[d]!
        const nodeDepth = this.depth[d]!
        const start = i - nodeDepth + 1
        for (let bi = 0; bi < b.length; bi += 1) {
          const ni = b[bi]!
          const needle = this.needles[ni]!
          const end = start + needle.length
          if (end <= text.length && (needle.length === nodeDepth || text.startsWith(needle, start))) {
            candidates.push({ start, end, placeholder: this.placeholders[ni]! })
          }
        }
        d = this.dict[d]!
      }
    }

    if (candidates.length === 0) return text
    if (candidates.length === 1) {
      const c = candidates[0]!
      return text.slice(0, c.start) + c.placeholder + text.slice(c.end)
    }

    candidates.sort((a, b) => (b.end - b.start) - (a.end - a.start) || a.start - b.start)
    const accepted = selectNonOverlappingSpans(candidates, text.length)
    const parts: string[] = []
    let cursor = 0
    for (const span of accepted) {
      parts.push(text.slice(cursor, span.start), span.placeholder)
      cursor = span.end
    }
    parts.push(text.slice(cursor))
    return parts.join('')
  }

  /** Returns indices into `this.dedupedSecrets` for any secret whose variant occurs in `text`. */
  findMatchedSecretIndices(text: string): Set<number> {
    const matched = new Set<number>()
    if (!text || this.needleCount === 0 || text.length < this.minNeedleLength) return matched
    let state = 0
    for (let i = 0; i < text.length; i += 1) {
      state = this.step(state, text.charCodeAt(i))
      let d = this.bucket[state] ? state : this.dict[state]!
      while (d !== -1) {
        const b = this.bucket[d]!
        const nodeDepth = this.depth[d]!
        const start = i - nodeDepth + 1
        for (let bi = 0; bi < b.length; bi += 1) {
          const ni = b[bi]!
          const needle = this.needles[ni]!
          if (start + needle.length <= text.length && (needle.length === nodeDepth || text.startsWith(needle, start))) {
            matched.add(this.primarySecretIdx[ni]!)
            const extra = this.sharedSecretIndices.get(ni)
            if (extra) {
              for (const si of extra) matched.add(si)
            }
          }
        }
        d = this.dict[d]!
      }
    }
    return matched
  }
}

function selectNonOverlappingSpans(sortedCandidates: readonly MatchSpan[], textLength: number): MatchSpan[] {
  if (sortedCandidates.length <= 256) {
    const accepted: MatchSpan[] = []
    for (const cand of sortedCandidates) {
      let lo = 0
      let hi = accepted.length
      while (lo < hi) {
        const mid = (lo + hi) >>> 1
        if (accepted[mid]!.end <= cand.start) lo = mid + 1
        else hi = mid
      }
      if (lo < accepted.length && accepted[lo]!.start < cand.end) continue
      accepted.splice(lo, 0, cand)
    }
    return accepted
  }

  const used = new Uint8Array(textLength)
  const accepted: MatchSpan[] = []
  for (const cand of sortedCandidates) {
    if (used[cand.start] || used[cand.end - 1]) continue
    if (used.subarray(cand.start, cand.end).includes(1)) continue
    used.fill(1, cand.start, cand.end)
    accepted.push(cand)
  }
  accepted.sort((a, b) => a.start - b.start)
  return accepted
}

const EMPTY_SECRET_MATCHER = new SecretMatcher([], [], [], [], new Map(), Infinity)

interface WeakMatcherEntry {
  minLen: number
  maxSecrets: number
  variantFloor: number
  rawSnapshot: readonly NamedSecret[]
  matcher: SecretMatcher
}

interface LruMatcherEntry {
  minLen: number
  variantFloor: number
  deduped: readonly NamedSecret[]
  matcher: SecretMatcher
}

const matcherWeakCache = new WeakMap<readonly NamedSecret[], WeakMatcherEntry>()
const matcherLruCache = new Map<string, LruMatcherEntry>()

function sameSecretEntries(a: readonly NamedSecret[], b: readonly NamedSecret[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) {
    if (a[i]!.value !== b[i]!.value || a[i]!.placeholder !== b[i]!.placeholder) return false
  }
  return true
}

function hashSecretList(secrets: readonly NamedSecret[], minLen: number, variantFloor: number): string {
  let h1 = 2166136261 ^ minLen
  let h2 = 2166136261 ^ variantFloor
  for (let i = 0; i < secrets.length; i += 1) {
    const { value, placeholder } = secrets[i]!
    for (let j = 0; j < value.length; j += 1) {
      h1 = Math.imul(h1 ^ value.charCodeAt(j), 16777619)
    }
    h1 = Math.imul(h1 ^ 0xff, 16777619)
    for (let j = 0; j < placeholder.length; j += 1) {
      h2 = Math.imul(h2 ^ placeholder.charCodeAt(j), 16777619)
    }
    h2 = Math.imul(h2 ^ 0xff, 16777619)
  }
  return `${secrets.length}:${minLen}:${variantFloor}:${h1 >>> 0}:${h2 >>> 0}`
}

/**
 * Compiles (or retrieves from bounded LRU/WeakMap cache) a deduplicated, bounded `SecretMatcher`
 * for exact + encoded secret scrubbing.
 */
export function compileSecretMatcher(
  secrets: readonly NamedSecret[] = [],
  options: SecretMatcherOptions = {},
): SecretMatcher {
  if (secrets.length === 0) return EMPTY_SECRET_MATCHER
  const minLen = Math.max(1, options.minLength ?? 4)
  const maxSecrets = Math.max(1, options.maxSecrets ?? DEFAULT_MAX_EXACT_SECRETS)
  const variantFloor = Math.min(options.variantMinLengthFloor ?? 4, minLen)

  const weakHit = matcherWeakCache.get(secrets)
  if (
    weakHit &&
    weakHit.minLen === minLen &&
    weakHit.maxSecrets === maxSecrets &&
    weakHit.variantFloor === variantFloor &&
    sameSecretEntries(weakHit.rawSnapshot, secrets)
  ) {
    return weakHit.matcher
  }

  const deduped: NamedSecret[] = []
  const seenValues = new Set<string>()
  for (let i = 0; i < secrets.length; i += 1) {
    const s = secrets[i]
    if (!s || !s.value || s.value.length < minLen) continue
    const boundedVal = s.value.length > MAX_EXACT_SECRET_CHARS ? s.value.slice(0, MAX_EXACT_SECRET_CHARS) : s.value
    if (seenValues.has(boundedVal)) continue
    seenValues.add(boundedVal)
    deduped.push(boundedVal === s.value ? s : { value: boundedVal, placeholder: s.placeholder })
    if (deduped.length >= maxSecrets) break
  }

  if (deduped.length === 0) return EMPTY_SECRET_MATCHER

  const cacheKey = hashSecretList(deduped, minLen, variantFloor)
  const lruHit = matcherLruCache.get(cacheKey)
  if (
    lruHit &&
    lruHit.minLen === minLen &&
    lruHit.variantFloor === variantFloor &&
    sameSecretEntries(lruHit.deduped, deduped)
  ) {
    matcherLruCache.delete(cacheKey)
    matcherLruCache.set(cacheKey, lruHit)
    matcherWeakCache.set(secrets, {
      minLen,
      maxSecrets,
      variantFloor,
      rawSnapshot: secrets.map(s => ({ value: s.value, placeholder: s.placeholder })),
      matcher: lruHit.matcher,
    })
    return lruHit.matcher
  }

  const needles: string[] = []
  const placeholders: string[] = []
  const primarySecretIdx: number[] = []
  const sharedSecretIndices = new Map<number, number[]>()
  const needleToIdx = new Map<string, number>()
  let minNeedleLength = Infinity

  for (let si = 0; si < deduped.length; si += 1) {
    const secret = deduped[si]!
    const forms = secret.value.length > MAX_SECRET_VARIANT_INPUT_CHARS
      ? [secret.value]
      : getCachedEncodingVariants(secret.value, variantFloor)
    for (let fi = 0; fi < forms.length; fi += 1) {
      const variant = forms[fi]!
      const existingIdx = needleToIdx.get(variant)
      if (existingIdx !== undefined) {
        if (primarySecretIdx[existingIdx] !== si) {
          let extra = sharedSecretIndices.get(existingIdx)
          if (!extra) {
            extra = []
            sharedSecretIndices.set(existingIdx, extra)
          }
          if (!extra.includes(si)) extra.push(si)
        }
        continue
      }
      const ni = needles.length
      needleToIdx.set(variant, ni)
      needles.push(variant)
      placeholders.push(secret.placeholder)
      primarySecretIdx.push(si)
      if (variant.length < minNeedleLength) minNeedleLength = variant.length
    }
  }

  const matcher = needles.length === 0
    ? EMPTY_SECRET_MATCHER
    : new SecretMatcher(deduped, needles, placeholders, primarySecretIdx, sharedSecretIndices, minNeedleLength)

  if (matcherLruCache.size >= MAX_MATCHER_LRU_ENTRIES) {
    const oldest = matcherLruCache.keys().next().value
    if (oldest !== undefined) matcherLruCache.delete(oldest)
  }
  matcherLruCache.set(cacheKey, { minLen, variantFloor, deduped, matcher })
  matcherWeakCache.set(secrets, {
    minLen,
    maxSecrets,
    variantFloor,
    rawSnapshot: secrets.map(s => ({ value: s.value, placeholder: s.placeholder })),
    matcher,
  })
  return matcher
}

/**
 * Exact-value secret redaction ONLY (zero heuristic keyword regexes).
 * Safe for model tool arguments, scripts, code, and structured JSON payloads.
 */
export function redactExactValues(
  text: string,
  secrets: readonly NamedSecret[] = [],
  options: { minLength?: number } = {},
): string {
  if (!text || secrets.length === 0) return text
  return compileSecretMatcher(secrets, { minLength: options.minLength ?? 4 }).redact(text)
}

function applyHeuristicRedaction(text: string): string {
  if (!text || text.length < 7) return text
  let out = text
  out = out.replace(credentialPatterns[0]!, '[redacted]')
  if (out.includes('eyJ')) {
    out = out.replace(credentialPatterns[1]!, '[redacted]')
  }
  out = redactPemPrivateKeys(out)
  if (out.includes(':')) {
    out = out.replace(credentialPatterns[2]!, '[redacted]')
  }
  out = out.replace(credentialPatterns[3]!, '[redacted]')
  if (out.includes(':') || out.includes('=')) {
    out = out.replace(credentialPatterns[4]!, (_m, jsonPrefix?: string, preserved?: string) => (
      jsonPrefix ? `${jsonPrefix}${preserved !== undefined ? preserved : '"[redacted]"'}` : '[redacted]'
    ))
  }
  return out
}

export function redactWithMatcher(text: string, matcher?: SecretMatcher): string {
  if (!text) return text
  const bounded = text.length > MAX_REDACT_INPUT_BYTES ? `${text.slice(0, MAX_REDACT_INPUT_BYTES)}…[truncated]` : text
  const exact = matcher ? matcher.redact(bounded) : bounded
  return applyHeuristicRedaction(exact)
}

export function redact(text: string, secrets: readonly NamedSecret[] = []): string {
  if (!text) return text
  const matcher = secrets.length > 0 ? compileSecretMatcher(secrets, { minLength: 4 }) : undefined
  return redactWithMatcher(text, matcher)
}

export const secretMatchKinds = [
  'named_secret',
  'credential',
  'jwt',
  'private_key',
  'credential_header',
  'bearer',
  'key_value',
] as const
export type SecretMatchKind = typeof secretMatchKinds[number]

/**
 * Redacted structural evidence that a secret-shaped value appeared in a broker exchange.
 *
 * Safety contract: this shape never contains the raw secret, not even a substring. Only a
 * truncated SHA-256 fingerprint is kept so a verifier that already holds the secret (e.g. from
 * the persona vault) can prove the disclosed bytes match without the value ever leaving the
 * broker, entering logs, the DB body artifact, or an LLM prompt.
 */
export interface SecretMatch {
  kind: SecretMatchKind
  /** First 12 hex chars of SHA-256(rawSecretValue). Enough for correlation, not reversal. */
  sha256Prefix: string
  /** Where the match was observed: `headers.<name>` or a bounded JSON path such as `body.items[0].key`. */
  fieldPath?: string
  /** Bounded occurrence count within that field path. */
  count: number
}

export interface SecretScanOptions {
  secrets?: readonly NamedSecret[]
  /** Walk JSON bodies to attribute matches to key paths. Defaults to true. */
  jsonPaths?: boolean
  /** Maximum number of returned match entries. Defaults to 64. */
  maxMatches?: number
  /** Maximum occurrence count per entry. Defaults to 1000. */
  maxCountPerMatch?: number
}

const defaultMaxMatches = 64
const defaultMaxCountPerMatch = 1_000
const maxScannedMatchLength = 16_384
const maxJsonBodyScanBytes = 262_144
const maxJsonNodes = 4_000
const maxJsonDepth = 8
const maxFieldPathLength = 256
const maxHeaderScanLength = 8_192

interface CredentialDescriptor {
  kind: SecretMatchKind
  pattern: RegExp
  extract?: (match: string) => string | null
  minValueLength: number
}

/**
 * Structural detection mirrors `credentialPatterns` above: the same shapes that redaction
 * scrubs are fingerprintable. Keep these two lists in sync when redaction patterns change.
 */
const credentialDescriptors: readonly CredentialDescriptor[] = [
  { kind: 'credential', pattern: credentialPatterns[0]!, minValueLength: 0 },
  { kind: 'jwt', pattern: credentialPatterns[1]!, minValueLength: 0 },
  { kind: 'credential_header', pattern: credentialPatterns[2]!, extract: extractHeaderValue, minValueLength: 6 },
  { kind: 'bearer', pattern: credentialPatterns[3]!, extract: extractBearerValue, minValueLength: 6 },
  { kind: 'key_value', pattern: credentialPatterns[4]!, extract: extractKeyValue, minValueLength: 6 },
]

/** True when the text itself contains a redactable credential shape (used to keep field paths clean). */
function containsSecretShape(text: string): boolean {
  if (!text) return false
  if (findPemPrivateKeySpans(text, 1).length > 0) return true
  for (const descriptor of credentialDescriptors) {
    const pattern = new RegExp(descriptor.pattern.source, descriptor.pattern.flags)
    for (const match of text.matchAll(pattern)) {
      const raw = descriptor.extract ? descriptor.extract(match[0]) : match[0]
      if (raw && raw.length >= descriptor.minValueLength) return true
    }
  }
  return false
}

/** Stable fingerprint used by verifiers to compare against a locally held secret. */
export function sha256Prefix(value: string): string {
  const bounded = value.length > maxScannedMatchLength ? value.slice(0, maxScannedMatchLength) : value
  return createHash('sha256').update(bounded, 'utf8').digest('hex').slice(0, 12)
}

interface CompiledScanContext {
  matcher: SecretMatcher
  fingerprints: readonly string[]
  variantsBySecret: ReadonlyArray<readonly string[]>
}

function buildScanContext(secrets: readonly NamedSecret[]): CompiledScanContext | null {
  if (secrets.length === 0) return null
  const matcher = compileSecretMatcher(secrets, { minLength: 4 })
  if (matcher.secretCount === 0) return null
  const fingerprints = matcher.dedupedSecrets.map(s => sha256Prefix(s.value))
  const variantsBySecret = matcher.dedupedSecrets.map(s => (
    s.value.length > MAX_SECRET_VARIANT_INPUT_CHARS ? [s.value] : getCachedEncodingVariants(s.value, 4)
  ))
  return { matcher, fingerprints, variantsBySecret }
}

/**
 * Scans a pre-redaction text body for secret-shaped values and registered named secrets,
 * returning redacted structural metadata only. Call this before `redact()`; the original
 * string is never mutated and never returned.
 */
export function scanSecrets(text: string, options: SecretScanOptions = {}): SecretMatch[] {
  if (!text) return []
  const boundedText = text.length > MAX_BODY_SCAN_BYTES ? text.slice(0, MAX_BODY_SCAN_BYTES) : text
  const acc = new MatchAccumulator(options.maxMatches ?? defaultMaxMatches, options.maxCountPerMatch ?? defaultMaxCountPerMatch)
  const named = options.secrets ?? []
  const scanCtx = buildScanContext(named)
  const leaves = options.jsonPaths === false ? null : tryJsonStringLeaves(boundedText)
  if (leaves) {
    for (const leaf of leaves) scanRegion(acc, leaf.text, leaf.path, named, scanCtx)
    // Whole-body pass only fills in shapes that JSON leaves could not attribute
    // (e.g. a PEM block spanning string boundaries, or malformed JSON).
    scanRegion(acc, boundedText, 'body', named, scanCtx, acc.fingerprints())
    return acc.list()
  }
  scanRegion(acc, boundedText, 'body', named, scanCtx)
  return acc.list()
}

/** Same structural scan for response headers (pass the pre-redaction header map). */
export function scanSecretHeaders(
  headers: Record<string, string | string[] | undefined>,
  options: SecretScanOptions = {},
): SecretMatch[] {
  const acc = new MatchAccumulator(options.maxMatches ?? defaultMaxMatches, options.maxCountPerMatch ?? defaultMaxCountPerMatch)
  const named = options.secrets ?? []
  const scanCtx = buildScanContext(named)
  for (const [name, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const value = (Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)).slice(0, maxHeaderScanLength)
    if (!value) continue
    scanRegion(acc, value, `headers.${cleanPathSegment(name).toLowerCase()}`, named, scanCtx)
  }
  return acc.list()
}

class MatchAccumulator {
  private readonly entries = new Map<string, SecretMatch>()
  private readonly fingerprintsSeen = new Set<string>()
  private readonly maxMatches: number
  private readonly maxCount: number

  constructor(maxMatches: number, maxCount: number) {
    this.maxMatches = maxMatches
    this.maxCount = maxCount
  }

  fingerprints(): ReadonlySet<string> {
    return this.fingerprintsSeen
  }

  countCap(): number {
    return this.maxCount
  }

  add(kind: SecretMatchKind, sha256PrefixValue: string, fieldPath: string, count = 1): void {
    const key = `${kind}\u0000${sha256PrefixValue}\u0000${fieldPath}`
    const existing = this.entries.get(key)
    if (existing) {
      existing.count = Math.min(this.maxCount, existing.count + count)
      return
    }
    this.fingerprintsSeen.add(sha256PrefixValue)
    if (this.entries.size >= this.maxMatches) return
    this.entries.set(key, { kind, sha256Prefix: sha256PrefixValue, fieldPath, count: Math.min(count, this.maxCount) })
  }

  list(): SecretMatch[] {
    return [...this.entries.values()]
  }
}

function scanRegion(
  acc: MatchAccumulator,
  text: string,
  fieldPath: string,
  namedSecrets: readonly NamedSecret[],
  scanCtx: CompiledScanContext | null,
  skipFingerprints?: ReadonlySet<string>,
): void {
  if (!text) return
  // Field paths derive from attacker-influenceable JSON keys / header names. Never let a secret
  // value ride along inside structured metadata: drop to a generic path when the path itself looks
  // like (or contains) a secret.
  const safeFieldPath = isSafeMetadataPath(fieldPath, namedSecrets)
    ? fieldPath
    : (fieldPath.startsWith('headers.') ? 'headers' : 'body')
  for (const span of findPemPrivateKeySpans(text)) {
    const raw = text.slice(span.start, span.end)
    const fingerprint = sha256Prefix(raw)
    if (skipFingerprints?.has(fingerprint)) continue
    acc.add('private_key', fingerprint, safeFieldPath)
  }
  for (const descriptor of credentialDescriptors) {
    const pattern = new RegExp(descriptor.pattern.source, descriptor.pattern.flags)
    for (const match of text.matchAll(pattern)) {
      const raw = descriptor.extract ? descriptor.extract(match[0]) : match[0]
      if (!raw || raw.length < descriptor.minValueLength) continue
      const fingerprint = sha256Prefix(raw)
      if (skipFingerprints?.has(fingerprint)) continue
      acc.add(descriptor.kind, fingerprint, safeFieldPath)
    }
  }
  if (!scanCtx) return
  const matchedIndices = scanCtx.matcher.findMatchedSecretIndices(text)
  if (matchedIndices.size === 0) return
  for (const si of matchedIndices) {
    const fingerprint = scanCtx.fingerprints[si]!
    if (skipFingerprints?.has(fingerprint)) continue
    let occurrences = 0
    for (const form of scanCtx.variantsBySecret[si]!) {
      occurrences += countOccurrences(text, form, acc.countCap())
      if (occurrences >= acc.countCap()) break
    }
    if (occurrences === 0) continue
    acc.add('named_secret', fingerprint, safeFieldPath, occurrences)
  }
}

const metadataPathPattern = /^[A-Za-z0-9_.\[\]<> -]{1,256}$/

/**
 * Field paths are attacker-influenced (JSON keys / header names), so metadata paths must be
 * structurally boring: printable identifiers only, no secret shapes, no registered secrets, and no
 * high-entropy blobs. Anything else is dropped by callers rather than persisted.
 */
export function isSafeMetadataPath(fieldPath: string, namedSecrets: readonly NamedSecret[] = []): boolean {
  if (!fieldPath || !metadataPathPattern.test(fieldPath)) return false
  if (containsSecretShape(fieldPath)) return false
  if (looksHighEntropy(fieldPath)) return false
  for (const secret of namedSecrets) {
    if (secret.value && secret.value.length >= 4 && fieldPath.includes(secret.value)) return false
  }
  return true
}

function looksHighEntropy(segment: string): boolean {
  if (segment.length < 24) return false
  const digits = segment.match(/\d/g)?.length ?? 0
  const letters = segment.match(/[A-Za-z]/g)?.length ?? 0
  return digits >= 6 && letters >= 6
}

function countOccurrences(haystack: string, needle: string, cap: number): number {
  if (cap <= 0) return 0
  let count = 0
  let index = 0
  while (count < cap) {
    index = haystack.indexOf(needle, index)
    if (index === -1) break
    count += 1
    index += needle.length
  }
  return count
}

function extractHeaderValue(match: string): string | null {
  const index = match.indexOf(':')
  if (index === -1) return null
  const value = match.slice(index + 1).trim()
  return value || null
}

function extractBearerValue(match: string): string | null {
  const parsed = /^\s*Bearer\s+(\S+)\s*$/i.exec(match)
  return parsed?.[1] ?? null
}

function extractKeyValue(match: string): string | null {
  const separator = match.search(/[:=]/)
  if (separator === -1) return null
  let value = match.slice(separator + 1).trim()
  if (value.length >= 2) {
    const first = value[0]
    const last = value[value.length - 1]
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) value = value.slice(1, -1)
  }
  return value || null
}

/**
 * Parses a JSON body and returns its string leaves with bounded key paths. Returns null when the
 * body is not JSON or exceeds the scan budget, in which case callers attribute matches to `body`.
 */
function tryJsonStringLeaves(text: string): Array<{ path: string; text: string }> | null {
  const trimmed = text.trim()
  if (trimmed.length < 2 || trimmed.length > maxJsonBodyScanBytes) return null
  if (trimmed[0] !== '{' && trimmed[0] !== '[') return null
  let root: unknown
  try {
    root = JSON.parse(trimmed)
  } catch {
    return null
  }
  const leaves: Array<{ path: string; text: string }> = []
  let nodes = 0
  const walk = (value: unknown, path: string, depth: number): void => {
    if (nodes >= maxJsonNodes || depth > maxJsonDepth || path.length > maxFieldPathLength) return
    nodes += 1
    if (typeof value === 'string') {
      if (value) leaves.push({ path, text: value })
      return
    }
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        walk(value[index], `${path}[${index}]`, depth + 1)
        if (nodes >= maxJsonNodes) return
      }
      return
    }
    if (value && typeof value === 'object') {
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        const segment = cleanPathSegment(key)
        if (!segment) continue
        walk(child, path ? `${path}.${segment}` : segment, depth + 1)
        if (nodes >= maxJsonNodes) return
      }
    }
  }
  walk(root, 'body', 0)
  return leaves
}

function cleanPathSegment(key: string): string {
  // Key names are attacker-influenced. Strip control characters, bound length, and replace
  // high-entropy blobs so the metadata stays log-safe even when a response uses pathological keys.
  const cleaned = key.replace(/[\u0000-\u001f\u007f]/g, '').replace(/\s+/g, ' ').trim()
  if (looksHighEntropy(cleaned)) return '<key>'
  return cleaned.slice(0, 48)
}

export function redactHeaders(
  headers: Record<string, string | string[] | undefined>,
  secrets: readonly NamedSecret[] = [],
): Record<string, string> {
  const matcher = secrets.length > 0 ? compileSecretMatcher(secrets, { minLength: 4 }) : undefined
  const out: Record<string, string> = {}
  for (const [key, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const value = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
    out[key] = SENSITIVE_HTTP_HEADER_RE.test(key) ? '[redacted]' : redactWithMatcher(value, matcher)
  }
  return out
}

function scrubSensitiveSubtree(value: unknown): unknown {
  if (typeof value === 'string') return '[redacted]'
  if (Array.isArray(value)) return value.map(item => scrubSensitiveSubtree(item))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubSensitiveSubtree(v)
    }
    return out
  }
  return value
}

const sensitiveCredentialKeyPattern = /^(?:[A-Za-z0-9_-]*(?:password|passwd|api[_-]?key|signing[_-]?key|private[_-]?key|token|secret|session[_-]?(?:id|key)|service[_-]?role[_-]?key)|credentials?|authorization|cookie|set-cookie)$/i

function redactJsonNode<T>(value: T, matcher?: SecretMatcher): T {
  if (typeof value === 'string') return redactWithMatcher(value, matcher) as unknown as T
  if (Array.isArray(value)) return value.map(item => redactJsonNode(item, matcher)) as unknown as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = sensitiveCredentialKeyPattern.test(k) ? scrubSensitiveSubtree(v) : redactJsonNode(v, matcher)
    }
    return out as T
  }
  return value
}

export function redactJsonValue<T>(value: T, secrets: readonly NamedSecret[] = []): T {
  const matcher = secrets.length > 0 ? compileSecretMatcher(secrets, { minLength: 4 }) : undefined
  return redactJsonNode(value, matcher)
}

// ============================================================================
// v7 M4: Zero-Data-Retention (ZDR) & PII Redaction
// ============================================================================

export interface PiiRedactionOptions {
  secrets?: readonly NamedSecret[]
  /** Scrub email addresses (`[pii:email]`). Default true. */
  emails?: boolean
  /** Scrub US SSN shapes (`[pii:ssn]`). Default true. */
  ssns?: boolean
  /** Scrub Luhn-valid payment card numbers (`[pii:card]`). Default true. */
  cards?: boolean
  /** Scrub phone numbers (`[pii:phone]`). Default true. */
  phones?: boolean
  /** Scrub IPv4 client addresses (`[pii:ip]`). Default false. */
  ipAddresses?: boolean
  /** Scrub auth tokens, cookies, JWTs, API keys, and named secrets. Default true. */
  credentials?: boolean
}

const emailPiiPattern = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g
const ssnPiiPattern = /(?<![A-Za-z0-9-])(?!000|666|9\d\d)\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}(?![A-Za-z0-9-])/g
const cardCandidatePattern = /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g
const phonePiiPattern = /(?<![A-Za-z0-9-])(?:\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)|\d{1,4})[\s.-]?\d{2,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?|\(\d{3}\)\s?\d{3}[-\s]\d{4}|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b)(?![A-Za-z0-9-])/g
const ipv4PiiPattern = /(?<!\d)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d)/g
const sensitivePiiKeyPattern = /^(?:ssn|social[_-]?security|credit[_-]?card|card[_-]?number|pan|cvv|cvc|phone|phone[_-]?number|mobile|email|email[_-]?address|dob|date[_-]?of[_-]?birth|tax[_-]?id|passport|national[_-]?id)$/i

function passesLuhn(digits: string): boolean {
  if (digits.length < 13 || digits.length > 19) return false
  let sum = 0
  let alt = false
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48
    if (n < 0 || n > 9) return false
    if (alt) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    alt = !alt
  }
  return sum % 10 === 0
}

/** True when Zero-Data-Retention (ZDR) mode is enabled via environment configuration. */
export function isZdrModeEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env.KOVO_ZDR_MODE ?? '').trim().toLowerCase()
  return raw === '1' || raw === 'true' || raw === 'yes'
}

/**
 * Scrubs credentials (tokens, cookies, JWTs, named secrets) and PII (emails, SSNs, Luhn-valid
 * payment cards, phone numbers, optional IPs) from free text for ZDR storage and portable exports.
 */
function redactPiiWithMatcher(text: string, options: PiiRedactionOptions, matcher?: SecretMatcher): string {
  if (!text) return text
  let out = options.credentials === false
    ? (text.length > MAX_REDACT_INPUT_BYTES ? `${text.slice(0, MAX_REDACT_INPUT_BYTES)}…[truncated]` : text)
    : redactWithMatcher(text, matcher)
  if (options.emails !== false) {
    out = out.replace(emailPiiPattern, '[pii:email]')
  }
  if (options.cards !== false) {
    out = out.replace(cardCandidatePattern, match => {
      const digits = match.replace(/\D/g, '')
      return passesLuhn(digits) ? '[pii:card]' : match
    })
  }
  if (options.ssns !== false) {
    out = out.replace(ssnPiiPattern, '[pii:ssn]')
  }
  if (options.phones !== false) {
    out = out.replace(phonePiiPattern, match => {
      // Avoid redacting ISO dates like 2026-11-24 or version strings.
      if (/^\d{4}-\d{2}-\d{2}$/.test(match.trim())) return match
      const digitCount = match.replace(/\D/g, '').length
      return digitCount >= 10 && digitCount <= 15 ? '[pii:phone]' : match
    })
  }
  if (options.ipAddresses === true) {
    out = out.replace(ipv4PiiPattern, '[pii:ip]')
  }
  return out
}

export function redactPii(text: string, options: PiiRedactionOptions = {}): string {
  if (!text) return text
  const secrets = options.secrets ?? []
  const matcher = options.credentials !== false && secrets.length > 0
    ? compileSecretMatcher(secrets, { minLength: 4 })
    : undefined
  return redactPiiWithMatcher(text, options, matcher)
}

/** Full ZDR text scrubber (all credentials + emails/SSNs/cards/phones). */
export function redactZdr(text: string, secrets: readonly NamedSecret[] = []): string {
  return redactPii(text, { secrets })
}

function redactZdrJsonNode<T>(value: T, options: PiiRedactionOptions, matcher?: SecretMatcher): T {
  if (typeof value === 'string') return redactPiiWithMatcher(value, options, matcher) as unknown as T
  if (Array.isArray(value)) return value.map(item => redactZdrJsonNode(item, options, matcher)) as unknown as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (sensitiveCredentialKeyPattern.test(k)) {
        out[k] = scrubSensitiveSubtree(v)
      } else if (sensitivePiiKeyPattern.test(k)) {
        out[k] = typeof v === 'string' || typeof v === 'number' ? '[pii:redacted]' : scrubSensitiveSubtree(v)
      } else {
        out[k] = redactZdrJsonNode(v, options, matcher)
      }
    }
    return out as T
  }
  return value
}

/** Recursively scrubs secrets AND PII across JSON payloads (including PII-named keys). */
export function redactZdrJsonValue<T>(value: T, options: PiiRedactionOptions = {}): T {
  const secrets = options.secrets ?? []
  const matcher = options.credentials !== false && secrets.length > 0
    ? compileSecretMatcher(secrets, { minLength: 4 })
    : undefined
  return redactZdrJsonNode(value, options, matcher)
}
