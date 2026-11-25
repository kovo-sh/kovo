import { createHash } from 'node:crypto'

export interface NamedSecret {
  value: string
  placeholder: string
}

export const SENSITIVE_HTTP_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-refresh-token|x-session-token|x-session-id|x-csrf-token|x-xsrf-token|csrf-token|xsrf-token|x-amz-security-token|x-forwarded-authorization)$/i

const SECRET_KEY_CORE = '(?:[A-Za-z0-9_-]*(?:password|passwd|api[_-]?key|signing[_-]?key|private[_-]?key|encryption[_-]?key|master[_-]?key|hmac[_-]?key|jwt[_-]?key|secret[_-]?key(?:[_-]?base)?|secret[_-]?access[_-]?key|token|secret|session[_-]?(?:id|key|cookie)|service[_-]?role[_-]?key)|authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)'

const credentialPatterns = [
  /\b(?:sk-or-v1-[A-Za-z0-9_-]+|sk-ant-[A-Za-z0-9_-]+|sk-proj-[A-Za-z0-9_-]+|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|(?:AKIA|ASIA)[0-9A-Z]{16}|(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}|whsec_[0-9A-Za-z]{16,}|xox[baprs]-[0-9A-Za-z-]{10,}|glpat-[0-9A-Za-z_-]{16,}|SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}|AIza[0-9A-Za-z_-]{35}|npm_[0-9A-Za-z]{20,}|pypi-[0-9A-Za-z_-]{20,}|hf_[0-9A-Za-z]{20,})\b/g,
  /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g,
  /-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g,
  /(?<!")\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)\s*:\s*[^\n\r"]+/gi,
  /\bBearer\s+[a-z0-9._~+/=-]{8,}/gi,
  new RegExp(
    `("${SECRET_KEY_CORE}"\\s*:\\s*)(?:(null|\\{|\\[|"")|"(?:\\\\.|[^"\\\\])*"|-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?|true|false)|(?<![A-Za-z0-9_-])${SECRET_KEY_CORE}["']?\\s*[:=]\\s*(?:"(?:\\\\.|[^"\\\\])*"|'[^']*'|[^\\s&,;}"']+)`,
    'gi',
  ),
]

function htmlEscapeBasic(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

/**
 * Generates exact encoded variants of a registered secret for zero-heuristic scrubbing (M-14):
 * raw, URL-encoded (uppercase/lowercase/form), base64 (padded/unpadded/URL-encoded), base64url,
 * JSON-escaped, PHP slash-escaped (`\/`), and HTML-entity-encoded.
 */
export function buildSecretEncodingVariants(value: string, minEncodedLength = 4): string[] {
  const forms = new Set<string>([value])
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
  }
  const buf = Buffer.from(value, 'utf8')
  const b64 = buf.toString('base64')
  add(b64)
  add(b64.replace(/=+$/, ''))
  const b64UrlEnc = encodeURIComponent(b64)
  if (b64UrlEnc !== b64) add(b64UrlEnc)
  const b64url = buf.toString('base64url')
  add(b64url)
  const jsonEscaped = JSON.stringify(value).slice(1, -1)
  add(jsonEscaped)
  if (value.includes('/')) {
    add(value.replaceAll('/', '\\/'))
    add(jsonEscaped.replaceAll('/', '\\/'))
  }
  if (/[&<>"']/.test(value)) {
    const htmlEsc = htmlEscapeBasic(value)
    add(htmlEsc)
    if (value.includes("'")) add(htmlEsc.replaceAll('&#39;', '&#x27;'))
  }
  return [...forms]
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
  const minLen = Math.max(1, options.minLength ?? 4)
  const needles: Array<{ needle: string; placeholder: string }> = []
  for (const secret of secrets) {
    if (!secret.value || secret.value.length < minLen) continue
    for (const variant of buildSecretEncodingVariants(secret.value, Math.min(4, minLen))) {
      needles.push({ needle: variant, placeholder: secret.placeholder })
    }
  }
  if (needles.length === 0) return text
  needles.sort((a, b) => b.needle.length - a.needle.length)
  let out = text
  for (const { needle, placeholder } of needles) {
    if (out.includes(needle)) out = out.replaceAll(needle, () => placeholder)
  }
  return out
}

export function redact(text: string, secrets: readonly NamedSecret[] = []): string {
  let out = redactExactValues(text, secrets, { minLength: 4 })
  out = credentialPatterns.slice(0, 5).reduce((value, pattern) => value.replace(pattern, '[redacted]'), out)
  return out.replace(credentialPatterns[5]!, (_m, jsonPrefix?: string, preserved?: string) => (
    jsonPrefix ? `${jsonPrefix}${preserved !== undefined ? preserved : '"[redacted]"'}` : '[redacted]'
  ))
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
  { kind: 'private_key', pattern: credentialPatterns[2]!, minValueLength: 0 },
  { kind: 'credential_header', pattern: credentialPatterns[3]!, extract: extractHeaderValue, minValueLength: 6 },
  { kind: 'bearer', pattern: credentialPatterns[4]!, extract: extractBearerValue, minValueLength: 6 },
  { kind: 'key_value', pattern: credentialPatterns[5]!, extract: extractKeyValue, minValueLength: 6 },
]

/** True when the text itself contains a redactable credential shape (used to keep field paths clean). */
function containsSecretShape(text: string): boolean {
  if (!text) return false
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

/**
 * Scans a pre-redaction text body for secret-shaped values and registered named secrets,
 * returning redacted structural metadata only. Call this before `redact()`; the original
 * string is never mutated and never returned.
 */
export function scanSecrets(text: string, options: SecretScanOptions = {}): SecretMatch[] {
  if (!text) return []
  const acc = new MatchAccumulator(options.maxMatches ?? defaultMaxMatches, options.maxCountPerMatch ?? defaultMaxCountPerMatch)
  const named = options.secrets ?? []
  const leaves = options.jsonPaths === false ? null : tryJsonStringLeaves(text)
  if (leaves) {
    for (const leaf of leaves) scanRegion(acc, leaf.text, leaf.path, named)
    // Whole-body pass only fills in shapes that JSON leaves could not attribute
    // (e.g. a PEM block spanning string boundaries, or malformed JSON).
    scanRegion(acc, text, 'body', named, acc.fingerprints())
    return acc.list()
  }
  scanRegion(acc, text, 'body', named)
  return acc.list()
}

/** Same structural scan for response headers (pass the pre-redaction header map). */
export function scanSecretHeaders(
  headers: Record<string, string | string[] | undefined>,
  options: SecretScanOptions = {},
): SecretMatch[] {
  const acc = new MatchAccumulator(options.maxMatches ?? defaultMaxMatches, options.maxCountPerMatch ?? defaultMaxCountPerMatch)
  const named = options.secrets ?? []
  for (const [name, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const value = (Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)).slice(0, maxHeaderScanLength)
    if (!value) continue
    scanRegion(acc, value, `headers.${cleanPathSegment(name).toLowerCase()}`, named)
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
  skipFingerprints?: ReadonlySet<string>,
): void {
  if (!text) return
  // Field paths derive from attacker-influenceable JSON keys / header names. Never let a secret
  // value ride along inside structured metadata: drop to a generic path when the path itself looks
  // like (or contains) a secret.
  const safeFieldPath = isSafeMetadataPath(fieldPath, namedSecrets)
    ? fieldPath
    : (fieldPath.startsWith('headers.') ? 'headers' : 'body')
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
  for (const secret of namedSecrets) {
    if (!secret.value || secret.value.length < 4) continue
    let occurrences = 0
    for (const form of secretVariants(secret.value)) {
      occurrences += countOccurrences(text, form, acc.countCap())
      if (occurrences >= acc.countCap()) break
    }
    if (occurrences === 0) continue
    const fingerprint = sha256Prefix(secret.value)
    if (skipFingerprints?.has(fingerprint)) continue
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

function secretVariants(value: string): string[] {
  return buildSecretEncodingVariants(value, 4)
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
  const out: Record<string, string> = {}
  for (const [key, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const value = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
    out[key] = SENSITIVE_HTTP_HEADER_RE.test(key) ? '[redacted]' : redact(value, secrets)
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

export function redactJsonValue<T>(value: T, secrets: readonly NamedSecret[] = []): T {
  if (typeof value === 'string') return redact(value, secrets) as unknown as T
  if (Array.isArray(value)) return value.map(item => redactJsonValue(item, secrets)) as unknown as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = sensitiveCredentialKeyPattern.test(k) ? scrubSensitiveSubtree(v) : redactJsonValue(v, secrets)
    }
    return out as T
  }
  return value
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
export function redactPii(text: string, options: PiiRedactionOptions = {}): string {
  if (!text) return text
  let out = options.credentials === false ? text : redact(text, options.secrets ?? [])
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

/** Full ZDR text scrubber (all credentials + emails/SSNs/cards/phones). */
export function redactZdr(text: string, secrets: readonly NamedSecret[] = []): string {
  return redactPii(text, { secrets })
}

/** Recursively scrubs secrets AND PII across JSON payloads (including PII-named keys). */
export function redactZdrJsonValue<T>(value: T, options: PiiRedactionOptions = {}): T {
  if (typeof value === 'string') return redactPii(value, options) as unknown as T
  if (Array.isArray(value)) return value.map(item => redactZdrJsonValue(item, options)) as unknown as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (sensitiveCredentialKeyPattern.test(k)) {
        out[k] = scrubSensitiveSubtree(v)
      } else if (sensitivePiiKeyPattern.test(k)) {
        out[k] = typeof v === 'string' || typeof v === 'number' ? '[pii:redacted]' : scrubSensitiveSubtree(v)
      } else {
        out[k] = redactZdrJsonValue(v, options)
      }
    }
    return out as T
  }
  return value
}
