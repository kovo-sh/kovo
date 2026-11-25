import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { containsDestructivePayload, containsWebshellSignature } from '../src/replay-spec.ts'
import {
  normalizeTechTagSet,
  parseSafeTemplateYaml,
  templateTechTags,
  type SafeTemplate,
  type TemplateTechTag,
} from '../src/templates/loader.ts'

// ============================================================================
// Types
// ============================================================================

export interface TranspileTemplateOptions {
  sourceFile?: string
  existingIds?: ReadonlySet<string>
  reviewedTier3Ids?: ReadonlySet<string>
}

export type TranspileTemplateOutcome =
  | { ok: true; id: string; yaml: string; template: SafeTemplate }
  | { ok: false; id?: string; reason: string }

export interface TranspileDirectoryOptions {
  maxTemplates?: number
  cleanOutput?: boolean
  existingIds?: ReadonlySet<string>
  reviewedTier3Ids?: ReadonlySet<string>
}

export interface TranspileDirectoryReport {
  scanned: number
  transpiled: number
  rejected: Array<{ file: string; reason: string }>
  rejectionReasons: Record<string, number>
  outputFiles: string[]
  durationMs: number
}

// ============================================================================
// Strict Zero-Dependency Nuclei Input YAML Parser (supports | / > block scalars,
// rejects anchors &, aliases *, custom tags !!/!, merge keys <<, multi-doc ---)
// ============================================================================

interface RawLine {
  indent: number
  raw: string
  trimmed: string
  no: number
}

class NucleiYamlError extends Error {
  constructor(message: string, line?: number) {
    super(line ? `Nuclei YAML line ${line}: ${message}` : `Nuclei YAML: ${message}`)
    this.name = 'NucleiYamlError'
  }
}

function stripYamlComment(line: string): string {
  let quote: string | null = null
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    if (quote) {
      if (ch === '\\' && quote === '"') { i += 1; continue }
      if (ch === quote) {
        if (quote === "'" && line[i + 1] === "'") { i += 1; continue }
        quote = null
      }
    } else if (ch === '"' || ch === "'") {
      const prev = i === 0 ? ' ' : line[i - 1]
      if (/[\s:\[{,\-]/.test(prev)) quote = ch
    } else if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i)
    }
  }
  return line
}

function unquoteScalar(s: string, no: number): string {
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2) throw new NucleiYamlError('unterminated double-quoted string', no)
    return s.slice(1, -1).replace(/\\(["\\nrtbf/]|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})/g, (_m, c: string) => {
      if (c === 'n') return '\n'
      if (c === 'r') return '\r'
      if (c === 't') return '\t'
      if (c === 'b') return '\b'
      if (c === 'f') return '\f'
      if (c.startsWith('u') || c.startsWith('x')) return String.fromCharCode(parseInt(c.slice(1), 16))
      return c
    })
  }
  if (!s.endsWith("'") || s.length < 2) throw new NucleiYamlError('unterminated single-quoted string', no)
  return s.slice(1, -1).replaceAll("''", "'")
}

function splitFlowTopLevel(s: string, sep: string): string[] {
  const parts: string[] = []
  let depth = 0
  let quote: string | null = null
  let cur = ''
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i]
    if (quote) {
      cur += ch
      if (ch === '\\' && quote === '"') { cur += s[i + 1] ?? ''; i += 1; continue }
      if (ch === quote) {
        if (quote === "'" && s[i + 1] === "'") { cur += "'"; i += 1; continue }
        quote = null
      }
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue }
    if (ch === '[' || ch === '{') depth += 1
    if (ch === ']' || ch === '}') depth -= 1
    if (ch === sep && depth === 0) { parts.push(cur); cur = ''; continue }
    cur += ch
  }
  if (cur.trim() !== '' || parts.length > 0) parts.push(cur)
  return parts
}

function findSplitColon(text: string): number {
  let quote: string | null = null
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (ch === '\\' && quote === '"') { i += 1; continue }
      if (ch === quote) {
        if (quote === "'" && text[i + 1] === "'") { i += 1; continue }
        quote = null
      }
      continue
    }
    if (ch === '"' || ch === "'") { if (i === 0) quote = ch; continue }
    if (ch === ':' && (i === text.length - 1 || text[i + 1] === ' ')) return i
  }
  return -1
}

function hasBalancedFlow(text: string): boolean {
  let depth = 0
  let quote: string | null = null
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (ch === '\\' && quote === '"') { i += 1; continue }
      if (ch === quote) {
        if (quote === "'" && text[i + 1] === "'") { i += 1; continue }
        quote = null
      }
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; continue }
    if (ch === '[' || ch === '{') depth += 1
    if (ch === ']' || ch === '}') depth -= 1
  }
  return depth <= 0
}

function parseInlineValue(raw: string, no: number): unknown {
  const s = raw.trim()
  if (s === '' || s === '~' || s === 'null') return null
  if (s.startsWith('[')) {
    if (!s.endsWith(']')) throw new NucleiYamlError('unterminated flow sequence', no)
    return splitFlowTopLevel(s.slice(1, -1), ',')
      .map(p => p.trim())
      .filter(p => p !== '')
      .map(p => parseInlineValue(p, no))
  }
  if (s.startsWith('{')) {
    if (!s.endsWith('}')) throw new NucleiYamlError('unterminated flow map', no)
    const obj: Record<string, unknown> = {}
    for (const part of splitFlowTopLevel(s.slice(1, -1), ',').map(p => p.trim()).filter(p => p !== '')) {
      const at = findSplitColon(part)
      if (at < 0) throw new NucleiYamlError(`invalid flow map entry`, no)
      const rk = part.slice(0, at).trim()
      const quoted = rk.startsWith('"') || rk.startsWith("'")
      if (!quoted && /^[&*!]/.test(rk)) throw new NucleiYamlError(`unsupported YAML construct "${rk[0]}"`, no)
      const key = quoted ? unquoteScalar(rk, no) : rk
      if (key === '<<') throw new NucleiYamlError('merge keys are not supported', no)
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new NucleiYamlError(`forbidden key "${key}"`, no)
      }
      obj[key] = parseInlineValue(part.slice(at + 1), no)
    }
    return obj
  }
  if (s.startsWith('"') || s.startsWith("'")) return unquoteScalar(s, no)
  if (/^[&*!]/.test(s)) throw new NucleiYamlError(`unsupported YAML construct "${s[0]}"`, no)
  if (/^(?:true|True|TRUE)$/.test(s)) return true
  if (/^(?:false|False|FALSE)$/.test(s)) return false
  if (/^-?\d+$/.test(s)) return Number(s)
  if (/^-?\d+\.\d+$/.test(s)) return Number(s)
  return s
}

interface ParseState {
  rawLines: string[]
  lines: RawLine[]
  i: number
}

function isBlockScalarHeader(s: string): { style: '|' | '>'; chomp: '' | '-' | '+'; indentHint?: number } | null {
  const m = s.match(/^([|>])([+-])?([1-9])?(?:\s+#.*)?$/)
  if (!m) return null
  return {
    style: m[1] as '|' | '>',
    chomp: (m[2] ?? '') as '' | '-' | '+',
    indentHint: m[3] ? Number(m[3]) : undefined,
  }
}

function readBlockScalar(
  state: ParseState,
  parentIndent: number,
  header: { style: '|' | '>'; chomp: '' | '-' | '+'; indentHint?: number },
  startRawLineNo: number,
): string {
  // Block scalar content lives in rawLines starting after line startRawLineNo (1-indexed -> rawLines[startRawLineNo])
  const collected: Array<{ indent: number; text: string }> = []
  let blockIndent: number | null = header.indentHint ? parentIndent + header.indentHint : null
  let rawIdx = startRawLineNo // 0-indexed next line after header
  while (rawIdx < state.rawLines.length) {
    const raw = state.rawLines[rawIdx]
    if (/^\t/.test(raw)) throw new NucleiYamlError('tabs are not allowed for indentation', rawIdx + 1)
    if (raw.trim() === '') {
      collected.push({ indent: 0, text: '' })
      rawIdx += 1
      continue
    }
    const ind = raw.length - raw.trimStart().length
    if (ind <= parentIndent) break
    if (blockIndent === null) blockIndent = ind
    if (ind < blockIndent) break
    collected.push({ indent: ind, text: raw.slice(blockIndent) })
    rawIdx += 1
  }
  // Advance state.i past any tokenized lines whose line.no <= rawIdx
  while (state.i < state.lines.length && state.lines[state.i].no <= rawIdx) {
    state.i += 1
  }
  // Trim trailing empty lines according to chomp
  let trailingEmpty = 0
  while (collected.length > 0 && collected[collected.length - 1].text === '') {
    collected.pop()
    trailingEmpty += 1
  }
  const linesOut = collected.map(c => c.text)
  let body = header.style === '|' ? linesOut.join('\n') : linesOut.join(' ')
  if (header.chomp === '') {
    if (linesOut.length > 0) body += '\n'
  } else if (header.chomp === '+') {
    body += '\n'.repeat(trailingEmpty + (linesOut.length > 0 ? 1 : 0))
  }
  return body
}

function joinMultilineFlow(state: ParseState, initial: string): string {
  let acc = initial
  while (!hasBalancedFlow(acc) && state.i < state.lines.length) {
    acc += ' ' + state.lines[state.i].trimmed
    state.i += 1
  }
  return acc
}

function parseNBlock(state: ParseState, indent: number): unknown {
  const line = state.lines[state.i]
  if (line.trimmed === '-' || line.trimmed.startsWith('- ')) return parseNSeq(state, line.indent)
  return parseNMap(state, indent)
}

function parseNMap(state: ParseState, indent: number): Record<string, unknown> {
  const obj: Record<string, unknown> = {}
  while (state.i < state.lines.length) {
    const line = state.lines[state.i]
    if (line.indent < indent) break
    if (line.indent > indent) throw new NucleiYamlError('unexpected indentation', line.no)
    if (line.trimmed === '-' || line.trimmed.startsWith('- ')) break
    const at = findSplitColon(line.trimmed)
    if (at < 0) throw new NucleiYamlError(`expected "key: value"`, line.no)
    const rawKey = line.trimmed.slice(0, at).trim()
    const isQuoted = rawKey.startsWith('"') || rawKey.startsWith("'")
    if (!isQuoted && /^[&*!|>]/.test(rawKey)) throw new NucleiYamlError(`unsupported YAML construct "${rawKey[0]}"`, line.no)
    const key = isQuoted ? unquoteScalar(rawKey, line.no) : rawKey
    if (key === '<<') throw new NucleiYamlError('merge keys are not supported', line.no)
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new NucleiYamlError(`forbidden key "${key}"`, line.no)
    }
    const rest = line.trimmed.slice(at + 1).trim()
    state.i += 1
    const blockHeader = rest ? isBlockScalarHeader(rest) : null
    if (blockHeader) {
      obj[key] = readBlockScalar(state, line.indent, blockHeader, line.no)
    } else if (rest === '') {
      const next = state.lines[state.i]
      if (next && next.indent > indent) {
        obj[key] = parseNBlock(state, next.indent)
      } else if (next && next.indent === indent && (next.trimmed === '-' || next.trimmed.startsWith('- '))) {
        obj[key] = parseNSeq(state, indent)
      } else {
        obj[key] = null
      }
    } else if ((rest.startsWith('[') || rest.startsWith('{')) && !hasBalancedFlow(rest)) {
      const joined = joinMultilineFlow(state, rest)
      obj[key] = parseInlineValue(joined, line.no)
    } else {
      obj[key] = parseInlineValue(rest, line.no)
    }
  }
  return obj
}

function parseNSeq(state: ParseState, indent: number): unknown[] {
  const arr: unknown[] = []
  while (state.i < state.lines.length) {
    const line = state.lines[state.i]
    if (line.indent < indent) break
    if (line.indent > indent) throw new NucleiYamlError('unexpected indentation in sequence', line.no)
    if (!(line.trimmed === '-' || line.trimmed.startsWith('- '))) break
    const content = line.trimmed.slice(1).trimStart()
    const offset = line.trimmed.length - content.length
    const blockHeader = content ? isBlockScalarHeader(content) : null
    if (blockHeader) {
      state.i += 1
      arr.push(readBlockScalar(state, line.indent, blockHeader, line.no))
      continue
    }
    if (content === '') {
      state.i += 1
      const next = state.lines[state.i]
      arr.push(next && next.indent > indent ? parseNBlock(state, next.indent) : null)
      continue
    }
    const startsFlowOrQuote = content.startsWith('[') || content.startsWith('{') || content.startsWith('"') || content.startsWith("'")
    if (!startsFlowOrQuote && findSplitColon(content) >= 0) {
      state.lines[state.i] = { indent: indent + offset, raw: line.raw, trimmed: content, no: line.no }
      arr.push(parseNMap(state, indent + offset))
      continue
    }
    if (startsFlowOrQuote && (content.startsWith('"') || content.startsWith("'")) && findSplitColon(content) > 0) {
      state.lines[state.i] = { indent: indent + offset, raw: line.raw, trimmed: content, no: line.no }
      arr.push(parseNMap(state, indent + offset))
      continue
    }
    state.i += 1
    if ((content.startsWith('[') || content.startsWith('{')) && !hasBalancedFlow(content)) {
      const joined = joinMultilineFlow(state, content)
      arr.push(parseInlineValue(joined, line.no))
    } else {
      arr.push(parseInlineValue(content, line.no))
    }
  }
  return arr
}

export function parseNucleiYaml(src: string): unknown {
  const rawLines = src.replace(/\r\n?/g, '\n').split('\n')
  const lines: RawLine[] = []
  let ended = false
  for (let n = 0; n < rawLines.length; n += 1) {
    const raw = rawLines[n]
    const stripped = stripYamlComment(raw).replace(/\s+$/, '')
    if (!stripped.trim()) continue
    if (/^\t/.test(stripped)) throw new NucleiYamlError('tabs are not allowed for indentation', n + 1)
    if (/^---\s*$/.test(stripped)) {
      if (lines.length === 0 && !ended) continue
      throw new NucleiYamlError('multi-document streams are not supported', n + 1)
    }
    if (/^\.\.\.\s*$/.test(stripped)) {
      ended = true
      continue
    }
    if (ended) throw new NucleiYamlError('content after document end marker', n + 1)
    const indent = stripped.length - stripped.trimStart().length
    lines.push({ indent, raw, trimmed: stripped.trimStart(), no: n + 1 })
  }
  if (lines.length === 0) return null
  const state: ParseState = { rawLines, lines, i: 0 }
  const value = parseNBlock(state, lines[0].indent)
  if (state.i < state.lines.length) throw new NucleiYamlError('unexpected trailing content', state.lines[state.i].no)
  return value
}

// ============================================================================
// Safety Filters, Placeholder Rewriting, Tech Mapping & MiniYaml Emission
// ============================================================================

const NON_HTTP_PROTOCOLS = [
  'network', 'tcp', 'dns', 'file', 'headless', 'code', 'javascript', 'websocket', 'ssl', 'whois', 'multiprotocol',
]
const ALLOWED_READONLY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const TIER3_MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH'])
const FORBIDDEN_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|content-length|transfer-encoding)$/i
const BOILERPLATE_RAW_HEADERS = new Set(['user-agent', 'accept', 'accept-encoding', 'accept-language', 'connection', 'cache-control', 'pragma', 'upgrade-insecure-requests'])
const THIRD_PARTY_OAST_RE = /(?:interact\.sh|interactsh|oast\.(?:pro|live|site|online|fun|me)|oast\.[a-z]{2,10}\b|burpcollaborator|requestbin|pipedream|webhook\.site|ngrok|canarytokens|dnslog|ceye\.io|oastify|beeceptor|requestcatcher|dnsbin\.|bxss\.me|xss\.ht)/i
const PRIVATE_HOST_RE = /(?:\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b|\b169\.254\.\d{1,3}\.\d{1,3}\b|\b0\.0\.0\.0\b|\blocalhost\b|\[::1?\]|::ffff:|metadata\.google\.internal|metadata\.azure\.internal|100\.100\.100\.200|\b2852039166\b|\b0xa9fea9fe\b|\bfd[0-9a-f]{2}:)/i
const ALLOWED_TECH_SET = new Set<string>(templateTechTags)

function decodeLoose(text: string): string {
  try { return decodeURIComponent(text) } catch { return text }
}

function normalizeId(rawId: string): string {
  const cleaned = rawId
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
  if (cleaned.length >= 3 && cleaned.length <= 64 && /^[a-z0-9][a-z0-9-]{2,63}$/.test(cleaned)) {
    return cleaned
  }
  const hash = createHash('sha256').update(rawId).digest('hex').slice(0, 6)
  const base = (cleaned || 'tmpl').slice(0, 56).replace(/-+$/g, '')
  const candidate = `${base}-${hash}`
  return candidate.length >= 3 ? candidate : `tpl-${hash}`
}

function rewritePlaceholders(
  input: string,
  preferDnsCanary: boolean,
): { ok: true; value: string } | { ok: false; reason: string } {
  let out = input
  // Strip {{BaseURL}} / {{RootURL}} prefixes
  out = out.replace(/\{\{(?:BaseURL|RootURL)\}\}/gi, '')
  // Rewrite scheme-prefixed interactsh URLs first so loader's :// check passes and runtime doesn't double-prefix http://
  out = out.replace(/https?:\/\/\{\{interactsh-?url\}\}/gi, '{{kovo_canary_http}}')
  // Rewrite bare interactsh URLs
  out = out.replace(/\{\{interactsh-?url\}\}/gi, preferDnsCanary ? '{{kovo_canary_dns}}' : '{{kovo_canary_http}}')
  // Rewrite benign random generators
  out = out.replace(/\{\{(?:randstr|rand_int\([^)]*\)|rand_text_alpha\([^)]*\)|rand_text_alphanumeric\([^)]*\)|rand_base\([^)]*\)|rand_char\([^)]*\))\}\}/gi, '{{rand}}')
  // Reject any unresolved {{...}} other than Kovo Hunter's 3 safe placeholders
  const stripped = out.replace(/\{\{(?:rand|kovo_canary_http|kovo_canary_dns)\}\}/g, 'X')
  if (/\{\{[^}]*\}\}/.test(stripped)) {
    return { ok: false, reason: 'unresolved_placeholder' }
  }
  return { ok: true, value: out }
}

function parseRawHttpRequest(rawText: string): {
  ok: true
  method: string
  path: string
  headers: Record<string, string>
  body?: string
} | { ok: false; reason: string } {
  const normalized = rawText.replace(/\r\n/g, '\n')
  const splitIdx = normalized.indexOf('\n\n')
  const headPart = splitIdx >= 0 ? normalized.slice(0, splitIdx) : normalized
  const bodyPart = splitIdx >= 0 ? normalized.slice(splitIdx + 2) : ''
  const headLines = headPart.split('\n').filter(l => l.trim() !== '')
  if (headLines.length === 0) return { ok: false, reason: 'empty_raw_request' }
  const reqLine = headLines[0].trim().match(/^([A-Z]+)\s+(\S+)\s+HTTP\/[\d.]+$/i)
  if (!reqLine) return { ok: false, reason: 'invalid_raw_request_line' }
  const method = reqLine[1].toUpperCase()
  const path = reqLine[2]
  const headers: Record<string, string> = {}
  for (let i = 1; i < headLines.length; i += 1) {
    const colon = headLines[i].indexOf(':')
    if (colon <= 0) return { ok: false, reason: 'malformed_raw_header' }
    const name = headLines[i].slice(0, colon).trim()
    const val = headLines[i].slice(colon + 1).trim()
    const lower = name.toLowerCase()
    if (lower === 'host') {
      if (!/^\{\{host(?:name)?\}\}(?::\d+)?$/i.test(val)) {
        return { ok: false, reason: 'forbidden_host_header' }
      }
      continue
    }
    if (BOILERPLATE_RAW_HEADERS.has(lower)) continue
    if (FORBIDDEN_HEADER_RE.test(name)) {
      return { ok: false, reason: `forbidden_header:${lower}` }
    }
    headers[name] = val
  }
  return {
    ok: true,
    method,
    path,
    headers,
    ...(bodyPart.trim() !== '' ? { body: bodyPart } : {}),
  }
}

const VENDOR_APPLIANCE_HINTS: ReadonlyArray<{ re: RegExp; tag: string }> = [
  { re: /\bcisco\b|ios[- ]xe|webex|prime infrastructure|small business rv/i, tag: 'cisco' },
  { re: /\baem\b|adobe experience manager|cq5|granite|crx|experience manager/i, tag: 'aem' },
  { re: /\bcoldfusion\b|\badobe\b/i, tag: 'adobe' },
  { re: /\b3cx\b/i, tag: '3cx' },
  { re: /\bavtech\b/i, tag: 'avtech' },
  { re: /\bhikvision\b/i, tag: 'hikvision' },
  { re: /\bdahua\b/i, tag: 'dahua' },
  { re: /\baxis communications?\b|\baxis camera\b/i, tag: 'axis' },
  { re: /\bfortinet\b|\bfortigate\b|\bfortios\b|\bfortiweb\b/i, tag: 'fortinet' },
  { re: /\bcitrix\b|netscaler/i, tag: 'citrix' },
  { re: /\bvmware\b|\bvcenter\b|\besxi\b|vrealize|workspace one/i, tag: 'vmware' },
  { re: /\bsonicwall\b|\bsslvpn\b/i, tag: 'sonicwall' },
  { re: /\bjuniper\b|\bjunos\b/i, tag: 'juniper' },
  { re: /\bmikrotik\b|routeros/i, tag: 'mikrotik' },
  { re: /\bzyxel\b|\bzywall\b/i, tag: 'zyxel' },
  { re: /\bsynology\b|diskstation|\bdsm\b/i, tag: 'synology' },
  { re: /\bqnap\b|\bqts\b/i, tag: 'qnap' },
  { re: /\bd-?link\b|\bdir-\d+/i, tag: 'dlink' },
  { re: /\btp-?link\b|\barcher\b|\bdeco\b/i, tag: 'tplink' },
  { re: /\bnetgear\b/i, tag: 'netgear' },
  { re: /\bdraytek\b|\bvigor\b/i, tag: 'draytek' },
  { re: /\bgrandstream\b/i, tag: 'grandstream' },
  { re: /\bpolycom\b/i, tag: 'polycom' },
  { re: /\bf5 networks\b|\bbig-?ip\b/i, tag: 'f5' },
  { re: /\bpalo ?alto\b|pan-os/i, tag: 'paloalto' },
  { re: /\bsophos\b|\butm\b/i, tag: 'sophos' },
]

const UNIVERSAL_EXPOSURE_PATH_RE = /(?:^|\/)(?:\.env(?:\.|$)|\.git(?:\/|$)|\.svn(?:\/|$)|\.ds_store$|swagger(?:-ui)?|openapi|api-docs|v2\/api-docs|v3\/api-docs|metrics$|debug(?:\/|$)|server-status|phpinfo|source[-_.]?map|\.map$|graphiql|actuator(?:\/|$)|trace$|heapdump|config\.json$|backup(?:\.|$)|\.bak$|\.old$|\.sql$|\.htaccess|security\.txt|\.well-known\/)/i

function detectVendorAppliance(haystack: string): string | null {
  for (const entry of VENDOR_APPLIANCE_HINTS) {
    if (entry.re.test(haystack)) return entry.tag
  }
  return null
}

function mapTechTags(rawTags: string[], id: string, name: string, path: string): TemplateTechTag[] {
  const pathLower = path.toLowerCase()
  const pathHints: string[] = []
  if (pathLower.includes('/_next') || pathLower.includes('nextjs')) pathHints.push('nextjs')
  if (pathLower.includes('/wp-') || pathLower.includes('wordpress')) pathHints.push('wordpress')
  if (pathLower.includes('/actuator')) pathHints.push('actuator', 'springboot')
  if (pathLower.includes('/swagger') || pathLower.includes('openapi')) pathHints.push('swagger')
  if (pathLower.includes('/graphql') || pathLower.includes('graphiql')) pathHints.push('graphql')
  if (pathLower.includes('/@vite')) pathHints.push('vite')
  if (pathLower.includes('/_nuxt')) pathHints.push('nuxt')
  if (pathLower.includes('.php')) pathHints.push('php')
  if (pathLower.includes('.jsp') || pathLower.includes('/manager/html')) pathHints.push('tomcat', 'java')
  if (pathLower.includes('.aspx') || pathLower.includes('.ashx')) pathHints.push('dotnet', 'iis')

  // Vendor/appliance family detection wins over incidental tokens (e.g. an AEM template
  // that happens to mention GraphQL or a PHP path must not be treated as a GraphQL app).
  const haystack = `${rawTags.join(' ')} ${id} ${name} ${path}`.toLowerCase()
  const vendor = detectVendorAppliance(haystack)
  if (vendor) return [vendor as TemplateTechTag]

  const candidates: string[] = [...rawTags, ...id.split('-'), ...name.toLowerCase().split(/[^a-z0-9]+/), ...pathHints]
  const norm = normalizeTechTagSet(candidates)
  const matched: TemplateTechTag[] = []
  for (const tag of norm) {
    if (tag !== 'generic' && tag !== 'generic-web-exposure' && ALLOWED_TECH_SET.has(tag) && !matched.includes(tag as TemplateTechTag)) {
      matched.push(tag as TemplateTechTag)
      if (matched.length >= 6) break
    }
  }
  if (matched.length === 0) {
    // Split the legacy catch-all bucket: universal web exposure checks stay eligible on
    // every origin; everything else is excluded from consumer-stack runs.
    const looksUniversal = UNIVERSAL_EXPOSURE_PATH_RE.test(path) ||
      rawTags.some(t => /^(?:exposure|exposures|misconfig|misconfiguration|config|backup|disclosure|debug)$/i.test(t))
    matched.push((looksUniversal ? 'generic-web-exposure' : 'generic') as TemplateTechTag)
  }
  return matched
}

function normalizeTagsList(rawTags: string[]): string[] {
  const out: string[] = []
  for (const t of rawTags) {
    const clean = t.trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '')
    if (/^[a-z0-9-]{2,32}$/.test(clean) && !out.includes(clean)) {
      out.push(clean)
      if (out.length >= 8) break
    }
  }
  return out
}

function sanitizeScalarString(s: string): string {
  return JSON.stringify(s)
}

export function emitSafeTemplateYaml(t: {
  id: string
  name: string
  severity: string
  description: string
  tech: string[]
  tags: string[]
  cve?: string
  cwe?: string
  reference?: string
  requiresTier3?: boolean
  spaExclusion?: boolean
  request: {
    method: string
    path: string
    headers?: Record<string, string>
    body?: string
  }
  control?: {
    method?: string
    path?: string
    headers?: Record<string, string>
    body?: string
  }
  'matchers-condition': 'and' | 'or'
  matchers: Array<Record<string, unknown>>
}): string {
  const lines: string[] = []
  lines.push(`id: ${sanitizeScalarString(t.id)}`)
  lines.push(`name: ${sanitizeScalarString(t.name)}`)
  lines.push(`severity: ${sanitizeScalarString(t.severity)}`)
  lines.push(`description: ${sanitizeScalarString(t.description)}`)
  lines.push('tech:')
  for (const x of t.tech) lines.push(`  - ${sanitizeScalarString(x)}`)
  if (t.tags.length > 0) {
    lines.push('tags:')
    for (const x of t.tags) lines.push(`  - ${sanitizeScalarString(x)}`)
  }
  if (t.cve) lines.push(`cve: ${sanitizeScalarString(t.cve)}`)
  if (t.cwe) lines.push(`cwe: ${sanitizeScalarString(t.cwe)}`)
  if (t.reference) lines.push(`reference: ${sanitizeScalarString(t.reference)}`)
  if (t.requiresTier3) lines.push('requiresTier3: true')
  if (t.spaExclusion) lines.push('spaExclusion: true')

  lines.push('request:')
  lines.push(`  method: ${sanitizeScalarString(t.request.method)}`)
  lines.push(`  path: ${sanitizeScalarString(t.request.path)}`)
  if (t.request.headers && Object.keys(t.request.headers).length > 0) {
    lines.push('  headers:')
    for (const [k, v] of Object.entries(t.request.headers)) {
      lines.push(`    ${sanitizeScalarString(k)}: ${sanitizeScalarString(v)}`)
    }
  }
  if (t.request.body !== undefined) {
    lines.push(`  body: ${sanitizeScalarString(t.request.body)}`)
  }

  if (t.control) {
    lines.push('control:')
    if (t.control.method) lines.push(`  method: ${sanitizeScalarString(t.control.method)}`)
    if (t.control.path) lines.push(`  path: ${sanitizeScalarString(t.control.path)}`)
    if (t.control.headers) {
      if (Object.keys(t.control.headers).length === 0) {
        lines.push('  headers: {}')
      } else {
        lines.push('  headers:')
        for (const [k, v] of Object.entries(t.control.headers)) {
          lines.push(`    ${sanitizeScalarString(k)}: ${sanitizeScalarString(v)}`)
        }
      }
    }
    if (t.control.body !== undefined) lines.push(`  body: ${sanitizeScalarString(t.control.body)}`)
  }

  lines.push(`matchers-condition: ${sanitizeScalarString(t['matchers-condition'])}`)
  lines.push('matchers:')
  for (const m of t.matchers) {
    lines.push(`  - type: ${sanitizeScalarString(String(m.type))}`)
    if (m.type === 'status') {
      lines.push('    status:')
      for (const s of m.status as number[]) lines.push(`      - ${s}`)
    } else if (m.type === 'word') {
      lines.push(`    part: ${sanitizeScalarString(String(m.part))}`)
      lines.push('    words:')
      for (const w of m.words as string[]) lines.push(`      - ${sanitizeScalarString(w)}`)
      if (m.condition && m.condition !== 'or') lines.push(`    condition: ${sanitizeScalarString(String(m.condition))}`)
      if (m.negative) lines.push('    negative: true')
    } else if (m.type === 'regex') {
      lines.push(`    part: ${sanitizeScalarString(String(m.part))}`)
      lines.push('    regex:')
      for (const r of m.regex as string[]) lines.push(`      - ${sanitizeScalarString(r)}`)
      if (m.condition && m.condition !== 'or') lines.push(`    condition: ${sanitizeScalarString(String(m.condition))}`)
      if (m.negative) lines.push('    negative: true')
    } else if (m.type === 'canary') {
      lines.push(`    protocol: ${sanitizeScalarString(String(m.protocol ?? 'any'))}`)
    }
  }
  return lines.join('\n') + '\n'
}

export function transpileNucleiTemplate(
  yamlSource: string,
  opts: TranspileTemplateOptions = {},
): TranspileTemplateOutcome {
  let doc: unknown
  try {
    doc = parseNucleiYaml(yamlSource)
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'yaml_parse_error' }
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return { ok: false, reason: 'invalid_root_document' }
  }
  const root = doc as Record<string, unknown>
  const rawId = typeof root.id === 'string' ? root.id.trim() : ''
  if (!rawId) return { ok: false, reason: 'missing_id' }
  const id = normalizeId(rawId)

  if (opts.existingIds?.has(id)) {
    return { ok: false, id, reason: 'duplicate_id' }
  }

  for (const proto of NON_HTTP_PROTOCOLS) {
    if (root[proto] !== undefined) {
      return { ok: false, id, reason: `non_http_protocol:${proto}` }
    }
  }
  if (root.flow !== undefined) {
    return { ok: false, id, reason: 'multi_step_flow_unsupported' }
  }

  const httpBlocks = Array.isArray(root.http) ? root.http : Array.isArray(root.requests) ? root.requests : null
  if (!httpBlocks || httpBlocks.length !== 1 || !httpBlocks[0] || typeof httpBlocks[0] !== 'object') {
    return { ok: false, id, reason: 'requires_single_http_block' }
  }
  const block = httpBlocks[0] as Record<string, unknown>
  if (block['self-contained'] === true || block.payloads !== undefined || block.attack !== undefined) {
    return { ok: false, id, reason: 'unsupported_fuzz_or_self_contained' }
  }
  if (block.race === true || block.threads !== undefined || block.unsafe === true) {
    return { ok: false, id, reason: 'unsupported_unsafe_or_race_directive' }
  }
  if (block.host !== undefined && Array.isArray(block.host)) {
    return { ok: false, id, reason: 'explicit_host_override' }
  }

  const info = root.info && typeof root.info === 'object' ? (root.info as Record<string, unknown>) : null
  if (!info || typeof info.name !== 'string' || info.name.trim().length < 3) {
    return { ok: false, id, reason: 'missing_info_name' }
  }
  const name = info.name.trim().slice(0, 160)
  const rawSev = typeof info.severity === 'string' ? info.severity.trim().toLowerCase() : 'info'
  const severityMap: Record<string, SafeTemplate['severity']> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    info: 'info',
    unknown: 'info',
  }
  const severity = severityMap[rawSev] ?? 'info'

  const rawDescription = typeof info.description === 'string'
    ? info.description.trim().replace(/\s+/g, ' ').replace(/interactsh-?url/gi, 'kovo_canary_http').replace(/interactsh/gi, 'kovo_canary')
    : ''
  const description = (rawDescription.length >= 5 ? rawDescription : `Safe check derived from ${id}: ${name}`).slice(0, 600)

  const rawTags = typeof info.tags === 'string'
    ? info.tags.split(',').map(s => s.trim()).filter(Boolean)
    : Array.isArray(info.tags)
      ? info.tags.map(s => String(s).trim()).filter(Boolean)
      : []

  // Extract CVE / CWE / Reference
  const classification = info.classification && typeof info.classification === 'object'
    ? (info.classification as Record<string, unknown>)
    : undefined
  let cve: string | undefined
  const cveCandidate = classification?.['cve-id'] ?? (/^CVE-\d{4}-\d{4,7}$/i.test(rawId) ? rawId.toUpperCase() : undefined)
  if (typeof cveCandidate === 'string' && /^CVE-\d{4}-\d{4,7}$/i.test(cveCandidate.trim())) {
    cve = cveCandidate.trim().toUpperCase()
  } else if (Array.isArray(cveCandidate) && typeof cveCandidate[0] === 'string' && /^CVE-\d{4}-\d{4,7}$/i.test(cveCandidate[0].trim())) {
    cve = cveCandidate[0].trim().toUpperCase()
  }
  let cwe: string | undefined
  const cweCandidate = classification?.['cwe-id']
  const firstCwe = Array.isArray(cweCandidate) ? cweCandidate[0] : cweCandidate
  if (typeof firstCwe === 'string') {
    const m = firstCwe.trim().toUpperCase().match(/^CWE-(\d{1,5})$/)
    if (m) cwe = `CWE-${m[1]}`
  }
  let reference: string | undefined
  if (typeof info.reference === 'string' && info.reference.trim()) {
    reference = info.reference.trim().slice(0, 300)
  } else if (Array.isArray(info.reference) && typeof info.reference[0] === 'string' && info.reference[0].trim()) {
    reference = info.reference[0].trim().slice(0, 300)
  }

  // Determine matchers & whether canary prefers DNS
  const rawMatchers = Array.isArray(block.matchers) ? block.matchers : []
  if (rawMatchers.length === 0) return { ok: false, id, reason: 'missing_matchers' }
  const matchersCondition: 'and' | 'or' = block['matchers-condition'] === 'and' ? 'and' : 'or'

  const interactshWords: string[] = []
  for (const rm of rawMatchers) {
    if (!rm || typeof rm !== 'object') continue
    const m = rm as Record<string, unknown>
    const part = typeof m.part === 'string' ? m.part.toLowerCase() : ''
    if (part.startsWith('interactsh_') && Array.isArray(m.words)) {
      for (const w of m.words) interactshWords.push(String(w).toLowerCase())
    }
  }
  const preferDnsCanary = interactshWords.includes('dns') && !interactshWords.includes('http')

  // Extract request (method+path OR raw)
  let method = ''
  let rawPath = ''
  let rawHeaders: Record<string, string> = {}
  let rawBody: string | undefined

  if (Array.isArray(block.raw)) {
    if (block.raw.length !== 1 || typeof block.raw[0] !== 'string') {
      return { ok: false, id, reason: 'requires_single_raw_request' }
    }
    const parsedRaw = parseRawHttpRequest(block.raw[0])
    if (!parsedRaw.ok) return { ok: false, id, reason: parsedRaw.reason }
    method = parsedRaw.method
    rawPath = parsedRaw.path
    rawHeaders = parsedRaw.headers
    rawBody = parsedRaw.body
  } else if (Array.isArray(block.path)) {
    if (block.path.length === 0 || block.path.length > 2 || typeof block.path[0] !== 'string') {
      return { ok: false, id, reason: 'unsupported_multi_path' }
    }
    method = typeof block.method === 'string' ? block.method.trim().toUpperCase() : 'GET'
    rawPath = block.path[0]
    if (block.headers && typeof block.headers === 'object' && !Array.isArray(block.headers)) {
      for (const [k, v] of Object.entries(block.headers as Record<string, unknown>)) {
        if (FORBIDDEN_HEADER_RE.test(k) || k.toLowerCase() === 'host') {
          return { ok: false, id, reason: `forbidden_header:${k.toLowerCase()}` }
        }
        rawHeaders[k] = String(v ?? '')
      }
    }
    if (typeof block.body === 'string') rawBody = block.body
  } else {
    return { ok: false, id, reason: 'missing_request_path_or_raw' }
  }

  let requiresTier3 = false
  if (ALLOWED_READONLY_METHODS.has(method)) {
    // ok
  } else if (TIER3_MUTATING_METHODS.has(method)) {
    if (opts.reviewedTier3Ids?.has(id) || opts.reviewedTier3Ids?.has(rawId)) {
      requiresTier3 = true
    } else {
      return { ok: false, id, reason: `unreviewed_mutating_method:${method}` }
    }
  } else {
    return { ok: false, id, reason: `disallowed_method:${method}` }
  }

  // Placeholder rewriting
  const rwPath = rewritePlaceholders(rawPath, preferDnsCanary)
  if (!rwPath.ok) return { ok: false, id, reason: rwPath.reason }
  let cleanPath = rwPath.value.trim()
  if (cleanPath.startsWith('//')) cleanPath = '/' + cleanPath.replace(/^\/+/, '')
  if (!cleanPath.startsWith('/') || cleanPath.startsWith('//')) {
    return { ok: false, id, reason: 'invalid_relative_path' }
  }
  if (cleanPath.length > 2048) return { ok: false, id, reason: 'path_too_long' }

  const cleanHeaders: Record<string, string> = {}
  for (const [k, v] of Object.entries(rawHeaders)) {
    const rw = rewritePlaceholders(v, preferDnsCanary)
    if (!rw.ok) return { ok: false, id, reason: rw.reason }
    if (k.length < 1 || k.length > 64 || rw.value.length > 1024) {
      return { ok: false, id, reason: 'header_size_exceeded' }
    }
    cleanHeaders[k] = rw.value
  }

  let cleanBody: string | undefined
  if (rawBody !== undefined) {
    const rw = rewritePlaceholders(rawBody, preferDnsCanary)
    if (!rw.ok) return { ok: false, id, reason: rw.reason }
    if (rw.value.length > 4096) return { ok: false, id, reason: 'body_too_long' }
    cleanBody = rw.value
  }

  // Pre-screen safety on rewritten request fields
  const fieldValues = [cleanPath, cleanBody ?? '', ...Object.values(cleanHeaders)]
  for (const val of fieldValues) {
    const d1 = decodeLoose(val)
    const d2 = decodeLoose(d1)
    const dPlus = decodeLoose(d2.replace(/\+/g, ' '))
    if (
      containsDestructivePayload(val) ||
      containsDestructivePayload(d1) ||
      containsDestructivePayload(d2) ||
      containsDestructivePayload(dPlus)
    ) {
      return { ok: false, id, reason: 'destructive_payload' }
    }
    if (
      containsWebshellSignature(val) ||
      containsWebshellSignature(d1) ||
      containsWebshellSignature(d2) ||
      containsWebshellSignature(dPlus)
    ) {
      return { ok: false, id, reason: 'webshell_signature' }
    }
    if (THIRD_PARTY_OAST_RE.test(d2)) return { ok: false, id, reason: 'third_party_oast' }
    if (PRIVATE_HOST_RE.test(d2)) return { ok: false, id, reason: 'private_or_metadata_host' }
  }

  // Normalize matchers
  const outMatchers: Array<Record<string, unknown>> = []
  let hasCanaryMatcher = false
  let droppedMatcher = false

  for (const rm of rawMatchers) {
    if (!rm || typeof rm !== 'object') { droppedMatcher = true; continue }
    const m = rm as Record<string, unknown>
    const mType = typeof m.type === 'string' ? m.type.toLowerCase() : ''
    const rawPart = typeof m.part === 'string' ? m.part.toLowerCase() : 'body'
    const negative = m.negative === true
    const condition = m.condition === 'and' ? 'and' : 'or'

    if (rawPart.startsWith('interactsh_')) {
      const protocol = preferDnsCanary ? 'dns' : (interactshWords.includes('http') && !interactshWords.includes('dns') ? 'http' : 'any')
      if (!hasCanaryMatcher) {
        outMatchers.push({ type: 'canary', protocol })
        hasCanaryMatcher = true
      }
      continue
    }

    const part = rawPart === 'header' || rawPart === 'headers'
      ? 'header'
      : rawPart === 'all' || rawPart === 'response'
        ? 'all'
        : rawPart === 'body' || rawPart === ''
          ? 'body'
          : null
    if (!part) { droppedMatcher = true; continue }

    if (mType === 'status') {
      const statuses = (Array.isArray(m.status) ? m.status : [])
        .map(s => Number(s))
        .filter(n => Number.isInteger(n) && n >= 100 && n <= 599)
        .slice(0, 8)
      if (statuses.length === 0) { droppedMatcher = true; continue }
      outMatchers.push({ type: 'status', status: statuses })
    } else if (mType === 'word') {
      const words = (Array.isArray(m.words) ? m.words : [])
        .map(w => String(w))
        .filter(w => w.length >= 1 && w.length <= 256)
        .slice(0, 10)
      if (words.length === 0) { droppedMatcher = true; continue }
      for (const w of words) {
        if (THIRD_PARTY_OAST_RE.test(w)) return { ok: false, id, reason: 'third_party_oast' }
      }
      outMatchers.push({
        type: 'word',
        part,
        words,
        ...(condition !== 'or' ? { condition } : {}),
        ...(negative ? { negative } : {}),
      })
    } else if (mType === 'regex') {
      const regexes = (Array.isArray(m.regex) ? m.regex : [])
        .map(r => String(r))
        .filter(r => r.length >= 1 && r.length <= 512)
        .slice(0, 6)
      if (regexes.length === 0) { droppedMatcher = true; continue }
      for (const r of regexes) {
        try { new RegExp(r, 'im') } catch { return { ok: false, id, reason: 'invalid_regex' } }
        if (/\((?:[^()]*[+*])\)[+*{]/.test(r)) return { ok: false, id, reason: 'redos_regex' }
      }
      outMatchers.push({
        type: 'regex',
        part,
        regex: regexes,
        ...(condition !== 'or' ? { condition } : {}),
        ...(negative ? { negative } : {}),
      })
    } else {
      // dsl, binary, xpath, size, etc.
      droppedMatcher = true
    }
  }

  if (droppedMatcher && matchersCondition === 'and') {
    return { ok: false, id, reason: 'unsupported_matcher_in_and_condition' }
  }
  if (outMatchers.length === 0 || outMatchers.length > 8) {
    return { ok: false, id, reason: 'matcher_count_out_of_bounds' }
  }
  if (!outMatchers.some(m => m.type !== 'status')) {
    return { ok: false, id, reason: 'status_only_matcher' }
  }

  const requestHasCanary = JSON.stringify({ cleanPath, cleanHeaders, cleanBody }).includes('kovo_canary_')
  if (requestHasCanary && !hasCanaryMatcher) {
    outMatchers.push({ type: 'canary', protocol: preferDnsCanary ? 'dns' : 'any' })
    hasCanaryMatcher = true
  }
  if (requestHasCanary !== hasCanaryMatcher) {
    return { ok: false, id, reason: 'canary_placeholder_matcher_mismatch' }
  }

  // Build control & spaExclusion metadata
  let control: { method?: string; path?: string; headers?: Record<string, string>; body?: string }
  let spaExclusion = false
  if (requestHasCanary) {
    control = {
      method: 'GET',
      path: cleanPath.replace(/\{\{kovo_canary_(?:http|dns)\}\}/g, 'kovo-none-{{rand}}'),
    }
    spaExclusion = true
  } else if (Object.keys(cleanHeaders).length > 0 && cleanPath === '/') {
    control = { headers: {} }
    spaExclusion = true
  } else {
    control = {
      method: 'GET',
      path: '/.kovo-none-{{rand}}',
    }
    spaExclusion = true
  }

  const tech = mapTechTags(rawTags, id, name, cleanPath)
  const tags = normalizeTagsList(rawTags)

  const emittedYaml = emitSafeTemplateYaml({
    id,
    name,
    severity,
    description,
    tech,
    tags,
    ...(cve ? { cve } : {}),
    ...(cwe ? { cwe } : {}),
    ...(reference ? { reference } : {}),
    ...(requiresTier3 ? { requiresTier3: true } : {}),
    ...(spaExclusion ? { spaExclusion: true } : {}),
    request: {
      method,
      path: cleanPath,
      ...(Object.keys(cleanHeaders).length > 0 ? { headers: cleanHeaders } : {}),
      ...(cleanBody !== undefined ? { body: cleanBody } : {}),
    },
    control,
    'matchers-condition': matchersCondition,
    matchers: outMatchers,
  })

  if (Buffer.byteLength(emittedYaml, 'utf8') >= 32 * 1024) {
    return { ok: false, id, reason: 'emitted_yaml_exceeds_32kib' }
  }

  try {
    const validated = parseSafeTemplateYaml(emittedYaml, opts.sourceFile)
    return { ok: true, id: validated.id, yaml: emittedYaml, template: validated }
  } catch (err) {
    return { ok: false, id, reason: err instanceof Error ? err.message : 'zod_validation_failed' }
  }
}

// ============================================================================
// Directory Walker & Transpiler
// ============================================================================

function walkInputYaml(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue
      walkInputYaml(full, out)
    } else if (/\.ya?ml$/i.test(entry.name)) {
      const st = statSync(full)
      if (st.isFile() && st.size < 256 * 1024) out.push(full)
    }
  }
  return out
}

function topLevelCategory(rel: string): string {
  const parts = rel.replaceAll('\\', '/').split('/')
  // Only the first segment under the nuclei root is a category (http/cves/2024/...).
  return parts.find(p => ['cves', 'exposures', 'misconfiguration', 'technologies', 'vulnerabilities', 'default-logins'].includes(p)) ?? ''
}

function cveYearOf(rel: string): number {
  const m = rel.match(/CVE-(\d{4})-/i) ?? rel.match(/(?:^|\/)(\d{4})(?:\/|_)/)
  return m ? Number(m[1]) : 0
}

/**
 * Order the nuclei corpus so a bounded compile keeps the highest-value checks:
 *   1. modern CVEs (year descending, 2026 -> 2021)
 *   2. universal exposures / misconfiguration
 *   3. technology fingerprints
 *   4. vulnerabilities + default logins
 *   5. legacy CVEs (< 2021) only with leftover capacity
 */
export function orderInputYaml(
  inputDir: string,
  options: { maxTemplates?: number; modernCveQuota?: number } = {},
): string[] {
  const all: string[] = []
  walkInputYaml(inputDir, all)
  const modern: string[] = []
  const legacy: string[] = []
  const buckets = new Map<string, string[]>()
  for (const file of all) {
    const rel = relative(inputDir, file)
    const category = topLevelCategory(rel)
    if (category === 'cves') {
      if (cveYearOf(rel) >= 2021) modern.push(file)
      else legacy.push(file)
    } else {
      const list = buckets.get(category) ?? []
      list.push(file)
      buckets.set(category, list)
    }
  }
  modern.sort((a, b) => cveYearOf(relative(inputDir, b)) - cveYearOf(relative(inputDir, a)) || a.localeCompare(b))
  legacy.sort((a, b) => cveYearOf(relative(inputDir, b)) - cveYearOf(relative(inputDir, a)) || a.localeCompare(b))
  const byName = (a: string, b: string) => a.localeCompare(b)
  for (const list of buckets.values()) list.sort(byName)

  const max = options.maxTemplates ?? Number.POSITIVE_INFINITY
  if (!Number.isFinite(max)) {
    return [
      ...modern,
      ...(buckets.get('') ?? []),
      ...(buckets.get('exposures') ?? []),
      ...(buckets.get('technologies') ?? []),
      ...(buckets.get('misconfiguration') ?? []),
      ...(buckets.get('vulnerabilities') ?? []),
      ...(buckets.get('default-logins') ?? []),
      ...legacy,
    ]
  }
  const modernQuota = Math.max(0, Math.min(options.modernCveQuota ?? Math.floor(max * 0.56), modern.length))
  const selected: string[] = [...(buckets.get('') ?? []).slice(0, max), ...modern.slice(0, modernQuota)]
  const sectionQuotas: Array<[string, number]> = [
    ['exposures', Math.floor(max * 0.30)],
    ['technologies', Math.floor(max * 0.21)],
    ['misconfiguration', Math.floor(max * 0.08)],
    ['vulnerabilities', Math.floor(max * 0.03)],
    ['default-logins', Math.floor(max * 0.01)],
  ]
  for (const [category, quota] of sectionQuotas) {
    selected.push(...(buckets.get(category) ?? []).slice(0, quota))
  }
  const remaining = Math.max(0, max - selected.length)
  selected.push(...legacy.slice(0, remaining))
  return selected.slice(0, max)
}

export function collectExistingNonCompiledTemplateIds(templatesRoot: string): Set<string> {
  const ids = new Set<string>()
  if (!existsSync(templatesRoot)) return ids
  for (const entry of readdirSync(templatesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === 'compiled') continue
    const subDir = join(templatesRoot, entry.name)
    for (const file of walkInputYaml(subDir)) {
      try {
        const parsed = parseSafeTemplateYaml(readFileSync(file, 'utf8'), file)
        ids.add(parsed.id)
      } catch {
        // ignore
      }
    }
  }
  return ids
}

export async function transpileNucleiDirectory(
  inputDir: string,
  outputDir: string,
  opts: TranspileDirectoryOptions = {},
): Promise<TranspileDirectoryReport> {
  const startedAt = Date.now()
  if (!existsSync(inputDir) || !statSync(inputDir).isDirectory()) {
    throw new Error(`Input directory does not exist: ${inputDir}`)
  }

  if (opts.cleanOutput && existsSync(outputDir)) {
    for (const entry of readdirSync(outputDir)) {
      if (/\.ya?ml$/i.test(entry)) {
        rmSync(join(outputDir, entry), { force: true })
      }
    }
  }
  mkdirSync(outputDir, { recursive: true })

  const maxTemplates = opts.maxTemplates ?? Number.POSITIVE_INFINITY
  const seenIds = new Set<string>(opts.existingIds ?? [])
  const files = orderInputYaml(inputDir, { maxTemplates })
  const rejected: Array<{ file: string; reason: string }> = []
  const rejectionReasons: Record<string, number> = {}
  const outputFiles: string[] = []
  let transpiled = 0
  let scanned = 0

  for (const file of files) {
    if (transpiled >= maxTemplates) break
    scanned += 1
    const rel = relative(inputDir, file)
    let raw = ''
    try {
      raw = readFileSync(file, 'utf8')
    } catch {
      const reason = 'unreadable_file'
      rejected.push({ file: rel, reason })
      rejectionReasons[reason] = (rejectionReasons[reason] ?? 0) + 1
      continue
    }

    const outcome = transpileNucleiTemplate(raw, {
      sourceFile: rel,
      existingIds: seenIds,
      reviewedTier3Ids: opts.reviewedTier3Ids,
    })

    if (!outcome.ok) {
      rejected.push({ file: rel, reason: outcome.reason })
      rejectionReasons[outcome.reason] = (rejectionReasons[outcome.reason] ?? 0) + 1
      continue
    }

    seenIds.add(outcome.id)
    const outPath = join(outputDir, `${outcome.id}.yaml`)
    writeFileSync(outPath, outcome.yaml, 'utf8')
    outputFiles.push(outPath)
    transpiled += 1
  }

  return {
    scanned,
    transpiled,
    rejected,
    rejectionReasons,
    outputFiles,
    durationMs: Date.now() - startedAt,
  }
}

// ============================================================================
// CLI Entrypoint (shallow sparse git clone into /tmp, cleaned in finally)
// ============================================================================

async function runCli() {
  const args = process.argv.slice(2)
  const getArg = (flag: string): string | undefined => {
    const idx = args.indexOf(flag)
    return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined
  }

  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  const sourceDirArg = getArg('--source-dir')
  const outDir = resolve(getArg('--out-dir') ?? join(repoRoot, 'src', 'templates', 'compiled'))
  const maxTemplates = Number(getArg('--max-templates') ?? '8000')
  const repoUrl = getArg('--repo-url') ?? 'https://github.com/projectdiscovery/nuclei-templates.git'
  const ref = getArg('--ref')
  const cleanOutput = !args.includes('--no-clean')

  const existingIds = collectExistingNonCompiledTemplateIds(join(repoRoot, 'src', 'templates'))
  let cloneDir: string | null = null
  let effectiveSourceDir = sourceDirArg ? resolve(sourceDirArg) : ''

  try {
    if (!effectiveSourceDir) {
      cloneDir = mkdtempSync(join(tmpdir(), 'kovo-nuclei-src-'))
      const cloneArgs = ['clone', '--depth', '1', '--filter=blob:none', '--sparse']
      if (ref) cloneArgs.push('--branch', ref)
      cloneArgs.push(repoUrl, cloneDir)
      execFileSync('git', cloneArgs, { stdio: 'inherit', timeout: 120_000 })
      const sparseTargets = [
        'http/exposures',
        'http/misconfiguration',
        'http/technologies',
        'http/cves',
        'http/vulnerabilities',
        'http/default-logins',
      ]
      execFileSync('git', ['-C', cloneDir, 'sparse-checkout', 'set', ...sparseTargets], {
        stdio: 'inherit',
        timeout: 120_000,
      })
      effectiveSourceDir = join(cloneDir, 'http')
      if (!existsSync(effectiveSourceDir)) effectiveSourceDir = cloneDir
    }

    const report = await transpileNucleiDirectory(effectiveSourceDir, outDir, {
      maxTemplates: Number.isFinite(maxTemplates) && maxTemplates > 0 ? maxTemplates : 8000,
      cleanOutput,
      existingIds,
    })

    const topReasons = Object.entries(report.rejectionReasons)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
    console.log(JSON.stringify({
      outDir,
      scanned: report.scanned,
      transpiled: report.transpiled,
      rejected: report.rejected.length,
      topRejectionReasons: Object.fromEntries(topReasons),
      durationMs: report.durationMs,
    }, null, 2))
  } finally {
    if (cloneDir && existsSync(cloneDir)) {
      rmSync(cloneDir, { recursive: true, force: true })
    }
  }
}

const isMain = (() => {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
})()

if (isMain) {
  runCli().catch(err => {
    console.error(err instanceof Error ? err.message : String(err))
    process.exitCode = 1
  })
}
