/**
 * Bounded Docker Compose YAML parser (v6 Phase 4, LabRunner cleanup).
 *
 * The v5 LabRunner parsed Compose with indentation-sensitive regexes that silently mis-parsed
 * anchors, aliases, flow collections, merge keys, block scalars and `${VAR}` interpolation. This
 * module replaces that with a real, dependency-free parser for a deliberately bounded YAML subset:
 *
 *   - block mappings / block sequences (spaces only, no tab indentation)
 *   - flow sequences `[a, b]` and flow mappings `{a: b}`
 *   - single/double quoted scalars with escapes
 *   - block scalars (`|`, `>`, with `-`/`+` chomping)
 *   - anchors (`&name`), aliases (`*name`) and merge keys (`<<`)
 *   - `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `${VAR:?err}`, `${VAR?err}` interpolation
 *
 * Anything outside that subset is rejected with an explicit `ComposeParseError` instead of being
 * guessed at. Security decisions (privileged, host ports, bind mounts, non-root user, env keys)
 * stay in `lab-runner.ts`; this module is purely structural and never emits container argv.
 *
 * Defensive QA note: this parser is used to sanitize *local-lab* fixture stacks only. It is
 * intentionally strict so an unsupported construct fails closed rather than launching a
 * mis-modelled stack.
 */

const MAX_COMPOSE_BYTES = 262_144
const MAX_COMPOSE_LINES = 4_000
const MAX_YAML_DEPTH = 16
const MAX_ANCHORS = 256
const MAX_FLOW_ITEMS = 256
const MAX_SCALAR_LENGTH = 8_192
const MAX_SERVICE_COUNT = 6

export class ComposeParseError extends Error {
  readonly lineNumber?: number

  constructor(message: string, lineNumber?: number) {
    super(lineNumber === undefined
      ? `Compose parse error: ${message}`
      : `Compose parse error (line ${lineNumber}): ${message}`)
    this.name = 'ComposeParseError'
    this.lineNumber = lineNumber
  }
}

export interface ComposeParseOptions {
  /** Interpolation environment. Defaults to `process.env`. */
  env?: Record<string, string | undefined>
  /** Hard cap on `services` entries. Defaults to 6 (LabRunner container budget). */
  maxServices?: number
  maxBytes?: number
}

export interface ComposeVolumeSpec {
  type: 'bind' | 'volume' | 'tmpfs'
  source?: string
  target?: string
  readOnly?: boolean
  raw: string
}

export interface ComposeHealthcheckSpec {
  test?: string | string[]
  intervalMs?: number
  timeoutMs?: number
  retries?: number
  startPeriodMs?: number
  disabled?: boolean
}

export interface ComposeBuildSpec {
  context: string
  dockerfile?: string
  target?: string
  args?: Record<string, string>
}

export interface NormalizedComposeService {
  name: string
  image?: string
  build?: ComposeBuildSpec
  command?: string | string[]
  entrypoint?: string | string[]
  environment?: Record<string, string>
  expose: number[]
  ports: string[]
  dependsOn: string[]
  volumes: ComposeVolumeSpec[]
  healthcheck?: ComposeHealthcheckSpec
  networks: string[]
  networkAliases: string[]
  user?: string
  workingDir?: string
  restart?: string
}

export interface ComposeServiceSource {
  name: string
  /** Raw (interpolated) service mapping; used by the lab-runner security scan. */
  config: Record<string, unknown>
  /** Normalized structural view of the same service. */
  normalized: NormalizedComposeService
}

export interface ParsedComposeDocument {
  version?: string
  name?: string
  services: ComposeServiceSource[]
}

// ---------------------------------------------------------------------------
// Line tokenizer
// ---------------------------------------------------------------------------

interface SourceLine {
  number: number
  raw: string
}

interface ContentLine {
  number: number
  indent: number
  text: string
}

function leadingSpaces(raw: string): number {
  let i = 0
  while (i < raw.length && raw[i] === ' ') i += 1
  return i
}

function stripInlineComment(raw: string): string {
  let quote: '"' | "'" | null = null
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i]
    if (quote === '"') {
      if (ch === '\\') { i += 1; continue }
      if (ch === '"') quote = null
      continue
    }
    if (quote === "'") {
      if (ch === "'") {
        if (raw[i + 1] === "'") { i += 1; continue }
        quote = null
      }
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; continue }
    if (ch === '#' && (i === 0 || /\s/.test(raw[i - 1]))) {
      return raw.slice(0, i)
    }
  }
  return raw
}

class LineCursor {
  index = 0
  private readonly lines: SourceLine[]

  constructor(lines: SourceLine[]) {
    this.lines = lines
  }

  private analyse(line: SourceLine): ContentLine | null {
    const raw = line.raw.replace(/\r$/, '')
    const indent = leadingSpaces(raw)
    if (raw[indent] === '\t') {
      throw new ComposeParseError('tab characters are not allowed for indentation', line.number)
    }
    const withoutComment = stripInlineComment(raw)
    const text = withoutComment.slice(indent).replace(/[ \t]+$/, '')
    if (text.trim() === '' || text.trimStart().startsWith('#')) return null
    return { number: line.number, indent, text }
  }

  peek(): ContentLine | null {
    for (let i = this.index; i < this.lines.length; i += 1) {
      const analysed = this.analyse(this.lines[i])
      if (analysed) return analysed
    }
    return null
  }

  next(): ContentLine | null {
    for (let i = this.index; i < this.lines.length; i += 1) {
      const analysed = this.analyse(this.lines[i])
      if (analysed) {
        this.index = i + 1
        return analysed
      }
    }
    this.index = this.lines.length
    return null
  }

  /**
   * Consume a block scalar body starting at the current cursor position. Stops at the first
   * non-blank line whose indentation is <= the parent key indentation.
   */
  consumeBlockBody(parentIndent: number): { lines: string[]; trailingBlanks: number } {
    const collected: string[] = []
    let contentIndent = Number.POSITIVE_INFINITY
    let trailingBlanks = 0
    let i = this.index
    for (; i < this.lines.length; i += 1) {
      const raw = this.lines[i].raw.replace(/\r$/, '')
      if (raw.trim() === '') {
        collected.push('')
        trailingBlanks += 1
        continue
      }
      const indent = leadingSpaces(raw)
      if (indent <= parentIndent) break
      if (contentIndent === Number.POSITIVE_INFINITY) contentIndent = indent
      collected.push(raw)
      trailingBlanks = 0
    }
    this.index = i
    const indent = contentIndent === Number.POSITIVE_INFINITY ? parentIndent + 1 : contentIndent
    const lines = collected.map(line => (line.trim() === '' ? '' : line.slice(indent)))
    return { lines, trailingBlanks }
  }
}

// ---------------------------------------------------------------------------
// Scalar / flow helpers
// ---------------------------------------------------------------------------

export function readQuotedScalar(text: string, start: number, lineNumber?: number): { value: string; next: number } {
  const quote = text[start]
  let out = ''
  let i = start + 1
  while (i < text.length) {
    const ch = text[i]
    if (quote === "'") {
      if (ch === "'") {
        if (text[i + 1] === "'") { out += "'"; i += 2; continue }
        return { value: out, next: i + 1 }
      }
      out += ch
      i += 1
      continue
    }
    if (ch === '"') return { value: out, next: i + 1 }
    if (ch === '\\') {
      const esc = text[i + 1]
      if (esc === 'u') {
        const hex = text.slice(i + 2, i + 6)
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          throw new ComposeParseError('invalid \\u escape in double-quoted scalar', lineNumber)
        }
        out += String.fromCharCode(Number.parseInt(hex, 16))
        i += 6
        continue
      }
      const escapes: Record<string, string> = {
        n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/', '0': '\0', b: '\b', f: '\f',
      }
      if (esc !== undefined && Object.prototype.hasOwnProperty.call(escapes, esc)) {
        out += escapes[esc]
        i += 2
        continue
      }
      throw new ComposeParseError(`unsupported escape sequence "\\${esc ?? ''}"`, lineNumber)
    }
    out += ch
    i += 1
  }
  throw new ComposeParseError('unterminated quoted scalar', lineNumber)
}

function coercePlainScalar(raw: string): unknown {
  const text = raw.trim()
  if (text === '' || text === '~' || /^(?:null|Null|NULL)$/.test(text)) return null
  if (/^(?:true|True|TRUE)$/.test(text)) return true
  if (/^(?:false|False|FALSE)$/.test(text)) return false
  if (/^-?(?:0|[1-9][0-9]{0,14})$/.test(text)) return Number(text)
  if (/^-?(?:0|[1-9][0-9]{0,14})\.[0-9]{1,12}$/.test(text)) return Number(text)
  return text
}

function cloneValue<T>(value: T): T {
  if (value === null || typeof value !== 'object') return value
  return structuredClone(value)
}

function isPlainMapping(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function isSequenceLine(text: string): boolean {
  return text === '-' || text.startsWith('- ')
}

function findMappingColon(text: string): number {
  if (text.startsWith('"') || text.startsWith("'")) {
    try {
      const quoted = readQuotedScalar(text, 0)
      let i = quoted.next
      while (text[i] === ' ') i += 1
      return text[i] === ':' ? i : -1
    } catch {
      return -1
    }
  }
  if (text.startsWith('[') || text.startsWith('{') || text.startsWith('|') || text.startsWith('>')) return -1
  if (text.startsWith('&') || text.startsWith('*') || text.startsWith('!') || text.startsWith('?')) return -1
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === ':' && (i + 1 === text.length || /\s/.test(text[i + 1]))) return i
  }
  return -1
}

function splitMappingEntry(text: string, lineNumber?: number): { key: string; rest: string } {
  if (text.startsWith('?')) {
    throw new ComposeParseError('complex mapping keys ("?") are not supported', lineNumber)
  }
  if (text.startsWith('"') || text.startsWith("'")) {
    const quoted = readQuotedScalar(text, 0, lineNumber)
    let i = quoted.next
    while (text[i] === ' ') i += 1
    if (text[i] !== ':') throw new ComposeParseError('expected ":" after quoted mapping key', lineNumber)
    return { key: quoted.value, rest: text.slice(i + 1) }
  }
  const colon = findMappingColon(text)
  if (colon < 0) throw new ComposeParseError('expected a "key: value" mapping entry', lineNumber)
  const key = text.slice(0, colon).trim()
  if (!key) throw new ComposeParseError('empty mapping key', lineNumber)
  if (key.length > 128) throw new ComposeParseError('mapping key exceeds 128 characters', lineNumber)
  return { key, rest: text.slice(colon + 1) }
}

class FlowParser {
  private i = 0
  private readonly text: string
  private readonly lineNumber: number
  private readonly anchors: Map<string, unknown>

  constructor(
    text: string,
    lineNumber: number,
    anchors: Map<string, unknown>,
  ) {
    this.text = text
    this.lineNumber = lineNumber
    this.anchors = anchors
  }

  parseComplete(): unknown {
    const value = this.parseValue()
    this.skipWhitespace()
    if (this.i !== this.text.length) {
      throw new ComposeParseError('unexpected characters after flow collection', this.lineNumber)
    }
    return value
  }

  private skipWhitespace(): void {
    while (this.i < this.text.length && /\s/.test(this.text[this.i])) this.i += 1
  }

  private parseValue(): unknown {
    this.skipWhitespace()
    const ch = this.text[this.i]
    if (ch === '[') return this.parseSequence()
    if (ch === '{') return this.parseMapping()
    if (ch === '"' || ch === "'") {
      const quoted = readQuotedScalar(this.text, this.i, this.lineNumber)
      this.i = quoted.next
      return quoted.value
    }
    if (ch === '*') {
      const match = /^\*([A-Za-z0-9_.-]{1,64})/.exec(this.text.slice(this.i))
      if (!match) throw new ComposeParseError('invalid alias reference', this.lineNumber)
      this.i += match[0].length
      if (!this.anchors.has(match[1])) {
        throw new ComposeParseError(`alias "*${match[1]}" was never defined`, this.lineNumber)
      }
      return cloneValue(this.anchors.get(match[1]))
    }
    if (ch === '&') {
      const match = /^&([A-Za-z0-9_.-]{1,64})\s*/.exec(this.text.slice(this.i))
      if (!match) throw new ComposeParseError('invalid anchor name', this.lineNumber)
      this.i += match[0].length
      const value = this.parseValue()
      if (this.anchors.size >= MAX_ANCHORS) throw new ComposeParseError('too many anchors', this.lineNumber)
      this.anchors.set(match[1], cloneValue(value))
      return value
    }
    if (ch === '!') throw new ComposeParseError('YAML tags are not supported', this.lineNumber)
    return coercePlainScalar(this.readPlain())
  }

  private readPlain(): string {
    const start = this.i
    while (this.i < this.text.length) {
      const ch = this.text[this.i]
      if (ch === ',' || ch === ']' || ch === '}') break
      if (ch === ':' && /[\s,\]}]/.test(this.text[this.i + 1] ?? ' ')) break
      this.i += 1
    }
    return this.text.slice(start, this.i).trim()
  }

  private parseSequence(): unknown[] {
    this.i += 1
    const out: unknown[] = []
    for (;;) {
      this.skipWhitespace()
      if (this.text[this.i] === ']') { this.i += 1; return out }
      out.push(this.parseValue())
      if (out.length > MAX_FLOW_ITEMS) {
        throw new ComposeParseError('flow sequence exceeds 256 items', this.lineNumber)
      }
      this.skipWhitespace()
      if (this.text[this.i] === ',') { this.i += 1; continue }
      if (this.text[this.i] === ']') { this.i += 1; return out }
      throw new ComposeParseError('expected "," or "]" in flow sequence', this.lineNumber)
    }
  }

  private parseMapping(): Record<string, unknown> {
    this.i += 1
    const out: Record<string, unknown> = {}
    for (;;) {
      this.skipWhitespace()
      if (this.text[this.i] === '}') { this.i += 1; return out }
      const key = this.parseKey()
      this.skipWhitespace()
      if (this.text[this.i] !== ':') {
        throw new ComposeParseError('expected ":" in flow mapping', this.lineNumber)
      }
      this.i += 1
      const value = this.parseValue()
      if (Object.prototype.hasOwnProperty.call(out, key)) {
        throw new ComposeParseError(`duplicate mapping key "${key}"`, this.lineNumber)
      }
      out[key] = value
      this.skipWhitespace()
      if (this.text[this.i] === ',') { this.i += 1; continue }
      if (this.text[this.i] === '}') { this.i += 1; return out }
      throw new ComposeParseError('expected "," or "}" in flow mapping', this.lineNumber)
    }
  }

  private parseKey(): string {
    this.skipWhitespace()
    const ch = this.text[this.i]
    if (ch === '"' || ch === "'") {
      const quoted = readQuotedScalar(this.text, this.i, this.lineNumber)
      this.i = quoted.next
      return quoted.value
    }
    const start = this.i
    while (this.i < this.text.length) {
      const current = this.text[this.i]
      if (current === ':' && /[\s,\]}]/.test(this.text[this.i + 1] ?? ' ')) break
      if (current === ',' || current === '}') break
      this.i += 1
    }
    const key = this.text.slice(start, this.i).trim()
    if (!key) throw new ComposeParseError('empty flow mapping key', this.lineNumber)
    return key
  }
}

// ---------------------------------------------------------------------------
// Block parser
// ---------------------------------------------------------------------------

class YamlSubsetParser {
  private readonly cursor: LineCursor
  private readonly anchors = new Map<string, unknown>()
  private depth = 0

  constructor(lines: SourceLine[]) {
    this.cursor = new LineCursor(lines)
  }

  parseRoot(): unknown {
    const first = this.cursor.peek()
    if (!first) throw new ComposeParseError('document is empty')
    if (first.indent !== 0) throw new ComposeParseError('document root must not be indented', first.number)
    const value = this.parseBlock(0)
    const leftover = this.cursor.peek()
    if (leftover) throw new ComposeParseError('unexpected trailing content', leftover.number)
    return value
  }

  private enter(): void {
    this.depth += 1
    if (this.depth > MAX_YAML_DEPTH) throw new ComposeParseError('nesting depth exceeds 16 levels')
  }

  private leave(): void {
    this.depth -= 1
  }

  private parseBlock(indent: number): unknown {
    const next = this.cursor.peek()
    if (!next) return null
    if (next.indent < indent) return null
    if (next.indent > indent) {
      throw new ComposeParseError('unexpected indentation', next.number)
    }
    this.enter()
    const value = isSequenceLine(next.text)
      ? this.parseSequence(indent)
      : this.parseMapping(indent)
    this.leave()
    return value
  }

  private parseMapping(indent: number, seed?: Record<string, unknown>): Record<string, unknown> {
    const out = seed ?? {}
    const merges: Record<string, unknown>[] = []
    for (;;) {
      const line = this.cursor.peek()
      if (!line || line.indent < indent) break
      if (line.indent > indent) throw new ComposeParseError('unexpected indentation', line.number)
      if (isSequenceLine(line.text)) break

      const { key, rest } = splitMappingEntry(line.text, line.number)
      if (Object.prototype.hasOwnProperty.call(out, key)) {
        throw new ComposeParseError(`duplicate mapping key "${key}"`, line.number)
      }
      this.cursor.next()
      const value = this.parseValue(indent, line.number, rest)

      if (key === '<<') {
        const contributions = Array.isArray(value) ? value : [value]
        for (const contribution of contributions) {
          if (!isPlainMapping(contribution)) {
            throw new ComposeParseError('merge key "<<" requires a mapping or a list of mappings', line.number)
          }
          if (merges.length >= MAX_ANCHORS) throw new ComposeParseError('too many merge keys', line.number)
          merges.push(contribution)
        }
        continue
      }
      out[key] = value
    }

    // YAML merge semantics: explicit keys win, and earlier merge sources win over later ones.
    for (const contribution of [...merges].reverse()) {
      for (const [key, value] of Object.entries(contribution)) {
        if (!Object.prototype.hasOwnProperty.call(out, key)) out[key] = cloneValue(value)
      }
    }
    return out
  }

  private parseSequence(indent: number): unknown[] {
    const out: unknown[] = []
    for (;;) {
      const line = this.cursor.peek()
      if (!line || line.indent < indent) break
      if (line.indent > indent) throw new ComposeParseError('unexpected indentation', line.number)
      if (!isSequenceLine(line.text)) break

      const restRaw = line.text.slice(1)
      const rest = restRaw.trim()
      this.cursor.next()

      if (rest === '') {
        const next = this.cursor.peek()
        out.push(next && next.indent > indent ? this.parseBlock(next.indent) : null)
        continue
      }

      const itemIndent = indent + 1 + (restRaw.length - restRaw.trimStart().length)
      if (findMappingColon(rest) >= 0) {
        const { key, rest: valueText } = splitMappingEntry(rest, line.number)
        if (key === '<<') {
          throw new ComposeParseError('merge keys inside sequence items are not supported', line.number)
        }
        const obj: Record<string, unknown> = {}
        obj[key] = this.parseValue(itemIndent, line.number, valueText)
        out.push(this.parseMapping(itemIndent, obj))
      } else {
        out.push(this.parseValue(indent, line.number, rest))
      }
      if (out.length > MAX_FLOW_ITEMS) {
        throw new ComposeParseError('sequence exceeds 256 items', line.number)
      }
    }
    return out
  }

  private parseValue(parentIndent: number, lineNumber: number, rawRest: string): unknown {
    const text = rawRest.trim()
    if (text === '') {
      const next = this.cursor.peek()
      if (!next || next.indent <= parentIndent) return null
      return this.parseBlock(next.indent)
    }

    if (text.startsWith('&')) {
      const match = /^&([A-Za-z0-9_.-]{1,64})(?:\s+([\s\S]*))?$/.exec(text)
      if (!match) throw new ComposeParseError('invalid anchor declaration', lineNumber)
      const name = match[1]
      if (this.anchors.has(name)) throw new ComposeParseError(`anchor "&${name}" is defined twice`, lineNumber)
      if (this.anchors.size >= MAX_ANCHORS) throw new ComposeParseError('too many anchors', lineNumber)
      const inner = (match[2] ?? '').trim()
      let value: unknown
      if (inner === '') {
        const next = this.cursor.peek()
        value = next && next.indent > parentIndent ? this.parseBlock(next.indent) : null
      } else {
        value = this.parseValue(parentIndent, lineNumber, inner)
      }
      this.anchors.set(name, cloneValue(value))
      return value
    }

    if (text.startsWith('*')) {
      const name = text.slice(1).trim()
      if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) {
        throw new ComposeParseError('invalid alias reference', lineNumber)
      }
      if (!this.anchors.has(name)) {
        throw new ComposeParseError(`alias "*${name}" was never defined`, lineNumber)
      }
      return cloneValue(this.anchors.get(name))
    }

    if (text.startsWith('!')) throw new ComposeParseError('YAML tags are not supported', lineNumber)
    if (text.startsWith('?')) throw new ComposeParseError('complex keys ("?") are not supported', lineNumber)
    if (text === '-' || text.startsWith('- ')) {
      throw new ComposeParseError('unexpected sequence item inside a mapping value', lineNumber)
    }

    if (text.startsWith('|') || text.startsWith('>')) {
      return this.readBlockScalar(text, parentIndent, lineNumber)
    }

    if (text.startsWith('[') || text.startsWith('{')) {
      return new FlowParser(text, lineNumber, this.anchors).parseComplete()
    }

    if (text.startsWith('"') || text.startsWith("'")) {
      const quoted = readQuotedScalar(text, 0, lineNumber)
      if (text.slice(quoted.next).trim() !== '') {
        throw new ComposeParseError('unexpected characters after quoted scalar', lineNumber)
      }
      if (quoted.value.length > MAX_SCALAR_LENGTH) {
        throw new ComposeParseError(`scalar exceeds ${MAX_SCALAR_LENGTH} characters`, lineNumber)
      }
      return quoted.value
    }

    if (text.length > MAX_SCALAR_LENGTH) {
      throw new ComposeParseError(`scalar exceeds ${MAX_SCALAR_LENGTH} characters`, lineNumber)
    }
    return coercePlainScalar(text)
  }

  private readBlockScalar(header: string, parentIndent: number, lineNumber: number): string {
    const style = header[0]
    const modifier = header.slice(1).trim()
    if (modifier !== '' && modifier !== '-' && modifier !== '+') {
      throw new ComposeParseError('unsupported block scalar header', lineNumber)
    }
    const { lines, trailingBlanks } = this.cursor.consumeBlockBody(parentIndent)
    let body: string
    if (style === '|') {
      body = lines.join('\n')
    } else {
      let folded = ''
      for (const line of lines) {
        if (line === '') { folded += '\n'; continue }
        if (folded !== '' && !folded.endsWith('\n')) folded += ' '
        folded += line
      }
      body = folded
    }

    if (modifier === '-') {
      body = body.replace(/\n+$/, '')
    } else if (modifier === '+') {
      body = body.replace(/\n+$/, '') + '\n'.repeat(Math.max(1, trailingBlanks + 1))
    } else if (body.length > 0) {
      body = body.replace(/\n+$/, '') + '\n'
    }
    if (body.length > MAX_SCALAR_LENGTH * 4) {
      throw new ComposeParseError('block scalar exceeds the supported size', lineNumber)
    }
    return body
  }
}

// ---------------------------------------------------------------------------
// `${VAR}` interpolation
// ---------------------------------------------------------------------------

export function interpolateComposeString(
  text: string,
  env: Record<string, string | undefined>,
  lineNumber?: number,
): string {
  let out = ''
  let i = 0
  while (i < text.length) {
    const ch = text[i]
    if (ch !== '$') { out += ch; i += 1; continue }
    const next = text[i + 1]
    if (next === '$') { out += '$'; i += 2; continue }
    if (next === '{') {
      const close = text.indexOf('}', i + 2)
      if (close < 0) throw new ComposeParseError('unterminated "${...}" interpolation', lineNumber)
      const expression = text.slice(i + 2, close)
      const match = /^([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-|:\?|\?)([\s\S]*))?$/.exec(expression)
      if (!match) throw new ComposeParseError('invalid interpolation expression', lineNumber)
      const name = match[1]
      const operator = match[2]
      const argument = match[3] ?? ''
      const raw = env[name]
      const present = raw !== undefined && raw !== ''
      if (!operator) {
        if (raw === undefined) {
          throw new ComposeParseError(`required environment variable "${name}" is not set`, lineNumber)
        }
        out += raw
      } else if (operator === ':-') {
        out += present ? raw : interpolateComposeString(argument, env, lineNumber)
      } else if (operator === '-') {
        out += raw !== undefined ? raw : interpolateComposeString(argument, env, lineNumber)
      } else {
        if (operator === ':?' ? !present : raw === undefined) {
          throw new ComposeParseError(
            `required environment variable "${name}" is missing${argument ? `: ${argument}` : ''}`,
            lineNumber,
          )
        }
        out += raw
      }
      i = close + 1
      continue
    }
    if (next && /[A-Za-z_]/.test(next)) {
      let j = i + 1
      while (j < text.length && /[A-Za-z0-9_]/.test(text[j])) j += 1
      const name = text.slice(i + 1, j)
      const raw = env[name]
      if (raw === undefined) {
        throw new ComposeParseError(`required environment variable "${name}" is not set`)
      }
      out += raw
      i = j
      continue
    }
    out += '$'
    i += 1
  }
  if (out.length > MAX_SCALAR_LENGTH) {
    throw new ComposeParseError(`interpolated scalar exceeds ${MAX_SCALAR_LENGTH} characters`, lineNumber)
  }
  return out
}

function interpolateTree(value: unknown, env: Record<string, string | undefined>): unknown {
  if (typeof value === 'string') return interpolateComposeString(value, env)
  if (Array.isArray(value)) return value.map(entry => interpolateTree(entry, env))
  if (isPlainMapping(value)) {
    const out: Record<string, unknown> = {}
    for (const [key, entry] of Object.entries(value)) out[key] = interpolateTree(entry, env)
    return out
  }
  return value
}

// ---------------------------------------------------------------------------
// Document pre-processing
// ---------------------------------------------------------------------------

function prepareLines(yamlText: string, maxBytes: number): SourceLine[] {
  if (typeof yamlText !== 'string' || yamlText.trim() === '') {
    throw new ComposeParseError('document is empty')
  }
  const bytes = Buffer.byteLength(yamlText, 'utf8')
  if (bytes > maxBytes) {
    throw new ComposeParseError(`document exceeds ${maxBytes} bytes`)
  }
  const normalized = yamlText.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n')
  const rawLines = normalized.split('\n')
  if (rawLines.length > MAX_COMPOSE_LINES) {
    throw new ComposeParseError(`document exceeds ${MAX_COMPOSE_LINES} lines`)
  }

  const lines: SourceLine[] = []
  let sawContent = false
  for (let i = 0; i < rawLines.length; i += 1) {
    const raw = rawLines[i]
    const trimmed = raw.trim()
    if (trimmed === '---') {
      if (sawContent) throw new ComposeParseError('multiple YAML documents are not supported', i + 1)
      continue
    }
    if (trimmed === '...') {
      if (rawLines.slice(i + 1).some(rest => rest.trim() !== '' && !rest.trim().startsWith('#'))) {
        throw new ComposeParseError('multiple YAML documents are not supported', i + 1)
      }
      break
    }
    if (trimmed !== '' && !trimmed.startsWith('#')) sawContent = true
    lines.push({ number: i + 1, raw })
  }
  return lines
}

/** Parse the bounded YAML subset into plain JS values (exported for parser tests). */
export function parseYamlSubset(yamlText: string, options: { env?: Record<string, string | undefined> } = {}): unknown {
  const lines = prepareLines(yamlText, MAX_COMPOSE_BYTES)
  const parsed = new YamlSubsetParser(lines).parseRoot()
  return interpolateTree(parsed, options.env ?? (process.env as Record<string, string | undefined>))
}

// ---------------------------------------------------------------------------
// Compose normalization
// ---------------------------------------------------------------------------

const TOP_LEVEL_KEYS = new Set(['version', 'name', 'services', 'networks', 'volumes'])
const REJECTED_TOP_LEVEL_KEYS = new Set(['secrets', 'configs', 'include'])

const SERVICE_KEYS = new Set([
  'image', 'build', 'command', 'entrypoint', 'environment', 'env_file', 'expose', 'ports',
  'depends_on', 'volumes', 'volumes_from', 'healthcheck', 'networks', 'network_mode', 'container_name',
  'hostname', 'user', 'working_dir', 'restart', 'labels', 'cap_add', 'cap_drop', 'devices',
  'privileged', 'read_only', 'tmpfs', 'pid', 'ipc', 'uts', 'userns_mode', 'security_opt', 'sysctls',
  'extra_hosts', 'shm_size', 'stop_grace_period', 'pids_limit', 'mem_limit', 'cpus', 'platform',
  'tty', 'stdin_open', 'init', 'logging', 'deploy', 'profiles', 'secrets', 'configs', 'extends', 'links',
  'ulimits', 'oom_score_adj', 'memswap_limit', 'dns', 'dns_search', 'domainname', 'mac_address',
])
const REJECTED_SERVICE_KEYS = new Set([
  'env_file', 'volumes_from', 'extends', 'links', 'tmpfs', 'deploy', 'profiles', 'secrets', 'configs',
])

function ensureStringScalar(value: unknown, label: string): string {
  if (typeof value === 'string') return value.trim()
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  throw new ComposeParseError(`${label} must be a scalar`)
}

function normalizeStringOrArray(value: unknown, label: string): string | string[] {
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed) throw new ComposeParseError(`${label} must not be empty`)
    return trimmed
  }
  if (Array.isArray(value)) {
    const out = value.map((entry, index) => {
      if (typeof entry !== 'string' && typeof entry !== 'number') {
        throw new ComposeParseError(`${label}[${index}] must be a scalar`)
      }
      return String(entry)
    })
    if (out.length === 0) throw new ComposeParseError(`${label} must not be an empty list`)
    if (out.length > 64) throw new ComposeParseError(`${label} exceeds 64 entries`)
    return out
  }
  throw new ComposeParseError(`${label} must be a string or a list of strings`)
}

function normalizeEnvironment(value: unknown): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined
  const out: Record<string, string> = {}
  const assign = (key: unknown, val: unknown): void => {
    const name = ensureStringScalar(key, 'environment key')
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name)) {
      throw new ComposeParseError(`invalid environment variable name "${name}"`)
    }
    if (val === null || val === undefined) return
    if (typeof val !== 'string' && typeof val !== 'number' && typeof val !== 'boolean') {
      throw new ComposeParseError(`environment variable "${name}" must be a scalar`)
    }
    if (Object.keys(out).length >= 64) throw new ComposeParseError('environment exceeds 64 entries')
    out[name] = String(val)
  }
  if (Array.isArray(value)) {
    for (const entry of value) {
      if (typeof entry !== 'string') throw new ComposeParseError('environment list entries must be strings')
      const eq = entry.indexOf('=')
      if (eq <= 0) {
        assign(entry, undefined)
      } else {
        assign(entry.slice(0, eq), entry.slice(eq + 1))
      }
    }
    return out
  }
  if (isPlainMapping(value)) {
    for (const [key, val] of Object.entries(value)) assign(key, val)
    return out
  }
  throw new ComposeParseError('environment must be a mapping or a list of KEY=VALUE strings')
}

function normalizeExpose(value: unknown): number[] {
  if (value === undefined) return []
  const list = Array.isArray(value) ? value : [value]
  const out: number[] = []
  for (const entry of list) {
    const text = ensureStringScalar(entry, 'expose entry').split('/')[0].trim()
    const port = Number(text)
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new ComposeParseError(`invalid expose port "${text}"`)
    }
    out.push(port)
  }
  return [...new Set(out)]
}

function normalizePorts(value: unknown): string[] {
  if (value === undefined) return []
  const list = Array.isArray(value) ? value : [value]
  if (list.length > 32) throw new ComposeParseError('ports exceeds 32 entries')
  return list.map(entry => {
    if (isPlainMapping(entry)) {
      const target = entry.target
      if (target === undefined) throw new ComposeParseError('ports mapping requires "target"')
      return `${ensureStringScalar(entry.published ?? '', 'ports.published')}:${ensureStringScalar(target, 'ports.target')}`
    }
    return ensureStringScalar(entry, 'ports entry')
  })
}

function normalizeDependsOn(value: unknown): string[] {
  if (value === undefined || value === null) return []
  const names = Array.isArray(value)
    ? value.map(entry => ensureStringScalar(entry, 'depends_on entry'))
    : isPlainMapping(value)
      ? Object.keys(value)
      : [ensureStringScalar(value, 'depends_on')]
  for (const name of names) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) {
      throw new ComposeParseError(`invalid depends_on service name "${name}"`)
    }
  }
  return [...new Set(names)]
}

function normalizeVolumes(value: unknown): ComposeVolumeSpec[] {
  if (value === undefined || value === null) return []
  if (!Array.isArray(value)) throw new ComposeParseError('volumes must be a list')
  if (value.length > 32) throw new ComposeParseError('volumes exceeds 32 entries')
  const out: ComposeVolumeSpec[] = []
  for (const entry of value) {
    if (typeof entry === 'string') {
      const parts = entry.split(':')
      const source = parts.length > 1 ? parts[0].trim() : undefined
      const target = parts.length > 1 ? parts[1].trim() : parts[0].trim()
      const readOnly = parts.slice(2).some(flag => flag.trim() === 'ro')
      const type: ComposeVolumeSpec['type'] = source === undefined
        ? 'volume'
        : (source.startsWith('/') || source.startsWith('.') || source.startsWith('~') ? 'bind' : 'volume')
      out.push({ type, ...(source ? { source } : {}), ...(target ? { target } : {}), readOnly, raw: entry })
      continue
    }
    if (isPlainMapping(entry)) {
      const type = ensureStringScalar(entry.type ?? 'volume', 'volumes.type') as ComposeVolumeSpec['type']
      if (type !== 'bind' && type !== 'volume' && type !== 'tmpfs') {
        throw new ComposeParseError(`unsupported volume type "${type}"`)
      }
      out.push({
        type,
        ...(entry.source !== undefined ? { source: ensureStringScalar(entry.source, 'volumes.source') } : {}),
        ...(entry.target !== undefined ? { target: ensureStringScalar(entry.target, 'volumes.target') } : {}),
        ...(entry.read_only === true ? { readOnly: true } : {}),
        raw: JSON.stringify(entry),
      })
      continue
    }
    throw new ComposeParseError('volumes entries must be strings or mappings')
  }
  return out
}

function parseDurationMs(value: unknown, label: string): number {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) throw new ComposeParseError(`${label} must be positive`)
    return Math.round(value)
  }
  if (typeof value !== 'string') throw new ComposeParseError(`${label} must be a duration string`)
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(value.trim())
  if (!match) throw new ComposeParseError(`${label} must be a duration like "10s" or "500ms"`)
  const amount = Number(match[1])
  const multiplier = match[2] === 'ms' ? 1 : match[2] === 's' ? 1_000 : match[2] === 'm' ? 60_000 : 3_600_000
  const ms = Math.round(amount * multiplier)
  if (!Number.isFinite(ms) || ms <= 0 || ms > 3_600_000) throw new ComposeParseError(`${label} is out of range`)
  return ms
}

function normalizeHealthcheck(value: unknown): ComposeHealthcheckSpec | undefined {
  if (value === undefined || value === null) return undefined
  if (typeof value === 'string') return { test: value }
  if (!isPlainMapping(value)) throw new ComposeParseError('healthcheck must be a mapping')
  const allowed = new Set(['test', 'interval', 'timeout', 'retries', 'start_period', 'disable'])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new ComposeParseError(`unsupported healthcheck key "${key}"`)
  }
  const spec: ComposeHealthcheckSpec = {}
  if (value.test !== undefined) {
    spec.test = normalizeStringOrArray(value.test, 'healthcheck.test')
    if (Array.isArray(spec.test)) {
      if (spec.test.length > 16) throw new ComposeParseError('healthcheck.test exceeds 16 entries')
      if (spec.test.some(entry => entry.length > 1_024)) {
        throw new ComposeParseError('healthcheck.test entry exceeds 1024 characters')
      }
    } else if (spec.test.length > 4_096) {
      throw new ComposeParseError('healthcheck.test exceeds 4096 characters')
    }
  }
  if (value.interval !== undefined) spec.intervalMs = parseDurationMs(value.interval, 'healthcheck.interval')
  if (value.timeout !== undefined) spec.timeoutMs = parseDurationMs(value.timeout, 'healthcheck.timeout')
  if (value.start_period !== undefined) spec.startPeriodMs = parseDurationMs(value.start_period, 'healthcheck.start_period')
  if (value.retries !== undefined) {
    const retries = Number(value.retries)
    if (!Number.isInteger(retries) || retries < 0 || retries > 100) {
      throw new ComposeParseError('healthcheck.retries must be an integer between 0 and 100')
    }
    spec.retries = retries
  }
  if (value.disable !== undefined) {
    if (typeof value.disable !== 'boolean') throw new ComposeParseError('healthcheck.disable must be a boolean')
    spec.disabled = value.disable
  }
  return spec
}

function normalizeNetworks(value: unknown): { networks: string[]; aliases: string[] } {
  if (value === undefined || value === null) return { networks: [], aliases: [] }
  const namePattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
  const aliasPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
  const networks: string[] = []
  const aliases: string[] = []

  const addAlias = (alias: unknown): void => {
    const text = ensureStringScalar(alias, 'network alias')
    if (!aliasPattern.test(text)) throw new ComposeParseError(`invalid network alias "${text}"`)
    if (aliases.length >= 8) throw new ComposeParseError('network aliases exceed 8 entries')
    if (!aliases.includes(text)) aliases.push(text)
  }

  if (Array.isArray(value)) {
    for (const entry of value) {
      const name = ensureStringScalar(entry, 'networks entry')
      if (!namePattern.test(name)) throw new ComposeParseError(`invalid network name "${name}"`)
      networks.push(name)
    }
    return { networks, aliases }
  }
  if (isPlainMapping(value)) {
    for (const [name, settings] of Object.entries(value)) {
      if (!namePattern.test(name)) throw new ComposeParseError(`invalid network name "${name}"`)
      networks.push(name)
      if (settings === null || settings === undefined) continue
      if (!isPlainMapping(settings)) throw new ComposeParseError(`network "${name}" settings must be a mapping`)
      if (settings.aliases !== undefined) {
        const list = Array.isArray(settings.aliases) ? settings.aliases : [settings.aliases]
        for (const alias of list) addAlias(alias)
      }
    }
    return { networks, aliases }
  }
  throw new ComposeParseError('networks must be a list or a mapping')
}

function normalizeBuild(value: unknown): ComposeBuildSpec {
  if (typeof value === 'string') {
    const context = value.trim()
    if (!context) throw new ComposeParseError('build context must not be empty')
    return { context }
  }
  if (!isPlainMapping(value)) throw new ComposeParseError('build must be a string or a mapping')
  const allowed = new Set(['context', 'dockerfile', 'target', 'args'])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new ComposeParseError(`unsupported build key "${key}"`)
  }
  const context = value.context === undefined ? '.' : ensureStringScalar(value.context, 'build.context')
  const spec: ComposeBuildSpec = { context }
  if (value.dockerfile !== undefined) spec.dockerfile = ensureStringScalar(value.dockerfile, 'build.dockerfile')
  if (value.target !== undefined) spec.target = ensureStringScalar(value.target, 'build.target')
  if (value.args !== undefined) {
    const args = normalizeEnvironment(value.args)
    if (args) spec.args = args
  }
  return spec
}

function normalizeService(name: string, config: unknown): ComposeServiceSource {
  if (!isPlainMapping(config)) {
    throw new ComposeParseError(`service "${name}" must be a mapping`)
  }
  for (const key of Object.keys(config)) {
    if (key.startsWith('x-')) continue
    if (REJECTED_SERVICE_KEYS.has(key)) {
      throw new ComposeParseError(`unsupported compose service key "${key}" on service "${name}"`)
    }
    if (!SERVICE_KEYS.has(key)) {
      throw new ComposeParseError(`unsupported compose service key "${key}" on service "${name}"`)
    }
  }

  const normalized: NormalizedComposeService = {
    name,
    expose: [],
    ports: [],
    dependsOn: [],
    volumes: [],
    networks: [],
    networkAliases: [],
  }

  if (config.image !== undefined && config.image !== null) {
    normalized.image = ensureStringScalar(config.image, `service "${name}" image`)
  }
  if (config.build !== undefined) normalized.build = normalizeBuild(config.build)
  if (config.command !== undefined) normalized.command = normalizeStringOrArray(config.command, `service "${name}" command`)
  if (config.entrypoint !== undefined) {
    normalized.entrypoint = normalizeStringOrArray(config.entrypoint, `service "${name}" entrypoint`)
  }
  const environment = normalizeEnvironment(config.environment)
  if (environment) normalized.environment = environment
  normalized.expose = normalizeExpose(config.expose)
  normalized.ports = normalizePorts(config.ports)
  normalized.dependsOn = normalizeDependsOn(config.depends_on)
  normalized.volumes = normalizeVolumes(config.volumes)
  const healthcheck = normalizeHealthcheck(config.healthcheck)
  if (healthcheck) normalized.healthcheck = healthcheck
  const networkSettings = normalizeNetworks(config.networks)
  normalized.networks = networkSettings.networks
  normalized.networkAliases = networkSettings.aliases
  if (config.user !== undefined && config.user !== null) {
    normalized.user = ensureStringScalar(config.user, `service "${name}" user`)
  }
  if (config.working_dir !== undefined) {
    normalized.workingDir = ensureStringScalar(config.working_dir, `service "${name}" working_dir`)
  }
  if (config.restart !== undefined) {
    normalized.restart = ensureStringScalar(config.restart, `service "${name}" restart`)
  }

  return { name, config, normalized }
}

/**
 * Parse and normalize a Docker Compose document. Structural only: security whitelisting happens
 * in `lab-runner.ts` so the policy stays in one place.
 */
export function parseComposeDocument(yamlText: string, options: ComposeParseOptions = {}): ParsedComposeDocument {
  const maxServices = options.maxServices ?? MAX_SERVICE_COUNT
  const root = parseYamlSubset(yamlText, { env: options.env })
  if (!isPlainMapping(root)) throw new ComposeParseError('compose document root must be a mapping')

  for (const key of Object.keys(root)) {
    if (key.startsWith('x-')) continue
    if (REJECTED_TOP_LEVEL_KEYS.has(key)) {
      throw new ComposeParseError(`unsupported top-level compose key "${key}"`)
    }
    if (!TOP_LEVEL_KEYS.has(key)) {
      throw new ComposeParseError(`unsupported top-level compose key "${key}"`)
    }
  }

  const servicesRaw = root.services
  if (!isPlainMapping(servicesRaw)) throw new ComposeParseError('compose document must define a "services" mapping')
  const serviceNames = Object.keys(servicesRaw)
  if (serviceNames.length === 0) throw new ComposeParseError('compose document contains no services')
  if (serviceNames.length > maxServices) {
    throw new ComposeParseError(`compose document declares ${serviceNames.length} services; the limit is ${maxServices}`)
  }

  const document: ParsedComposeDocument = { services: [] }
  if (root.version !== undefined && root.version !== null) {
    document.version = ensureStringScalar(root.version, 'version')
  }
  if (root.name !== undefined && root.name !== null) {
    document.name = ensureStringScalar(root.name, 'name')
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(document.name)) {
      throw new ComposeParseError(`invalid compose project name "${document.name}"`)
    }
  }

  const declaredNetworks = root.networks
  if (declaredNetworks !== undefined && declaredNetworks !== null && !isPlainMapping(declaredNetworks)) {
    throw new ComposeParseError('top-level "networks" must be a mapping')
  }
  const declaredVolumes = root.volumes
  if (declaredVolumes !== undefined && declaredVolumes !== null && !isPlainMapping(declaredVolumes)) {
    throw new ComposeParseError('top-level "volumes" must be a mapping')
  }

  for (const name of serviceNames) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) {
      throw new ComposeParseError(`invalid service name "${name}"`)
    }
    document.services.push(normalizeService(name, servicesRaw[name]))
  }
  return document
}

export const COMPOSE_PARSER_LIMITS = {
  maxBytes: MAX_COMPOSE_BYTES,
  maxLines: MAX_COMPOSE_LINES,
  maxDepth: MAX_YAML_DEPTH,
  maxAnchors: MAX_ANCHORS,
  maxFlowItems: MAX_FLOW_ITEMS,
  maxScalarLength: MAX_SCALAR_LENGTH,
} as const
