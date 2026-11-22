// Minimal, dependency-free parser for the restricted YAML subset used by Guardian's vetted safe templates.
// Supported: block mappings, block sequences (including `- key: value` maps), flow sequences/maps (flat),
// quoted/plain scalars, and `#` comments. Not supported (rejected or ignored by design): anchors, tags,
// multi-document streams, block scalars (`|`, `>`), and merge keys.

interface Line {
  indent: number
  text: string
  no: number
}

interface Ctx {
  lines: Line[]
  i: number
}

export class MiniYamlError extends Error {
  constructor(message: string, line?: number) {
    super(line ? `YAML line ${line}: ${message}` : `YAML: ${message}`)
    this.name = 'MiniYamlError'
  }
}

function stripComment(raw: string): string {
  let quote: string | null = null
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i]
    if (quote) {
      if (ch === '\\' && quote === '"') { i += 1; continue }
      if (ch === quote) {
        if (quote === "'" && raw[i + 1] === "'") { i += 1; continue }
        quote = null
      }
    } else if (ch === '"' || ch === "'") {
      const prev = i === 0 ? ' ' : raw[i - 1]
      if (/[\s:\[{,\-]/.test(prev)) quote = ch
    } else if (ch === '#' && (i === 0 || /\s/.test(raw[i - 1]))) {
      return raw.slice(0, i)
    }
  }
  return raw
}

function tokenize(src: string): Line[] {
  const out: Line[] = []
  const rawLines = src.replace(/\r\n?/g, '\n').split('\n')
  for (let n = 0; n < rawLines.length; n += 1) {
    const stripped = stripComment(rawLines[n]).replace(/\s+$/, '')
    if (!stripped.trim()) continue
    if (/^\t/.test(stripped)) throw new MiniYamlError('tabs are not allowed for indentation', n + 1)
    if (/^(?:---|\.\.\.)\s*$/.test(stripped)) {
      if (/^---\s*$/.test(stripped) && out.length === 0) continue
      throw new MiniYamlError('multi-document streams are not supported', n + 1)
    }
    const indent = stripped.length - stripped.trimStart().length
    out.push({ indent, text: stripped.trimStart(), no: n + 1 })
  }
  return out
}

function unquote(s: string, no: number): string {
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2) throw new MiniYamlError('unterminated double-quoted string', no)
    return s.slice(1, -1).replace(/\\(["\\nrtbf/]|u[0-9a-fA-F]{4})/g, (_m, c: string) => {
      if (c === 'n') return '\n'
      if (c === 'r') return '\r'
      if (c === 't') return '\t'
      if (c === 'b') return '\b'
      if (c === 'f') return '\f'
      if (c.startsWith('u')) return String.fromCharCode(parseInt(c.slice(1), 16))
      return c
    })
  }
  if (!s.endsWith("'") || s.length < 2) throw new MiniYamlError('unterminated single-quoted string', no)
  return s.slice(1, -1).replaceAll("''", "'")
}

function splitTopLevel(s: string, sep: string): string[] {
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

function findKeySplit(text: string): number {
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

function parseInline(raw: string, no: number): unknown {
  const s = raw.trim()
  if (s === '' || s === '~' || s === 'null') return null
  if (s.startsWith('[')) {
    if (!s.endsWith(']')) throw new MiniYamlError('unterminated flow sequence', no)
    const inner = s.slice(1, -1)
    return splitTopLevel(inner, ',').map(p => p.trim()).filter(p => p !== '').map(p => parseInline(p, no))
  }
  if (s.startsWith('{')) {
    if (!s.endsWith('}')) throw new MiniYamlError('unterminated flow map', no)
    const inner = s.slice(1, -1)
    const obj: Record<string, unknown> = {}
    for (const part of splitTopLevel(inner, ',').map(p => p.trim()).filter(p => p !== '')) {
      const at = findKeySplit(part)
      if (at < 0) throw new MiniYamlError(`invalid flow map entry "${part}"`, no)
      const k = part.slice(0, at).trim()
      const quoted = k.startsWith('"') || k.startsWith("'")
      if (!quoted && /^[&*!|>]/.test(k)) {
        throw new MiniYamlError(`unsupported YAML construct "${k[0]}"`, no)
      }
      const key = quoted ? unquote(k, no) : k
      if (key === '<<') throw new MiniYamlError('merge keys are not supported', no)
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new MiniYamlError(`forbidden key "${key}"`, no)
      }
      if (Object.prototype.hasOwnProperty.call(obj, key)) throw new MiniYamlError(`duplicate key "${key}"`, no)
      obj[key] = parseInline(part.slice(at + 1), no)
    }
    return obj
  }
  if (s.startsWith('"') || s.startsWith("'")) return unquote(s, no)
  if (/^(?:true|True|TRUE)$/.test(s)) return true
  if (/^(?:false|False|FALSE)$/.test(s)) return false
  if (/^-?\d+$/.test(s)) return Number(s)
  if (/^-?\d+\.\d+$/.test(s)) return Number(s)
  if (/^[|>&*!]/.test(s)) throw new MiniYamlError(`unsupported YAML construct "${s[0]}"`, no)
  return s
}

function parseBlock(ctx: Ctx, indent: number): unknown {
  const line = ctx.lines[ctx.i]
  if (line.text === '-' || line.text.startsWith('- ')) return parseSeq(ctx, line.indent)
  return parseMap(ctx, indent)
}

function parseMap(ctx: Ctx, indent: number): Record<string, unknown> {
  const obj: Record<string, unknown> = {}
  while (ctx.i < ctx.lines.length) {
    const line = ctx.lines[ctx.i]
    if (line.indent < indent) break
    if (line.indent > indent) throw new MiniYamlError('unexpected indentation', line.no)
    if (line.text === '-' || line.text.startsWith('- ')) break
    const at = findKeySplit(line.text)
    if (at < 0) throw new MiniYamlError(`expected "key: value" but found "${line.text}"`, line.no)
    const rawKey = line.text.slice(0, at).trim()
    const isQuoted = rawKey.startsWith('"') || rawKey.startsWith("'")
    if (!isQuoted && /^[&*!|>]/.test(rawKey)) {
      throw new MiniYamlError(`unsupported YAML construct "${rawKey[0]}"`, line.no)
    }
    const key = isQuoted ? unquote(rawKey, line.no) : rawKey
    if (key === '<<') {
      throw new MiniYamlError('merge keys are not supported', line.no)
    }
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new MiniYamlError(`forbidden key "${key}"`, line.no)
    }
    if (Object.prototype.hasOwnProperty.call(obj, key)) throw new MiniYamlError(`duplicate key "${key}"`, line.no)
    const rest = line.text.slice(at + 1).trim()
    ctx.i += 1
    if (rest === '') {
      const next = ctx.lines[ctx.i]
      if (next && next.indent > indent) {
        obj[key] = parseBlock(ctx, next.indent)
      } else if (next && next.indent === indent && (next.text === '-' || next.text.startsWith('- '))) {
        obj[key] = parseSeq(ctx, indent)
      } else {
        obj[key] = null
      }
    } else {
      obj[key] = parseInline(rest, line.no)
    }
  }
  return obj
}

function parseSeq(ctx: Ctx, indent: number): unknown[] {
  const arr: unknown[] = []
  while (ctx.i < ctx.lines.length) {
    const line = ctx.lines[ctx.i]
    if (line.indent < indent) break
    if (line.indent > indent) throw new MiniYamlError('unexpected indentation in sequence', line.no)
    if (!(line.text === '-' || line.text.startsWith('- '))) break
    const content = line.text.slice(1).trimStart()
    const offset = line.text.length - content.length
    if (content === '') {
      ctx.i += 1
      const next = ctx.lines[ctx.i]
      arr.push(next && next.indent > indent ? parseBlock(ctx, next.indent) : null)
      continue
    }
    const startsFlowOrQuote = content.startsWith('[') || content.startsWith('{') || content.startsWith('"') || content.startsWith("'")
    if (!startsFlowOrQuote && findKeySplit(content) >= 0) {
      ctx.lines[ctx.i] = { indent: indent + offset, text: content, no: line.no }
      arr.push(parseMap(ctx, indent + offset))
      continue
    }
    if (startsFlowOrQuote && (content.startsWith('"') || content.startsWith("'")) && findKeySplit(content) > 0) {
      ctx.lines[ctx.i] = { indent: indent + offset, text: content, no: line.no }
      arr.push(parseMap(ctx, indent + offset))
      continue
    }
    arr.push(parseInline(content, line.no))
    ctx.i += 1
  }
  return arr
}

export function parseMiniYaml(src: string): unknown {
  const lines = tokenize(src)
  if (lines.length === 0) return null
  const ctx: Ctx = { lines, i: 0 }
  const value = parseBlock(ctx, lines[0].indent)
  if (ctx.i < lines.length) throw new MiniYamlError('unexpected trailing content', lines[ctx.i].no)
  return value
}
