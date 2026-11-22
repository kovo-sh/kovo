// Safe mini template engine with its OWN expression interpreter (no eval / Function / vm). Models an
// SSTI sink: when the template SOURCE is request-derived and at least one embedded expression is
// evaluated, a `template_code_exec` impact event is recorded. Passing user content as context DATA
// (not inside the source) never triggers it.
import type { Oracle } from './oracle.ts'
import { isFromInput } from './oracle.ts'

export interface RenderOpts { oracle?: Oracle; inputDerived?: boolean }

const secretBearing = new WeakSet<object>()
/** Mark an object whose property values are secrets; traversing it during eval sets reachedSecret. */
export function markSecretBearing<T extends object>(obj: T): T { secretBearing.add(obj); return obj }

export function htmlEscape(v: unknown): string {
  return String(v).replace(/[&<>"']/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;')
}

interface EvalState { evaluated: boolean; reachedSecret: boolean }

// ---- expression lexer -------------------------------------------------------------------------
type Tok = { t: string; v: string }
const PUNCT = ['===', '!==', '==', '!=', '<=', '>=', '&&', '||', '.', '[', ']', '(', ')', ',', '|',
  '+', '-', '*', '/', '%', '<', '>', '!']

function lexExpr(s: string): Tok[] {
  const toks: Tok[] = []
  let i = 0
  while (i < s.length) {
    const c = s[i]!
    if (/\s/.test(c)) { i++; continue }
    if (c === '"' || c === "'") {
      let j = i + 1; let str = ''
      while (j < s.length && s[j] !== c) { if (s[j] === '\\') { str += s[j + 1] ?? ''; j += 2; continue } str += s[j]; j++ }
      toks.push({ t: 'str', v: str }); i = j + 1; continue
    }
    if (/[0-9]/.test(c)) { let j = i; while (j < s.length && /[0-9.]/.test(s[j]!)) j++; toks.push({ t: 'num', v: s.slice(i, j) }); i = j; continue }
    if (/[A-Za-z_$]/.test(c)) { let j = i; while (j < s.length && /[A-Za-z0-9_$]/.test(s[j]!)) j++; toks.push({ t: 'id', v: s.slice(i, j) }); i = j; continue }
    const p = PUNCT.find((op) => s.startsWith(op, i))
    if (p) { toks.push({ t: p, v: p }); i += p.length; continue }
    i++ // skip unknown char
  }
  return toks
}

// ---- recursive-descent parser -> evaluator ----------------------------------------------------
type Node = (scope: Frame[], st: EvalState) => unknown
interface Frame { [k: string]: unknown }
const METHODS = new Set(['toUpperCase', 'toLowerCase', 'slice', 'join'])

function parseExpr(toks: Tok[]): Node {
  let p = 0
  const peek = () => toks[p]
  const eat = (t?: string) => { const tk = toks[p]; if (t && (!tk || tk.t !== t)) throw new Error('parse'); p++; return tk! }

  const binary = (next: () => Node, ops: string[]): Node => {
    let left = next()
    while (peek() && ops.includes(peek()!.t)) {
      const op = eat().t; const right = next(); const l = left
      left = (sc, st) => applyOp(op, l(sc, st), right(sc, st))
    }
    return left
  }
  const or = (): Node => binary(and, ['||'])
  const and = (): Node => binary(cmp, ['&&'])
  const cmp = (): Node => binary(add, ['===', '!==', '==', '!=', '<=', '>=', '<', '>'])
  const add = (): Node => binary(mul, ['+', '-'])
  const mul = (): Node => binary(unary, ['*', '/', '%'])
  function unary(): Node {
    if (peek() && (peek()!.t === '!' || peek()!.t === '-')) {
      const op = eat().t; const operand = unary()
      return (sc, st) => (op === '!' ? !operand(sc, st) : -(operand(sc, st) as number))
    }
    return postfix()
  }
  function postfix(): Node {
    let node = primary()
    while (peek()) {
      const t = peek()!.t
      if (t === '.') {
        eat('.'); const name = eat('id').v
        if (peek() && peek()!.t === '(') { node = methodCall(node, name) }
        else { const base = node; node = (sc, st) => member(base(sc, st), name, st) }
      } else if (t === '[') {
        eat('['); const idx = or(); eat(']'); const base = node
        node = (sc, st) => member(base(sc, st), String(idx(sc, st)), st)
      } else break
    }
    return node
  }
  function methodCall(base: Node, name: string): Node {
    eat('('); const args: Node[] = []
    while (peek() && peek()!.t !== ')') { args.push(or()); if (peek() && peek()!.t === ',') eat(',') }
    eat(')')
    return (sc, st) => {
      const recv = base(sc, st) as Record<string, unknown>
      if (!METHODS.has(name)) throw new Error('method not allowed: ' + name)
      const fn = recv == null ? undefined : (recv as never)[name]
      if (typeof fn !== 'function') return undefined
      return (fn as (...a: unknown[]) => unknown).apply(recv, args.map((a) => a(sc, st)))
    }
  }
  function primary(): Node {
    const tk = peek()
    if (!tk) throw new Error('eof')
    if (tk.t === 'num') { eat(); return () => Number(tk.v) }
    if (tk.t === 'str') { eat(); return () => tk.v }
    if (tk.t === '(') { eat('('); const e = or(); eat(')'); return e }
    if (tk.t === 'id') {
      eat()
      if (tk.v === 'true') return () => true
      if (tk.v === 'false') return () => false
      if (tk.v === 'null') return () => null
      return (sc, st) => lookup(sc, tk.v, st)
    }
    throw new Error('unexpected ' + tk.t)
  }
  const root = or()
  return root
}

function lookup(scope: Frame[], name: string, st: EvalState): unknown {
  for (let i = scope.length - 1; i >= 0; i--) if (name in scope[i]!) {
    const frame = scope[i]!
    if (secretBearing.has(frame)) st.reachedSecret = true
    return frame[name]
  }
  return undefined
}
function member(base: unknown, name: string, st: EvalState): unknown {
  if (base != null && typeof base === 'object' && secretBearing.has(base as object)) st.reachedSecret = true
  if (base == null) return undefined
  return (base as Record<string, unknown>)[name]
}
function applyOp(op: string, a: unknown, b: unknown): unknown {
  switch (op) {
    case '+': return (typeof a === 'string' || typeof b === 'string') ? String(a) + String(b) : (a as number) + (b as number)
    case '-': return (a as number) - (b as number)
    case '*': return (a as number) * (b as number)
    case '/': return (a as number) / (b as number)
    case '%': return (a as number) % (b as number)
    case '&&': return a && b
    case '||': return a || b
    case '==': case '===': return a === b
    case '!=': case '!==': return a !== b
    case '<': return (a as number) < (b as number)
    case '>': return (a as number) > (b as number)
    case '<=': return (a as number) <= (b as number)
    case '>=': return (a as number) >= (b as number)
  }
  return undefined
}

// ---- filters ----------------------------------------------------------------------------------
const FILTERS: Record<string, (v: unknown) => unknown> = {
  upper: (v) => String(v).toUpperCase(),
  lower: (v) => String(v).toLowerCase(),
  escape: (v) => htmlEscape(v),
  json: (v) => JSON.stringify(v),
  money: (v) => '$' + Number(v).toFixed(2),
  date: (v) => { const d = new Date(v as never); return isNaN(d.getTime()) ? String(v) : d.toISOString().slice(0, 10) },
}

function compileOutput(expr: string): { run: (sc: Frame[], st: EvalState) => unknown } {
  const parts = splitPipes(expr)
  const node = parseExpr(lexExpr(parts[0]!))
  const filters = parts.slice(1).map((f) => f.trim())
  return {
    run: (sc, st) => {
      let v = node(sc, st)
      for (const f of filters) { const fn = FILTERS[f]; if (fn) v = fn(v) }
      return v
    },
  }
}
// split on top-level `|` only (not `||`)
function splitPipes(s: string): string[] {
  const out: string[] = []; let depth = 0; let cur = ''
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!
    if (c === '(' || c === '[') depth++
    else if (c === ')' || c === ']') depth--
    if (c === '|' && s[i + 1] !== '|' && s[i - 1] !== '|' && depth === 0) { out.push(cur); cur = ''; continue }
    cur += c
  }
  out.push(cur)
  return out
}

// ---- template parse + render ------------------------------------------------------------------
type TplNode =
  | { k: 'text'; v: string }
  | { k: 'out'; expr: string; raw: boolean }
  | { k: 'if'; expr: string; body: TplNode[] }
  | { k: 'for'; varName: string; expr: string; body: TplNode[] }

function parseTemplate(src: string): TplNode[] {
  const re = /\{\{\{(.+?)\}\}\}|\{\{(.+?)\}\}|\{%(.+?)%\}/gs
  const stack: TplNode[][] = [[]]
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(src)) !== null) {
    if (m.index > last) stack[stack.length - 1]!.push({ k: 'text', v: src.slice(last, m.index) })
    last = re.lastIndex
    if (m[1] !== undefined) stack[stack.length - 1]!.push({ k: 'out', expr: m[1].trim(), raw: true })
    else if (m[2] !== undefined) stack[stack.length - 1]!.push({ k: 'out', expr: m[2].trim(), raw: false })
    else {
      const tag = m[3]!.trim()
      if (tag.startsWith('if ')) { const node: TplNode = { k: 'if', expr: tag.slice(3).trim(), body: [] }; stack[stack.length - 1]!.push(node); stack.push(node.body) }
      else if (tag.startsWith('for ')) {
        const fm = /^for\s+(\w+)\s+in\s+(.+)$/.exec(tag)!
        const node: TplNode = { k: 'for', varName: fm[1]!, expr: fm[2]!.trim(), body: [] }
        stack[stack.length - 1]!.push(node); stack.push(node.body)
      } else if (tag === 'endif' || tag === 'endfor') { if (stack.length > 1) stack.pop() }
    }
  }
  if (last < src.length) stack[0]!.push({ k: 'text', v: src.slice(last) })
  return stack[0]!
}

function renderNodes(nodes: TplNode[], scope: Frame[], st: EvalState): string {
  let out = ''
  for (const node of nodes) {
    if (node.k === 'text') { out += node.v; continue }
    if (node.k === 'out') { st.evaluated = true; const v = compileOutput(node.expr).run(scope, st); out += node.raw ? String(v ?? '') : htmlEscape(v ?? ''); continue }
    if (node.k === 'if') { st.evaluated = true; if (parseExpr(lexExpr(node.expr))(scope, st)) out += renderNodes(node.body, scope, st); continue }
    if (node.k === 'for') {
      st.evaluated = true
      const iter = parseExpr(lexExpr(node.expr))(scope, st)
      if (iter && typeof (iter as Iterable<unknown>)[Symbol.iterator] === 'function') {
        for (const item of iter as Iterable<unknown>) { const frame: Frame = {}; frame[node.varName] = item; out += renderNodes(node.body, [...scope, frame], st) }
      }
    }
  }
  return out
}

export function render(source: string, context: Record<string, unknown>, opts: RenderOpts = {}): string {
  const st: EvalState = { evaluated: false, reachedSecret: false }
  let result: string
  try { result = renderNodes(parseTemplate(source), [context], st) }
  catch { result = '' }
  const inputDerived = opts.inputDerived === true || isFromInput(source)
  if (inputDerived && st.evaluated) opts.oracle?.emit('template_code_exec', { reachedSecret: st.reachedSecret }, 'template')
  return result
}
