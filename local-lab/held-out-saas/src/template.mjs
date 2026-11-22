// Notification template engine. The planted flaw (hos-19) is that user-controlled template text reaches an
// expression evaluator. The evaluator is a closed arithmetic/string interpreter — it can never run host code.

export class TemplateError extends Error {}

const TOKEN = /\s*(?:(\d+(?:\.\d+)?)|('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")|([A-Za-z_]\w*)|(\*\*|[-+*/%()]))/y

function tokenize(src) {
  const tokens = []
  TOKEN.lastIndex = 0
  while (TOKEN.lastIndex < src.length) {
    if (/^\s*$/.test(src.slice(TOKEN.lastIndex))) break
    const m = TOKEN.exec(src)
    if (!m) throw new TemplateError(`unexpected token in expression "${src.slice(0, 40)}"`)
    if (m[1] !== undefined) tokens.push({ t: 'num', v: Number(m[1]) })
    else if (m[2] !== undefined) tokens.push({ t: 'str', v: m[2].slice(1, -1) })
    else if (m[3] !== undefined) tokens.push({ t: 'id', v: m[3] })
    else tokens.push({ t: 'op', v: m[4] })
  }
  return tokens
}

function evalExpression(src, vars) {
  const tokens = tokenize(src)
  if (!tokens.length) throw new TemplateError('empty expression')
  let i = 0
  const peekOp = () => (tokens[i]?.t === 'op' ? tokens[i].v : null)

  function primary() {
    const tk = tokens[i++]
    if (!tk) throw new TemplateError('unexpected end of expression')
    if (tk.t === 'num' || tk.t === 'str') return tk.v
    if (tk.t === 'id') {
      if (!Object.prototype.hasOwnProperty.call(vars, tk.v)) throw new TemplateError(`undefined variable ${tk.v}`)
      return vars[tk.v]
    }
    if (tk.v === '(') {
      const v = additive()
      if (tokens[i++]?.v !== ')') throw new TemplateError('missing )')
      return v
    }
    if (tk.v === '-') return -Number(primary())
    throw new TemplateError(`unexpected "${tk.v}"`)
  }
  function power() {
    const base = primary()
    if (peekOp() === '**') {
      i++
      return Number(base) ** Math.min(Number(power()), 64)
    }
    return base
  }
  function multiplicative() {
    let left = power()
    for (let op = peekOp(); op === '*' || op === '/' || op === '%'; op = peekOp()) {
      i++
      const right = power()
      if (op === '*') {
        if (typeof left === 'string' && typeof right === 'number') left = left.repeat(Math.max(0, Math.min(right, 100)))
        else if (typeof left === 'number' && typeof right === 'string') left = right.repeat(Math.max(0, Math.min(left, 100)))
        else left = Number(left) * Number(right)
      } else if (op === '/') left = Number(left) / Number(right)
      else left = Number(left) % Number(right)
    }
    return left
  }
  function additive() {
    let left = multiplicative()
    for (let op = peekOp(); op === '+' || op === '-'; op = peekOp()) {
      i++
      const right = multiplicative()
      left = op === '+'
        ? (typeof left === 'string' || typeof right === 'string' ? `${left}${right}` : left + right)
        : Number(left) - Number(right)
    }
    return left
  }

  const result = additive()
  if (i !== tokens.length) throw new TemplateError('trailing tokens in expression')
  return result
}

const DELIMITERS = /\{\{([\s\S]{1,200}?)\}\}|\$\{([\s\S]{1,200}?)\}|<%=([\s\S]{1,200}?)%>|#\{([\s\S]{1,200}?)\}/g

export function renderTemplate(source, vars) {
  return String(source).slice(0, 4000).replace(DELIMITERS, (_m, a, b, c, d) => String(evalExpression(String(a ?? b ?? c ?? d).trim(), vars)))
}

/** Hardened renderer: plain `{{name}}`-style substitution from a fixed allowlist, no expression evaluation. */
export function renderTemplateSafe(source, vars, allowed) {
  return String(source).slice(0, 4000).replace(/\{\{\s*([A-Za-z_]\w*)\s*\}\}/g, (m, key) =>
    (allowed.includes(key) && Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : m))
}
