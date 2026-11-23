// Self-contained HTML templating + DOM shim. This is deliberately NOT a browser:
// it renders fixture templates and parses the resulting markup into a tag tree so
// self-tests can assert what an authenticated admin view would contain, without
// invoking Playwright or executing any script.

export function escapeHtml(input: unknown): string {
  return String(input ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

/**
 * `{{name}}` is HTML-escaped, `{{{name}}}` is inserted raw. The raw form mirrors a
 * template engine's "unescaped" helper — the fixture opts into it where a stored XSS
 * is meant to render.
 */
export function template(source: string, vars: Record<string, string | number>): string {
  return source
    .replace(/\{\{\{([a-zA-Z0-9_]+)\}\}\}/g, (_m, key: string) => String(vars[key] ?? ''))
    .replace(/\{\{([a-zA-Z0-9_]+)\}\}/g, (_m, key: string) => escapeHtml(vars[key] ?? ''))
}

export interface DomNode {
  tag: string
  attrs: Record<string, string>
  children: DomNode[]
  text: string
}

const VOID_TAGS = new Set([
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'param',
  'source',
  'track',
  'wbr',
])

const RAW_TAGS = new Set(['script', 'style'])

function parseAttrs(raw: string): Record<string, string> {
  const attrs: Record<string, string> = {}
  const re = /([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g
  let match: RegExpExecArray | null
  while ((match = re.exec(raw)) !== null) {
    const name = match[1].toLowerCase()
    attrs[name] = match[2] ?? match[3] ?? match[4] ?? ''
  }
  return attrs
}

/** Parse a small, well-formed HTML subset into a node tree. Tolerant of attributes and raw text. */
export function parseHtml(html: string): DomNode {
  const root: DomNode = { tag: '#root', attrs: {}, children: [], text: '' }
  const stack: DomNode[] = [root]
  const tagRe = /<!--[\s\S]*?-->|<\/([a-zA-Z][\w:-]*)\s*>|<([a-zA-Z][\w:-]*)((?:"[^"]*"|'[^']*'|[^>])*?)(\/?)>/g
  let cursor = 0
  let match: RegExpExecArray | null

  const pushText = (text: string) => {
    if (!text) return
    const parent = stack[stack.length - 1]
    parent.text += text
    parent.children.push({ tag: '#text', attrs: {}, children: [], text })
  }

  while ((match = tagRe.exec(html)) !== null) {
    pushText(html.slice(cursor, match.index))
    cursor = tagRe.lastIndex
    const [full, closing, openTag, rawAttrs, selfClosing] = match
    if (full.startsWith('<!--')) continue
    if (closing) {
      const tag = closing.toLowerCase()
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].tag === tag) {
          stack.length = i
          break
        }
      }
      continue
    }
    if (!openTag) continue
    const tag = openTag.toLowerCase()
    const node: DomNode = { tag, attrs: parseAttrs(rawAttrs ?? ''), children: [], text: '' }
    stack[stack.length - 1].children.push(node)
    if (selfClosing || VOID_TAGS.has(tag)) continue
    if (RAW_TAGS.has(tag)) {
      const closeRe = new RegExp(`</${tag}\\s*>`, 'i')
      const rest = html.slice(cursor)
      const close = closeRe.exec(rest)
      const inner = close ? rest.slice(0, close.index) : rest
      if (inner) node.children.push({ tag: '#text', attrs: {}, children: [], text: inner })
      node.text = inner
      if (close) tagRe.lastIndex = cursor + close.index + close[0].length
      cursor = tagRe.lastIndex
      continue
    }
    stack.push(node)
  }
  pushText(html.slice(cursor))
  return root
}

export function findAll(node: DomNode, predicate: (node: DomNode) => boolean): DomNode[] {
  const out: DomNode[] = []
  const visit = (current: DomNode) => {
    if (predicate(current)) out.push(current)
    for (const child of current.children) visit(child)
  }
  visit(node)
  return out
}

export function textOf(node: DomNode): string {
  return node.children.map((child) => (child.tag === '#text' ? child.text : textOf(child))).join('')
}

export function findByTag(node: DomNode, tag: string): DomNode[] {
  return findAll(node, (n) => n.tag === tag.toLowerCase())
}

export function findById(node: DomNode, id: string): DomNode | null {
  return findAll(node, (n) => n.attrs.id === id)[0] ?? null
}

/** True when the tree contains an element carrying an inline event-handler attribute. */
export function inlineHandlers(node: DomNode): DomNode[] {
  return findAll(node, (n) => Object.keys(n.attrs).some((attr) => attr.startsWith('on') || attr === 'srcdoc'))
}
