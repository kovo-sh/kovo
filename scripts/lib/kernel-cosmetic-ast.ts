/**
 * AST-Verified Confirmation-Kernel Cosmetic Exemption (`Kernel-cosmetic: <reason>`).
 *
 * Parses `base` and `head` versions of every touched confirmation-kernel `.ts` file with
 * TypeScript's `ts.createSourceFile` and compares their normalized executable ASTs in lockstep.
 *
 * Strictly FAILS CLOSED if ANY executable AST node, operator, modifier, flag, condition, regex,
 * numeric literal, control flow, type/union/enum literal, or non-copy string literal changes.
 *
 * Permits ONLY:
 *   1. Comment, JSDoc, whitespace, quote-style, semicolon, or formatting-only edits (stripped by AST).
 *   2. Pure human-facing copy or brand-copy (`Kovo Hunter` <-> `Kovo`) string literal edits that are
 *      NOT inside any logic-sensitive context (regex, comparison, route/path/URL/header/key lookup,
 *      `Set`/`Map`/`Record` key, `switch`/`case`, type/enum literal, `oracleFamily`, or object property name).
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'

export const KERNEL_COSMETIC_TRAILER_RE = /^\s*Kernel-cosmetic:\s*(.*)$/im

export interface KernelCosmeticTrailerResult {
  present: boolean
  reason: string | null
  malformed: string | null
}

export interface CosmeticFileCheckResult {
  ok: boolean
  reason: string | null
}

export interface CosmeticKernelDiffResult {
  ok: boolean
  checkedFiles: string[]
  failedFiles: Array<{ file: string; reason: string }>
}

export interface VerifyCosmeticKernelDiffOptions {
  rootDir: string
  baseRef?: string | null
  headRef?: string | null
  kernelFiles: readonly string[]
  filePairs?: ReadonlyMap<string, { base: string | null; head: string | null }>
}

const TS_FILE_RE = /\.(?:ts|tsx|mts|cts)$/i

const COMPARISON_OPERATORS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.LessThanToken,
  ts.SyntaxKind.LessThanEqualsToken,
  ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.GreaterThanEqualsToken,
  ts.SyntaxKind.InKeyword,
  ts.SyntaxKind.InstanceOfKeyword,
])

const FORBIDDEN_CONSTRUCTORS = new Set<string>([
  'RegExp',
  'Set',
  'Map',
  'URL',
  'URLSearchParams',
  'Headers',
  'Request',
  'Response',
])

const FORBIDDEN_DIRECT_CALLS = new Set<string>(['RegExp', 'require', 'fetch'])

const FORBIDDEN_METHODS = new Set<string>([
  'includes',
  'startsWith',
  'endsWith',
  'indexOf',
  'lastIndexOf',
  'match',
  'matchAll',
  'search',
  'replace',
  'replaceAll',
  'split',
  'test',
  'exec',
  'has',
  'get',
  'set',
  'delete',
  'add',
  'getHeader',
  'setHeader',
  'append',
  'fetch',
  'request',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
  'join',
  'resolve',
  'readFileSync',
  'writeFileSync',
  'createHash',
  'createHmac',
  'sign',
  'verify',
])

const FORBIDDEN_PROP_NAMES = new Set<string>([
  'oracleFamily',
  'status',
  'statusCode',
  'method',
  'path',
  'route',
  'url',
  'origin',
  'host',
  'hostname',
  'header',
  'headers',
  'key',
  'id',
  'code',
  'type',
  'kind',
  'side',
  'vulnClass',
  'probeClass',
  'arm',
  'role',
  'capability',
  'stage',
  'verdict',
  'outcome',
  'action',
  'command',
  'event',
  'selector',
  'pattern',
  'regex',
  'flag',
  'flags',
  'env',
  'tag',
  'format',
  'protocol',
  'encoding',
  'contentType',
  'mimeType',
  'endpoint',
  'cookie',
  'token',
  'secret',
  'auth',
  'scope',
])

const ALLOWED_COPY_PROP_NAMES = new Set<string>([
  'reason',
  'reasons',
  'message',
  'messages',
  'summary',
  'description',
  'detail',
  'details',
  'hint',
  'hints',
  'warning',
  'warnings',
  'error',
  'errors',
  'note',
  'notes',
  'label',
  'title',
  'explanation',
  'remediation',
  'usage',
  'help',
  'banner',
  'diagnostic',
  'diagnostics',
  'claimedImpact',
  'claimedDelta',
])

const ALLOWED_COPY_VAR_RE =
  /(?:usage|help|msg|message|reason|description|summary|label|title|warning|err(?:or)?msg|banner|hint|note|detail|copy|prompt|notice|text)$/i

const ALLOWED_PUSH_TARGET_RE =
  /(?:reason|message|warning|error|violation|diagnostic|note|hint|line|detail)s?$/i

const LOG_METHOD_NAMES = new Set<string>(['log', 'warn', 'error', 'info', 'debug', 'write'])

const TECHNICAL_PATH_OR_URL_RE = /^(?:\/|https?:\/\/|wss?:\/\/|tcp:\/\/|unix:\/\/|file:\/\/)/i

export function parseKernelCosmeticTrailer(commitMessages: string): KernelCosmeticTrailerResult {
  const m = KERNEL_COSMETIC_TRAILER_RE.exec(commitMessages)
  if (!m) return { present: false, reason: null, malformed: null }
  const raw = (m[1] ?? '').trim()
  if (raw.length < 6) {
    return { present: true, reason: null, malformed: raw || '(empty)' }
  }
  return { present: true, reason: raw, malformed: null }
}

function normalizeBrandCopy(text: string): string {
  return text
    .replace(/https?:\/\/github\.com\/(?:wwwillchen|kovo-sh)\/(?:guardian|kovo-hunter|kovo)/gi, 'https://github.com/kovo-sh/kovo')
    .replace(/\b(?:wwwillchen|kovo-sh)\/(?:guardian|kovo-hunter|kovo)\b/gi, 'kovo-sh/kovo')
    .replace(/\bghcr\.io\/wwwillchen\//gi, 'ghcr.io/kovo-sh/')
    .replace(/\bKovo Hunter\b/g, 'Kovo')
    .replace(/\bKovoHunter\b/g, 'Kovo')
    .replace(/\bkovo-hunter\b/g, 'kovo')
    .replace(/\bKOVO_HUNTER\b/g, 'KOVO')
}

function isExactBrandCopyReplacement(oldText: string, newText: string): boolean {
  if (oldText === newText) return true
  return normalizeBrandCopy(oldText) === normalizeBrandCopy(newText)
}

function getPropertyNameText(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text
  }
  return null
}

function getCalleeIdentifierName(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text
  return null
}

function findForbiddenStringContext(node: ts.Node): string | null {
  let child: ts.Node = node
  let cur: ts.Node | undefined = node.parent
  while (cur) {
    if (ts.isTaggedTemplateExpression(cur)) return 'tagged template literal'
    if (ts.isPropertyAssignment(cur) && cur.name === child) return 'object property name'
    if (
      (ts.isMethodDeclaration(cur) ||
        ts.isPropertyDeclaration(cur) ||
        ts.isPropertySignature(cur) ||
        ts.isMethodSignature(cur) ||
        ts.isGetAccessorDeclaration(cur) ||
        ts.isSetAccessorDeclaration(cur) ||
        ts.isEnumMember(cur)) &&
      cur.name === child
    ) {
      return 'member/property name'
    }
    if (ts.isComputedPropertyName(cur)) return 'computed property name'
    if (ts.isElementAccessExpression(cur) && cur.argumentExpression === child) return 'indexed property/key access'
    if ((ts.isImportDeclaration(cur) || ts.isExportDeclaration(cur)) && cur.moduleSpecifier === child) {
      return 'import/export module specifier'
    }
    if (ts.isExternalModuleReference(cur)) return 'external module reference'
    if (ts.isTypeNode(cur) || ts.isEnumMember(cur)) return 'type or enum literal'
    if (ts.isCaseClause(cur) && cur.expression === child) return 'switch case label'
    if (ts.isSwitchStatement(cur) && cur.expression === child) return 'switch expression'
    if (ts.isBinaryExpression(cur) && COMPARISON_OPERATORS.has(cur.operatorToken.kind)) {
      return `comparison (${ts.SyntaxKind[cur.operatorToken.kind]})`
    }
    if (ts.isNewExpression(cur)) {
      const ctor = getCalleeIdentifierName(cur.expression)
      if (ctor && FORBIDDEN_CONSTRUCTORS.has(ctor)) return `new ${ctor}(...)`
    }
    if (ts.isCallExpression(cur)) {
      if (cur.expression.kind === ts.SyntaxKind.ImportKeyword) return 'dynamic import(...)'
      if (ts.isIdentifier(cur.expression) && FORBIDDEN_DIRECT_CALLS.has(cur.expression.text)) {
        return `${cur.expression.text}(...)`
      }
      if (ts.isPropertyAccessExpression(cur.expression) && FORBIDDEN_METHODS.has(cur.expression.name.text)) {
        return `.${cur.expression.name.text}(...)`
      }
    }
    if (ts.isPropertyAssignment(cur) && cur.initializer === child) {
      const propName = getPropertyNameText(cur.name)
      if (propName && FORBIDDEN_PROP_NAMES.has(propName)) {
        return `logic property "${propName}"`
      }
    }
    if (ts.isBlock(cur) || ts.isSourceFile(cur) || ts.isFunctionLike(cur)) {
      break
    }
    child = cur
    cur = cur.parent
  }
  return null
}

function isHumanCopyContext(node: ts.Node): boolean {
  let child: ts.Node = node
  let cur: ts.Node | undefined = node.parent
  while (cur) {
    if (ts.isThrowStatement(cur)) return true
    if (ts.isNewExpression(cur)) {
      const ctor = getCalleeIdentifierName(cur.expression)
      if (ctor && /Error$/.test(ctor)) return true
    }
    if (ts.isCallExpression(cur)) {
      if (ts.isIdentifier(cur.expression) && /Error$/.test(cur.expression.text)) return true
      if (ts.isPropertyAccessExpression(cur.expression)) {
        const method = cur.expression.name.text
        if (LOG_METHOD_NAMES.has(method)) {
          const recv = cur.expression.expression.getText()
          if (/(?:^|\.)(?:console|logger|log|stdout|stderr)$/i.test(recv)) return true
        }
        if (method === 'push') {
          const recvName = getCalleeIdentifierName(cur.expression.expression)
          if (recvName && ALLOWED_PUSH_TARGET_RE.test(recvName)) return true
        }
      }
    }
    if (ts.isPropertyAssignment(cur) && cur.initializer === child) {
      const propName = getPropertyNameText(cur.name)
      if (propName && ALLOWED_COPY_PROP_NAMES.has(propName)) return true
    }
    if (ts.isVariableDeclaration(cur) && cur.initializer === child && ts.isIdentifier(cur.name)) {
      if (ALLOWED_COPY_VAR_RE.test(cur.name.text)) return true
    }
    if (ts.isBlock(cur) || ts.isSourceFile(cur) || ts.isFunctionLike(cur)) {
      break
    }
    child = cur
    cur = cur.parent
  }
  return false
}

function checkAllowedStringChange(
  baseNode: ts.Node,
  headNode: ts.Node,
  oldText: string,
  newText: string,
  headSf: ts.SourceFile,
): string | null {
  if (oldText === newText) return null

  const line = headSf.getLineAndCharacterOfPosition(headNode.getStart(headSf)).line + 1
  const baseForbidden = findForbiddenStringContext(baseNode)
  if (baseForbidden) {
    return `line ${line}: non-cosmetic string change inside ${baseForbidden}`
  }
  const headForbidden = findForbiddenStringContext(headNode)
  if (headForbidden) {
    return `line ${line}: non-cosmetic string change inside ${headForbidden}`
  }

  if (isExactBrandCopyReplacement(oldText, newText)) {
    if (oldText.startsWith('/') || newText.startsWith('/')) {
      return `line ${line}: string change touches route/path literal`
    }
    return null
  }

  if (TECHNICAL_PATH_OR_URL_RE.test(oldText) || TECHNICAL_PATH_OR_URL_RE.test(newText)) {
    return `line ${line}: non-brand string change touches route/path/URL literal`
  }

  if (isHumanCopyContext(baseNode) && isHumanCopyContext(headNode)) {
    return null
  }

  return `line ${line}: non-copy string literal changed outside allowed error/log/brand-copy context`
}

function isSimpleStringLike(node: ts.Node): node is ts.StringLiteral | ts.NoSubstitutionTemplateLiteral {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
}

function isTemplateLiteralChunk(
  node: ts.Node,
): node is ts.TemplateHead | ts.TemplateMiddle | ts.TemplateTail {
  return ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)
}

function getAstChildren(node: ts.Node): ts.Node[] {
  const children: ts.Node[] = []
  ts.forEachChild(node, child => {
    children.push(child)
  })
  return children
}

function formatLine(sf: ts.SourceFile, node: ts.Node): string {
  const pos = node.getStart(sf)
  return `line ${sf.getLineAndCharacterOfPosition(pos).line + 1}`
}

function compareAstNodes(
  baseNode: ts.Node,
  headNode: ts.Node,
  baseSf: ts.SourceFile,
  headSf: ts.SourceFile,
): string | null {
  if (isSimpleStringLike(baseNode) && isSimpleStringLike(headNode)) {
    return checkAllowedStringChange(baseNode, headNode, baseNode.text, headNode.text, headSf)
  }

  if (baseNode.kind !== headNode.kind) {
    return `${formatLine(headSf, headNode)}: AST node kind changed (${ts.SyntaxKind[baseNode.kind]} -> ${ts.SyntaxKind[headNode.kind]})`
  }

  if (isTemplateLiteralChunk(baseNode) && isTemplateLiteralChunk(headNode)) {
    return checkAllowedStringChange(baseNode, headNode, baseNode.text, headNode.text, headSf)
  }

  if (ts.isIdentifier(baseNode) && ts.isIdentifier(headNode)) {
    if (baseNode.text !== headNode.text) {
      return `${formatLine(headSf, headNode)}: identifier changed (${baseNode.text} -> ${headNode.text})`
    }
    return null
  }

  if (ts.isPrivateIdentifier(baseNode) && ts.isPrivateIdentifier(headNode)) {
    if (baseNode.text !== headNode.text) {
      return `${formatLine(headSf, headNode)}: private identifier changed (${baseNode.text} -> ${headNode.text})`
    }
    return null
  }

  if (ts.isNumericLiteral(baseNode) && ts.isNumericLiteral(headNode)) {
    if (baseNode.text !== headNode.text) {
      return `${formatLine(headSf, headNode)}: numeric literal changed (${baseNode.text} -> ${headNode.text})`
    }
    return null
  }

  if (ts.isBigIntLiteral(baseNode) && ts.isBigIntLiteral(headNode)) {
    if (baseNode.text !== headNode.text) {
      return `${formatLine(headSf, headNode)}: bigint literal changed (${baseNode.text} -> ${headNode.text})`
    }
    return null
  }

  if (ts.isRegularExpressionLiteral(baseNode) && ts.isRegularExpressionLiteral(headNode)) {
    if (baseNode.text !== headNode.text) {
      return `${formatLine(headSf, headNode)}: regex literal changed`
    }
    return null
  }

  if (ts.isJsxText(baseNode) && ts.isJsxText(headNode)) {
    if (baseNode.text !== headNode.text) {
      return `${formatLine(headSf, headNode)}: JSX text changed`
    }
    return null
  }

  if (ts.isPrefixUnaryExpression(baseNode) && ts.isPrefixUnaryExpression(headNode)) {
    if (baseNode.operator !== headNode.operator) {
      return `${formatLine(headSf, headNode)}: prefix unary operator changed (${ts.SyntaxKind[baseNode.operator]} -> ${ts.SyntaxKind[headNode.operator]})`
    }
  }

  if (ts.isPostfixUnaryExpression(baseNode) && ts.isPostfixUnaryExpression(headNode)) {
    if (baseNode.operator !== headNode.operator) {
      return `${formatLine(headSf, headNode)}: postfix unary operator changed (${ts.SyntaxKind[baseNode.operator]} -> ${ts.SyntaxKind[headNode.operator]})`
    }
  }

  if (ts.isBinaryExpression(baseNode) && ts.isBinaryExpression(headNode)) {
    if (baseNode.operatorToken.kind !== headNode.operatorToken.kind) {
      return `${formatLine(headSf, headNode)}: binary operator changed (${ts.SyntaxKind[baseNode.operatorToken.kind]} -> ${ts.SyntaxKind[headNode.operatorToken.kind]})`
    }
  }

  if (ts.isVariableDeclarationList(baseNode) && ts.isVariableDeclarationList(headNode)) {
    const mask = ts.NodeFlags.Const | ts.NodeFlags.Let | ts.NodeFlags.Using | ts.NodeFlags.AwaitUsing
    if ((baseNode.flags & mask) !== (headNode.flags & mask)) {
      return `${formatLine(headSf, headNode)}: variable declaration kind (const/let/var) changed`
    }
  }

  if (ts.isImportClause(baseNode) && ts.isImportClause(headNode)) {
    if (baseNode.isTypeOnly !== headNode.isTypeOnly) {
      return `${formatLine(headSf, headNode)}: import type-only modifier changed`
    }
  }

  if (ts.isImportSpecifier(baseNode) && ts.isImportSpecifier(headNode)) {
    if (baseNode.isTypeOnly !== headNode.isTypeOnly) {
      return `${formatLine(headSf, headNode)}: import specifier type-only modifier changed`
    }
  }

  if (ts.isExportDeclaration(baseNode) && ts.isExportDeclaration(headNode)) {
    if (baseNode.isTypeOnly !== headNode.isTypeOnly) {
      return `${formatLine(headSf, headNode)}: export type-only modifier changed`
    }
  }

  if (ts.isExportSpecifier(baseNode) && ts.isExportSpecifier(headNode)) {
    if (baseNode.isTypeOnly !== headNode.isTypeOnly) {
      return `${formatLine(headSf, headNode)}: export specifier type-only modifier changed`
    }
  }

  if (ts.isExportAssignment(baseNode) && ts.isExportAssignment(headNode)) {
    if (Boolean(baseNode.isExportEquals) !== Boolean(headNode.isExportEquals)) {
      return `${formatLine(headSf, headNode)}: export assignment kind changed`
    }
  }

  if (
    (ts.isCallExpression(baseNode) && ts.isCallExpression(headNode)) ||
    (ts.isPropertyAccessExpression(baseNode) && ts.isPropertyAccessExpression(headNode)) ||
    (ts.isElementAccessExpression(baseNode) && ts.isElementAccessExpression(headNode))
  ) {
    if (baseNode.questionDotToken?.kind !== headNode.questionDotToken?.kind) {
      return `${formatLine(headSf, headNode)}: optional chaining (?.) changed`
    }
  }

  if (ts.isYieldExpression(baseNode) && ts.isYieldExpression(headNode)) {
    if (baseNode.asteriskToken?.kind !== headNode.asteriskToken?.kind) {
      return `${formatLine(headSf, headNode)}: yield* modifier changed`
    }
  }

  if (ts.isForOfStatement(baseNode) && ts.isForOfStatement(headNode)) {
    if (baseNode.awaitModifier?.kind !== headNode.awaitModifier?.kind) {
      return `${formatLine(headSf, headNode)}: for-await modifier changed`
    }
  }

  const baseChildren = getAstChildren(baseNode)
  const headChildren = getAstChildren(headNode)
  if (baseChildren.length !== headChildren.length) {
    return `${formatLine(headSf, headNode)}: AST child count changed in ${ts.SyntaxKind[headNode.kind]} (${baseChildren.length} -> ${headChildren.length})`
  }

  for (let i = 0; i < baseChildren.length; i += 1) {
    const mismatch = compareAstNodes(baseChildren[i]!, headChildren[i]!, baseSf, headSf)
    if (mismatch) return mismatch
  }

  return null
}

function getParseDiagnostics(sf: ts.SourceFile): readonly ts.Diagnostic[] {
  return (sf as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? []
}

function scriptKindForPath(filePath: string): ts.ScriptKind {
  return filePath.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
}

/**
 * Compare `baseSource` and `headSource` for a single TypeScript file and verify that
 * every change is strictly cosmetic (comments/whitespace/formatting or allowed copy strings).
 */
export function verifyCosmeticTsChange(
  filePath: string,
  baseSource: string,
  headSource: string,
): CosmeticFileCheckResult {
  if (!TS_FILE_RE.test(filePath)) {
    return { ok: false, reason: 'only TypeScript (.ts/.tsx/.mts/.cts) kernel files can be AST-verified as cosmetic' }
  }
  const kind = scriptKindForPath(filePath)
  const baseSf = ts.createSourceFile(filePath, baseSource, ts.ScriptTarget.Latest, true, kind)
  const headSf = ts.createSourceFile(filePath, headSource, ts.ScriptTarget.Latest, true, kind)

  const baseDiags = getParseDiagnostics(baseSf)
  if (baseDiags.length > 0) {
    return { ok: false, reason: `base file failed TypeScript parse (${baseDiags.length} diagnostic(s))` }
  }
  const headDiags = getParseDiagnostics(headSf)
  if (headDiags.length > 0) {
    return { ok: false, reason: `head file failed TypeScript parse (${headDiags.length} diagnostic(s))` }
  }

  const mismatch = compareAstNodes(baseSf, headSf, baseSf, headSf)
  if (mismatch) {
    return { ok: false, reason: mismatch }
  }
  return { ok: true, reason: null }
}

function readGitBlob(rootDir: string, spec: string): string | null {
  try {
    return execFileSync('git', ['show', spec], {
      cwd: rootDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    })
  } catch {
    return null
  }
}

function resolveFilePair(
  file: string,
  opts: VerifyCosmeticKernelDiffOptions,
): { base: string | null; head: string | null } | null {
  const fromMap = opts.filePairs?.get(file)
  if (fromMap) return fromMap

  if (!opts.baseRef) return null
  const base = readGitBlob(opts.rootDir, `${opts.baseRef}:${file}`)
  const headRef = opts.headRef ?? 'HEAD'
  let head: string | null
  if (headRef === 'WORKTREE') {
    const abs = join(opts.rootDir, file)
    head = existsSync(abs) ? readFileSync(abs, 'utf8') : null
  } else if (headRef === 'STAGED') {
    head = readGitBlob(opts.rootDir, `:${file}`)
  } else {
    head = readGitBlob(opts.rootDir, `${headRef}:${file}`)
  }
  return { base, head }
}

/**
 * Verify that EVERY touched confirmation-kernel file passes strict TypeScript AST cosmetic
 * verification. Fails closed if any file cannot be read, was added/deleted, is non-TS, or
 * has any executable AST difference.
 */
export function verifyCosmeticKernelDiff(opts: VerifyCosmeticKernelDiffOptions): CosmeticKernelDiffResult {
  const checkedFiles: string[] = []
  const failedFiles: Array<{ file: string; reason: string }> = []

  if (opts.kernelFiles.length === 0) {
    return { ok: true, checkedFiles, failedFiles }
  }

  for (const file of opts.kernelFiles) {
    checkedFiles.push(file)
    const pair = resolveFilePair(file, opts)
    if (!pair) {
      failedFiles.push({
        file,
        reason: 'unable to resolve base/head file contents for AST verification (fail-closed)',
      })
      continue
    }
    if (pair.base === null) {
      failedFiles.push({
        file,
        reason: 'newly added or unreadable base kernel file cannot qualify as cosmetic',
      })
      continue
    }
    if (pair.head === null) {
      failedFiles.push({
        file,
        reason: 'deleted or unreadable head kernel file cannot qualify as cosmetic',
      })
      continue
    }
    const check = verifyCosmeticTsChange(file, pair.base, pair.head)
    if (!check.ok) {
      failedFiles.push({ file, reason: check.reason ?? 'AST mismatch' })
    }
  }

  return {
    ok: failedFiles.length === 0,
    checkedFiles,
    failedFiles,
  }
}
