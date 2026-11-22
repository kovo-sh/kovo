// Hardened static-file + SPA-fallback server. THIS IS THE ONLY module that reads the real filesystem
// from a request path, so the jail is strict: resolve to a real path and verify it stays inside uiDir.
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { join, resolve, sep, extname } from 'node:path'

export interface StaticResult {
  status: number
  body: Buffer
  contentType: string
  spaFallback: boolean
}

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
}

function contentTypeFor(file: string): string {
  return CONTENT_TYPES[extname(file).toLowerCase()] ?? 'application/octet-stream'
}

type Resolution =
  | { kind: 'file'; real: string }
  | { kind: 'miss'; cleanPath: string }
  | { kind: 'reject' } // malformed or traversal/escape: refuse, never SPA-fallback

/**
 * Safely resolve a RAW (un-normalized) request path to a real file inside `rootReal`. Traversal
 * attempts (literal `..` or percent-encoded, which the URL layer does not collapse) are rejected
 * outright rather than falling through to the SPA index.
 */
function resolveWithin(rootReal: string, rawPath: string): Resolution {
  let decoded: string
  try {
    decoded = decodeURIComponent(rawPath)
  } catch {
    return { kind: 'reject' }
  }
  if (decoded.includes('\0')) return { kind: 'reject' }
  const rel = decoded.startsWith('/') ? decoded : `/${decoded}`
  // Any `..` segment (post-decode) is a traversal attempt — refuse.
  if (rel.split('/').some((s) => s === '..')) return { kind: 'reject' }
  const candidate = resolve(rootReal, `.${rel}`)
  if (candidate !== rootReal && !candidate.startsWith(rootReal + sep)) return { kind: 'reject' }
  if (!existsSync(candidate)) return { kind: 'miss', cleanPath: rel }
  // Defeat symlink escapes: the REAL path must still be inside the jail.
  let real: string
  try {
    real = realpathSync(candidate)
  } catch {
    return { kind: 'reject' }
  }
  if (real !== rootReal && !real.startsWith(rootReal + sep)) return { kind: 'reject' }
  try {
    if (!statSync(real).isFile()) return { kind: 'miss', cleanPath: rel }
  } catch {
    return { kind: 'reject' }
  }
  return { kind: 'file', real }
}

/** Does this path name an asset (has a file extension in its final segment)? */
function looksLikeAsset(pathname: string): boolean {
  const last = pathname.split('/').pop() ?? ''
  return extname(last).length > 0
}

function notFound(): StaticResult {
  return { status: 404, body: Buffer.from('not found'), contentType: 'text/plain; charset=utf-8', spaFallback: false }
}

/**
 * Serve a GET for `rawPath` (the request path BEFORE URL normalization) from `uiDir`.
 * - A real file inside the jail is served directly.
 * - A traversal/escape attempt yields 404 (never served, never SPA-falls back).
 * - An asset-looking miss yields 404; any other miss SPA-falls back to index.html (spaFallback: true).
 */
export function serveStatic(uiDir: string, rawPath: string): StaticResult {
  let rootReal: string
  try {
    rootReal = realpathSync(uiDir)
  } catch {
    return notFound()
  }
  const r = resolveWithin(rootReal, rawPath)
  if (r.kind === 'reject') return notFound()
  if (r.kind === 'file') return { status: 200, body: readFileSync(r.real), contentType: contentTypeFor(r.real), spaFallback: false }
  if (looksLikeAsset(r.cleanPath)) return notFound()
  const indexPath = join(rootReal, 'index.html')
  if (existsSync(indexPath)) return { status: 200, body: readFileSync(indexPath), contentType: CONTENT_TYPES['.html']!, spaFallback: true }
  return notFound()
}
