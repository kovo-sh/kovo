/**
 * Single authoritative security & safety predicate module (`R3-10`).
 *
 * Consolidates previously duplicated safety primitives across `src/server/`:
 *  - `isSensitiveRepoEntry` & `isSensitiveRepoRelativePath` (`H-39` repo secret exclusion)
 *  - `constantTimeStringEqual` (timing-safe secret/token comparison)
 *
 * Preserves the strictest semantics across all consolidated callers.
 */
import { timingSafeEqual } from 'node:crypto'

const SENSITIVE_DOT_DIRS = new Set(['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.git'])

const SENSITIVE_EXACT_FILES = new Set([
  '.git-credentials',
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.htpasswd',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'github-app.json',
  'credentials.json',
  'service-account.json',
  'vault.json',
  'vault.key',
  'token.txt',
  'secrets.json',
])

const SENSITIVE_FILE_EXT_RE = /\.(?:pat|salt|pem|key|p12|pfx|jks|keystore|kdbx|token)$/i
const SAFE_ENV_TEMPLATE_RE = /^\.env\.(?:example|sample|template|dist|schema)$/i
const SOURCE_CODE_EXT_RE =
  /\.(?:ts|tsx|mts|cts|js|jsx|mjs|cjs|py|go|rs|java|kt|rb|php|cs|c|h|cc|cpp|hpp|swift|scala|sql|graphql|gql|md|html|css|scss|vue|svelte)$/i
const GIT_CREDENTIAL_FILE_RE = /(?:^|\/)\.git\/(?:config|credentials|fetch_head)$/i

/**
 * Shared sensitive-entry filter (`H-39`) enforcing repository secret exclusion across host
 * variant-sweep walks and worker `/repos` staging so `.env`, `.env.*.js`, `.ssh/*`, `.git/*`,
 * private keys, and credential stores are never read or staged.
 */
export function isSensitiveRepoEntry(relPosixPath: string, entryName: string, isDir: boolean): boolean {
  const relLower = relPosixPath.replace(/\\/g, '/').toLowerCase()
  const nameLower = entryName.toLowerCase()
  const parentSegments = relLower.split('/').slice(0, -1)
  if (isDir) {
    if (SENSITIVE_DOT_DIRS.has(nameLower)) return true
    if (relLower === '.git/hooks' || relLower.endsWith('/.git/hooks')) return true
    if (parentSegments.some(seg => SENSITIVE_DOT_DIRS.has(seg))) return true
    return false
  }
  if (GIT_CREDENTIAL_FILE_RE.test(relLower)) return true
  if (SENSITIVE_EXACT_FILES.has(nameLower)) return true
  if (SENSITIVE_FILE_EXT_RE.test(nameLower)) return true
  if (nameLower === '.env' || (nameLower.startsWith('.env.') && !SAFE_ENV_TEMPLATE_RE.test(nameLower))) {
    return true
  }
  if (parentSegments.some(seg => SENSITIVE_DOT_DIRS.has(seg))) return true
  if (parentSegments.includes('credentials') && !SOURCE_CODE_EXT_RE.test(nameLower)) {
    return true
  }
  return false
}

/**
 * Fail-closed relative path check (`H-39`): returns true when the path is empty, contains null
 * bytes or `..` traversal segments, or has any sensitive directory segment or sensitive leaf file.
 */
export function isSensitiveRepoRelativePath(relPosixPath: string): boolean {
  if (typeof relPosixPath !== 'string' || relPosixPath.includes('\0')) return true
  const cleaned = relPosixPath.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '')
  if (!cleaned) return true
  const parts = cleaned.split('/').filter(Boolean)
  if (parts.length === 0) return true
  if (parts.includes('..')) return true
  for (let i = 0; i < parts.length - 1; i += 1) {
    const prefix = parts.slice(0, i + 1).join('/')
    if (isSensitiveRepoEntry(prefix, parts[i]!, true)) return true
  }
  const leaf = parts[parts.length - 1]!
  return isSensitiveRepoEntry(parts.join('/'), leaf, false)
}

/**
 * Constant-time UTF-8 string comparison backed by `node:crypto.timingSafeEqual`.
 * Fails closed on non-string inputs and performs a dummy comparison on length mismatch.
 */
export function constantTimeStringEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length !== bufB.length) {
    timingSafeEqual(bufA, bufA)
    return false
  }
  return timingSafeEqual(bufA, bufB)
}
