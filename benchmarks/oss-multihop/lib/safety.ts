// Containment and static safety guards for benchmarks/oss-multihop/.
// Zero npm dependencies (node:* only); Node 24+ native TypeScript erasable syntax.

export const LOOPBACK_HOST = '127.0.0.1'

const PINNED_SHA_RE = /^[0-9a-f]{40}$/
const PINNED_DIGEST_RE = /^sha256:[0-9a-f]{64}$/
const FLOATING_TAG_RE = /^(latest|main|master|nightly|edge|dev|head|canary|snapshot)$/i
const LOOPBACK_BIND_RE = /^127\.0\.0\.1:(\d{1,5}):(\d{1,5})(?:\/(?:tcp|udp))?$/
const SYNTHETIC_CRED_RE = /^oss_lab_[a-z0-9_]{4,64}$/

const FORBIDDEN_SECRET_PATTERNS: readonly RegExp[] = [
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
]

export function localLabAllowed(): boolean {
  return process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1'
}

export function assertLocalLabAllowed(): void {
  if (!localLabAllowed()) {
    throw new Error(
      'oss-multihop refuses to run: set GUARDIAN_ALLOW_LOCAL_LAB=1 to enable local benchmark lab checks.',
    )
  }
}

/**
 * Validates that a Docker port publication spec binds strictly to loopback (`127.0.0.1:<hostPort>:<containerPort>`).
 * Rejects bare `<port>:<port>` (which binds `0.0.0.0`), `0.0.0.0:...`, `[::]:...`, and invalid ports.
 */
export function isLoopbackBindSpec(bind: string): boolean {
  const match = LOOPBACK_BIND_RE.exec(bind.trim())
  if (!match) return false
  const hostPort = Number(match[1])
  const containerPort = Number(match[2])
  if (!Number.isInteger(hostPort) || hostPort < 0 || hostPort > 65535) return false
  if (!Number.isInteger(containerPort) || containerPort < 1 || containerPort > 65535) return false
  return true
}

/** Validates that an OOB collector URL targets strictly loopback (`127.0.0.1` or `[::1]`). */
export function isLoopbackUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
    return parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]' || parsed.hostname === '::1'
  } catch {
    return false
  }
}

export function isPinnedCommitSha(sha: string): boolean {
  return PINNED_SHA_RE.test(sha.trim())
}

export function isPinnedImageDigest(digest: string): boolean {
  return PINNED_DIGEST_RE.test(digest.trim())
}

export function isFloatingTag(tag: string): boolean {
  const trimmed = tag.trim()
  if (trimmed.length === 0) return true
  return FLOATING_TAG_RE.test(trimmed)
}

export function isSyntheticCredentialRef(ref: string): boolean {
  return SYNTHETIC_CRED_RE.test(ref.trim())
}

export function containsForbiddenSecretPattern(value: string): boolean {
  return FORBIDDEN_SECRET_PATTERNS.some((re) => re.test(value))
}
