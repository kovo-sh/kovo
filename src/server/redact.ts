export interface NamedSecret {
  value: string
  placeholder: string
}

const credentialPatterns = [
  /\b(?:sk-or-v1-[a-z0-9_-]+|sk-ant-[a-z0-9_-]+|sk-proj-[a-z0-9_-]+|github_pat_[a-z0-9_]+|gh[pousr]_[a-z0-9_]+)\b/gi,
  /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g,
  /-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g,
  /\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\n\r]+/gi,
  /\bBearer\s+[a-z0-9._~+/=-]{8,}/gi,
  /(?<![A-Za-z0-9])(password|api[_-]?key|token|secret|session[_-]?(?:id|key)|client[_-]?secret|service[_-]?role[_-]?key)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi,
]

export function redact(text: string, secrets: readonly NamedSecret[] = []): string {
  let out = text
  for (const secret of secrets) {
    if (!secret.value || secret.value.length < 4) continue
    out = out.replaceAll(secret.value, secret.placeholder)
    // Also scrub URL-encoded and base64/base64url forms of registered persona/API secrets.
    const encoded = encodeURIComponent(secret.value)
    if (encoded !== secret.value && encoded.length >= 6) out = out.replaceAll(encoded, secret.placeholder)
    const b64 = Buffer.from(secret.value, 'utf8').toString('base64')
    if (b64 !== secret.value && b64.length >= 4) out = out.replaceAll(b64, secret.placeholder)
    const b64url = Buffer.from(secret.value, 'utf8').toString('base64url')
    if (b64url !== secret.value && b64url !== b64 && b64url.length >= 4) out = out.replaceAll(b64url, secret.placeholder)
  }
  return credentialPatterns.reduce((value, pattern) => value.replace(pattern, '[redacted]'), out)
}

export function redactHeaders(headers: Record<string, string>, secrets: readonly NamedSecret[] = []): Record<string, string> {
  const sensitiveHeader = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)$/i
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    out[key] = sensitiveHeader.test(key) ? '[redacted]' : redact(value, secrets)
  }
  return out
}

function scrubSensitiveSubtree(value: unknown): unknown {
  if (typeof value === 'string') return '[redacted]'
  if (Array.isArray(value)) return value.map(item => scrubSensitiveSubtree(item))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubSensitiveSubtree(v)
    }
    return out
  }
  return value
}

export function redactJsonValue<T>(value: T, secrets: readonly NamedSecret[] = []): T {
  if (typeof value === 'string') return redact(value, secrets) as unknown as T
  if (Array.isArray(value)) return value.map(item => redactJsonValue(item, secrets)) as unknown as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const sensitiveKey = /^(?:password|api[_-]?key|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|token|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|secret|client[_-]?secret|service[_-]?role[_-]?key|private[_-]?key|session[_-]?(?:id|key)|credentials?|authorization|cookie|set-cookie)$/i.test(k)
      out[k] = sensitiveKey ? scrubSensitiveSubtree(v) : redactJsonValue(v, secrets)
    }
    return out as T
  }
  return value
}
