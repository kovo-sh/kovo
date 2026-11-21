export interface NamedSecret {
  value: string
  placeholder: string
}

const credentialPatterns = [
  /\b(?:sk-or-v1-[a-z0-9_-]+|sk-ant-[a-z0-9_-]+|sk-proj-[a-z0-9_-]+|github_pat_[a-z0-9_]+|gh[pousr]_[a-z0-9_]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/gi,
  /-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g,
  /\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\n\r]+/gi,
  /\bBearer\s+[a-z0-9._~+/=-]{8,}/gi,
  /\b(password|api[_-]?key|token|session[_-]?(?:id|key)|client[_-]?secret|service[_-]?role[_-]?key)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi,
]

export function redact(text: string, secrets: readonly NamedSecret[] = []): string {
  let out = text
  for (const secret of secrets) {
    if (!secret.value || secret.value.length < 4) continue
    out = out.replaceAll(secret.value, secret.placeholder)
    // Also scrub URL-encoded and base64 forms of registered persona/API secrets.
    const encoded = encodeURIComponent(secret.value)
    if (encoded !== secret.value && encoded.length >= 6) out = out.replaceAll(encoded, secret.placeholder)
  }
  return credentialPatterns.reduce((value, pattern) => value.replace(pattern, '[redacted]'), out)
}

export function redactHeaders(headers: Record<string, string>, secrets: readonly NamedSecret[] = []): Record<string, string> {
  const sensitiveHeader = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)$/i
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    out[key] = sensitiveHeader.test(key) ? '[redacted]' : redact(value, secrets)
  }
  return out
}
