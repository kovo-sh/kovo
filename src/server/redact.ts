const credentialPatterns = [
  /\b(?:sk-or-v1-[a-z0-9_-]+|github_pat_[a-z0-9_]+|gh[pousr]_[a-z0-9_]+)\b/gi,
  /-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g,
  /\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\n\r]+/gi,
  /\bBearer\s+[a-z0-9._~+/=-]+/gi,
  /\b(password|api[_-]?key|token|session[_-]?(?:id|key))["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi,
]

export function redact(text: string) {
  return credentialPatterns.reduce((value, pattern) => value.replace(pattern, '[redacted]'), text)
}
