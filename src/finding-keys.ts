/**
 * Browser-safe finding classification and deduplication keys shared between the server
 * fingerprinting/dedupe layer (`src/server/finding-fingerprint.ts`, `src/server/dedupe.ts`)
 * and the report/UI layer (`src/report-summary.ts`).
 *
 * Keep this module free of `node:*` and `src/server/*` imports so it bundles cleanly into
 * the browser build.
 */

/**
 * Origin-wide vulnerability classes where distinct probe paths on the same origin
 * typically share a single middleware/edge/server root cause.
 */
export const ORIGIN_WIDE_CWE_KEYS: ReadonlySet<string> = new Set([
  'CWE-942', // Permissive Cross-domain Policy (CORS)
  'CWE-346', // Origin Validation Error
  'CWE-693', // Protection Mechanism Failure (CSP / security headers)
  'CWE-1021', // Clickjacking / Frame Protection
  'CWE-319', // Cleartext Transmission / HSTS
  'CWE-295', // Improper Certificate Validation / TLS
  'CWE-327', // Broken/Risky Crypto / TLS cipher
  'CWE-614', // Sensitive Cookie without Secure
  'CWE-1004', // Sensitive Cookie without HttpOnly
  'CWE-1275', // Sensitive Cookie SameSite
])

/** Normalize a CWE identifier (or fall back to lowercase category / `'unknown'`). */
export function normalizeCwe(cwe?: string | null, category?: string | null): string {
  const cleanCwe = cwe?.trim().toUpperCase()
  if (cleanCwe && /^CWE-\d{1,5}$/.test(cleanCwe)) return cleanCwe
  const digits = cleanCwe?.match(/(\d{1,5})/)
  if (cleanCwe && digits && cleanCwe.includes('CWE')) return `CWE-${digits[1]}`
  const cleanCat = category?.trim().toLowerCase()
  return cleanCat || 'unknown'
}

/** True for vulnerability classes whose root cause is shared by every route on an origin. */
export function isOriginWideCwe(cwe?: string | null, category?: string | null): boolean {
  return ORIGIN_WIDE_CWE_KEYS.has(normalizeCwe(cwe, category))
}
