// Orbit Workspace (held-out modern SaaS lab) — static configuration.
// Everything here is synthetic. No real credentials, hosts or files are ever used.

export const LAB_NAME = 'held-out-saas'

// Synthetic lab-only HS256 signing secret (never reused anywhere else).
export const JWT_SECRET = 'orbit-lab-synthetic-hs256-signing-material-v1'
export const JWT_ISSUER = 'orbit-workspace.lab'
export const JWT_FAR_FUTURE_EXP = 4102444800 // 2100-01-01

// Egress policy for every server-side fetch (SSRF / XXE / JKU sinks): loopback / lab-internal only.
export const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])

// Next.js-style server action ids (hex, as emitted by the App Router compiler).
export const ACTION_IDS = {
  updateOrgPlan: '40b7c2e91d3a5f6081c4d2e7a9b0f3c5d61e8a7b2c',
  exportOrgSummary: '60e1a4d8f2b9c3075a6d1e4f8b2c9a0d3e7f5b1c48',
}

// Patch switchboard. Each `patches/<id>.patch` flips exactly one line below to `true`
// (and `startHeldOutSaasServer({ patchedIds })` flips the same switch at runtime).
// One entry per line so single-line zero-context diffs apply independently of each other.
export const PATCH_STATE = {
  'hos-01': false,
  'hos-02': false,
  'hos-03': false,
  'hos-04': false,
  'hos-05': false,
  'hos-06': false,
  'hos-07': false,
  'hos-08': false,
  'hos-09': false,
  'hos-10': false,
  'hos-11': false,
  'hos-12': false,
  'hos-13': false,
  'hos-14': false,
  'hos-15': false,
  'hos-16': false,
  'hos-17': false,
  'hos-18': false,
  'hos-19': false,
  'hos-20': false,
}

export const CACHEABLE_EXT_RE = /\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|json)$/i
export const CACHE_TTL_MS = 300_000
