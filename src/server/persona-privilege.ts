/**
 * Single authoritative structured persona privilege & tenant metadata classifier
 * (`src/server/persona-privilege.ts`).
 *
 * Prefers explicit structured persona config fields (`privilege`, `tenant`, `tenantRef`,
 * `tenants`, `memberships`, `role` / `roleLabel`) with a minimal safe fallback on `handle`
 * ONLY when structured fields are absent — retiring ad-hoc `_a`/`_b` suffix and `dual`
 * handle-regex classifiers.
 */

export type PersonaPrivilegeLevel = 'low' | 'elevated' | 'revoked'
export type PersonaPrivilegeTier = 'low' | 'standard' | 'multi_tenant' | 'revoked_stale' | 'elevated'

export interface PersonaMembershipInput {
  tenant: string
  role?: string | null
  privilege?: string | null
}

export interface PersonaMetadataInput {
  handle: string
  role?: string | null
  roleLabel?: string | null
  privilege?: string | null
  tenant?: string | null
  tenantRef?: string | null
  tenants?: readonly string[] | null
  memberships?: readonly (string | PersonaMembershipInput)[] | Readonly<Record<string, string>> | null
}

export interface PersonaPrivilegeClassification {
  /** Authoritative 3-level privilege classification. */
  privilege: PersonaPrivilegeLevel
  /** Normalized unique tenant identifiers from structured metadata (never `_a`/`_b` handle suffixes). */
  tenants: string[]
  /** Ordering tier for low-priv-first scheduling. */
  tier: PersonaPrivilegeTier
  elevated: boolean
  multiTenant: boolean
  revokedStale: boolean
  rank: number
}

const REVOKED_TOKEN_RE = /(?:^|[^a-z0-9])(?:revoked|demoted|disabled|suspended|former|expired)(?:[^a-z0-9]|$)/i
const HIGH_ADMIN_TOKEN_RE = /(?:^|[^a-z0-9])(?:owner|admin|superadmin|superuser|root)(?:[^a-z0-9]|$)/i
const ELEVATED_ROLE_TOKEN_RE = /(?:^|[^a-z0-9])(?:owner|admin|superadmin|superuser|root|elevated|bot|service|svc|system|internal|moderator|mod|staff|operator)(?:[^a-z0-9]|$)/i
const LOW_PRIV_ROLE_TOKEN_RE = /(?:^|[^a-z0-9])(?:low|viewer|guest|readonly|read_only|limited|basic|member|user|standard|customer|employee|external|unprivileged|analyst|contributor|reader|free)(?:[^a-z0-9]|$)/i
const MULTI_TENANT_ROLE_RE = /(?:^|[^a-z0-9])(?:multi[_-]?tenant|cross[_-]?tenant|shared[_-]?tenant)(?:[^a-z0-9]|$)/i
const MEMBERSHIP_PAIR_RE = /(?:\[[^\]]+\]|[^,;\s]+[:@][^,;\s]+)/
const GENERIC_TENANT_TOKENS = new Set([
  'member', 'user', 'admin', 'owner', 'viewer', 'editor', 'guest', 'staff', 'operator', 'manager',
  'support', 'service', 'bot', 'moderator', 'revoked', 'stale', 'expired', 'disabled', 'inactive',
  'active', 'default', 'standard', 'primary', 'secondary', 'low', 'high', 'read', 'write', 'public',
  'anon', 'anonymous', 'dual', 'multi', 'tenant', 'org', 'workspace', 'account', 'team', 'company', 'role',
])

function normalizeTenantToken(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined
  const norm = raw.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (norm.length < 2 || GENERIC_TENANT_TOKENS.has(norm)) return undefined
  return norm
}

function addTenant(target: Set<string>, raw: unknown): void {
  const norm = normalizeTenantToken(raw)
  if (norm) target.add(norm)
}

interface ParsedMembership {
  tenant?: string
  roleText: string
}

function parseRoleLabelMemberships(roleLabel: string): ParsedMembership[] {
  const raw = roleLabel.trim()
  if (!raw) return []
  const stripped = raw.replace(/^.*?\bmemberships?\s*[:=]\s*/i, '')
  const hadPrefix = stripped !== raw
  const parts = stripped.split(/[,;]+/).map(s => s.trim()).filter(Boolean)
  if (parts.length < 2) return []
  const pairCount = parts.filter(part => MEMBERSHIP_PAIR_RE.test(part)).length
  if (!hadPrefix && pairCount < 2) return []
  return parts.map(part => {
    const bracket = /\[([^\]]+)\]/.exec(part)
    if (bracket) {
      return { tenant: normalizeTenantToken(bracket[1]), roleText: part.replace(bracket[0], ' ').trim() }
    }
    const colon = /^([^:@\s]+)\s*[:@]\s*([^:@\s]+)$/.exec(part)
    if (colon) {
      const left = colon[1]!, right = colon[2]!
      const leftIsRole = ELEVATED_ROLE_TOKEN_RE.test(left) || LOW_PRIV_ROLE_TOKEN_RE.test(left)
      const rightIsRole = ELEVATED_ROLE_TOKEN_RE.test(right) || LOW_PRIV_ROLE_TOKEN_RE.test(right)
      if (rightIsRole && !leftIsRole) return { tenant: normalizeTenantToken(left), roleText: right }
      return { tenant: normalizeTenantToken(right), roleText: left }
    }
    return { roleText: part }
  })
}

function collectStructuredMemberships(input: PersonaMetadataInput, tenants: Set<string>): ParsedMembership[] {
  const out: ParsedMembership[] = []
  const raw = input.memberships
  if (Array.isArray(raw)) {
    for (const item of raw) {
      if (typeof item === 'string') {
        const parsed = parseRoleLabelMemberships(`memberships=${item}`)
        if (parsed.length) out.push(...parsed)
        else {
          const colon = /^([^:@\s]+)\s*[:@]\s*([^:@\s]+)$/.exec(item.trim())
          if (colon) {
            const left = colon[1]!, right = colon[2]!
            const rightIsRole = ELEVATED_ROLE_TOKEN_RE.test(right) || LOW_PRIV_ROLE_TOKEN_RE.test(right)
            const leftIsRole = ELEVATED_ROLE_TOKEN_RE.test(left) || LOW_PRIV_ROLE_TOKEN_RE.test(left)
            const tenant = normalizeTenantToken(rightIsRole && !leftIsRole ? left : right)
            const roleText = rightIsRole && !leftIsRole ? right : left
            if (tenant) tenants.add(tenant)
            out.push({ tenant, roleText })
          } else {
            addTenant(tenants, item)
          }
        }
      } else if (item && typeof item === 'object') {
        const tenant = normalizeTenantToken(item.tenant)
        if (tenant) tenants.add(tenant)
        out.push({ tenant, roleText: `${item.privilege ?? ''} ${item.role ?? ''}`.trim() })
      }
    }
  } else if (raw && typeof raw === 'object') {
    for (const [k, v] of Object.entries(raw)) {
      const tenant = normalizeTenantToken(k)
      if (tenant) tenants.add(tenant)
      out.push({ tenant, roleText: typeof v === 'string' ? v : '' })
    }
  }
  const roleLabel = (input.roleLabel ?? input.role ?? '').trim()
  if (out.length === 0 && roleLabel) {
    for (const m of parseRoleLabelMemberships(roleLabel)) {
      if (m.tenant) tenants.add(m.tenant)
      out.push(m)
    }
  }
  return out
}

function extractStructuredTenants(input: PersonaMetadataInput, tenants: Set<string>): void {
  addTenant(tenants, input.tenant)
  addTenant(tenants, input.tenantRef)
  if (Array.isArray(input.tenants)) {
    for (const t of input.tenants) addTenant(tenants, t)
  }
  const roleLabel = (input.roleLabel ?? input.role ?? '').trim()
  if (!roleLabel) return
  for (const m of roleLabel.matchAll(/(?:tenant|org|workspace|account|team)\s*[:=]\s*([a-z0-9][a-z0-9._-]{1,40})/gi)) {
    addTenant(tenants, m[1])
  }
  for (const m of roleLabel.matchAll(/\(([a-z0-9][a-z0-9._-]{1,40})\)/gi)) {
    addTenant(tenants, m[1])
  }
  for (const m of roleLabel.matchAll(/\[([a-z0-9][a-z0-9._-]{1,40})\]/gi)) {
    addTenant(tenants, m[1])
  }
}

function makeClassification(
  privilege: PersonaPrivilegeLevel,
  tier: PersonaPrivilegeTier,
  rank: number,
  tenants: string[],
  multiTenant = false,
): PersonaPrivilegeClassification {
  return {
    privilege,
    tenants,
    tier,
    elevated: privilege === 'elevated',
    multiTenant,
    revokedStale: privilege === 'revoked',
    rank,
  }
}

/**
 * Authoritative structured persona metadata classifier.
 * Precedence:
 *   1. Explicit `privilege` config field
 *   2. Explicit `memberships` (structured array/map or `memberships=...` in `roleLabel`)
 *   3. Explicit `role` / `roleLabel`
 *   4. Minimal safe fallback on `handle` ONLY when structured fields are absent
 */
export function classifyPersonaMetadata(input: PersonaMetadataInput): PersonaPrivilegeClassification {
  const handle = (input.handle ?? '').trim()
  const roleLabel = (input.roleLabel ?? input.role ?? '').trim()
  const explicitPriv = (input.privilege ?? '').trim().toLowerCase()

  const tenantSet = new Set<string>()
  const memberships = collectStructuredMemberships(input, tenantSet)
  const explicitTenantsCount = new Set((input.tenants ?? []).map(normalizeTenantToken).filter((t): t is string => Boolean(t))).size
  extractStructuredTenants(input, tenantSet)
  const tenants = [...tenantSet]
  const hasExplicitMultiTenants = memberships.length >= 2 || explicitTenantsCount >= 2

  // 1. Explicit structured `privilege` field always wins (never overridden by handle substrings).
  if (explicitPriv) {
    if (REVOKED_TOKEN_RE.test(explicitPriv)) {
      return makeClassification('revoked', 'revoked_stale', 3, tenants, false)
    }
    if (HIGH_ADMIN_TOKEN_RE.test(explicitPriv) || explicitPriv === 'elevated') {
      return makeClassification('elevated', 'elevated', 5, tenants, false)
    }
    if (ELEVATED_ROLE_TOKEN_RE.test(explicitPriv)) {
      return makeClassification('elevated', 'elevated', 4, tenants, false)
    }
    return makeClassification('low', hasExplicitMultiTenants ? 'multi_tenant' : 'low', hasExplicitMultiTenants ? 2 : 0, tenants, hasExplicitMultiTenants)
  }

  // 2. Explicit structured revoked status in roleLabel.
  if (roleLabel && REVOKED_TOKEN_RE.test(roleLabel)) {
    return makeClassification('revoked', 'revoked_stale', 3, tenants, false)
  }

  // 3. Explicit multi-tenant memberships (structured or `memberships=...` / multi-bracket).
  if (memberships.length >= 2) {
    const hasNonElevated = memberships.some(
      m => LOW_PRIV_ROLE_TOKEN_RE.test(m.roleText) || !ELEVATED_ROLE_TOKEN_RE.test(m.roleText),
    )
    if (hasNonElevated) {
      return makeClassification('low', 'multi_tenant', 2, tenants, true)
    }
    return makeClassification('elevated', 'elevated', 5, tenants, false)
  }

  // 4. Explicit `role` / `roleLabel` (authoritative over handle substrings such as `support_bot_free`).
  if (roleLabel) {
    if (MULTI_TENANT_ROLE_RE.test(roleLabel) || explicitTenantsCount >= 2) {
      if (!ELEVATED_ROLE_TOKEN_RE.test(roleLabel) || LOW_PRIV_ROLE_TOKEN_RE.test(roleLabel)) {
        return makeClassification('low', 'multi_tenant', 2, tenants, true)
      }
    }
    if (HIGH_ADMIN_TOKEN_RE.test(roleLabel)) {
      return makeClassification('elevated', 'elevated', 5, tenants, false)
    }
    if (ELEVATED_ROLE_TOKEN_RE.test(roleLabel)) {
      return makeClassification('elevated', 'elevated', 4, tenants, false)
    }
    if (LOW_PRIV_ROLE_TOKEN_RE.test(roleLabel)) {
      return makeClassification('low', 'low', 0, tenants, false)
    }
    return makeClassification('low', 'standard', 1, tenants, false)
  }

  // 5. Minimal safe fallback on `handle` ONLY when no explicit privilege/role/memberships exist.
  //    Never flags non-admin words like `bot`/`svc`/`mod`/`staff` or `_a`/`_b`/`dual` suffixes.
  if (REVOKED_TOKEN_RE.test(handle)) {
    return makeClassification('revoked', 'revoked_stale', 3, tenants, false)
  }
  if (HIGH_ADMIN_TOKEN_RE.test(handle)) {
    return makeClassification('elevated', 'elevated', 5, tenants, false)
  }
  if (explicitTenantsCount >= 2) {
    return makeClassification('low', 'multi_tenant', 2, tenants, true)
  }
  if (LOW_PRIV_ROLE_TOKEN_RE.test(handle)) {
    return makeClassification('low', 'low', 0, tenants, false)
  }
  return makeClassification('low', 'standard', 1, tenants, false)
}

/** Backwards-compatible wrapper accepting either `(handle, roleLabel?, extras?)` or a structured `PersonaMetadataInput`. */
export function classifyPersonaPrivilege(
  handleOrInput: string | PersonaMetadataInput,
  roleLabel?: string | null,
  extras?: Omit<PersonaMetadataInput, 'handle' | 'roleLabel'>,
): PersonaPrivilegeClassification {
  if (typeof handleOrInput === 'object' && handleOrInput !== null) {
    return classifyPersonaMetadata(handleOrInput)
  }
  return classifyPersonaMetadata({
    handle: handleOrInput,
    roleLabel,
    ...extras,
  })
}
