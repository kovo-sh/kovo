// Canary tokens embedded in seeded data. When a response to actor of tenant X contains tenant Y's
// canary (Y != X), the oracle records a cross-tenant read — unless that token first arrived as input
// from the same actor (so a scanner cannot "launder" a value it supplied into a false positive).
import { createHash } from 'node:crypto'
import type { Oracle } from './oracle.ts'
import { currentCtx } from './oracle.ts'

function tag(s: string): string {
  return s.replace(/[^a-z0-9]/gi, '').slice(0, 10).toLowerCase() || 't'
}

export interface CanaryRegistry {
  /** Data canary for a tenant: rbc_<tenantTag>_<hex>. Appears in that tenant's records. */
  tenantToken(tenant: string, label: string): string
  /** Secret canary owned by a principal: rbs_<ownerTag>_<hex>. Disclosure to the unentitled = leak. */
  secretToken(owner: string, label: string): string
  ownerOf(token: string): { kind: 'tenant' | 'secret'; owner: string } | null
  /** Scan a response body served to `actorTenant`; emit cross_tenant_read for foreign tenant canaries. */
  scanResponse(oracle: Oracle, body: string, actorTenant: string | null): void
}

export function createCanaryRegistry(salt: string): CanaryRegistry {
  const tenantOwner = new Map<string, string>()
  const secretOwner = new Map<string, string>()

  const mk = (kind: 'rbc' | 'rbs', owner: string, label: string): string => {
    const hex = createHash('sha256').update(`${salt}:${kind}:${owner}:${label}`).digest('hex').slice(0, 12)
    return `${kind}_${tag(owner)}_${hex}`
  }

  return {
    tenantToken(tenant, label) {
      const t = mk('rbc', tenant, label)
      tenantOwner.set(t, tenant)
      return t
    },
    secretToken(owner, label) {
      const t = mk('rbs', owner, label)
      secretOwner.set(t, owner)
      return t
    },
    ownerOf(token) {
      if (tenantOwner.has(token)) return { kind: 'tenant', owner: tenantOwner.get(token)! }
      if (secretOwner.has(token)) return { kind: 'secret', owner: secretOwner.get(token)! }
      return null
    },
    scanResponse(oracle, body, actorTenant) {
      if (!body) return
      const ctx = currentCtx()
      const seen = ctx?.inputSet
      // tenant canaries
      for (const [token, owner] of tenantOwner) {
        if (owner === actorTenant) continue
        if (!body.includes(token)) continue
        if (seen && seen.has(token)) continue // laundered input — not a disclosure
        oracle.emit('cross_tenant_read', { token, owner, actorTenant: actorTenant ?? 'none' }, `data:${owner}`)
      }
    },
  }
}
