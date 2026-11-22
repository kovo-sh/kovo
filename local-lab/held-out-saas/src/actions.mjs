'use server'
// Server actions (Next.js App Router style). Invoked through `/_actions/<name>` or `/_next/action/<id>`.
import { marker } from './markers.mjs'

// hos-05: this action mutates the organisation plan for ANY orgId and performs no authentication or
// authorisation check — server actions are public endpoints and the author assumed the UI gates them.
export async function updateOrgPlan(ctx, caller, orgId, plan) {
  if (ctx.fixed('hos-05')) {
    if (!caller) return { status: 401, body: { error: 'unauthorized' } }
    if (caller.role !== 'admin' || caller.tenant !== orgId) return { status: 403, body: { error: 'forbidden' } }
  }
  const org = ctx.s.tenants.get(String(orgId))
  if (!org) return { status: 404, body: { error: 'org_not_found' } }
  if (!/^[a-z0-9_-]{1,32}$/i.test(String(plan))) return { status: 400, body: { error: 'invalid_plan' } }
  org.plan = String(plan)
  return { status: 200, body: { ok: true, org, auditRef: marker('hos-05') } }
}

// Correctly guarded sibling action (control for authorisation differential testing).
export async function exportOrgSummary(ctx, caller, orgId) {
  if (!caller) return { status: 401, body: { error: 'unauthorized' } }
  if (caller.tenant !== String(orgId)) return { status: 403, body: { error: 'forbidden' } }
  const org = ctx.s.tenants.get(caller.tenant)
  return { status: 200, body: { org, projects: [...ctx.s.projects.values()].filter(p => p.tenantId === caller.tenant).length } }
}
