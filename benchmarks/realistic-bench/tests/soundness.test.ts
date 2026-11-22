// Oracle soundness: on a clean (fully hardened) app, ordinary non-malicious usage must never trip an
// impact event. Each app is booted with every planted site forced HARDENED, then each persona logs in
// and browses their own resources with benign inputs. Any oracle event here would be a detector false
// positive, undermining the benchmark's precision claim. (Forcing sites vulnerable and hitting an
// always-on sink — e.g. a secret-disclosing list — is real exploitation, not a soundness signal, so
// the hardened baseline is the right control.)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { personaIds } from '../lib/types.ts'
import type { AppModule, VariantPlan } from '../lib/types.ts'
import { generateVariant } from '../generator/variant.ts'
import { bootForced, makeSolverCtx } from './helpers/site-matrix.ts'
import acme from '../apps/acme-saas/index.ts'
import opsportal from '../apps/opsportal/index.ts'
import shopflow from '../apps/shopflow/index.ts'

const SESSION_COOKIE: Record<string, string> = { 'acme-saas': 'acme_sid', opsportal: 'rb_sid', shopflow: 'rb_sid' }

// Benign GET routes: parameterless list/read endpoints present in most apps. Unknown keys are skipped.
const BENIGN_GET = [
  'health', 'me', 'appConfig', 'listProjects', 'listInvoices', 'listFiles', 'notifications',
  'listOrders', 'listProducts', 'listReviews', 'listTickets', 'listAccounts', 'dashboard',
  'integrationList', 'listTokens', 'listApiKeys', 'listMembers', 'listWebhooks',
]

async function benignTraffic(mod: AppModule): Promise<{ app: string; events: string[] }> {
  const plan: VariantPlan = generateVariant(mod.blueprint, 1)
  const app = await bootForced(mod, plan, 'hardened')
  try {
    const ctx = makeSolverCtx(app, SESSION_COOKIE[mod.name])
    for (const persona of personaIds) {
      const session = await ctx.login(persona)
      for (const key of BENIGN_GET) {
        if (!plan.routes[key]) continue
        // Only hit parameterless routes with benign query values.
        if (/[:{]/.test(plan.routes[key]!.path)) continue
        await ctx.fetch(ctx.path(key, {}, { q: 'quarterly report', page: '1' }), { session }).catch(() => undefined)
      }
    }
    return { app: mod.name, events: app.oracle.events().map((e) => `${e.kind}@${e.routeKey}`) }
  } finally {
    await app.stop()
  }
}

for (const mod of [acme, opsportal, shopflow] as AppModule[]) {
  test(`${mod.name}: benign browsing produces zero impact events`, async () => {
    const { events } = await benignTraffic(mod)
    assert.deepEqual(events, [], `benign traffic unexpectedly tripped the oracle:\n${events.join('\n')}`)
  })
}
