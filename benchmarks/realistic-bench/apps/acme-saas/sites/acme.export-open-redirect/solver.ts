// Open redirect on the legacy export download: omit the signature so the endpoint falls back to the
// caller-supplied target, pointed at a foreign origin.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const target = 'https://exports.attacker.example/grab'
  await ctx.fetch(ctx.path('exportRedirect', {}, { url: target }))
}
