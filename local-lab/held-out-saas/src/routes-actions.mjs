// HTTP binding for server actions.
import { ACTION_IDS } from './config.mjs'
import { sendJson } from './http-util.mjs'
import * as actions from './actions.mjs'

export function register(router, ctx) {
  const run = async (c, name) => {
    const fn = actions[name]
    if (typeof fn !== 'function') return sendJson(c.res, 404, { error: 'server_action_not_found' })
    const raw = await c.json()
    // Action arguments arrive either as a positional array (`[orgId, plan]`) or as a keyed object.
    const [a, b] = Array.isArray(raw) ? raw : [raw.orgId, raw.plan]
    const result = await fn(ctx, c.user(), a, b)
    sendJson(c.res, result.status, result.body)
  }

  router.post('/_actions/:name', c => run(c, c.params.name))
  router.post('/_next/action/:id', c => {
    const entry = Object.entries(ACTION_IDS).find(([, id]) => id === c.params.id)
    if (!entry) return sendJson(c.res, 404, { error: 'server_action_not_found' })
    return run(c, entry[0])
  })
}
