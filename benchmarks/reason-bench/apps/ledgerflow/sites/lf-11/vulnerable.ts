// Partner delivery endpoint. The partner signs the timestamped body; the receiving workspace is
// taken from the delivery headers so a single signed stream can serve several ledgers.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { AppContext } from '../../src/context.ts'
import { body } from '../../src/common.ts'

function digest(secret: string, ts: string, raw: string): string {
  return createHmac('sha256', secret).update(`${ts}.${raw}`).digest('hex')
}

function equalHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false
  const left = Buffer.from(a, 'hex')
  const right = Buffer.from(b, 'hex')
  return left.length === right.length && left.length > 0 && timingSafeEqual(left, right)
}

export default function register(app: AppContext): void {
  app.route('receiveWebhook', (req) => {
    const payload = body(req)
    const header = (name: string): string => String(req.headers[name] ?? '')
    const tenant = header('x-tenant-id') || String(payload.tenant ?? '')
    const eventType = header('x-event-type') || String(payload.type ?? '')
    const ts = header('x-ts') || String(payload.ts ?? '')
    const signature = header('x-signature') || String(payload.signature ?? '')
    const raw = typeof payload.payload === 'string' ? payload.payload : JSON.stringify(payload.event ?? payload)
    const endpoint = app.db.get<Record<string, unknown>>(
      'SELECT * FROM webhook_endpoints WHERE tenant_id = ? ORDER BY id LIMIT 1', [tenant])
    if (!endpoint) return req.json({ error: 'unknown_endpoint' }, 404)
    const declared = String(endpoint.events ?? '').split(',').map((s) => s.trim())
    if (declared.length && !declared.includes('all') && !declared.includes(eventType)) return req.json({ error: 'event_not_subscribed' }, 400)
    if (!ts || !signature || !equalHex(digest(String(endpoint.secret), ts, raw), signature)) {
      return req.json({ error: 'bad_signature' }, 401)
    }
    const ext = app.newId('hookevent')
    app.db.run('INSERT INTO webhook_events (external_id,tenant_id,event_type,signature,ts,payload,processed,received_at) VALUES (?,?,?,?,?,?,?,?)',
      [ext, tenant, eventType, signature, ts, raw, 1, Date.now()])
    app.recordActivity(tenant, 'webhook', 'webhook_received', ext, eventType)
    return req.json({ ok: true, id: ext })
  })
}
