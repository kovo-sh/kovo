// Operations area: export queue + downloads, jailed file access, signed artifact links and the
// inbound webhook receiver. Safe defaults re-check the caller's current role on download, jail VFS
// reads to the tenant export directory and bind webhook signatures to tenant + event type.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { AppContext, ExportRow } from '../context.ts'
import { body, exportView, fileView, forbidden, notFound, param, requireRole, requireSession, unauthorized } from '../common.ts'
import { jailFor } from '../seed.ts'

function equalHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  const ab = Buffer.from(a, 'hex'); const bb = Buffer.from(b, 'hex')
  return ab.length === bb.length && ab.length > 0 && timingSafeEqual(ab, bb)
}

function artifactSignature(secret: string, path: string): string {
  return createHmac('sha256', secret).update(path).digest('hex')
}

export function registerOpsRoutes(ctx: AppContext): void {
  ctx.route('listExports', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM exports WHERE tenant_id = ? ORDER BY id DESC LIMIT 100', [id.tenant])
    return req.json({ items: rows.map(exportView) })
  })

  ctx.route('queueExport', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const kind = String(body(req).kind ?? 'billing').replace(/[^a-z0-9-]/gi, '').slice(0, 24) || 'billing'
    const ext = ctx.newId('export')
    const path = `/exports/${id.tenant}/${kind}-${ext}.json`
    const payload = JSON.stringify({
      tenant: id.tenant, kind, generated: new Date().toISOString(),
      marker: ctx.canary.tenantToken(id.tenant, `export-${ext}`),
      rows: ctx.db.all('SELECT external_id,total_cents,status FROM orders WHERE tenant_id = ?', [id.tenant]),
    })
    ctx.vfs.write(path, payload)
    ctx.db.run('INSERT INTO exports (external_id,tenant_id,creator_id,creator_role,kind,status,vfs_path,created_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [ext, id.tenant, id.userExtId, id.role, kind, 'complete', path, Date.now(), Date.now()])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'export_queued', ext, kind)
    return req.json({ id: ext, status: 'complete', path }, 201)
  })

  // Safe default: the download re-checks the caller's *current* role, not the role that queued it.
  ctx.route('downloadExport', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return forbidden(req)
    const job = ctx.db.get<ExportRow>('SELECT * FROM exports WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'exportId'), id.tenant])
    if (!job || !job.vfs_path) return notFound(req)
    const content = ctx.vfs.read(job.vfs_path)
    if (content === null) return notFound(req)
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'export_downloaded', job.external_id)
    return req.json({ id: job.external_id, kind: job.kind, content })
  })

  ctx.route('listFiles', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM files WHERE tenant_id = ? ORDER BY id', [id.tenant])
    return req.json({ items: rows.map(fileView) })
  })

  // Safe default: reads stay inside the caller tenant's jail.
  ctx.route('downloadFile', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>('SELECT * FROM files WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'fileId'), id.tenant])
    if (!row) return notFound(req)
    const content = ctx.vfs.readWithin(jailFor(id.tenant), String(row.vfs_path))
    if (content === null) return notFound(req)
    return req.json({ id: row.external_id, name: row.name, content })
  })

  ctx.route('uploadFile', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const b = body(req)
    const name = String(b.name ?? 'note.txt').replace(/[^a-z0-9._-]/gi, '_').slice(0, 64)
    const content = String(b.content ?? '')
    const ext = ctx.newId('file')
    const path = `${jailFor(id.tenant)}/${ext}-${name}`
    ctx.vfs.write(path, content)
    ctx.db.run('INSERT INTO files (external_id,tenant_id,name,vfs_path,note,created_at) VALUES (?,?,?,?,?,?)',
      [ext, id.tenant, name, path, '', Date.now()])
    return req.json({ id: ext, name, path }, 201)
  })

  // Signed artifact link. The safe default enforces a trailing-slash directory boundary and binds
  // the signature to the exact path, so a prefix-overlapping sibling tenant cannot be reached.
  ctx.route('signedDownload', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const path = String(req.query.path ?? '')
    const token = String(req.query.token ?? '')
    const expected = artifactSignature(ctx.config.jwtSecret, path)
    if (!equalHex(expected, token)) return req.json({ error: 'bad_signature' }, 401)
    const jail = `/exports/${id.tenant}/`
    if (!path.startsWith(jail)) return forbidden(req)
    const content = ctx.vfs.readWithin(`/exports/${id.tenant}`, path)
    if (content === null) return notFound(req)
    return req.json({ path, content })
  })

  // Safe default: the delivery signature covers timestamp, tenant, event type and payload.
  ctx.route('receiveWebhook', (req) => {
    const b = body(req)
    const endpointId = String(b.endpoint ?? b.endpointId ?? '')
    const endpoint = ctx.db.get<Record<string, unknown>>('SELECT * FROM webhook_endpoints WHERE external_id = ?', [endpointId])
    if (!endpoint) return req.json({ error: 'unknown_endpoint' }, 404)
    const event = (b.event ?? {}) as Record<string, unknown>
    const tenant = String(event.tenant ?? b[ctx.field('tenantId')] ?? '')
    const eventType = String(event.type ?? b.eventType ?? '')
    const ts = String(b.ts ?? '')
    const sig = String(b.signature ?? b[ctx.field('token')] ?? '')
    if (tenant !== endpoint.tenant_id) return req.json({ error: 'tenant_mismatch' }, 403)
    const declared = String(endpoint.events ?? '').split(',').map((s) => s.trim())
    if (declared.length && !declared.includes('all') && !declared.includes(eventType)) return req.json({ error: 'event_not_subscribed' }, 400)
    const payload = JSON.stringify(event)
    const scope = `${tenant}.${eventType}`
    if (!ctx.webhook.verifyScoped(String(endpoint.secret), scope, payload, ts, sig)) return req.json({ error: 'bad_signature' }, 401)
    const ext = ctx.newId('hookevent')
    ctx.db.run('INSERT INTO webhook_events (external_id,tenant_id,event_type,signature,ts,payload,processed,received_at) VALUES (?,?,?,?,?,?,?,?)',
      [ext, tenant, eventType, sig, ts, payload, 1, Date.now()])
    ctx.recordActivity(tenant, 'webhook', 'webhook_received', ext, eventType)
    return req.json({ ok: true, id: ext })
  })
}
