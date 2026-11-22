// Virtual file system + export downloads. Nothing here ever touches the real host file system.
import { posix } from 'node:path'
import { sendText, sendJson } from './http-util.mjs'
import { marker } from './markers.mjs'

export const VFS = new Map([
  ['/srv/exports/report-2024.csv', 'month,revenue\njan,1200\nfeb,1350\n'],
  ['/srv/exports/q3-summary.txt', 'Q3 summary: pipeline healthy.\n'],
  ['/srv/internal/lab-notes.txt', `internal lab notes ${marker('hos-20')}\n`],
  ['/etc/passwd', `root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nlabuser:x:1000:1000:${marker('hos-20')}:/home/labuser:/bin/sh\n`],
  ['/etc/hostname', `orbit-app-${marker('hos-10')}\n`],
])

/** Resolves `file:///path` URIs against the virtual FS only. */
export function readVirtualUri(uri) {
  let path
  try {
    path = posix.normalize(decodeURIComponent(new URL(uri).pathname))
  } catch {
    return null
  }
  return VFS.get(path) ?? null
}

export function register(router, ctx) {
  router.get('/api/v1/exports', c => {
    const user = c.requireUser()
    if (!user) return
    const files = [...VFS.keys()].filter(p => p.startsWith('/srv/exports/')).map(p => p.slice('/srv/exports/'.length))
    sendJson(c.res, 200, { files })
  })

  // hos-20: path traversal — the requested name is resolved relative to the export root without confinement.
  router.get('/api/v1/exports/download', c => {
    const user = c.requireUser()
    if (!user) return
    const requested = String(c.query.file ?? '')
    if (!requested || requested.includes('\0')) return sendJson(c.res, 400, { error: 'file_required' })
    const resolved = posix.resolve('/srv/exports', requested)
    if (ctx.fixed('hos-20') && !resolved.startsWith('/srv/exports/')) return sendJson(c.res, 400, { error: 'invalid_path' })
    const content = VFS.get(resolved)
    if (content === undefined) return sendJson(c.res, 404, { error: 'file_not_found', file: requested })
    sendText(c.res, 200, content, 'text/plain; charset=utf-8', { 'content-disposition': `attachment; filename="${posix.basename(resolved)}"` })
  })
}
