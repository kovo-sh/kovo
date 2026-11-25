import http from 'node:http'
import { writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

const OUT_DIR = process.env.KOVO_IAST_OUT_DIR || '/var/run/kovo-iast'
const MAX_BYTES = 65_536

const SECRET_PATTERNS = [
  /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g,
  /\b(?:sk-or-v1-[a-z0-9_-]+|sk-ant-[a-z0-9_-]+|sk-proj-[a-z0-9_-]+|github_pat_[a-z0-9_]+|gh[pousr]_[a-z0-9_]+)\b/gi,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g,
  /\bBearer\s+[a-z0-9._~+/=-]{8,}/gi,
  /\b(?:authorization|cookie|set-cookie)\s*:\s*[^\n\r]+/gi,
]

const SQL_ERROR_RE = /SQLITE_ERROR|syntax error|PG::|psycopg|mysql|mariadb|ORA-\d{5}|SequelizeDatabaseError|PrismaClientKnownRequestError|SQLSTATE/i
const TEMPLATE_ERROR_RE = /TemplateError|RenderError|Jinja|EJS|Handlebars|Pug:/i

function scrub(text) {
  let out = String(text ?? '')
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, '[redacted]')
  }
  return out
}

function safeId(raw) {
  return String(raw || 'trace').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 96) || 'trace'
}

const recentExceptions = []

process.on('uncaughtExceptionMonitor', (err) => {
  if (recentExceptions.length > 16) recentExceptions.shift()
  recentExceptions.push({
    message: scrub(err && err.message ? err.message : String(err)).slice(0, 512),
    stack: scrub(err && err.stack ? err.stack : '').slice(0, 2048),
    ts: Date.now(),
  })
})

function writeTelemetryRecord(traceId, record) {
  try {
    mkdirSync(OUT_DIR, { recursive: true })
    let serialized = JSON.stringify(record)
    if (Buffer.byteLength(serialized, 'utf8') > MAX_BYTES) {
      const compact = {
        traceId: record.traceId,
        routesHit: (record.routesHit || []).slice(0, 32),
        newLinesCovered: record.newLinesCovered || 0,
        sinkEvents: (record.sinkEvents || []).slice(0, 16).map(ev => ({
          sink: String(ev.sink || 'unknown').slice(0, 64),
          error: ev.error ? scrub(ev.error).slice(0, 512) : undefined,
        })),
        exceptions: (record.exceptions || []).slice(0, 8).map(ex => ({
          message: scrub(ex.message || '').slice(0, 256),
        })),
        truncated: true,
        ts: record.ts,
      }
      serialized = JSON.stringify(compact)
    }
    const filePath = join(OUT_DIR, `${safeId(traceId)}.json`)
    writeFileSync(filePath, serialized, { encoding: 'utf8', mode: 0o644 })
  } catch {
    // Never crash the target app if telemetry directory is unavailable.
  }
}

const seenRoutes = new Set()
const origEmit = http.Server.prototype.emit

http.Server.prototype.emit = function kovoIastEmit(event, ...args) {
  if (event === 'request' && args.length >= 2) {
    const req = args[0]
    const res = args[1]
    const rawTrace = req && req.headers ? req.headers['x-kovo-trace-id'] : undefined
    const traceId = Array.isArray(rawTrace) ? rawTrace[0] : rawTrace
    if (typeof traceId === 'string' && traceId.trim()) {
      let pathname = '/'
      let queryStr = ''
      try {
        const u = new URL(req.url || '/', 'http://localhost')
        pathname = u.pathname
        queryStr = u.search
      } catch {
        pathname = String(req.url || '/').split('?')[0] || '/'
      }
      const isNewRoute = !seenRoutes.has(pathname)
      seenRoutes.add(pathname)

      const bodyChunks = []
      let bodyBytes = 0
      const origWrite = res.write
      const origEnd = res.end
      let flushed = false

      const captureChunk = (chunk) => {
        if (!chunk || bodyBytes >= 4096) return
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))
        bodyChunks.push(buf.subarray(0, 4096 - bodyBytes))
        bodyBytes += buf.length
      }

      res.write = function kovoIastWrite(chunk, ...rest) {
        captureChunk(chunk)
        return origWrite.call(this, chunk, ...rest)
      }

      res.end = function kovoIastEnd(chunk, ...rest) {
        if (chunk && typeof chunk !== 'function') captureChunk(chunk)
        if (!flushed) {
          flushed = true
          const bodyPreview = scrub(Buffer.concat(bodyChunks).toString('utf8'))
          const sinkEvents = []
          if (res.statusCode >= 500 || SQL_ERROR_RE.test(bodyPreview)) {
            sinkEvents.push({
              sink: SQL_ERROR_RE.test(bodyPreview) ? 'sql.query' : 'http.error',
              route: pathname,
              status: res.statusCode,
              error: bodyPreview.slice(0, 512),
              queryHint: scrub(queryStr).slice(0, 256),
            })
          } else if (TEMPLATE_ERROR_RE.test(bodyPreview)) {
            sinkEvents.push({
              sink: 'template.render',
              route: pathname,
              status: res.statusCode,
              error: bodyPreview.slice(0, 512),
            })
          }
          const exceptions = recentExceptions.splice(0, recentExceptions.length)
          writeTelemetryRecord(traceId, {
            traceId: scrub(traceId),
            method: String(req.method || 'GET').toUpperCase(),
            routesHit: [scrub(pathname)],
            newLinesCovered: isNewRoute ? 5 : 1,
            statusCode: res.statusCode,
            sinkEvents,
            exceptions,
            ts: Date.now(),
          })
        }
        return origEnd.call(this, chunk, ...rest)
      }
    }
  }
  return origEmit.call(this, event, ...args)
}
