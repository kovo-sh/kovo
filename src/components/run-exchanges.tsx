import { useMemo, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { readExchange } from '../actions.ts'
import { formatExchangeAsCurl } from './curl-parser.ts'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { Input, NativeSelect } from './ui/input.tsx'

type ExchangeItem = RunDetail['exchangesSummary'][number]
type FullExchange = Awaited<ReturnType<typeof readExchange>>

function safeHost(origin: string) {
  try {
    const u = new URL(origin)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch {
    return origin
  }
}

function statusBucket(status: number) {
  if (status >= 200 && status < 300) return '2xx'
  if (status >= 300 && status < 400) return '3xx'
  if (status >= 400 && status < 500) return '4xx'
  if (status >= 500) return '5xx'
  return 'other'
}

function prettyBody(body: string, mediaType: string) {
  const trimmed = body.trim()
  if (!trimmed) return '(empty response body)'
  if (mediaType.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2)
    } catch {
      return body
    }
  }
  return body
}

export function RunExchanges({
  runId,
  exchanges,
  assignments,
  compact = false,
  initialExpandedId,
}: {
  runId: string
  exchanges: ExchangeItem[]
  assignments?: RunDetail['assignments']
  compact?: boolean
  initialExpandedId?: string
}) {
  const [personaFilter, setPersonaFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [hostFilter, setHostFilter] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(initialExpandedId ?? null)
  const [loaded, setLoaded] = useState<Record<string, FullExchange | 'loading' | 'error'>>({})
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const workerById = useMemo(
    () => new Map((assignments ?? []).map(a => [a.id, a])),
    [assignments],
  )

  const personaOptions = useMemo(() => {
    const handles = new Set<string>()
    let hasAnon = false
    for (const ex of exchanges) {
      if (ex.personaHandle) handles.add(ex.personaHandle)
      else hasAnon = true
    }
    return ['all', ...(hasAnon ? ['anon'] : []), ...[...handles].sort()]
  }, [exchanges])

  const hostOptions = useMemo(() => {
    const hosts = [...new Set(exchanges.map(ex => ex.origin))].sort()
    return hosts
  }, [exchanges])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return exchanges.filter(ex => {
      if (personaFilter === 'anon' && ex.personaHandle) return false
      if (personaFilter !== 'all' && personaFilter !== 'anon' && ex.personaHandle !== personaFilter) return false
      if (statusFilter !== 'all' && statusBucket(ex.status) !== statusFilter) return false
      if (hostFilter !== 'all' && ex.origin !== hostFilter) return false
      if (q) {
        const hay = `${ex.method} ${ex.origin} ${ex.pathAndQuery} ${ex.status} ${ex.personaHandle ?? 'anon'} ${ex.mediaType} ${ex.bodyPreview}`.toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [exchanges, personaFilter, statusFilter, hostFilter, search])

  async function toggleExpand(ex: ExchangeItem) {
    if (expandedId === ex.id) {
      setExpandedId(null)
      return
    }
    setExpandedId(ex.id)
    if (loaded[ex.id] && loaded[ex.id] !== 'error') return
    setLoaded(prev => ({ ...prev, [ex.id]: 'loading' }))
    try {
      const full = await readExchange({ data: { runId, exchangeId: ex.id } })
      setLoaded(prev => ({ ...prev, [ex.id]: full }))
    } catch {
      setLoaded(prev => ({ ...prev, [ex.id]: 'error' }))
    }
  }

  function handleCopyCurl(ex: ExchangeItem, full?: FullExchange) {
    const cmd = formatExchangeAsCurl({
      method: ex.method,
      origin: ex.origin,
      pathAndQuery: ex.pathAndQuery,
      reqHeaders: full?.reqHeaders,
      personaHandle: ex.personaHandle,
    })
    void navigator.clipboard?.writeText(cmd).catch(() => {})
    setCopiedId(ex.id)
    window.setTimeout(() => setCopiedId(curr => curr === ex.id ? null : curr), 1800)
  }

  if (exchanges.length === 0) {
    return <div className="empty-panel">
      <p className="muted">No brokered HTTP exchanges recorded {compact ? 'for this worker yet.' : 'for this run yet.'}</p>
    </div>
  }

  return <div className={compact ? 'exchanges-panel compact' : 'exchanges-panel'}>
    <div className="exchanges-toolbar">
      <div className="filter-chips" role="group" aria-label="Filter by persona">
        {personaOptions.map(p => <button
          key={p}
          type="button"
          className={`filter-chip${personaFilter === p ? ' active' : ''}`}
          onClick={() => setPersonaFilter(p)}
        >
          {p === 'all' ? `All (${exchanges.length})` : p}
        </button>)}
      </div>

      <div className="exchanges-filters-right">
        <div className="filter-chips" role="group" aria-label="Filter by HTTP status">
          {(['all', '2xx', '3xx', '4xx', '5xx'] as const).map(bucket => <button
            key={bucket}
            type="button"
            className={`filter-chip xs${statusFilter === bucket ? ' active' : ''}`}
            onClick={() => setStatusFilter(bucket)}
          >
            {bucket === 'all' ? 'Any status' : bucket}
          </button>)}
        </div>
        {!compact && hostOptions.length > 1 && <NativeSelect
          aria-label="Filter by host"
          value={hostFilter}
          onChange={e => setHostFilter(e.target.value)}
          className="compact-select"
        >
          <option value="all">All hosts ({hostOptions.length})</option>
          {hostOptions.map(origin => <option key={origin} value={origin}>{safeHost(origin)}</option>)}
        </NativeSelect>}
        <Input
          type="search"
          aria-label="Search exchanges"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search path, status, body…"
          className="exchange-search-input"
        />
      </div>
    </div>

    {filtered.length === 0 ? <div className="empty-panel">
      <p className="muted">No exchanges match the active filters.</p>
    </div> : <div className="exchange-list">
      {filtered.map(ex => {
        const isOpen = expandedId === ex.id
        const detail = loaded[ex.id]
        const full = detail && typeof detail === 'object' ? detail : undefined
        const worker = workerById.get(ex.assignmentId)
        const statusCls = ex.status >= 200 && ex.status < 300 ? 's2'
          : ex.status >= 300 && ex.status < 400 ? 's3'
            : ex.status >= 400 && ex.status < 500 ? 's4' : 's5'
        const personaLabel = ex.personaHandle || 'anon'

        return <div key={ex.id} className={`exchange-row-card${isOpen ? ' open' : ''}`}>
          <button type="button" className="exchange-row-trigger" onClick={() => void toggleExpand(ex)}>
            <span className={`method-tag m-${ex.method.toLowerCase()}`}>{ex.method}</span>
            <span className={`status-pill ${statusCls}`}>{ex.status}</span>
            <span className={`persona-pill ${ex.personaHandle ? 'auth' : 'anon'}`}>{personaLabel}</span>
            <span className="mono exchange-path truncate" title={`${ex.origin}${ex.pathAndQuery}`}>
              {!compact && hostOptions.length > 1 && <span className="muted">{safeHost(ex.origin)}</span>}
              {ex.pathAndQuery}
            </span>
            <span className="muted mono xs tabular">{ex.durationMs}ms</span>
            <span className="disclosure-chevron-inline" aria-hidden="true">{isOpen ? '▾' : '▸'}</span>
          </button>

          {isOpen && <div className="exchange-detail-drawer">
            <div className="exchange-detail-bar">
              <div className="inline-badges">
                <code className="xs">{ex.origin}{ex.pathAndQuery}</code>
                <span className="badge">{ex.mediaType || 'unknown'}</span>
                {!compact && worker && <Link
                  to="/runs/$runId/workers/$workerId"
                  params={{ runId, workerId: worker.id }}
                  search={{ view: 'trace' }}
                  className="text-button xs"
                >
                  Worker: {worker.title} ↗
                </Link>}
              </div>
              <Button type="button" variant="ghost" onClick={() => handleCopyCurl(ex, full)}>
                {copiedId === ex.id ? 'Copied cURL ✓' : 'Copy as cURL'}
              </Button>
            </div>

            {detail === 'loading' && <p className="muted xs">Loading full request &amp; response headers…</p>}
            {detail === 'error' && <p className="form-error xs">Could not load full exchange details.</p>}

            {full && <div className={compact ? 'exchange-split stacked' : 'exchange-split'}>
              <div className="exchange-pane">
                <div className="pane-kicker">Request Headers</div>
                <pre className="code-block">
                  {Object.entries(full.reqHeaders).length > 0
                    ? Object.entries(full.reqHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')
                    : '(default broker headers)'}
                </pre>
              </div>
              <div className="exchange-pane">
                <div className="pane-kicker">Response Headers ({full.status})</div>
                <pre className="code-block">
                  {Object.entries(full.respHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}
                </pre>
              </div>
            </div>}

            <div className="exchange-body-section">
              <div className="pane-kicker">Response Body {full?.body && full.body.length > 12000 ? '(preview)' : ''}</div>
              <pre className="code-block code-block-body">
                {prettyBody((full?.body ?? ex.bodyPreview).slice(0, 12000), ex.mediaType)}
              </pre>
            </div>
          </div>}
        </div>
      })}
    </div>}
  </div>
}
