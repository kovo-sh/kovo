import { useMemo, useState } from 'react'
import { Input, NativeSelect } from './ui/input.tsx'
import type { RunDetail } from './run-state.ts'

function safeHost(origin: string) {
  try {
    const u = new URL(origin)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch {
    return origin
  }
}

export function RunSurface({ detail }: { detail: RunDetail }) {
  const endpoints = detail.endpoints ?? []
  const endpointParams = detail.endpointParams ?? []
  const apiDependencies = detail.apiDependencies ?? []
  const labTelemetry = detail.labTelemetry ?? []

  const [query, setQuery] = useState('')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [sourceFilter, setSourceFilter] = useState('ALL')

  const endpointById = useMemo(
    () => new Map(endpoints.map(ep => [ep.id, ep])),
    [endpoints],
  )

  const paramsByEndpoint = useMemo(() => {
    const map = new Map<string, typeof endpointParams>()
    for (const p of endpointParams) {
      const list = map.get(p.endpointId) ?? []
      list.push(p)
      map.set(p.endpointId, list)
    }
    return map
  }, [endpointParams])

  const methods = useMemo(
    () => [...new Set(endpoints.map(e => e.method))].sort(),
    [endpoints],
  )
  const sources = useMemo(
    () => [...new Set(endpoints.map(e => e.source))].sort(),
    [endpoints],
  )

  const filteredEndpoints = useMemo(() => {
    const q = query.trim().toLowerCase()
    return endpoints.filter(ep => {
      if (methodFilter !== 'ALL' && ep.method !== methodFilter) return false
      if (sourceFilter !== 'ALL' && ep.source !== sourceFilter) return false
      if (!q) return true
      const epParams = paramsByEndpoint.get(ep.id) ?? []
      return (
        ep.pathTemplate.toLowerCase().includes(q) ||
        ep.origin.toLowerCase().includes(q) ||
        ep.method.toLowerCase().includes(q) ||
        epParams.some(p => p.name.toLowerCase().includes(q) || p.location.toLowerCase().includes(q))
      )
    })
  }, [endpoints, methodFilter, sourceFilter, query, paramsByEndpoint])

  const coveredCount = endpoints.filter(ep => (ep.coveragePct ?? 0) > 0).length

  return <section className="surface-graph-view" aria-label="Surface graph">
    <div className="exchanges-page-head">
      <div>
        <h2>Application Surface Graph</h2>
        <p className="muted">
          SQLite-backed inventory of discovered endpoints, normalized parameters, and producer-consumer API dependencies.
        </p>
      </div>
      <div className="inline-badges">
        <span className="badge badge-accent mono">{endpoints.length} endpoints</span>
        <span className="badge badge-trace mono">{endpointParams.length} params</span>
        <span className="badge mono">{apiDependencies.length} dependencies</span>
        {labTelemetry.length > 0 && <span className="badge badge-complete mono">{labTelemetry.length} IAST traces</span>}
      </div>
    </div>

    <div className="kpi-strip" aria-label="Surface graph metrics">
      <div className="kpi-card">
        <span className="kpi-label">Endpoints</span>
        <span className="kpi-val tabular mono">{endpoints.length}</span>
      </div>
      <div className="kpi-card">
        <span className="kpi-label">Parameters</span>
        <span className="kpi-val tabular mono">{endpointParams.length}</span>
      </div>
      <div className="kpi-card">
        <span className="kpi-label">API Dependencies</span>
        <span className="kpi-val tabular mono">{apiDependencies.length}</span>
      </div>
      <div className="kpi-card">
        <span className="kpi-label">Covered Routes</span>
        <span className="kpi-val tabular mono">{coveredCount}/{endpoints.length}</span>
      </div>
    </div>

    <div className="surface-filter-bar">
      <Input
        aria-label="Filter surface endpoints"
        placeholder="Filter by path, host, or parameter name…"
        value={query}
        onChange={e => setQuery(e.target.value)}
      />
      <NativeSelect aria-label="Filter by HTTP method" value={methodFilter} onChange={e => setMethodFilter(e.target.value)}>
        <option value="ALL">All methods</option>
        {methods.map(m => <option key={m} value={m}>{m}</option>)}
      </NativeSelect>
      <NativeSelect aria-label="Filter by discovery source" value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}>
        <option value="ALL">All sources</option>
        {sources.map(s => <option key={s} value={s}>{s}</option>)}
      </NativeSelect>
    </div>

    <div className="overview-card">
      <div className="section-heading">
        <h3>Discovered endpoints ({filteredEndpoints.length})</h3>
        <span className="muted xs">Normalized route templates with parameters, risk score, and coverage</span>
      </div>
      {filteredEndpoints.length > 0 ? <div className="table-scroll">
        <table className="compact-table surface-table">
          <thead>
            <tr>
              <th scope="col">Endpoint</th>
              <th scope="col">Parameters</th>
              <th scope="col">Source &amp; Guards</th>
              <th scope="col">Risk / Coverage</th>
            </tr>
          </thead>
          <tbody>
            {filteredEndpoints.map(ep => {
              const epParams = paramsByEndpoint.get(ep.id) ?? []
              return <tr key={ep.id}>
                <td>
                  <div className="inline-badges">
                    <span className="badge badge-trace mono">{ep.method}</span>{' '}
                    <code className="mono">{ep.pathTemplate}</code>{' '}
                  </div>
                  <div className="muted xs mono"> {safeHost(ep.origin)} </div>
                </td>
                <td>
                  {epParams.length > 0 ? <div className="param-chip-list">
                    {epParams.map(p => <span key={p.id} className="param-chip">
                      {' '}<strong className="mono">{p.name}</strong>{' '}
                      <span className="muted">{p.location}</span>{' '}
                      {p.isObjectId && <span className="badge badge-attention"> ID </span>}
                      {p.isCsrf && <span className="badge badge-complete"> CSRF </span>}
                    </span>)}
                  </div> : <span className="muted xs">—</span>}
                </td>
                <td>
                  <div className="inline-badges">
                    <span className="badge">{ep.source}</span>{' '}
                    {ep.framework && <span className="badge">{ep.framework}</span>}
                    {ep.authRequirement && <span className="badge badge-trace">{ep.authRequirement}</span>}
                    {ep.ownershipGuard && <span className="badge badge-complete">{ep.ownershipGuard}</span>}
                  </div>
                  {ep.testedClasses.length > 0 && <div className="muted xs" style={{ marginTop: 4 }}>
                    Tested: {ep.testedClasses.join(', ')}
                  </div>}
                </td>
                <td className="mono xs">
                  <div>Risk: <strong>{ep.riskScore}</strong></div>
                  <div>Coverage: <strong>{ep.coveragePct !== null && ep.coveragePct !== undefined ? `${Math.round(ep.coveragePct)}%` : '—'}</strong></div>
                </td>
              </tr>
            })}
          </tbody>
        </table>
      </div> : <p className="muted">No endpoints discovered yet. Phase-0 recon and worker discovery will populate the Surface Graph automatically.</p>}
    </div>

    <div className="overview-card">
      <div className="section-heading">
        <h3>API dependencies ({apiDependencies.length})</h3>
        <span className="muted xs">Inferred producer → consumer object lifecycle edges for BOLA/BFLA and workflow verification</span>
      </div>
      {apiDependencies.length > 0 ? <div className="dep-edge-list">
        {apiDependencies.map(dep => {
          const producer = endpointById.get(dep.producerEndpointId)
          const consumer = endpointById.get(dep.consumerEndpointId)
          const producerLabel = producer ? `${producer.method} ${producer.pathTemplate}` : dep.producerEndpointId
          const consumerLabel = consumer ? `${consumer.method} ${consumer.pathTemplate}` : dep.consumerEndpointId
          return <article key={dep.id} className="dep-edge-row">
            <div className="dep-edge-main">
              <code className="mono">{producerLabel}</code>{' '}
              <span className="dep-edge-arrow" aria-label="produces resource for">→</span>{' '}
              <code className="mono">{consumerLabel}</code>{' '}
            </div>
            <div className="inline-badges">
              <span className="badge badge-accent mono">{' '}{dep.resourceKey}{' '}</span>
              {dep.personaHandle && <span className="badge badge-trace">{' '}{dep.personaHandle}{' '}</span>}
              <span className={`badge ${dep.testedBola ? 'badge-complete' : 'badge-attention'}`}>
                {' '}{dep.testedBola ? 'BOLA tested' : 'Pending BOLA'}{' '}
              </span>
              {dep.observedTransitions.length > 0 && <span className="muted xs">
                {' '}{dep.observedTransitions.join(' → ')}{' '}
              </span>}
            </div>
          </article>
        })}
      </div> : <p className="muted">No producer-consumer API dependencies recorded yet.</p>}
    </div>
  </section>
}
