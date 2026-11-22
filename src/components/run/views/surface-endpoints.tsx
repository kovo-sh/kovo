// Surface → Endpoints: the discovered route inventory (normalised templates,
// parameters, guards, risk / coverage), producer → consumer API dependencies
// and IAST traces. Carried over from the previous Surface Graph view.
import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { Dropdown, FilterBox, matchQ } from '../controls.tsx'
import { useRun } from '../data.tsx'
import { EmptyState, LinkRow, Props, Section, Tag } from '../display.tsx'
import { fmtN, host } from '../format.ts'
import { Icon } from '../icons.tsx'
import { useLinks, useListNav, useNav, useViewState } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'

export function EndpointsList({ modeSeg }: { modeSeg: ReactNode }) {
  const { detail } = useRun()
  const nav = useNav()
  const endpoints = detail.endpoints ?? []
  const params = detail.endpointParams ?? []
  const deps = detail.apiDependencies ?? []
  const iast = detail.labTelemetry ?? []
  const [q, setQ] = useViewState('surface.ep.q', '')
  const [method, setMethod] = useViewState('surface.ep.method', '')
  const [source, setSource] = useViewState('surface.ep.source', '')
  const byEp = useMemo(() => {
    const m = new Map<string, typeof params>()
    params.forEach(p => m.set(p.endpointId, [...(m.get(p.endpointId) ?? []), p]))
    return m
  }, [params])
  const methods = useMemo(() => [...new Set(endpoints.map(e => e.method))].sort(), [endpoints])
  const sources = useMemo(() => [...new Set(endpoints.map(e => e.source))].sort(), [endpoints])
  const items = useMemo(() => endpoints.filter(ep => (!method || ep.method === method) && (!source || ep.source === source)
    && matchQ(q, [ep.method, ep.origin, ep.pathTemplate, ...(byEp.get(ep.id) ?? []).flatMap(p => [p.name, p.location])].join(' ')))
    .sort((a, b) => b.riskScore - a.riskScore || a.pathTemplate.localeCompare(b.pathTemplate)), [endpoints, method, source, q, byEp])
  const ids = useMemo(() => items.map(e => e.id), [items])
  useListNav({ ids, kind: 'endpoint' })
  const covered = endpoints.filter(e => (e.coveragePct ?? 0) > 0).length
  const selId = nav.sel?.kind === 'endpoint' ? nav.sel.id : null
  const active = (method ? 1 : 0) + (source ? 1 : 0)
  return <>
    <div className="toolbar">
      <span className="sf-tbt num"><b>{fmtN(endpoints.length)}</b> endpoints · {fmtN(params.length)} params · {fmtN(deps.length)} dependencies{iast.length ? ` · ${fmtN(iast.length)} IAST traces` : ''} · {covered}/{endpoints.length} covered</span>
      <span className="tb-sp" />
      <FilterBox value={q} onChange={setQ} placeholder="Path, host or param" onEnter={() => ids[0] && nav.select({ kind: 'endpoint', id: ids[0] })} />
      <Dropdown icon="sliders" label={<><span className="dim">Filter</span><span>{active ? active + ' on' : 'All'}</span></>}>
        <div className="dd-sec">Method</div>
        <div className="sf-chips">{['', ...methods].map(m => <button key={m || 'all'} type="button" className={'sf-chip' + (method === m ? ' on' : '')} onClick={() => setMethod(m)}>{m || 'All'}</button>)}</div>
        <div className="dd-sec">Discovery source</div>
        <div className="sf-chips">{['', ...sources].map(s => <button key={s || 'all'} type="button" className={'sf-chip' + (source === s ? ' on' : '')} onClick={() => setSource(s)}>{s || 'All'}</button>)}</div>
      </Dropdown>
      {modeSeg}
    </div>
    <div className="list" tabIndex={-1} role="region" aria-label="Endpoint inventory">
      {!items.length ? <EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter.</EmptyState> : items.map(ep => {
        const ps = byEp.get(ep.id) ?? []
        return <div key={ep.id} className={'row' + (selId === ep.id ? ' cur' : '')} onClick={() => nav.select({ kind: 'endpoint', id: ep.id })}>
          <span className="c-meth mono">{ep.method}</span>
          <span className="c-path mono" title={ep.origin + ep.pathTemplate}>{ep.pathTemplate}</span>
          {ps.length > 0 && <span className="nbadge" title={ps.map(p => p.name + ' (' + p.location + ')').join(', ')}>{ps.length} params</span>}
          {ep.authRequirement && <Tag>{ep.authRequirement}</Tag>}
          <span className="mono muted sf-host">{host(ep.origin)}</span>
          <span className="c-req num" title="Risk score">{ep.riskScore}</span>
          <span className="c-dur num" title="Coverage">{ep.coveragePct != null ? Math.round(ep.coveragePct) + '%' : '—'}</span>
        </div>
      })}
      {deps.length > 0 && <div className="listnote" style={{ paddingBottom: 12 }}><Icon name="chain" />{fmtN(deps.length)} producer → consumer dependencies, {deps.filter(d => d.testedBola).length} BOLA-tested. Open an endpoint to see its edges.</div>}
    </div>
  </>
}

export function EndpointInspector({ sel }: InspectorProps) {
  const { detail } = useRun()
  const links = useLinks()
  const nav = useNav()
  const endpoints = detail.endpoints ?? []
  const ep = endpoints.find(e => e.id === sel.id)
  if (!ep) return <><PaneHeader title="Endpoint" /><PaneBody><EmptyState icon="node" title="Endpoint not found">It may belong to an earlier scope revision.</EmptyState></PaneBody></>
  const byId = new Map(endpoints.map(e => [e.id, e]))
  const ps = (detail.endpointParams ?? []).filter(p => p.endpointId === ep.id)
  const deps = (detail.apiDependencies ?? []).filter(d => d.producerEndpointId === ep.id || d.consumerEndpointId === ep.id)
  const label = (id: string) => { const e = byId.get(id); return e ? e.method + ' ' + e.pathTemplate : id }
  const loc = ep.codeLocation
  return <>
    <PaneHeader title="Endpoint" sub={<span className="mono">{ep.method}</span>} />
    <PaneBody><div className="d">
      <div className="d-meta">
        <Tag>{ep.source}</Tag>
        {ep.framework && <Tag>{ep.framework}</Tag>}
        {ep.authRequirement && <Tag icon="lock">{ep.authRequirement}</Tag>}
        {ep.ownershipGuard && <Tag icon="shield">{ep.ownershipGuard}</Tag>}
      </div>
      <h2 className="mono" style={{ fontSize: 13, wordBreak: 'break-all' }}><span className="muted">{ep.origin}</span>{ep.pathTemplate}</h2>
      <Props rows={[
        ['Risk score', <span className="num">{ep.riskScore}</span>],
        ['Coverage', ep.coveragePct != null ? Math.round(ep.coveragePct) + '%' : '—'],
        ['Tested', ep.testedClasses.length ? ep.testedClasses.join(', ') : 'Nothing yet'],
        ...(ep.sinkKinds.length ? [['Sinks', ep.sinkKinds.join(', ')] as [ReactNode, ReactNode]] : []),
        ...(loc ? [['Code', <span className="mono">{loc.file}:{loc.startLine}</span>] as [ReactNode, ReactNode]] : []),
        ['Origin', <span className="mono">{host(ep.origin)}</span>, () => links.host(ep.origin)],
      ]} />
      {ps.length > 0 && <Section title="Parameters" right={ps.length}>
        <table className="hdrs mono"><tbody>{ps.map(p => <tr key={p.id}>
          <td>{p.name}{' '}</td>
          <td>{p.location}{p.inferredType ? ' · ' + p.inferredType : ''}{p.isObjectId ? ' · object id' : ''}{p.isCsrf ? ' · CSRF' : ''}{' '}</td>
        </tr>)}</tbody></table>
      </Section>}
      {deps.length > 0 && <Section title="API dependencies" right={deps.length}>
        {deps.map(d => {
          const other = d.producerEndpointId === ep.id ? d.consumerEndpointId : d.producerEndpointId
          return <LinkRow key={d.id} icon="chain" trailing={null} right={d.testedBola ? 'BOLA tested' : 'Pending BOLA'}
            sub={[d.resourceKey, d.personaHandle, d.observedTransitions.join(' → ')].filter(Boolean).join(' · ')}
            onClick={() => nav.select({ kind: 'endpoint', id: other }, { push: true })}>
            {d.producerEndpointId === ep.id ? 'Produces for ' : 'Consumes from '}<span className="mono">{label(other)}</span>
          </LinkRow>
        })}
      </Section>}
    </div></PaneBody>
  </>
}
