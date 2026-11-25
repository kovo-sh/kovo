// Surface → Endpoints: the discovered route inventory (normalised templates,
// parameters, guards, risk / coverage), producer → consumer API dependencies
// and runtime traces. Virtualized with VList, sticky column header, and grouping.
import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { Dropdown, FilterBox, matchQ, VList } from '../controls.tsx'
import { useRun } from '../data.tsx'
import { EmptyState, LinkRow, Props, Section, Seg, Tag } from '../display.tsx'
import { fmtN, host } from '../format.ts'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { useLinks, useListNav, useNav, useViewState } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'

type EpGroup = 'origin' | 'auth' | 'none'
const EP_GROUPS: [EpGroup, string][] = [['origin', 'Origin'], ['auth', 'Auth'], ['none', 'None']]

export function EndpointsList({ modeSeg }: { modeSeg: ReactNode }) {
  const { detail } = useRun()
  const nav = useNav()
  const endpoints = detail.endpoints ?? []
  const params = detail.endpointParams ?? []
  const deps = detail.apiDependencies ?? []
  const traces = detail.labTelemetry ?? []
  const [q, setQ] = useViewState('surface.ep.q', '')
  const [method, setMethod] = useViewState('surface.ep.method', '')
  const [source, setSource] = useViewState('surface.ep.source', '')
  const [group, setGroup] = useViewState<EpGroup>('surface.ep.group', 'none')
  const [collapsed, setCollapsed] = useViewState<Record<string, boolean>>('surface.ep.collapsed', {})

  const byEp = useMemo(() => {
    const m = new Map<string, typeof params>()
    params.forEach(p => m.set(p.endpointId, [...(m.get(p.endpointId) ?? []), p]))
    return m
  }, [params])
  const methods = useMemo(() => [...new Set(endpoints.map(e => e.method))].sort(), [endpoints])
  const sources = useMemo(() => [...new Set(endpoints.map(e => e.source))].sort(), [endpoints])

  const filtered = useMemo(() => endpoints.filter(ep => (!method || ep.method === method) && (!source || ep.source === source)
    && matchQ(q, [ep.method, ep.origin, ep.pathTemplate, ep.authRequirement ?? '', ...(byEp.get(ep.id) ?? []).flatMap(p => [p.name, p.location])].join(' ')))
    .sort((a, b) => b.riskScore - a.riskScore || a.pathTemplate.localeCompare(b.pathTemplate)), [endpoints, method, source, q, byEp])

  type EpItem =
    | { type: 'head'; key: string; label: string; count: number; icon: 'globe' | 'lock' }
    | { type: 'row'; key: string; ep: (typeof endpoints)[number] }

  const vItems = useMemo<EpItem[]>(() => {
    if (group === 'none') return filtered.map(ep => ({ type: 'row', key: ep.id, ep }))
    const m = new Map<string, typeof filtered>()
    for (const ep of filtered) {
      const k = group === 'origin' ? ep.origin : (ep.authRequirement || 'Unauthenticated')
      const list = m.get(k)
      if (list) list.push(ep)
      else m.set(k, [ep])
    }
    const entries = [...m.entries()].sort((a, b) =>
      group === 'origin' ? host(a[0]).localeCompare(host(b[0])) : a[0].localeCompare(b[0]),
    )
    const out: EpItem[] = []
    for (const [k, list] of entries) {
      const ck = group + ':' + k
      out.push({
        type: 'head',
        key: 'h:' + ck,
        label: group === 'origin' ? (host(k) || '—') : k,
        count: list.length,
        icon: group === 'origin' ? 'globe' : 'lock',
      })
      if (!collapsed[ck]) {
        for (const ep of list) out.push({ type: 'row', key: ep.id, ep })
      }
    }
    return out
  }, [filtered, group, collapsed])

  const ids = useMemo(() => vItems.flatMap(it => it.type === 'row' ? [it.ep.id] : []), [vItems])
  const { index } = useListNav({ ids, kind: 'endpoint' })
  const scrollIdx = useMemo(() => index < 0 ? -1 : vItems.findIndex(it => it.key === ids[index]), [index, vItems, ids])
  useShortcuts([{ key: 'G', run: () => setGroup(group === 'none' ? 'origin' : group === 'origin' ? 'auth' : 'none') }])

  const covered = endpoints.filter(e => (e.coveragePct ?? 0) > 0).length
  const selId = nav.sel?.kind === 'endpoint' ? nav.sel.id : null
  const active = (method ? 1 : 0) + (source ? 1 : 0)
  const height = (it: EpItem) => (it.type === 'head' ? 32 : 36)

  const footer = deps.length > 0
    ? <div className="listnote" style={{ paddingBottom: 12 }} title="Producer → consumer dependencies verified by cross-account checks">
      <Icon name="chain" />{fmtN(deps.length)} endpoint data-flow links · {deps.filter(d => d.testedBola).length} cross-account checks completed. Open an endpoint to inspect its links.
    </div>
    : undefined

  return <>
    <div className="toolbar">
      <span className="sf-tbt num">
        <b>{fmtN(endpoints.length)}</b> endpoints · {fmtN(params.length)} params
        {deps.length > 0 ? ` · ${fmtN(deps.length)} links` : ''}
        {traces.length > 0 ? ` · ${fmtN(traces.length)} runtime traces` : ''}
        {' · '}{covered}/{endpoints.length} covered
      </span>
      <span className="tb-sp" />
      <FilterBox value={q} onChange={setQ} placeholder="Path, host or param" onEnter={() => ids[0] && nav.select({ kind: 'endpoint', id: ids[0] })} />
      <Dropdown icon="sliders" title="Grouping (⇧G cycles) and filters"
        label={<><span className="dim">Group</span><span>{EP_GROUPS.find(g => g[0] === group)?.[1]}</span>{active > 0 && <span className="sf-ddn num">{active}</span>}</>}>
        <div className="dd-sec">Group by<span className="kbd-group" style={{ marginLeft: 'auto' }}><span className="kbd">⇧</span><span className="kbd">G</span></span></div>
        <Seg<EpGroup> value={group} onChange={setGroup} options={EP_GROUPS.map(([value, label]) => ({ value, label }))} />
        <div className="dd-sec">Method</div>
        <div className="sf-chips">{['', ...methods].map(m => <button key={m || 'all'} type="button" className={'sf-chip' + (method === m ? ' on' : '')} onClick={() => setMethod(m)}>{m || 'All'}</button>)}</div>
        <div className="dd-sec">Discovery source</div>
        <div className="sf-chips">{['', ...sources].map(s => <button key={s || 'all'} type="button" className={'sf-chip' + (source === s ? ' on' : '')} onClick={() => setSource(s)}>{s || 'All'}</button>)}</div>
      </Dropdown>
      {modeSeg}
    </div>
    {vItems.length > 0 && <div className="sf-ep-head" aria-hidden="true">
      <span className="c-meth">Method</span>
      <span className="c-path">Endpoint</span>
      {group !== 'auth' && <span className="sf-ep-auth">Auth</span>}
      {group !== 'origin' && <span className="sf-host">Host</span>}
      <span className="c-req">Risk</span>
      <span className="c-dur">Coverage</span>
    </div>}
    <VList
      items={vItems}
      itemKey={it => it.key}
      height={height}
      scrollToIndex={scrollIdx}
      footer={vItems.length ? footer : undefined}
      empty={<EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter.</EmptyState>}
      render={(it, _i, style) => {
        if (it.type === 'head') {
          const ck = it.key.slice(2)
          const col = !!collapsed[ck]
          return <div key={it.key} style={style} className={'ghead sf-ghead' + (col ? ' collapsed' : '')} role="button" tabIndex={-1}
            onClick={() => setCollapsed(c => ({ ...c, [ck]: !col }))}>
            <Icon name="chev" />
            <span className="g muted"><Icon name={it.icon} /></span>
            <span className={it.icon === 'globe' ? 'mono' : ''}>{it.label}</span>
            <span className="ct num">{fmtN(it.count)}</span>
          </div>
        }
        const ep = it.ep
        const ps = byEp.get(ep.id) ?? []
        return <div key={it.key} style={style} className={'row' + (selId === ep.id ? ' cur' : '')} data-id={ep.id}
          onClick={() => nav.select({ kind: 'endpoint', id: ep.id })}>
          <span className="c-meth mono">{ep.method}</span>
          <span className="c-path mono" title={ep.origin + ep.pathTemplate}>
            {ep.pathTemplate}
            {ps.length > 0 && <span className="sf-ep-pnum" title={ps.map(p => p.name + ' (' + p.location + ')').join(', ')}> · {ps.length}p</span>}
          </span>
          {group !== 'auth' && <span className="sf-ep-auth">{ep.authRequirement ? <Tag>{ep.authRequirement}</Tag> : <span className="muted">—</span>}</span>}
          {group !== 'origin' && <span className="mono muted sf-host">{host(ep.origin)}</span>}
          <span className="c-req num" title="Risk score">{ep.riskScore}</span>
          <span className="c-dur num" title="Coverage">{ep.coveragePct != null ? Math.round(ep.coveragePct) + '%' : '—'}</span>
        </div>
      }}
    />
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
        ...(ep.sinkKinds.length ? [['Code sinks', ep.sinkKinds.join(', ')] as [ReactNode, ReactNode]] : []),
        ...(loc ? [['Code', <span className="mono">{loc.file}:{loc.startLine}</span>] as [ReactNode, ReactNode]] : []),
        ['Origin', <span className="mono">{host(ep.origin)}</span>, () => links.host(ep.origin)],
      ]} />
      {ps.length > 0 && <Section title="Parameters" right={ps.length}>
        <table className="hdrs mono"><tbody>{ps.map(p => <tr key={p.id}>
          <td>{p.name}{' '}</td>
          <td>{p.location}{p.inferredType ? ' · ' + p.inferredType : ''}{p.isObjectId ? ' · object id' : ''}{p.isCsrf ? ' · CSRF' : ''}{' '}</td>
        </tr>)}</tbody></table>
      </Section>}
      {deps.length > 0 && <Section title="Cross-account checks" right={deps.length}>
        {deps.map(d => {
          const other = d.producerEndpointId === ep.id ? d.consumerEndpointId : d.producerEndpointId
          return <LinkRow key={d.id} icon="chain" trailing={null} right={<span title="Cross-account object access check">{d.testedBola ? 'Checked' : 'Pending'}</span>}
            sub={[d.resourceKey, d.personaHandle, d.observedTransitions.join(' → ')].filter(Boolean).join(' · ')}
            onClick={() => nav.select({ kind: 'endpoint', id: other }, { push: true })}>
            {d.producerEndpointId === ep.id ? 'Produces for ' : 'Consumes from '}<span className="mono">{label(other)}</span>
          </LinkRow>
        })}
      </Section>}
    </div></PaneBody>
  </>
}
