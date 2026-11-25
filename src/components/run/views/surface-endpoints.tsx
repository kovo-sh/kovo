// Surface → Endpoints: the discovered route inventory (normalised templates,
// parameters, guards, risk / coverage), producer → consumer API dependencies
// and runtime traces. Virtualized with VList, sticky column header, and grouping.
import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { Dropdown, FilterBox, matchQ, VList } from '../controls.tsx'
import { useRun } from '../data.tsx'
import { EmptyState, KbdGroup, LinkRow, Props, Section, Seg, Tag } from '../display.tsx'
import { fmtN, host } from '../format.ts'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { useLinks, useListNav, useNav, useViewState } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'
import { cn, RW } from '../tw.ts'

type EpGroup = 'origin' | 'auth' | 'none'
const EP_GROUPS: [EpGroup, string][] = [['origin', 'Origin'], ['auth', 'Auth'], ['none', 'None']]

const CLASS_LABELS: Record<string, string> = {
  sqli: 'SQL injection',
  sql_injection: 'SQL injection',
  nosqli: 'NoSQL injection',
  xss: 'Cross-site scripting',
  ssrf: 'SSRF',
  csrf: 'CSRF',
  idor: 'IDOR',
  bola: 'Broken object-level access',
  bfla: 'Broken function-level access',
  rce: 'Remote code execution',
  xxe: 'XXE',
  ssti: 'Template injection',
  lfi: 'Local file inclusion',
  path_traversal: 'Path traversal',
  open_redirect: 'Open redirect',
  cors: 'CORS',
  jwt: 'JWT',
  graphql: 'GraphQL',
  cmdi: 'Command injection',
  command_injection: 'Command injection',
  deserialization: 'Deserialization',
  mass_assignment: 'Mass assignment',
  rate_limit: 'Rate limiting',
  race_condition: 'Race condition',
  auth_bypass: 'Auth bypass',
  broken_auth: 'Broken authentication',
  file_upload: 'File upload',
}

const SINK_LABELS: Record<string, string> = {
  sql_query: 'SQL query',
  raw_sql: 'Raw SQL',
  nosql_query: 'NoSQL query',
  command_exec: 'Command execution',
  shell_exec: 'Shell execution',
  file_read: 'File read',
  file_write: 'File write',
  file_access: 'File access',
  path_join: 'Path resolution',
  http_request: 'HTTP request',
  http_fetch: 'HTTP request',
  ssrf_fetch: 'Outbound HTTP',
  template_render: 'Template render',
  html_render: 'HTML render',
  dom_sink: 'DOM sink',
  eval_exec: 'Dynamic eval',
  xml_parse: 'XML parse',
  redirect: 'Redirect',
  deserialize: 'Deserialization',
  ldap_query: 'LDAP query',
}

function humanizeToken(raw: string, dict: Record<string, string>): string {
  const key = raw.trim().toLowerCase()
  if (dict[key]) return dict[key]
  const spaced = raw.replace(/[_-]+/g, ' ').trim()
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : raw
}

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
    ? <div className={cn(RW.listnote, 'pb-3')} title="Producer → consumer dependencies verified by cross-account checks">
      <Icon name="chain" />{fmtN(deps.length)} endpoint data-flow links · {deps.filter(d => d.testedBola).length} cross-account checks completed. Open an endpoint to inspect its links.
    </div>
    : undefined

  return <>
    <div className={RW.toolbar}>
      <span className="min-w-0 truncate whitespace-nowrap text-[12px] tabular-nums text-fg-subtle">
        <b className="font-medium text-fg">{fmtN(endpoints.length)}</b> endpoints · {fmtN(params.length)} params
        {deps.length > 0 ? ` · ${fmtN(deps.length)} links` : ''}
        {traces.length > 0 ? ` · ${fmtN(traces.length)} runtime traces` : ''}
        {' · '}{covered}/{endpoints.length} covered
      </span>
      <span className="min-w-2 flex-1" />
      <FilterBox value={q} onChange={setQ} placeholder="Path, host or param" onEnter={() => ids[0] && nav.select({ kind: 'endpoint', id: ids[0] })} />
      <Dropdown icon="sliders" title="Grouping (⇧G cycles) and filters"
        label={<><span className="text-fg-subtle">Group</span><span>{EP_GROUPS.find(g => g[0] === group)?.[1]}</span>{active > 0 && <span className="inline-grid h-4 min-w-4 place-items-center rounded-[8px] bg-press px-1 text-[10.5px] font-semibold tabular-nums text-fg">{active}</span>}</>}>
        <div className={RW.ddSec}>Group by<KbdGroup keys={['⇧', 'G']} className="ml-auto" /></div>
        <Seg<EpGroup> fullWidth value={group} onChange={setGroup} options={EP_GROUPS.map(([value, label]) => ({ value, label }))} />
        <div className={RW.ddSec}>Method</div>
        <div className="flex flex-wrap gap-1">{['', ...methods].map(m => <button key={m || 'all'} type="button" className={cn(RW.chip, method === m && RW.chipOn)} onClick={() => setMethod(m)}>{m || 'All'}</button>)}</div>
        <div className={RW.ddSec}>Discovery source</div>
        <div className="flex flex-wrap gap-1">{['', ...sources].map(s => <button key={s || 'all'} type="button" className={cn(RW.chip, source === s && RW.chipOn)} onClick={() => setSource(s)}>{s || 'All'}</button>)}</div>
      </Dropdown>
      {modeSeg}
    </div>
    {vItems.length > 0 && <div className="flex h-7 flex-none select-none items-center gap-2.5 border-b border-line bg-sunk px-[18px] text-[11px] font-medium tracking-[0.01em] text-fg-subtle" aria-hidden="true">
      <span className="w-[46px] flex-none">Method</span>
      <span className="min-w-0 flex-1 truncate">Endpoint</span>
      {group !== 'auth' && <span className="inline-flex w-[120px] min-w-0 flex-none items-center overflow-hidden">Auth</span>}
      {group !== 'origin' && <span className="w-[160px] flex-none truncate">Host</span>}
      <span className="w-[52px] flex-none text-right">Risk</span>
      <span className="w-[56px] flex-none text-right">Coverage</span>
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
          return <div key={it.key} style={style} className={cn(RW.ghead, 'absolute')} role="button" tabIndex={-1}
            onClick={() => setCollapsed(c => ({ ...c, [ck]: !col }))}>
            <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-guardian', col && '-rotate-90')} />
            <span className="inline-flex size-3.5 flex-none items-center justify-center text-fg-subtle"><Icon name={it.icon} /></span>
            <span className={it.icon === 'globe' ? 'font-mono text-[12px]' : undefined}>{it.label}</span>
            <span className="font-normal tabular-nums text-fg-subtle">{fmtN(it.count)}</span>
          </div>
        }
        const ep = it.ep
        const ps = byEp.get(ep.id) ?? []
        return <div key={it.key} style={style} className={cn(RW.row, selId === ep.id && RW.rowCur)} data-id={ep.id}
          onClick={() => nav.select({ kind: 'endpoint', id: ep.id })}>
          <span className="w-[46px] flex-none font-mono text-[12px] font-medium text-fg-muted">{ep.method}</span>
          <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-fg" title={ep.origin + ep.pathTemplate}>
            {ep.pathTemplate}
            {ps.length > 0 && <span className="text-[11px] text-fg-subtle" title={ps.map(p => p.name + ' (' + p.location + ')').join(', ')}> · {ps.length}p</span>}
          </span>
          {group !== 'auth' && <span className="inline-flex w-[120px] min-w-0 flex-none items-center overflow-hidden">{ep.authRequirement ? <Tag>{ep.authRequirement}</Tag> : <span className="text-fg-subtle">—</span>}</span>}
          {group !== 'origin' && <span className="w-[160px] flex-none truncate font-mono text-[12px] text-fg-subtle">{host(ep.origin)}</span>}
          <span className="w-[52px] flex-none text-right tabular-nums text-fg-subtle" title="Risk score">{ep.riskScore}</span>
          <span className="w-[56px] flex-none text-right tabular-nums text-fg-subtle" title="Coverage">{ep.coveragePct != null ? Math.round(ep.coveragePct) + '%' : '—'}</span>
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
    <PaneHeader title="Endpoint" sub={<span className="font-mono text-[12px]">{ep.method}</span>} />
    <PaneBody><div className={RW.detail}>
      <div className="mb-2.5 flex flex-wrap gap-1.5">
        <Tag>{ep.source}</Tag>
        {ep.framework && <Tag>{ep.framework}</Tag>}
        {ep.authRequirement && <Tag icon="lock">{ep.authRequirement}</Tag>}
        {ep.ownershipGuard && <Tag icon="shield">{ep.ownershipGuard}</Tag>}
      </div>
      <h2 className="m-0 mb-3 break-all font-mono text-[13px] font-semibold leading-[22px] text-fg"><span className="text-fg-subtle">{ep.origin}</span>{ep.pathTemplate}</h2>
      <Props rows={[
        ['Risk score', <span className="tabular-nums">{ep.riskScore}</span>],
        ['Coverage', ep.coveragePct != null ? Math.round(ep.coveragePct) + '%' : '—'],
        ['Tested', ep.testedClasses.length ? <span className="rw-wrap whitespace-normal break-words leading-[18px]">{ep.testedClasses.map(c => humanizeToken(c, CLASS_LABELS)).join(', ')}</span> : 'Nothing yet'],
        ...(ep.sinkKinds.length ? [['Code sinks', <span className="rw-wrap whitespace-normal break-words leading-[18px]">{ep.sinkKinds.map(s => humanizeToken(s, SINK_LABELS)).join(', ')}</span>] as [ReactNode, ReactNode]] : []),
        ...(loc ? [['Code', <span className="font-mono text-[12px]">{loc.file}:{loc.startLine}</span>] as [ReactNode, ReactNode]] : []),
        ['Origin', <span className="font-mono text-[12px]">{host(ep.origin)}</span>, () => links.host(ep.origin)],
      ]} />
      {ps.length > 0 && <Section title="Parameters" right={ps.length}>
        <table className={cn(RW.hdrs, 'font-mono text-[12px]')}><tbody>{ps.map(p => <tr key={p.id}>
          <td className="w-[42%] break-all border-b border-line py-[3px] pr-2.5 align-top text-[11.5px] leading-[17px] text-fg-subtle">{p.name}{' '}</td>
          <td className="break-all border-b border-line py-[3px] align-top text-[11.5px] leading-[17px] text-fg-muted">{p.location}{p.inferredType ? ' · ' + p.inferredType : ''}{p.isObjectId ? ' · object id' : ''}{p.isCsrf ? ' · CSRF' : ''}{' '}</td>
        </tr>)}</tbody></table>
      </Section>}
      {deps.length > 0 && <Section title="Cross-account checks" right={deps.length}>
        {deps.map(d => {
          const other = d.producerEndpointId === ep.id ? d.consumerEndpointId : d.producerEndpointId
          return <LinkRow key={d.id} icon="chain" trailing={null} right={<span title="Cross-account object access check">{d.testedBola ? 'Checked' : 'Pending'}</span>}
            sub={[d.resourceKey, d.personaHandle, d.observedTransitions.join(' → ')].filter(Boolean).join(' · ')}
            onClick={() => nav.select({ kind: 'endpoint', id: other }, { push: true })}>
            {d.producerEndpointId === ep.id ? 'Produces for ' : 'Consumes from '}<span className="font-mono text-[12px]">{label(other)}</span>
          </LinkRow>
        })}
      </Section>}
    </div></PaneBody>
  </>
}
