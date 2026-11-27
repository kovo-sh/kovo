// Exchanges: every brokered request, allowed or denied, newest first.
// Rows come from the detail's newest-500 window, then the `broker.exchange`
// event log for anything older (so the list covers the whole run), plus
// `broker.denied` events. Text search also runs server-side
// (`searchRunExchanges`: path, body and headers) and merges the hits.
// The inspector loads headers and body with `readExchange` on demand.
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { searchRunExchanges } from '../../../actions.ts'
import { formatExchangeAsCurl } from '../../curl-parser.ts'
import { Dropdown, FilterBox, matchQ, Tabs, useDebounced, VList } from '../controls.tsx'
import { useFullExchange, useRun, useRunModel } from '../data.tsx'
import { EmptyState, KbdGroup, LinkRow, Props, Section, Seg, Skeleton, Tag } from '../display.tsx'
import { fmtAgo, fmtFullDateTime, fmtN, fmtRel, fmtTimeS, host, plural, prettyBody } from '../format.ts'
import { SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { CHECK_HEADERS, normFStatus, PHASE_LABEL, stLabel } from '../meta.ts'
import type { RunEvent } from '../model.ts'
import { useLinks, useListNav, useNav, useViewState } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorMap, InspectorProps } from '../pane.tsx'
import { useToast } from '../toast.tsx'
import { cn, httpCodeClass, runBtn, runDdItem, runIconBtn, RW } from '../tw.ts'

type SearchHit = Awaited<ReturnType<typeof searchRunExchanges>>[number]

export interface XRow {
  id: string
  denied: boolean
  method: string
  status: number
  origin: string
  path: string
  persona: string | null
  dur: number | null
  t: number
  worker: string | null
  /** Reconstructed from the event log: headers/body load on open. */
  partial: boolean
  eventId?: number
  note?: string
  reason?: string | null
}

type Tab = 'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'denied'
type Group = 'none' | 'origin' | 'persona'
const bucket = (r: XRow): Tab => r.denied ? 'denied' : r.status >= 500 ? '5xx' : r.status >= 400 ? '4xx' : r.status >= 300 ? '3xx' : '2xx'
const str = (v: unknown) => (typeof v === 'string' && v.length > 0 ? v : null)

/** Convert a `broker.denied` / `broker.circuit_open` event into an Exchanges row, surfacing structured detail fields when present. */
export function deniedEventToRow(ev: RunEvent): XRow {
  const d = ev.detail ?? {}
  const method = str(d.method) ?? '—'
  const path = str(d.path) ?? str(d.pathAndQuery) ?? ''
  const persona = str(d.persona) ?? str(d.personaHandle) ?? null
  const reason = str(d.reason) ?? null
  return {
    id: 'ev:' + ev.id,
    denied: true,
    method,
    status: Number(d.status ?? 0),
    origin: str(d.origin) ?? '',
    path,
    persona,
    dur: null,
    t: ev.createdAt,
    worker: str(d.assignmentId),
    partial: false,
    eventId: ev.id,
    note: reason ?? ev.message,
    reason,
  }
}

/** Every exchange row we can show without fetching: summary window + event log + denials. */
function useExchangeRows(hits: SearchHit[]) {
  const { detail, events } = useRun()
  return useMemo(() => {
    const out: XRow[] = []
    const seen = new Set<string>()
    for (const e of detail.exchangesSummary) {
      seen.add(e.id)
      out.push({ id: e.id, denied: false, method: e.method, status: e.status, origin: e.origin, path: e.pathAndQuery, persona: e.personaHandle, dur: e.durationMs, t: e.createdAt, worker: e.assignmentId, partial: false })
    }
    for (const h of hits) {
      if (seen.has(h.id)) continue
      seen.add(h.id)
      out.push({ id: h.id, denied: false, method: h.method, status: h.status, origin: h.origin, path: h.pathAndQuery, persona: h.personaHandle, dur: h.durationMs, t: h.createdAt, worker: h.assignmentId, partial: false })
    }
    for (const ev of events) {
      if (ev.kind === 'broker.exchange') {
        const id = str(ev.detail.exchangeId)
        if (!id || seen.has(id)) continue
        seen.add(id)
        const origin = str(ev.detail.origin) ?? ''
        const m = ev.message.match(/^(\S+) (.*) → (\d+)$/)
        const target = m?.[2] ?? ''
        const path = target.startsWith(origin) ? target.slice(origin.length) : target
        out.push({ id, denied: false, method: m?.[1] ?? '—', status: Number(ev.detail.status ?? m?.[3] ?? 0), origin, path: path || '/', persona: str(ev.detail.personaHandle), dur: null, t: ev.createdAt, worker: str(ev.detail.assignmentId), partial: true, eventId: ev.id })
      } else if (ev.kind === 'broker.denied' || ev.kind === 'broker.circuit_open') {
        out.push(deniedEventToRow(ev))
      }
    }
    out.sort((a, b) => b.t - a.t || (b.eventId ?? 0) - (a.eventId ?? 0))
    return out
  }, [detail.exchangesSummary, events, hits])
}

type Item = { type: 'head'; key: string; label: string; count: number; icon: 'globe' | 'lock' } | { type: 'row'; key: string; r: XRow }

export function ExchangesView() {
  const { detail, counts, eventsReady } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const [tab, setTab] = useViewState<Tab>('exchanges.tab', 'all')
  const [group, setGroup] = useViewState<Group>('exchanges.group', 'none')
  const [q, setQ] = useViewState('exchanges.q', '')
  const [method, setMethod] = useViewState('exchanges.method', '')
  const [origin, setOrigin] = useViewState('exchanges.origin', '')
  const [persona, setPersona] = useViewState('exchanges.persona', '')
  const [collapsed, setCollapsed] = useViewState<Record<string, boolean>>('exchanges.collapsed', {})

  // Server-side search (bodies and headers too), merged into the rows.
  const dq = useDebounced(q.trim(), 260)
  const [search, setSearch] = useState<{ q: string; origin: string; hits: SearchHit[]; busy: boolean; error?: boolean }>({ q: '', origin: '', hits: [], busy: false })
  useEffect(() => {
    if (dq.length < 3) { setSearch({ q: '', origin: '', hits: [], busy: false }); return }
    let live = true
    setSearch(s => ({ ...s, busy: true }))
    searchRunExchanges({ data: { runId: detail.run.id, query: dq, origin: origin || undefined, limit: 100 } })
      .then(hits => { if (live) setSearch({ q: dq, origin, hits, busy: false }) },
        () => { if (live) setSearch({ q: dq, origin, hits: [], busy: false, error: true }) })
    return () => { live = false }
  }, [dq, origin, detail.run.id])
  const hitIds = useMemo(() => new Set(search.hits.map(h => h.id)), [search.hits])
  const rows = useExchangeRows(search.hits)

  // facets
  const facets = useMemo(() => {
    const methods = new Map<string, number>(), origins = new Map<string, number>(), personas = new Map<string, number>()
    for (const r of rows) {
      if (r.method && r.method !== '—') methods.set(r.method, (methods.get(r.method) ?? 0) + 1)
      if (r.origin) origins.set(r.origin, (origins.get(r.origin) ?? 0) + 1)
      if (!r.denied || r.persona) { const p = r.persona ?? ''; personas.set(p, (personas.get(p) ?? 0) + 1) }
    }
    const sorted = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    return { methods: sorted(methods), origins: sorted(origins), personas: sorted(personas) }
  }, [rows])

  const base = useMemo(() => rows.filter(r =>
    (!method || r.method === method) && (!origin || r.origin === origin) && (!persona || (persona === '-' ? !r.persona && !r.denied : r.persona === persona))
    && (!q.trim() || hitIds.has(r.id) || matchQ(q, [r.method, host(r.origin), r.path, r.status, r.persona ?? 'anonymous', r.denied ? 'denied' : 'allowed', r.reason ?? '', r.note ?? ''].join(' ')))), [rows, method, origin, persona, q, hitIds])
  const tabs = useMemo(() => {
    const t: Record<string, number> = { all: base.length }
    base.forEach(r => { const b = bucket(r); t[b] = (t[b] ?? 0) + 1 })
    return ([['all', 'All'], ['2xx', '2xx'], ['3xx', '3xx'], ['4xx', '4xx'], ['5xx', '5xx'], ['denied', 'Denied']] as [Tab, string][])
      .filter(([k]) => t[k] || k === tab).map(([k, l]) => [k, l, t[k] ?? 0] as [Tab, string, number])
  }, [base, tab])
  const shown = useMemo(() => tab === 'all' ? base : base.filter(r => bucket(r) === tab), [base, tab])

  const items = useMemo<Item[]>(() => {
    if (group === 'none') return shown.map(r => ({ type: 'row', key: r.id, r }))
    const m = new Map<string, XRow[]>()
    shown.forEach(r => { const k = group === 'origin' ? r.origin : (r.persona ?? (r.denied ? '(denied)' : '')); m.set(k, [...(m.get(k) ?? []), r]) })
    const out: Item[] = []
    ;[...m.entries()].sort((a, b) => group === 'origin' ? host(a[0]).localeCompare(host(b[0])) : a[0].localeCompare(b[0])).forEach(([k, list]) => {
      const ck = group + ':' + k
      out.push({ type: 'head', key: 'h:' + ck, label: group === 'origin' ? host(k) || '—' : k === '' ? 'Anonymous' : k === '(denied)' ? 'Denied (no test account)' : k, count: list.length, icon: group === 'origin' ? 'globe' : 'lock' })
      if (!collapsed[ck]) list.forEach(r => out.push({ type: 'row', key: r.id, r }))
    })
    return out
  }, [shown, group, collapsed])
  const ids = useMemo(() => items.flatMap(it => it.type === 'row' ? [it.r.id] : []), [items])
  const { index } = useListNav({ ids, kind: 'exchange' })
  const scrollIdx = useMemo(() => index < 0 ? -1 : items.findIndex(it => it.key === ids[index]), [index, items, ids])
  useShortcuts([{ key: 'G', run: () => setGroup(group === 'none' ? 'origin' : group === 'origin' ? 'persona' : 'none') }])
  const selId = nav.sel?.kind === 'exchange' ? nav.sel.id : null
  const active: [string, string, () => void][] = [
    ...(method ? [['Method', method, () => setMethod('')] as [string, string, () => void]] : []),
    ...(origin ? [['Origin', host(origin), () => setOrigin('')] as [string, string, () => void]] : []),
    ...(persona ? [['Test account', persona === '-' ? 'Anonymous' : persona, () => setPersona('')] as [string, string, () => void]] : []),
  ]
  const allowedCount = rows.filter(r => !r.denied).length
  const height = (it: Item) => (it.type === 'head' ? 32 : 36)

  if (!rows.length && eventsReady && !counts.exchanges) {
    return <EmptyState icon="exchanges" title="No exchanges yet"
      action={detail.run.status === 'waiting' ? <button type="button" className={runBtn()} onClick={() => nav.setView('overview')}>Review scope</button> : undefined}>
      Every request a worker makes passes through the safety proxy and is logged here, whether allowed or blocked.
    </EmptyState>
  }

  const missing = Math.max(0, counts.exchanges - allowedCount)
  const footer = <div className={RW.listnote}>
    <Icon name="exchanges" />
    {missing > 0
      ? <span>{fmtN(allowedCount)} of {fmtN(counts.exchanges)} exchanges loaded{!eventsReady ? '; the event log is still replaying' : ''}.</span>
      : <span>All {fmtN(counts.exchanges)} HTTP exchanges{rows.length > allowedCount ? ` and ${plural(rows.length - allowedCount, 'blocked request')}` : ''}. Rows older than the newest {fmtN(detail.exchangesSummary.length)} load their headers when opened.</span>}
  </div>

  return <>
    <div className={RW.toolbar}>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <FilterBox value={q} onChange={setQ} placeholder="Filter" onEnter={() => ids[0] && nav.select({ kind: 'exchange', id: ids[0] })} />
      <Dropdown icon="sliders" title="Grouping (⇧G cycles) and filters" menuClassName="w-[320px]"
        label={<><span className="text-fg-subtle">Group</span><span>{group === 'none' ? 'Time' : group === 'origin' ? 'Origin' : 'Test account'}</span>{active.length > 0 && <span className="inline-grid h-4 min-w-4 place-items-center rounded-[8px] bg-press px-1 text-[10.5px] font-semibold tabular-nums text-fg">{active.length}</span>}</>}>
        <div className={RW.ddSec}>Grouping<KbdGroup keys={['⇧', 'G']} className="ml-auto" /></div>
        <Seg<Group> fullWidth value={group} onChange={setGroup} options={[{ value: 'none', label: 'Time' }, { value: 'origin', label: 'Origin' }, { value: 'persona', label: 'Test account' }]} />
        <div className={RW.ddSec}>Method</div>
        <div className="flex flex-wrap gap-1">{[['', rows.filter(r => !r.denied).length] as [string, number], ...facets.methods].map(([m, n]) =>
          <button key={m || 'all'} type="button" className={cn(RW.chip, method === m && RW.chipOn)} onClick={() => setMethod(m)}>{m || 'All'}<span className="text-[11px] tabular-nums text-fg-subtle">{fmtN(n)}</span></button>)}</div>
        <div className={RW.ddSec}>Test account</div>
        <div className="flex flex-wrap gap-1">{[['', 0] as [string, number], ...facets.personas].map(([p, n]) => {
          const v = p === '' && n ? '-' : p
          return <button key={v || 'all'} type="button" className={cn(RW.chip, persona === v && RW.chipOn)} onClick={() => setPersona(v)}>
            {v === '' ? 'All' : v === '-' ? 'Anonymous' : v}{n > 0 && <span className="text-[11px] tabular-nums text-fg-subtle">{fmtN(n)}</span>}</button>
        })}</div>
        <div className={RW.ddSec}>Origin<span className="ml-auto font-normal tabular-nums">{facets.origins.length}</span></div>
        <div className="-mx-1 max-h-[240px] overflow-auto px-1">
          <button type="button" className={cn(runDdItem({ active: !origin }), 'h-7')} onClick={() => setOrigin('')}>All origins</button>
          {facets.origins.map(([o, n]) => <button key={o} type="button" className={cn(runDdItem({ active: origin === o }), 'h-7')} onClick={() => setOrigin(o)}>
            <span className="min-w-0 flex-1 truncate font-mono text-[12px]">{host(o)}</span><span className="ml-auto tabular-nums text-fg-subtle">{fmtN(n)}</span>
          </button>)}
        </div>
      </Dropdown>
    </div>
    {(active.length > 0 || search.busy || search.q) && <div className={cn(RW.strip, 'min-h-9 gap-2 py-1.5 pl-[18px] pr-3')}>
      {active.map(([k, v, clear]) => <span key={k} className="inline-flex h-[22px] items-center gap-1.5 rounded-[5px] bg-sunk pl-2 pr-1 text-[12px] text-fg shadow-[inset_0_0_0_1px_var(--line)]">
        <span className="text-fg-subtle">{k}</span><span className="font-mono text-[12px]">{v}</span>
        <button type="button" className="inline-flex h-auto cursor-pointer items-center justify-center rounded-[3px] border-0 bg-transparent p-0.5 text-fg-subtle shadow-none hover:bg-hover hover:text-fg" aria-label={'Clear ' + k} onClick={clear}><Icon name="close" size={11} /></button>
      </span>)}
      {search.busy ? <span className="text-fg-subtle">Searching paths, bodies and headers…</span>
        : search.q ? <span className="text-fg-subtle">{search.error ? 'Server search failed; showing local matches.' : search.hits.length >= 100 ? 'Server search stops at 100 matches in paths, bodies and headers; more may exist. Refine the query or add a filter to narrow it.' : `Server search: ${plural(search.hits.length, 'match', 'matches')} in paths, bodies and headers.`}</span> : null}
      <span className="min-w-2 flex-1" />
      {active.length > 0 && <button type="button" className={runBtn({ variant: 'link', size: 'none' })} onClick={() => { setMethod(''); setOrigin(''); setPersona('') }}>Clear filters</button>}
    </div>}
    {!rows.length && !eventsReady ? <Skeleton /> :
      <VList items={items} itemKey={it => it.key} height={height} scrollToIndex={scrollIdx} footer={shown.length ? footer : undefined}
        empty={<EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter or switch tabs.</EmptyState>}
        render={(it, _i, style) => {
          if (it.type === 'head') {
            const ck = it.key.slice(2)
            const col = !!collapsed[ck]
            return <div key={it.key} style={style} className={cn(RW.ghead, 'absolute')} role="button" tabIndex={-1} onClick={() => setCollapsed(c => ({ ...c, [ck]: !col }))}>
              <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', col && '-rotate-90')} />
              <span className="inline-flex size-3.5 flex-none items-center justify-center text-fg-subtle"><Icon name={it.icon} /></span>
              <span className={it.icon === 'globe' ? 'font-mono text-[12px]' : undefined}>{it.label}</span>
              <span className="font-normal tabular-nums text-fg-subtle">{fmtN(it.count)}</span>
            </div>
          }
          const r = it.r
          return <div key={it.key} style={style} className={cn(RW.row, selId === r.id && RW.rowCur)} data-id={r.id}
            onClick={() => nav.select({ kind: 'exchange', id: r.id })}>
            <span className="w-16 flex-none font-mono text-[12px] tabular-nums text-fg-subtle">{fmtRel(r.t, model.base)}</span>
            <span className={cn('w-[46px] flex-none font-mono text-[12px] font-medium', r.denied && r.method === '—' ? 'text-fg-faint' : 'text-fg-muted')}>{r.method}</span>
            <span className={cn('w-[34px] flex-none text-right font-mono text-[12px] tabular-nums', r.denied ? 'inline-flex justify-end text-danger' : httpCodeClass(r.status))}>
              {r.denied ? <Icon name="slash" size={13} /> : r.status}
            </span>
            {group !== 'origin' && <span className="max-w-[190px] flex-none truncate font-mono text-[12px] text-fg-subtle">{host(r.origin)}</span>}
            <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-fg" title={r.denied ? [r.path, r.reason ?? r.note].filter(Boolean).join(' · ') : r.path}>
              {r.denied
                ? r.path
                  ? <><span className="font-mono text-[12px] text-fg">{r.path}</span><span className="ml-2 font-sans text-[12.5px] text-danger">{r.reason ?? r.note ?? 'Blocked by safety rules'}</span></>
                  : <span className="font-sans text-[13px] text-danger">{r.reason ?? r.note ?? 'Blocked by safety rules'}</span>
                : r.path}
            </span>
            {r.persona && group !== 'persona' && <span className="flex-none"><Tag icon="lock">{r.persona}</Tag></span>}
            {hitIds.has(r.id) && <span className="inline-flex flex-none text-fg-subtle" title="Matched in the body or headers by server search"><Icon name="search" size={12} /></span>}
            <span className="w-[56px] flex-none text-right font-mono text-[12px] tabular-nums text-fg-subtle">{r.dur != null ? fmtN(r.dur) + 'ms' : ''}</span>
          </div>
        }} />}
  </>
}

// ---------------------------------------------------------------- inspector

/** Response headers that matter for security review (highlighted in the table). */
const SECURITY_HEADERS = new Set([
  'strict-transport-security', 'content-security-policy', 'content-security-policy-report-only', 'x-content-type-options',
  'x-frame-options', 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy',
  'cross-origin-resource-policy', 'access-control-allow-origin', 'access-control-allow-credentials', 'access-control-allow-methods',
  'access-control-allow-headers', 'set-cookie', 'server', 'x-powered-by', 'via', 'www-authenticate',
])
const BASELINE: [string, string][] = [
  ['strict-transport-security', 'HSTS'], ['content-security-policy', 'CSP'], ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'Frame options'], ['referrer-policy', 'Referrer policy'],
]

function HeaderTable({ headers, flagged }: { headers: Record<string, string> | undefined; flagged: Set<string> }) {
  const ks = Object.keys(headers ?? {})
  if (!ks.length) return <p className="text-fg-subtle!">None recorded</p>
  return <table className={cn(RW.hdrs, 'font-mono text-[12px]')}><tbody>{ks.map(k => {
    const lk = k.toLowerCase()
    const isFlag = flagged.has(lk)
    const isSec = !isFlag && SECURITY_HEADERS.has(lk)
    return <tr key={k}>
      <td className={cn(
        'w-[42%] break-all border-b border-line py-[3px] pr-2.5 align-top text-[11.5px] leading-[17px]',
        isFlag
          ? 'bg-warn-soft font-medium text-warn before:mb-px before:mr-1.5 before:inline-block before:size-[5px] before:rounded-full before:bg-warn before:align-middle before:content-[""]'
          : isSec
            ? 'text-fg before:mb-px before:mr-1.5 before:inline-block before:size-[5px] before:rounded-full before:bg-fg-subtle before:align-middle before:content-[""]'
            : 'text-fg-subtle',
      )}>{k}</td>
      <td className={cn('break-all border-b border-line py-[3px] align-top text-[11.5px] leading-[17px] text-fg-muted', isFlag && 'bg-warn-soft')}>
        {String(headers![k])}
      </td>
    </tr>
  })}</tbody></table>
}

function ExchangeInspector({ sel }: InspectorProps) {
  const { detail, events } = useRun()
  const model = useRunModel()
  const links = useLinks()
  const toast = useToast()
  const id = sel.id
  const denied = id.startsWith('ev:')
  const ev: RunEvent | undefined = useMemo(() => denied ? events.find(e => e.id === Number(id.slice(3))) : undefined, [denied, events, id])
  const sum = model.exchangeById.get(id)
  const loaded = useFullExchange(id, !denied)
  const full = loaded ?? undefined
  const err = loaded === null
  const [bodyAll, setBodyAll] = useState(false)

  if (denied) {
    const row = ev ? deniedEventToRow(ev) : null
    const origin = row?.origin ?? ''
    const method = row && row.method !== '—' ? row.method : null
    const path = row?.path || null
    const persona = row?.persona ?? null
    const reason = row?.reason ?? null
    const w = ev ? model.workerById.get(str(ev.detail.assignmentId) ?? '') : undefined
    return <>
      <PaneHeader title="Blocked request" sub={ev ? <span title={`${fmtFullDateTime(ev.createdAt)} · Event #${ev.id}`} suppressHydrationWarning>{fmtAgo(ev.createdAt)}</span> : undefined} />
      <PaneBody><div className={RW.detail}>
        {!ev ? <Skeleton rows={4} /> : <>
          <div className="mb-2.5 flex flex-wrap gap-1.5">
            <Tag icon="slash" title={ev.kind}>{ev.kind === 'broker.circuit_open' ? 'Rate limit pause' : 'Blocked by safety proxy'}</Tag>
            {method && <Tag mono>{method}</Tag>}
            {persona && <Tag icon="lock">{persona}</Tag>}
          </div>
          {path
            ? <h2 className="m-0 mb-3 break-all font-mono text-[13px] font-medium leading-5 text-fg"><span className="text-fg-subtle">{origin}</span>{path}</h2>
            : <h2 className="m-0 mb-3 break-words text-[14px] font-medium leading-[21px] text-fg">{reason ?? ev.message}</h2>}
          <Props rows={[
            ['Time', <span className="tabular-nums" title={fmtFullDateTime(ev.createdAt)}>{fmtTimeS(ev.createdAt)} <span className="font-mono text-[12px] text-fg-subtle">{fmtRel(ev.createdAt, model.base)}</span></span>],
            ...(reason ? [['Reason', <span className="text-danger">{reason}</span>] as [ReactNode, ReactNode]] : []),
            ...(method ? [['Method', <span className="font-mono text-[12px]">{method}</span>] as [ReactNode, ReactNode]] : []),
            ...(path ? [['Path', <span className="font-mono text-[12px] break-all">{path}</span>] as [ReactNode, ReactNode]] : []),
            ...(persona ? [['Test account', <span className="font-mono text-[12px]">{persona}</span>] as [ReactNode, ReactNode]] : []),
            ...(origin ? [['Origin', <span className="font-mono text-[12px]">{host(origin)}</span>, () => links.host(origin)] as [ReactNode, ReactNode, () => void]] : []),
            ...(w ? [['Worker', <><StatusGlyph status={w.status} /><span className="min-w-0 truncate">{w.title}</span><Icon name="workflow" /></>, () => links.worker(w.id)] as [ReactNode, ReactNode, () => void]] : []),
          ]} />
          <p className="my-1.5 mb-2 flex items-center gap-1.5 text-[12px] leading-[18px] text-fg-subtle">{reason ? ev.message : 'The safety proxy blocked this request before it left Kovo: the host is outside the approved scope or paused by a safety pause. Nothing was sent.'}</p>
          <Section title="Related"><LinkRow icon="activity" onClick={() => links.event(ev.id)}>Open in Activity</LinkRow></Section>
        </>}
      </div></PaneBody>
    </>
  }

  const evRow = !sum && !full ? events.find(e => e.kind === 'broker.exchange' && e.detail.exchangeId === id) : undefined
  const method = full?.method ?? sum?.method ?? evRow?.message.split(' ')[0] ?? ''
  const status = full?.status ?? sum?.status ?? Number(evRow?.detail.status ?? 0)
  const origin = full?.origin ?? sum?.origin ?? str(evRow?.detail.origin) ?? ''
  const path = full?.pathAndQuery ?? sum?.pathAndQuery ?? ''
  const persona = full ? full.personaHandle : sum ? sum.personaHandle : str(evRow?.detail.personaHandle)
  const dur = full?.durationMs ?? sum?.durationMs
  const t = full?.createdAt ?? sum?.createdAt ?? evRow?.createdAt
  const wid = full?.assignmentId ?? sum?.assignmentId ?? str(evRow?.detail.assignmentId)
  const w = wid ? model.workerById.get(wid) : undefined
  const finalOrigin = full?.finalOrigin ?? sum?.finalOrigin
  const redirects = full?.redirectOrigins ?? sum?.redirectOrigins ?? []
  const mediaType = full?.mediaType ?? sum?.mediaType ?? ''
  const fs = model.exchangeFindings.get(id) ?? []
  const evIds = [...new Set(fs.flatMap(f => f.evidenceIds))].filter(e => model.evidenceById.has(e))
  const bodyArt = full?.bodyArtifactId ?? sum?.bodyArtifactId
  const iast = (detail.labTelemetry ?? []).filter(x => x.exchangeId === id)
  // headers a citing finding's check inspects
  const flagged = new Set(fs.flatMap(f => CHECK_HEADERS[f.check?.id ?? ''] ?? []))
  const resp = full?.respHeaders ?? {}
  const respKeys = new Set(Object.keys(resp).map(k => k.toLowerCase()))
  const body = full ? prettyBody(full.body, mediaType) : sum ? prettyBody(sum.bodyPreview, mediaType) : ''
  const CAP = 12000
  const copyCurl = () => {
    const cmd = formatExchangeAsCurl({ method, origin, pathAndQuery: path, reqHeaders: full?.reqHeaders, personaHandle: persona })
    void navigator.clipboard?.writeText(cmd).then(() => toast.show('Copied as cURL', { icon: 'check', sub: full ? 'Sanitized request headers included' : 'Headers still loading; URL only' }),
      () => toast.show('Could not copy to the clipboard', { tone: 'error' }))
  }
  return <>
    <PaneHeader
      title="HTTP exchange"
      sub={
        <span
          title={`${method ? method + ' ' : ''}${origin}${path}${t ? ' · ' + fmtFullDateTime(t) : ''} · ID ${id}`}
          suppressHydrationWarning
        >
          {[method || null, status || null, t ? fmtAgo(t) : null].filter(Boolean).join(' · ') || 'Details'}
        </span>
      }
      extra={<button type="button" className={runIconBtn()} title="Copy as cURL" aria-label="Copy as cURL" onClick={copyCurl}><Icon name="copy" />cURL</button>}
    />
    <PaneBody><div className={RW.detail}>
      <div className="mb-2.5 flex flex-wrap gap-1.5">
        <Tag mono>{method || '—'}</Tag>
        <Tag mono className={httpCodeClass(status)}>{status || '—'}</Tag>
        {persona ? <Tag icon="lock">{persona}</Tag> : <Tag>Anonymous</Tag>}
        {dur != null && <Tag className="tabular-nums">{fmtN(dur)} ms</Tag>}
      </div>
      <h2 className="m-0 mb-3 break-all font-mono text-[13px] font-medium leading-5 text-fg"><span className="text-fg-subtle">{origin}</span>{path || (full ? '' : '…')}</h2>
      <Props rows={[
        ...(t ? [['Time', <span className="tabular-nums">{fmtTimeS(t)} <span className="font-mono text-[12px] text-fg-subtle">{fmtRel(t, model.base)}</span></span>] as [ReactNode, ReactNode]] : []),
        ['Origin', <span className="font-mono text-[12px]">{host(origin)}</span>, () => links.host(origin)],
        ...(finalOrigin && finalOrigin !== origin ? [['Final origin', <span className="font-mono text-[12px]">{host(finalOrigin)}</span>] as [ReactNode, ReactNode]] : []),
        ...(redirects.some(x => x !== origin && x !== finalOrigin) ? [['Redirects', <span className="rw-wrap whitespace-normal break-words font-mono text-[12px] leading-[18px]">{redirects.map(host).join(' → ')}</span>] as [ReactNode, ReactNode]] : []),
        ['Media type', <span className="font-mono text-[12px]">{mediaType || (full ? '—' : '…')}</span>],
        ...(w ? [['Worker', <><StatusGlyph status={w.status} /><span className="min-w-0 truncate">{w.title}</span><Icon name="workflow" /></>, () => links.worker(w.id)] as [ReactNode, ReactNode, () => void]] : []),
      ]} />
      {fs.length > 0 && <Section title="Cited by" right={plural(fs.length, 'finding')}>
        {fs.map(f => <LinkRow key={f.id} glyph={<SevGlyph sev={f.severity} />} right={stLabel(normFStatus(f.status))} onClick={() => links.finding(f.id)}>{f.title}</LinkRow>)}
      </Section>}
      {(evIds.length > 0 || (bodyArt && model.evidenceById.has(bodyArt))) && <Section title="Evidence" right={evIds.length || 1}>
        {(bodyArt && model.evidenceById.has(bodyArt) && !evIds.includes(bodyArt) ? [bodyArt, ...evIds] : evIds).slice(0, 8).map(e => {
          const evd = model.evidenceById.get(e)!
          return <LinkRow key={e} icon="fact" right={evd.kind} trailing="chevR" onClick={() => links.evidence(e)}>{evd.title}</LinkRow>
        })}
      </Section>}
      {err ? <p className="my-1.5 mb-2 flex items-center gap-1.5 text-[12px] leading-[18px] text-fg-subtle">Couldn’t load the full request and response for this exchange.</p> : !full ? <Section title="Headers"><Skeleton rows={5} /></Section> : <>
        <Section title="Security headers" right={BASELINE.filter(([h]) => respKeys.has(h)).length + ' of ' + BASELINE.length}>
          <div className="mb-2.5 flex flex-wrap gap-[5px]">{BASELINE.map(([h, l]) => {
            const has = respKeys.has(h)
            return <span
              key={h}
              className={cn(
                'inline-flex h-[22px] items-center gap-1 rounded-[5px] pl-1.5 pr-2 text-[12px]',
                has
                  ? 'text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]'
                  : 'bg-warn-soft text-warn shadow-[inset_0_0_0_1px_var(--warn-line)]',
                flagged.has(h) && 'font-medium',
              )}
              title={has ? h + ': ' + resp[Object.keys(resp).find(k => k.toLowerCase() === h)!] : h + ' is absent'}
            >
              <Icon name={has ? 'check' : 'x'} size={12} className={has ? 'text-fg-subtle' : 'text-warn'} />{l}
            </span>
          })}</div>
        </Section>
        <Section title="Request headers" right={Object.keys(full.reqHeaders ?? {}).length || undefined}><HeaderTable headers={full.reqHeaders} flagged={new Set()} /></Section>
        <Section title="Response headers" right={Object.keys(resp).length || undefined}><HeaderTable headers={resp} flagged={flagged} /></Section>
      </>}
      {iast.length > 0 && <Section title="Runtime traces" right={iast.length}>
        {iast.map(x => <LinkRow key={x.id} icon="node" title={`Trace ${x.traceId}`} trailing={model.evidenceById.has(x.artifactId) ? 'chevR' : null}
          sub={x.routesHit.join(', ') || undefined} right={`${x.newLinesCovered} lines · ${x.sinkEventsCount} sinks`}
          onClick={() => model.evidenceById.has(x.artifactId) && links.evidence(x.artifactId)}>
          {x.hasUnhandledException ? 'Unhandled exception' : 'Runtime trace'}
        </LinkRow>)}
      </Section>}
      {body && <Section title={full && full.body.length > (sum?.bodyPreview.length ?? 0) ? 'Response body' : 'Body preview'} right={full ? fmtN(full.body.length) + ' chars' : undefined}>
        <pre className={cn(RW.pre, 'max-h-[420px]')}>{bodyAll ? body : body.slice(0, CAP)}</pre>
        {body.length > CAP && !bodyAll && <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1')} onClick={() => setBodyAll(true)}>Show all {fmtN(body.length)} characters</button>}
      </Section>}
      {w && <Section title="Related">
        <LinkRow glyph={<StatusGlyph status={w.status} />} right={PHASE_LABEL[w.phase] ?? w.phase} trailing="workflow" onClick={() => links.worker(w.id)}>{w.title}</LinkRow>
        <LinkRow icon="surface" onClick={() => links.host(origin)}>{host(origin)} on the surface map</LinkRow>
      </Section>}
    </div></PaneBody>
  </>
}

/** Inspectors this view owns, keyed by selection kind ('exchange'). */
export const exchangesInspectors: InspectorMap = {
  exchange: ExchangeInspector,
}
