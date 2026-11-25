// Findings view (A's list inside F's frame), owned by Agent Q.
//
// The collapsible verdict strip (B's headline) sits above a toolbar with
// status tabs (low-priority tabs fold into "More · n"), a `/` filter and a
// display menu (group by severity / origin / status / none, ordering).
// Group headers collapse and carry status tallies. Confirmed is the quiet
// outlined check; accent means selection only. Long lists are windowed.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, ReactNode, RefObject } from 'react'
import { Dropdown, FilterBox, Tabs } from '../controls.tsx'
import { useRunModel, useVerdict } from '../data.tsx'
import { useDecisions, ACTIONS } from '../decisions.tsx'
import { EmptyState, KbdGroup, Seg } from '../display.tsx'
import { host } from '../format.ts'
import { SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { FSTAT_ORDER, normFStatus, prettyCat, SEV_LABEL, SEV_ORDER, stLabel } from '../meta.ts'
import type { FindingDisplayStatus } from '../meta.ts'
import type { FindingRow } from '../model.ts'
import { useListNav, useNav, useViewState } from '../nav.tsx'
import type { InspectorMap } from '../pane.tsx'
import { usePaletteCommands } from '../palette.tsx'
import { useToast } from '../toast.tsx'
import { FindingInspector, useFindingQueueKey } from './findings-inspector.tsx'

type Group = 'severity' | 'origin' | 'status' | 'none'
type Sort = 'severity' | 'status' | 'title'
type Tab = 'all' | FindingDisplayStatus
const GROUPS: [Group, string][] = [['severity', 'Severity'], ['origin', 'Origin'], ['status', 'Status'], ['none', 'None']]
const SORTS: [Sort, string][] = [['severity', 'Severity'], ['status', 'Status'], ['title', 'Title']]
const TABS: [Tab, string][] = [['all', 'All'], ['confirmed', 'Confirmed'], ['pending', 'Awaiting'], ['inconclusive', 'Inconclusive'], ['dismissed', 'Dismissed']]
const STATUS_KEYS: FindingDisplayStatus[] = ['confirmed', 'pending', 'inconclusive', 'dismissed']
/** Above this many rows the list is windowed (rows stay 36px, heads 32px). */
const VIRTUAL_AT = 300
const ROW_H = 36
const HEAD_H = 32

interface G { key: string; label: string; glyph: ReactNode; items: FindingRow[] }

function matches(f: FindingRow, q: string) {
  if (!q) return true
  const text = [f.title, f.origin, f.category, f.cwe, f.status, f.severity, f.id].join(' ').toLowerCase()
  return q.toLowerCase().split(/\s+/).filter(Boolean).every(t => text.includes(t))
}

function groupOf(items: FindingRow[], g: Group): G[] | null {
  if (g === 'none') return null
  const m = new Map<string, FindingRow[]>()
  const key = (f: FindingRow) => g === 'severity' ? (f.severity || 'informational') : g === 'origin' ? (host(f.origin) || '—') : normFStatus(f.status)
  for (const f of items) { const k = key(f); m.set(k, [...(m.get(k) ?? []), f]) }
  const order = (a: string, b: string) => g === 'severity' ? (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9)
    : g === 'status' ? (FSTAT_ORDER[a] ?? 9) - (FSTAT_ORDER[b] ?? 9) : a.localeCompare(b)
  return [...m.entries()].sort((a, b) => order(a[0], b[0])).map(([k, list]) => ({
    key: k,
    label: g === 'severity' ? (SEV_LABEL[k] ?? k) : g === 'status' ? stLabel(k) : k,
    glyph: g === 'severity' ? <SevGlyph sev={k} /> : g === 'status' ? <StatusGlyph status={k} /> : <span style={{ color: 'var(--fg-3)', display: 'inline-flex' }}><Icon name="globe" /></span>,
    items: list,
  }))
}

// ---------------------------------------------------------------- verdict strip

function VerdictStrip() {
  const model = useRunModel()
  const v = useVerdict()
  const nav = useNav()
  const [open, setOpen] = useViewState('findings.vstrip', true)
  if (model.run.status === 'waiting') return null
  return <div className={'vstrip' + (open ? '' : ' closed')} role="button" tabIndex={0} aria-expanded={open}
    title={(open ? 'Collapse' : 'Expand') + ' the run summary'} onClick={() => setOpen(!open)}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(!open) } }}>
    <Icon name="chev" />
    <span className="h">{v.hed}</span>
    <span className="conf">{v.conf.word === 'Not yet assessed' ? v.conf.word : v.conf.word + ' confidence'}</span>
    <button type="button" className="linkbtn" style={{ margin: 0 }} onClick={e => { e.stopPropagation(); nav.setView('overview') }}>Overview<Icon name="arrowR" /></button>
  </div>
}

// ---------------------------------------------------------------- toolbar

function Toolbar({ tabs, tab, setTab, filter, setFilter, filterRef, onFilterEnter, group, setGroup, sort, setSort }: {
  tabs: [Tab, string, number][]
  tab: Tab
  setTab: (t: Tab) => void
  filter: string
  setFilter: (s: string) => void
  filterRef: RefObject<HTMLInputElement | null>
  onFilterEnter: () => void
  group: Group
  setGroup: (g: Group) => void
  sort: Sort
  setSort: (s: Sort) => void
}) {
  return <div className="toolbar">
    <Tabs tabs={tabs} value={tab} onChange={setTab} label="Filter findings by status" />
    <span className="tb-sp" />
    <FilterBox ref={filterRef} value={filter} onChange={setFilter} onEnter={onFilterEnter} label="Filter findings" />
    <Dropdown icon="sliders" title="Display options (⇧G cycles grouping)"
      label={<><span className="dim">Group</span><span>{GROUPS.find(g => g[0] === group)?.[1]}</span></>}>
      <div className="dd-sec">Grouping<KbdGroup keys={['⇧', 'G']} style={{ marginLeft: 'auto' }} /></div>
      <Seg<Group> value={group} onChange={setGroup} options={GROUPS.map(([value, label]) => ({ value, label }))} />
      <div className="dd-sec">Ordering</div>
      <Seg<Sort> value={sort} onChange={setSort} options={SORTS.map(([value, label]) => ({ value, label }))} />
    </Dropdown>
  </div>
}

// ---------------------------------------------------------------- rows

function FindingRowView({ f, group, cur, onClick, style, local }: {
  f: FindingRow
  group: Group
  cur: boolean
  onClick: () => void
  style?: CSSProperties
  local?: string | null
}) {
  const st = normFStatus(f.status)
  return <div className={'row frow' + (cur ? ' cur' : '')} data-id={f.id} onClick={onClick} style={style} aria-selected={cur}>
    {group !== 'severity' && <span className="g" title={SEV_LABEL[f.severity] ?? f.severity}><SevGlyph sev={f.severity} /></span>}
    <span className="g" title={stLabel(st)}><StatusGlyph status={st} /></span>
    <span className="title">{f.title}</span>
    {local && <span className="dec fdec" title="Saved locally in this browser">{local}</span>}
    {f.category && <span className="c-cat">{prettyCat(f.category)}</span>}
    {group !== 'origin' && <span className="c-host mono">{host(f.origin)}</span>}
  </div>
}

function GroupHead({ g, group, collapsed, onToggle, style }: { g: G; group: Group; collapsed: boolean; onToggle: () => void; style?: CSSProperties }) {
  const t: Partial<Record<FindingDisplayStatus, number>> = {}
  for (const f of g.items) { const s = normFStatus(f.status); t[s] = (t[s] ?? 0) + 1 }
  return <div className={'ghead' + (collapsed ? ' collapsed' : '')} role="button" tabIndex={0} aria-expanded={!collapsed} style={style}
    onClick={onToggle} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle() } }}>
    <Icon name="chev" /><span className="g">{g.glyph}</span><span>{g.label}</span><span className="ct num">{g.items.length}</span>
    {group !== 'status' && <span className="gbar num">
      {STATUS_KEYS.filter(k => t[k]).map(k => <span key={k} className="gtally" title={stLabel(k)}><StatusGlyph status={k} />{t[k]}</span>)}
    </span>}
  </div>
}

// ---------------------------------------------------------------- view

export function FindingsView() {
  const model = useRunModel()
  const nav = useNav()
  const toast = useToast()
  const q = useDecisions()
  const keyOf = useFindingQueueKey()
  const [tab, setTab] = useViewState<Tab>('findings.tab', 'all')
  const [filter, setFilter] = useViewState('findings.filter', '')
  const [group, setGroup] = useViewState<Group>('findings.group', 'severity')
  const [sort, setSort] = useViewState<Sort>('findings.sort', 'severity')
  const [collapsed, setCollapsed] = useViewState<Record<string, boolean>>('findings.collapsed', {})
  const filterRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const tabs = useMemo(() => {
    const t: Record<string, number> = { all: model.findings.length }
    for (const f of model.findings) { const s = normFStatus(f.status); t[s] = (t[s] ?? 0) + 1 }
    return TABS.filter(([k]) => t[k]).map(([k, l]) => [k, l, t[k]] as [Tab, string, number])
  }, [model])
  const activeTab: Tab = tabs.some(t => t[0] === tab) ? tab : 'all'

  const items = useMemo(() => {
    const list = model.findings.filter(f => (activeTab === 'all' || normFStatus(f.status) === activeTab) && matches(f, filter))
    const sev = (a: FindingRow, b: FindingRow) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
    const st = (a: FindingRow, b: FindingRow) => (FSTAT_ORDER[a.status] ?? 9) - (FSTAT_ORDER[b.status] ?? 9)
    return list.sort((a, b) => sort === 'title' ? a.title.localeCompare(b.title)
      : sort === 'status' ? st(a, b) || sev(a, b) || a.title.localeCompare(b.title)
        : sev(a, b) || st(a, b) || a.title.localeCompare(b.title))
  }, [model, activeTab, filter, sort])
  const groups = useMemo(() => groupOf(items, group), [items, group])
  const ck = (g: G) => group + ':' + g.key
  const flatIds = useMemo(() => groups ? groups.flatMap(g => (collapsed[group + ':' + g.key] ? [] : g.items.map(f => f.id))) : items.map(f => f.id),
    [groups, items, collapsed, group])

  const { index } = useListNav({ ids: flatIds, kind: 'finding' })
  const cycleGroup = () => {
    const i = GROUPS.findIndex(g => g[0] === group)
    const next = GROUPS[(i + 1) % GROUPS.length]
    setGroup(next[0])
    toast.show(next[0] === 'none' ? 'Ungrouped' : 'Grouped by ' + next[1].toLowerCase())
  }
  useShortcuts([{ key: 'G', run: cycleGroup }])
  usePaletteCommands([
    ...GROUPS.map(([k, l]) => ({ id: 'f.group.' + k, section: 'Actions', label: k === 'none' ? 'Findings: no grouping' : 'Findings: group by ' + l.toLowerCase(), icon: 'sliders' as const, run: () => setGroup(k) })),
    { id: 'f.filter', section: 'Actions', label: 'Filter findings', icon: 'search', keys: ['/'], run: () => setTimeout(() => filterRef.current?.focus(), 0) },
  ])

  const selId = nav.sel?.kind === 'finding' ? nav.sel.id : null
  const select = (id: string) => nav.select({ kind: 'finding', id })
  const localLabel = (f: FindingRow) => {
    const k = keyOf(f.id)
    const d = k ? q.get(k) : undefined
    return d ? ACTIONS[d.act].label : null
  }

  // Windowed rendering for long lists.
  const flatEntries = useMemo(() => {
    const out: ({ t: 'h'; g: G } | { t: 'r'; f: FindingRow })[] = []
    if (groups) for (const g of groups) { out.push({ t: 'h', g }); if (!collapsed[ck(g)]) g.items.forEach(f => out.push({ t: 'r', f })) }
    else items.forEach(f => out.push({ t: 'r', f }))
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups, items, collapsed])
  const virtualAt = useVirtualThreshold()
  const virtual = items.length > virtualAt
  const offsets = useMemo(() => {
    const o: number[] = []
    let y = 0
    for (const e of flatEntries) { o.push(y); y += e.t === 'h' ? HEAD_H : ROW_H }
    o.push(y)
    return o
  }, [flatEntries])
  const [win, setWin] = useState<[number, number]>([0, 80])
  useLayoutEffect(() => {
    const el = listRef.current
    if (!el || !virtual) return
    const update = () => {
      const top = el.scrollTop
      const bottom = top + el.clientHeight
      let lo = 0, hi = flatEntries.length
      while (lo < hi) { const mid = (lo + hi) >> 1; if (offsets[mid + 1] <= top) lo = mid + 1; else hi = mid }
      let end = lo
      while (end < flatEntries.length && offsets[end] < bottom) end++
      const a = Math.max(0, lo - 10), b = Math.min(flatEntries.length, end + 10)
      setWin(w => (w[0] === a && w[1] === b ? w : [a, b]))
    }
    update()
    el.addEventListener('scroll', update, { passive: true })
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => { el.removeEventListener('scroll', update); ro.disconnect() }
  }, [virtual, flatEntries, offsets])

  // Keep the cursor row in view.
  useEffect(() => {
    if (!selId) return
    const el = listRef.current
    if (!el) return
    if (virtual) {
      const i = flatEntries.findIndex(e => e.t === 'r' && e.f.id === selId)
      if (i < 0) return
      const top = offsets[i]
      const head = groups ? HEAD_H : 0
      if (top - head < el.scrollTop) el.scrollTop = top - head
      else if (top + ROW_H > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW_H - el.clientHeight
      return
    }
    el.querySelector<HTMLElement>(`.row[data-id="${CSS.escape(selId)}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [selId, index, virtual, flatEntries, offsets, groups])

  const toggle = (g: G) => setCollapsed(c => ({ ...c, [ck(g)]: !c[ck(g)] }))
  const toolbar = <Toolbar tabs={tabs} tab={activeTab} setTab={setTab} filter={filter} setFilter={setFilter} filterRef={filterRef}
    onFilterEnter={() => { if (flatIds[0]) { select(flatIds[0]); filterRef.current?.blur() } }}
    group={group} setGroup={setGroup} sort={sort} setSort={setSort} />

  if (!model.findings.length) {
    return <>
      <VerdictStrip />
      {toolbar}
      <EmptyState icon="findings" title="No findings yet"
        action={model.run.status === 'waiting' ? <button type="button" className="btn" onClick={() => nav.setView('overview')}>Review scope</button> : undefined}>
        Findings appear here as workers propose them; each one is verified by automated replay before it is marked confirmed.
      </EmptyState>
    </>
  }

  let body: ReactNode
  if (!items.length) {
    body = <EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80, alignItems: 'flex-start' }}>Try a different filter or switch tabs.</EmptyState>
  } else if (virtual) {
    // current group head pinned at the top while scrolling (heads in the window scroll normally)
    let pinned: G | null = null
    if (groups) for (let i = win[0]; i >= 0; i--) { const e = flatEntries[i]; if (e?.t === 'h') { pinned = e.g; break } }
    body = <>
      {pinned && <div className="fpin"><GroupHead g={pinned} group={group} collapsed={!!collapsed[ck(pinned)]} onToggle={() => toggle(pinned!)} /></div>}
      <div className="vl-spacer" style={{ height: offsets[offsets.length - 1], position: 'relative' }}>
        {flatEntries.slice(win[0], win[1]).map((e, j) => {
          const i = win[0] + j
          const style: CSSProperties = { position: 'absolute', top: offsets[i], left: 0, right: 0, height: e.t === 'h' ? HEAD_H : ROW_H }
          return e.t === 'h'
            ? <GroupHead key={'h:' + e.g.key} g={e.g} group={group} collapsed={!!collapsed[ck(e.g)]} onToggle={() => toggle(e.g)} style={{ ...style, position: 'absolute' }} />
            : <FindingRowView key={e.f.id} f={e.f} group={group} cur={e.f.id === selId} onClick={() => select(e.f.id)} style={style} local={localLabel(e.f)} />
        })}
      </div>
    </>
  } else {
    body = groups
      ? groups.map(g => <div key={g.key} className="fgrp">
        <GroupHead g={g} group={group} collapsed={!!collapsed[ck(g)]} onToggle={() => toggle(g)} />
        {!collapsed[ck(g)] && g.items.map(f => <FindingRowView key={f.id} f={f} group={group} cur={f.id === selId} onClick={() => select(f.id)} local={localLabel(f)} />)}
      </div>)
      : items.map(f => <FindingRowView key={f.id} f={f} group={group} cur={f.id === selId} onClick={() => select(f.id)} local={localLabel(f)} />)
  }
  return <>
    <VerdictStrip />
    {toolbar}
    <div className={'list' + (virtual ? ' fvirt' : '')} ref={listRef} tabIndex={-1}>{body}</div>
  </>
}

/** Rows above which the list is windowed. `localStorage['guardian-rw-virtual-at']` overrides it (testing). */
function useVirtualThreshold() {
  const [n, setN] = useState(VIRTUAL_AT)
  useEffect(() => {
    const v = Number(localStorage.getItem('guardian-rw-virtual-at'))
    if (v > 0) setN(v)
  }, [])
  return n
}

/** Inspectors this view owns, keyed by selection kind ('finding'). */
export const findingsInspectors: InspectorMap = {
  finding: FindingInspector,
}
