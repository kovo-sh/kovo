// Workflow view (Agent W): execution trace in graph and list modes.
// Graph mode: phase columns of worker cards, handoff + causal edges, stacks,
// lineage highlight, camera, minimap, phase nav, replay. List mode: grouped
// worker rows. Inspectors: worker, stack, queued steps, step, graph digest.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Dropdown, FilterBox, Tabs } from '../controls.tsx'
import { useRun, useRunModel } from '../data.tsx'
import { EmptyState, Kbd, KbdGroup, Seg, Tag } from '../display.tsx'
import { fmtN, host, plural, readRunUrlParam, syncRunUrlParam } from '../format.ts'
import { LiveDot, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { PHASE_LABEL, PHASE_ORDER, stLabel } from '../meta.ts'
import { worstSeverity } from '../model.ts'
import type { Assignment } from '../model.ts'
import { useListNav, useNav, useViewState } from '../nav.tsx'
import { usePaletteCommands } from '../palette.tsx'
import type { InspectorMap } from '../pane.tsx'
import { cn, runBtn, runDdItem, RW } from '../tw.ts'
import { WorkflowGraph } from './workflow-graph.tsx'
import { DigestInspector, StackInspector, StepInspector, StepsInspector, WorkerInspector } from './workflow-inspector.tsx'
import { isLive, QUEUE_ID, setExpanded, useWorkflowLayout } from './workflow-layout.ts'

type Filter = 'all' | 'live' | 'complete' | 'findings' | 'failed'
type Mode = 'graph' | 'list'
const isWorkflowMode = (v: string | null): v is Mode => v === 'graph' || v === 'list'
type Group = 'phase' | 'step' | 'status' | 'none'
const GROUPS: [Group, string][] = [['phase', 'Phase'], ['step', 'Plan step'], ['status', 'Status'], ['none', 'None']]

export function WorkflowView() {
  const { detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const L = useWorkflowLayout()
  const runId = detail.run.id
  const [mode, setModeState] = useViewState<Mode>('wf.mode', 'graph')
  const [filter, setFilter] = useViewState<Filter>('wf.filter', 'all')
  const [query, setQuery] = useViewState('wf.q', '')
  const [replay, setReplay] = useState(false)
  const setMode = useCallback((next: Mode) => {
    setModeState(next)
    syncRunUrlParam('mode', next === 'graph' ? null : next)
  }, [setModeState])
  useEffect(() => {
    const fromUrl = readRunUrlParam('mode')
    if (isWorkflowMode(fromUrl)) {
      if (fromUrl !== mode) setModeState(fromUrl)
    } else if (mode !== 'graph') {
      syncRunUrlParam('mode', mode)
    }
    const onPop = () => {
      const u = readRunUrlParam('mode')
      setModeState(isWorkflowMode(u) ? u : 'graph')
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const filterRef = useRef<HTMLInputElement>(null)
  const assignments = detail.assignments

  // ---- filters + search
  const tabs = useMemo(() => {
    const t: Record<Filter, number> = { all: assignments.length, live: 0, complete: 0, findings: 0, failed: 0 }
    for (const a of assignments) {
      if (isLive(a)) t.live++
      if (a.status === 'complete') t.complete++
      if (a.status === 'failed') t.failed++
      if ((model.workerFindings.get(a.id) ?? []).length) t.findings++
    }
    const all: [Filter, string][] = [['all', 'All'], ['live', 'Running · paused'], ['complete', 'Complete'], ['findings', 'With findings'], ['failed', 'Failed']]
    return all.filter(([k]) => k === 'all' || t[k]).map(([k, l]) => ({ k, l, n: t[k] }))
  }, [assignments, model])
  const effFilter: Filter = tabs.some(t => t.k === filter) ? filter : 'all'
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
  const matches = useCallback((a: Assignment) => {
    if (effFilter === 'live' && !isLive(a)) return false
    if (effFilter === 'complete' && a.status !== 'complete') return false
    if (effFilter === 'failed' && a.status !== 'failed') return false
    if (effFilter === 'findings' && !(model.workerFindings.get(a.id) ?? []).length) return false
    if (!terms.length) return true
    const hay = (a.title + ' ' + a.objective + ' ' + (a.outcome ?? '') + ' ' + a.sourceOrigins.join(' ') + ' ' + a.phase).toLowerCase()
    return terms.every(t => hay.includes(t))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effFilter, model, terms.join(' ')])
  const nomatch = useMemo(() => {
    const out = new Set<string>()
    for (const n of L.nodes) {
      const ok = n.kind === 'worker' ? matches(n.a!) : n.kind === 'stack' ? n.members!.some(matches)
        : effFilter === 'all' && (!terms.length || n.steps!.some(s => terms.every(t => (s.title + ' ' + s.hypothesis).toLowerCase().includes(t))))
      if (!ok) out.add(n.id)
    }
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [L, matches, effFilter])

  // ---- selection ↔ graph node
  const sel = nav.sel
  const selWorker = sel?.kind === 'worker' ? model.workerById.get(sel.id) : undefined
  // cross-links to a stacked worker auto-expand its stack
  useEffect(() => {
    if (!selWorker) return
    const g = L.stacks.of.get(selWorker.id)
    if (g) setExpanded(runId, g, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selWorker?.id, runId])
  const selId = !sel ? null
    : sel.kind === 'worker' ? (L.byId.has(sel.id) ? sel.id : L.stacks.of.get(sel.id) ?? null)
      : sel.kind === 'stack' ? (L.byId.has(sel.id) ? sel.id : null)
        : sel.kind === 'steps' || sel.kind === 'step' ? (L.byId.has(QUEUE_ID) ? QUEUE_ID : null) : null
  const focusSet = useMemo(() => {
    if (sel?.kind !== 'digest') return null
    const dg = detail.digests.find(d => d.id === sel.id)
    if (!dg) return null
    const rep = (id: string) => (L.byId.has(id) ? id : L.stacks.of.get(id) ?? id)
    return new Set(dg.coveredAssignmentIds.map(rep).filter(id => L.byId.has(id)))
  }, [sel, detail.digests, L])

  const select = useCallback((id: string | null) => {
    if (!id) return nav.select(null)
    if (id === QUEUE_ID) return nav.select({ kind: 'steps', id: 'queued' })
    if (L.stacks.groups.has(id)) return nav.select({ kind: 'stack', id })
    nav.select({ kind: 'worker', id })
  }, [nav, L])
  const expand = useCallback((gid: string, on: boolean) => {
    setExpanded(runId, gid, on)
    if (!on && sel?.kind === 'worker' && L.stacks.of.get(sel.id) === gid) nav.select({ kind: 'stack', id: gid })
    if (on && sel?.kind === 'stack' && sel.id === gid) nav.select(null)
  }, [runId, sel, L, nav])

  // ---- replay, mode, keys, palette
  const startReplay = useCallback(() => {
    if (!assignments.length) return
    setMode('graph')
    setReplay(r => !r)
  }, [assignments.length, setMode])
  useShortcuts([
    { key: 'l', run: () => { setReplay(false); setMode(mode === 'graph' ? 'list' : 'graph') } },
    { key: 'R', run: startReplay },
    { key: 'Escape', run: () => { if (!replay) return false; setReplay(false) } },
  ])
  usePaletteCommands([
    { id: 'wf.replay', section: 'Actions', label: replay ? 'Stop the workflow replay' : 'Replay the run in the workflow graph', icon: 'replay', keys: ['⇧', 'R'], run: startReplay },
    { id: 'wf.mode', section: 'Actions', label: mode === 'graph' ? 'Show workers as a list' : 'Show the workflow graph', icon: mode === 'graph' ? 'list' : 'graph', keys: ['L'], run: () => setMode(mode === 'graph' ? 'list' : 'graph') },
  ])

  const firstMatch = () => {
    const ordered = L.nodes.filter(n => !nomatch.has(n.id) && n.kind !== 'queue').sort((a, b) => a.x - b.x || a.y - b.y)
    if (mode === 'list') {
      const a = assignments.filter(matches).sort((x, y) => x.createdAt - y.createdAt)[0]
      if (a) nav.select({ kind: 'worker', id: a.id })
    } else if (ordered[0]) {
      const n = ordered[0]
      if (n.kind === 'stack') { const m = n.members!.find(matches); if (m) nav.select({ kind: 'worker', id: m.id }) }
      else select(n.id)
    }
    filterRef.current?.blur()
  }

  const modeBtnCls = (on: boolean) => cn(
    'inline-flex h-[22px] cursor-pointer items-center justify-center gap-[5px] rounded-[4px] border-0 px-2 font-sans text-[12px] font-medium transition-[background-color,color,box-shadow] duration-[var(--d1)] @max-[760px]/wftb:px-[7px]',
    on
      ? 'bg-raise text-fg shadow-[0_0_0_1px_var(--line-2),0_1px_2px_rgba(0,0,0,.05)] hover:bg-raise'
      : 'bg-transparent text-fg-muted shadow-none hover:bg-transparent hover:text-fg',
  )

  const toolbar = <div className={cn(RW.toolbar, 'relative @container/wftb')} data-tb="workflow">
    <Tabs tabs={tabs.map(t => [t.k, t.l, t.n] as [Filter, string, number])} value={effFilter} onChange={setFilter} label="Filter workers" />
    <FilterBox
      ref={filterRef}
      value={query}
      onChange={setQuery}
      onEnter={firstMatch}
      label="Filter workers"
      className="@max-[760px]/wftb:w-24 @max-[760px]/wftb:focus-within:w-40"
    />
    {mode === 'list' && <GroupMenu />}
    {detail.digests.length > 0 && <DigestMenu />}
    <button
      type="button"
      className={runBtn({ variant: replay ? 'ghostOn' : 'ghost' })}
      title="Replay the run (⇧R)"
      onClick={startReplay}
      disabled={!assignments.length}
    >
      <Icon name="replay" /><span className="@max-[760px]/wftb:hidden">Replay</span>
    </button>
    <div
      className="inline-flex h-[26px] flex-none items-center rounded-control bg-sunk p-0.5 shadow-[inset_0_0_0_1px_var(--line)]"
      title="Graph or list (L)"
      role="radiogroup"
    >
      <button type="button" role="radio" aria-checked={mode === 'graph'} className={modeBtnCls(mode === 'graph')} onClick={() => setMode('graph')}>
        <Icon name="graph" /><span className="@max-[760px]/wftb:hidden">Graph</span>
      </button>
      <button type="button" role="radio" aria-checked={mode === 'list'} className={modeBtnCls(mode === 'list')} onClick={() => { setReplay(false); setMode('list') }}>
        <Icon name="list" /><span className="@max-[760px]/wftb:hidden">List</span>
      </button>
    </div>
  </div>

  if (!assignments.length) {
    return <>{toolbar}<EmptyState icon="workers" title="No workers dispatched"
      action={detail.run.status === 'waiting' ? <button type="button" className={runBtn()} onClick={() => nav.setView('overview')}>Review scope</button> : undefined}>
      The coordinator plans chain steps after scope consent, then dispatches sandboxed workers. Their execution graph builds up here.
    </EmptyState></>
  }
  return <>
    {toolbar}
    {mode === 'graph'
      ? <WorkflowGraph L={L} selId={selId} focusSet={focusSet} nomatch={nomatch} onSelect={select} onExpand={expand}
        onReport={() => nav.setView('report')} replay={replay} onReplayClose={() => setReplay(false)} />
      : <WorkerList matches={matches} />}
  </>
}

// ---------------------------------------------------------------- toolbar menus

function GroupMenu() {
  const [group, setGroup] = useViewState<Group>('wf.group', 'phase')
  return <Dropdown icon="sliders" title="Display options (⇧G cycles grouping)"
    label={<><span className="text-fg-subtle @max-[760px]/wftb:hidden">Group</span><span>{GROUPS.find(g => g[0] === group)?.[1]}</span></>}>
    <div className={RW.ddSec}>Grouping<KbdGroup keys={['⇧', 'G']} className="ml-auto" /></div>
    <Seg<Group> value={group} onChange={setGroup} fullWidth options={GROUPS.map(([value, label]) => ({ value, label }))} />
  </Dropdown>
}

/** Memory summaries (saved workspace snapshots of older facts). */
function DigestMenu() {
  const { detail } = useRun()
  const nav = useNav()
  const ds = detail.digests
  const active = ds.filter(d => d.active).length
  return <Dropdown icon="archive" title="Memory summaries: compacted summaries of older facts" menuClassName="w-[320px] p-1.5"
    btnClassName={runBtn({ variant: nav.sel?.kind === 'digest' ? 'ghostOn' : 'ghost' })}
    label={<><span className="text-fg-subtle @max-[760px]/wftb:hidden">Summaries</span><span className="tabular-nums">{active || ds.length}</span></>}>
    {close => <>
      <div className={cn(RW.ddSec, 'px-2 py-1.5')}>Memory summaries<span className="ml-auto font-normal tabular-nums">{active} active · {ds.length} total</span></div>
      {ds.map(d => <button
        key={d.id}
        type="button"
        role="menuitem"
        className={cn(runDdItem({ active: nav.sel?.kind === 'digest' && nav.sel.id === d.id }), 'h-auto min-h-8 py-[5px]')}
        onClick={() => { close(); nav.select({ kind: 'digest', id: d.id }) }}
      >
        <span className="min-w-0 truncate">Round {d.roundNo} · {d.level} summary{!d.active && <span className="text-fg-subtle"> · superseded</span>}</span>
        <span className="ml-auto flex-none text-fg-subtle tabular-nums">{plural(d.coveredFactIds.length, 'fact')} · {d.coveredAssignmentIds.length} w</span>
      </button>)}
      <p className="mx-2 mb-0.5 mt-1.5 text-[11.5px] text-fg-subtle">Selecting a summary highlights the workers it covers.</p>
    </>}
  </Dropdown>
}

// ---------------------------------------------------------------- list mode

function WorkerList({ matches }: { matches: (a: Assignment) => boolean }) {
  const model = useRunModel()
  const nav = useNav()
  const [group, setGroup] = useViewState<Group>('wf.group', 'phase')
  const [collapsed, setCollapsed] = useViewState<Record<string, boolean>>('wf.collapsed', {})
  const items = useMemo(() => model.detail.assignments.filter(matches).slice().sort((a, b) => a.createdAt - b.createdAt), [model, matches])
  const groups = useMemo(() => {
    if (group === 'none') return null
    const by = new Map<string, Assignment[]>()
    for (const a of items) {
      const k = group === 'phase' ? a.phase : group === 'status' ? a.status : a.stepId ?? '_none'
      by.set(k, [...(by.get(k) ?? []), a])
    }
    const keys = [...by.keys()]
    const seq = (k: string) => model.stepById.get(k)?.seq ?? -1
    keys.sort((a, b) => group === 'phase' ? (PHASE_ORDER[a] ?? 9) - (PHASE_ORDER[b] ?? 9) : group === 'step' ? seq(a) - seq(b) : a.localeCompare(b))
    return keys.map(k => {
      const step = group === 'step' ? model.stepById.get(k) : undefined
      const label = group === 'phase' ? PHASE_LABEL[k] ?? k : group === 'status' ? stLabel(k) : step ? '#' + step.seq + ' ' + step.title : 'Unplanned (system workers)'
      const glyph: ReactNode = group === 'phase' ? <span className="flex text-fg-subtle"><Icon name="workers" /></span> : <StatusGlyph status={group === 'status' ? k : step?.status ?? 'complete'} />
      return { key: k, label, glyph, items: by.get(k)! }
    })
  }, [items, group, model])
  const ck = (k: string) => group + ':' + k
  const ids = groups ? groups.flatMap(g => (collapsed[ck(g.key)] ? [] : g.items.map(a => a.id))) : items.map(a => a.id)
  const { index } = useListNav({ ids, kind: 'worker' })
  useShortcuts([{ key: 'G', run: () => setGroup(GROUPS[(GROUPS.findIndex(g => g[0] === group) + 1) % GROUPS.length][0]) }])
  const listRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (index < 0) return
    listRef.current?.querySelector(`[data-id="${CSS.escape(ids[index])}"]`)?.scrollIntoView({ block: 'nearest' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [index])
  const row = (a: Assignment) => {
    const fs = model.workerFindings.get(a.id) ?? []
    const nfa = (model.factsByWorker.get(a.id) ?? []).length
    const pct = a.maxTurns ? Math.min(100, a.turnsUsed / a.maxTurns * 100) : 0
    const cur = nav.sel?.kind === 'worker' && nav.sel.id === a.id
    return <div key={a.id} className={cn(RW.row, cur && RW.rowCur)} data-id={a.id} onClick={() => nav.select({ kind: 'worker', id: a.id })}>
      <span className="inline-flex size-3.5 flex-none items-center justify-center" title={stLabel(a.status)}>
        {isLive(a) ? <LiveDot paused={a.status !== 'running'} className="mx-[3px]" /> : <StatusGlyph status={a.status} />}
      </span>
      <span className="min-w-0 flex-1 truncate text-fg">{a.title}</span>
      {fs.length > 0 && <span className="inline-flex h-[17px] flex-none items-center gap-1 rounded-[9px] bg-panel px-1.5 text-[11px] font-medium text-fg shadow-[inset_0_0_0_1px_var(--line-2)]" title="Findings citing this worker's evidence or exchanges"><SevGlyph sev={worstSeverity(fs)} />{fs.length}</span>}
      {nfa > 0 && <span className="inline-flex h-[17px] flex-none items-center gap-1 rounded-[9px] bg-sunk px-1.5 text-[11px] font-medium text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]" title="Facts recorded">{nfa} facts</span>}
      {group !== 'phase' && <span className="max-w-[170px] flex-none truncate"><Tag>{PHASE_LABEL[a.phase] ?? a.phase}</Tag></span>}
      <span className="w-[150px] flex-none truncate text-right font-mono text-[12px] text-fg-subtle max-[1320px]:w-[120px] max-[1180px]:hidden">{host(a.sourceOrigins[0] ?? '')}</span>
      <span className="flex w-[88px] flex-none items-center justify-end gap-[7px] text-fg-subtle tabular-nums" title="Turns used">
        <span className="relative h-[3px] w-9 overflow-hidden rounded-[3px] bg-line-2"><i className="absolute inset-y-0 left-0 bg-fg-subtle" style={{ width: pct + '%' }} /></span>
        {a.turnsUsed}/{a.maxTurns}
      </span>
      <span className="w-[52px] flex-none text-right text-fg-subtle tabular-nums" title="Requests">{fmtN(a.requestsUsed)} req</span>
    </div>
  }
  if (!items.length) return <EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter or switch tabs.</EmptyState>
  return <div className={RW.list} ref={listRef} tabIndex={-1} role="region" aria-label="Worker list">
    {groups ? groups.map(g => {
      const col = !!collapsed[ck(g.key)]
      const tu = g.items.reduce((s, a) => s + a.turnsUsed, 0), req = g.items.reduce((s, a) => s + a.requestsUsed, 0)
      return <div key={g.key}>
        <div className={RW.ghead} role="button" tabIndex={0} aria-expanded={!col}
          onClick={() => setCollapsed(c => ({ ...c, [ck(g.key)]: !col }))}
          onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setCollapsed(c => ({ ...c, [ck(g.key)]: !col })) } }}>
          <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', col && '-rotate-90')} />
          <span className="inline-flex size-3.5 flex-none items-center justify-center">{g.glyph}</span>
          <span>{g.label}</span>
          <span className="font-normal text-fg-subtle tabular-nums">{g.items.length}</span>
          <span className="ml-auto flex items-center gap-2 font-normal text-fg-subtle tabular-nums">{fmtN(tu)} turns · {fmtN(req)} req</span>
        </div>
        {!col && g.items.map(row)}
      </div>
    }) : items.map(row)}
    <div className={cn(RW.listnote, 'gap-1')}><Kbd>L</Kbd> graph · <Kbd>⇧</Kbd><Kbd>G</Kbd> grouping</div>
  </div>
}

// ---------------------------------------------------------------- inspectors

/** Inspectors this view owns, keyed by selection kind. */
export const workflowInspectors: InspectorMap = {
  worker: WorkerInspector,
  stack: StackInspector,
  steps: StepsInspector,
  step: StepInspector,
  digest: DigestInspector,
}
