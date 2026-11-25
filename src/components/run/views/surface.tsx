// Surface (D's host × category map in A's visual system).
// Matrix: risk-band groups, shape + colour marks, legend-as-filter, pinned
// findings per host, fading crosshair, arrow-key cursor, ↵ opens the cell.
// List: every coverage note (with enforcing controls and proof gaps).
// Endpoints: the discovered route inventory (when the run recorded one).
import { useCallback, useEffect, useMemo, useRef } from 'react'
import type { MouseEvent as RMouseEvent, ReactNode } from 'react'
import { Dropdown, FilterBox, matchQ, Tabs, Tip } from '../controls.tsx'
import type { TipHandle } from '../controls.tsx'
import { useRun, useRunModel } from '../data.tsx'
import { EmptyState, HostLabel, LinkRow, Props, Section, Seg, Tag } from '../display.tsx'
import { fmtDate, fmtN, host, plural, readRunUrlParam, syncRunUrlParam } from '../format.ts'
import { CovSwatch, PinGlyph, SevGlyph, StatusGlyph, TierBars } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { CAT_IDX, CATS, COV_L, COV_ST, normFStatus, PHASE_LABEL, prettyCat, RISK, RISKL, SEV, SEV_LABEL, stLabel } from '../meta.ts'
import type { CoverageStatus, RiskTier } from '../meta.ts'
import { cellKey, cellStatus as cellStatusRaw } from '../model.ts'
import type { Coverage, SurfaceModel, SurfaceOrigin } from '../model.ts'
import { useLinks, useListNav, useNav, useViewState } from '../nav.tsx'
import { usePaletteCommands } from '../palette.tsx'
import { ExchangeLink, PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorMap, InspectorProps } from '../pane.tsx'
import { EndpointInspector, EndpointsList } from './surface-endpoints.tsx'

type Sort = 'risk' | 'findings' | 'az'
type Mode = 'matrix' | 'list' | 'endpoints'
const isSurfaceMode = (v: string | null): v is Mode => v === 'matrix' || v === 'list' || v === 'endpoints'
const SHORT: Record<string, string> = { reported: 'Reported', needs_follow_up: 'Follow-up', no_issue_found: 'No issue', ruled_out: 'Ruled out', not_applicable: 'N/A', untested: 'Uncharted' }
/** model.cellStatus, typed to include 'untested' (index access hides the fallback from TS). */
const cellStatus = (m: SurfaceModel, o: string, c: string) => cellStatusRaw(m, o, c) as CoverageStatus
const CHARTED: CoverageStatus[] = ['reported', 'needs_follow_up', 'no_issue_found', 'ruled_out', 'not_applicable']

function sortRows(m: SurfaceModel, sort: Sort) {
  const o = m.origins.slice()
  const ti = (t: RiskTier) => RISK.indexOf(t)
  if (sort === 'az') o.sort((a, b) => a.host.localeCompare(b.host))
  else if (sort === 'findings') o.sort((a, b) => b.nf - a.nf || a.host.localeCompare(b.host))
  else o.sort((a, b) => ti(a.tier) - ti(b.tier) || b.nf - a.nf || b.ncov - a.ncov || a.host.localeCompare(b.host))
  return o
}

export function SurfaceView() {
  const { detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const M = model.surface
  const [sort, setSort] = useViewState<Sort>('surface.sort', 'risk')
  const [mode, setModeState] = useViewState<Mode>('surface.mode', 'matrix')
  const [filter, setFilter] = useViewState<CoverageStatus | ''>('surface.filter', '')
  const [, setListTab] = useViewState<string>('surface.list.tab', 'all')
  const setMode = useCallback((next: Mode) => {
    setModeState(next)
    syncRunUrlParam('mode', next === 'matrix' ? null : next)
  }, [setModeState])
  useEffect(() => {
    const fromUrl = readRunUrlParam('mode')
    if (isSurfaceMode(fromUrl)) {
      if (fromUrl !== mode) setModeState(fromUrl)
    } else if (mode !== 'matrix') {
      syncRunUrlParam('mode', mode)
    }
    const onPop = () => {
      const u = readRunUrlParam('mode')
      setModeState(isSurfaceMode(u) ? u : 'matrix')
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const hasList = detail.coverageEntries.length > 0
  const hasEndpoints = (detail.endpoints?.length ?? 0) > 0
  const effMode: Mode = mode === 'list' && !hasList ? 'matrix' : mode === 'endpoints' && !hasEndpoints ? 'matrix' : mode

  usePaletteCommands([
    { id: 'sf.matrix', section: 'Actions', label: 'Surface: show the matrix', icon: 'grid', run: () => { nav.setView('surface'); setMode('matrix') } },
    ...(hasList ? [{ id: 'sf.list', section: 'Actions', label: 'Surface: list every coverage note', icon: 'list' as const, run: () => { nav.setView('surface'); setMode('list') } }] : []),
    ...(hasEndpoints ? [{ id: 'sf.endpoints', section: 'Actions', label: 'Surface: endpoint inventory', icon: 'node' as const, run: () => { nav.setView('surface'); setMode('endpoints') } }] : []),
    { id: 'sf.sort.risk', section: 'Actions', label: 'Surface: sort by risk', icon: 'sliders', run: () => { setMode('matrix'); setSort('risk') } },
    { id: 'sf.sort.findings', section: 'Actions', label: 'Surface: sort by findings', icon: 'sliders', run: () => { setMode('matrix'); setSort('findings') } },
    { id: 'sf.sort.az', section: 'Actions', label: 'Surface: sort A–Z', icon: 'sliders', run: () => { setMode('matrix'); setSort('az') } },
  ])

  const modeSeg = (hasList || hasEndpoints) && <Seg<Mode> title="Matrix, list or endpoints" value={effMode} onChange={setMode} options={[
    { value: 'matrix', label: 'Matrix', icon: 'grid' },
    ...(hasList ? [{ value: 'list' as const, label: 'List', icon: 'list' as const }] : []),
    ...(hasEndpoints ? [{ value: 'endpoints' as const, label: 'Endpoints', icon: 'node' as const }] : []),
  ]} />

  if (effMode === 'list') return <CoverageList modeSeg={modeSeg} />
  if (effMode === 'endpoints') return <EndpointsList modeSeg={modeSeg} />
  return <Matrix M={M} sort={sort} setSort={setSort} filter={filter} setFilter={setFilter} modeSeg={modeSeg}
    onGaps={() => { setListTab('gaps'); setMode('list') }} />
}

// ---------------------------------------------------------------- matrix

function Matrix({ M, sort, setSort, filter, setFilter, modeSeg, onGaps }: {
  M: SurfaceModel
  sort: Sort
  setSort: (s: Sort) => void
  filter: CoverageStatus | ''
  setFilter: (f: CoverageStatus | '') => void
  modeSeg: ReactNode
  onGaps: () => void
}) {
  const { detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const links = useLinks()
  const rows = useMemo(() => sortRows(M, sort), [M, sort])
  const [cur, setCur] = useViewState<[number, number] | null>('surface.cur', null)
  const tableRef = useRef<HTMLTableElement>(null)
  const tipRef = useRef<TipHandle>(null)
  const xh = useRef<[number, number]>([-1, -1])

  const selCell = nav.sel?.kind === 'cell' ? nav.sel.id : null
  const selHost = nav.sel?.kind === 'host' ? nav.sel.id : null

  // Keep the cursor on the selected cell (cross-links, Back).
  useEffect(() => {
    if (!selCell) return
    const i = selCell.indexOf('|')
    const r = rows.findIndex(o => o.origin === selCell.slice(0, i))
    const c = CAT_IDX[selCell.slice(i + 1)]
    if (r >= 0 && c != null && (!cur || cur[0] !== r || cur[1] !== c)) setCur([r, c])
  }, [selCell, rows]) // eslint-disable-line react-hooks/exhaustive-deps

  const counts = useMemo(() => {
    const ct: Record<string, number> = {}
    COV_ST.forEach(s => { ct[s[0]] = 0 })
    rows.forEach(o => CATS.forEach(c => { ct[cellStatus(M, o.origin, c[0])]++ }))
    return ct
  }, [rows, M])
  const nf = model.findings.length
  const conf = model.findings.filter(f => normFStatus(f.status) === 'confirmed').length
  const gaps = detail.coverageEntries.filter(x => x.proofGapReason).length
  const grouped = sort === 'risk' && !M.ghost

  // crosshair: class toggles, faded by CSS (no re-render while hovering)
  const cross = (r: number, c: number) => {
    const mx = tableRef.current
    if (!mx) return
    const [pr, pc] = xh.current
    if (pr === r && pc === c) return
    if (pr >= 0) mx.querySelector(`tbody tr[data-r="${pr}"]`)?.classList.remove('hr')
    if (pc >= 0) mx.querySelectorAll(`[data-c="${pc}"]`).forEach(el => el.classList.remove('hc'))
    xh.current = [r, c]
    if (r >= 0) mx.querySelector(`tbody tr[data-r="${r}"]`)?.classList.add('hr')
    if (c >= 0) mx.querySelectorAll(`[data-c="${c}"]`).forEach(el => el.classList.add('hc'))
  }

  const cellAt = (r: number, c: number) => rows[r] && CATS[c] ? cellKey(rows[r].origin, CATS[c][0]) : null
  const move = (dr: number, dc: number) => {
    if (!rows.length) return
    let [r, c] = cur ?? [0, -1]
    if (c < 0) { r = 0; c = 0 } else {
      r = Math.max(0, Math.min(rows.length - 1, r + dr))
      c = Math.max(0, Math.min(CATS.length - 1, c + dc))
    }
    setCur([r, c])
    cross(r, c)
    tableRef.current?.querySelector(`td.c[data-r="${r}"][data-c="${c}"]`)?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
    if (selCell) { const k = cellAt(r, c); if (k) nav.select({ kind: 'cell', id: k }) }
  }
  const openCur = () => {
    const [r, c] = cur ?? [0, 0]
    const k = cellAt(r, c)
    if (k) { if (!cur) setCur([r, c]); nav.select({ kind: 'cell', id: k }) }
  }
  useShortcuts([
    { key: ['ArrowDown', 'j'], run: () => move(1, 0) },
    { key: ['ArrowUp', 'k'], run: () => move(-1, 0) },
    { key: 'ArrowRight', run: () => move(0, 1) },
    { key: 'ArrowLeft', run: () => move(0, -1) },
    { key: ['Enter', 'o'], run: openCur },
    { key: 'Escape', run: () => { if (!filter) return false; setFilter('') } },
  ])

  const onOver = (e: RMouseEvent) => {
    const td = (e.target as HTMLElement).closest('td.c') as HTMLElement | null
    const th = (e.target as HTMLElement).closest('tbody th') as HTMLElement | null
    if (td) {
      const r = Number(td.dataset.r), c = Number(td.dataset.c)
      cross(r, c)
      const o = rows[r], cat = CATS[c]
      const st = cellStatus(M, o.origin, cat[0])
      const fl = M.findingsByCell[cellKey(o.origin, cat[0])] ?? []
      tipRef.current?.show(<>
        <b>{cat[1]}</b> <span className="o">· {o.host}</span><br />
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><CovSwatch status={st} size={[14, 11]} />{COV_L[st]}</span>
        {fl.length > 0 && <span className="o"> · {plural(fl.length, 'finding')}{st === 'untested' ? ' (mapped)' : ''}</span>}
      </>, e.clientX, e.clientY)
    } else {
      tipRef.current?.hide()
      cross(th ? Number(th.parentElement?.dataset.r ?? -1) : -1, -1)
    }
  }

  const legend = <div className={'legend-f' + (filter ? ' filtering' : '')} style={{ display: 'flex', gap: 2, minWidth: 0, overflow: 'hidden' }}>
    {COV_ST.map(([k, l]) => <button key={k} type="button" className={'lg' + (filter === k ? ' on' : '')} disabled={!counts[k]} aria-pressed={filter === k}
      title={`${l}: show only these cells (click again to clear)`} onClick={() => setFilter(filter === k ? '' : k)}>
      <CovSwatch status={k} /><span className="lt">{SHORT[k]}</span><span className="n num">{fmtN(counts[k])}</span>
    </button>)}
  </div>

  let lastTier: RiskTier | null = null
  const body: ReactNode[] = []
  if (M.ghost && rows.length) body.push(<tr key="g-ghost" className="grp"><th colSpan={CATS.length + 2}><span className="t">Project seeds · awaiting consent<span className="ct num">{rows.length}</span></span></th></tr>)
  rows.forEach((o, ri) => {
    if (grouped && o.tier !== lastTier) {
      lastTier = o.tier
      const ct = rows.filter(x => x.tier === o.tier).length
      body.push(<tr key={'g-' + o.tier} className="grp"><th colSpan={CATS.length + 2}><span className="t"><TierBars tier={o.tier} />{RISKL[o.tier]}<span className="ct num">{ct}</span></span></th></tr>)
    }
    const fl = M.findingsByOrigin[o.origin] ?? []
    const ap = (M.approvalsByOrigin[o.origin] ?? []).filter(a => a.status === 'pending').length
    const selRow = selHost === o.origin || (!!selCell && selCell.startsWith(o.origin + '|'))
    body.push(<tr key={o.origin} data-r={ri} className={selHost === o.origin ? 'selrow' : ''}>
      <th>
        <div className={'oh' + (selRow && !selHost ? ' selo' : '')} role="button" tabIndex={-1} title={o.host} onClick={() => nav.select({ kind: 'host', id: o.origin })}>
          <span className="host"><HostLabel host={o.host} apex={M.apex} /></span>
          {ap > 0 && <span className="warn" title={`${ap} pending approval${ap > 1 ? 's' : ''}`}><Icon name="lock" /></span>}
          {!M.ghost && !grouped && <TierBars tier={o.tier} />}
        </div>
      </th>
      {CATS.map((c, ci) => {
        const st = cellStatus(M, o.origin, c[0])
        const k = cellKey(o.origin, c[0])
        const fc = st === 'untested' ? 0 : (M.findingsByCell[k] ?? []).length
        const isSel = selCell === k
        const isCur = !!cur && cur[0] === ri && cur[1] === ci
        return <td key={c[0]} className={'c' + (isSel ? ' sel' : '') + (isCur ? ' cur' : '') + (filter === st ? ' hit' : '')} data-r={ri} data-c={ci}
          onClick={() => { setCur([ri, ci]); nav.select({ kind: 'cell', id: k }) }}>
          <span className={'b st-' + st}><span className={'gl gl-' + st} />{fc > 0 && <span className="fn num">{fc}</span>}</span>
        </td>
      })}
      <td><div className="pins">{!M.ghost && <>
        {fl.slice(0, 5).map(f => <span key={f.id} className="pin" title={`${SEV_LABEL[f.severity] ?? f.severity} · ${stLabel(normFStatus(f.status))}: ${f.title}`}
          onClick={() => links.finding(f.id)}><PinGlyph sev={f.severity} status={f.status} /></span>)}
        {fl.length ? <span className="more num">{fl.length > 5 ? '+' + (fl.length - 5) : ''}</span> : <span className="none" />}
      </>}</div></td>
    </tr>)
  })

  return <>
    <div className="toolbar sf-mxbar num" style={{ paddingLeft: 12 }}>
      {legend}
      <span className="sf-mxmeta hide-n" title={`${plural(rows.length, M.ghost ? 'seed host' : 'origin')} × ${CATS.length} categories · ${plural(nf, 'finding')}${nf ? ', ' + conf + ' confirmed' : ''}`}>
        {plural(rows.length, M.ghost ? 'seed' : 'origin')}
        {gaps > 0 && <> · <button type="button" className="linkbtn" style={{ margin: 0 }} title="Coverage notes the coordinator could not prove either way"
          onClick={onGaps}>{plural(gaps, 'gap')}<Icon name="arrowR" /></button></>}
      </span>
      <span className="tb-sp" />
      {!M.ghost && <Seg<Sort> label="Sort" value={sort} onChange={setSort} options={[{ value: 'risk', label: 'Risk' }, { value: 'findings', label: 'Findings' }, { value: 'az', label: 'A–Z' }]} />}
      {modeSeg}
    </div>
    <div className="sf" id="sf" tabIndex={0} aria-label="Surface map: arrow keys move the cell cursor, Enter opens the cell">
      <div className="sf-in">
        {M.ghost && <div className="banner" style={{ margin: '12px 0 4px', maxWidth: 720 }}>
          <StatusGlyph status="waiting" />
          <span>Uncharted. Nothing has been probed; the map fills in as workers report coverage after you approve scope.</span>
          <button type="button" className="btn" onClick={() => nav.setView('overview')}>Review scope</button>
        </div>}
        {!rows.length ? <EmptyState icon="surface" title="No hosts yet">The map lists every candidate host, then fills in as workers report coverage.</EmptyState> :
          <table ref={tableRef} className={'mx' + (filter ? ' dim' : '')} onMouseOver={onOver} onMouseMove={e => tipRef.current?.move(e.clientX, e.clientY)}
            onMouseLeave={() => { tipRef.current?.hide(); cross(-1, -1) }}>
            <thead><tr>
              <th className="rh"><div className="sf-oh">Origin</div></th>
              {CATS.map((c, ci) => <th key={c[0]} className="ch" data-c={ci}><span className="co">{c[2]}</span><span className="cl" title={c[1]}>{c[3]}</span></th>)}
              <th className="fh"><span className="co">&nbsp;</span><span className="sf-fh">Findings</span></th>
            </tr></thead>
            <tbody>{body}</tbody>
            {!M.ghost && <tfoot><tr>
              <th>Charted</th>
              {CATS.map((c, ci) => {
                const cs: Record<string, number> = {}
                let t = 0
                rows.forEach(o => { const s = cellStatus(M, o.origin, c[0]); if (s !== 'untested') { cs[s] = (cs[s] ?? 0) + 1; t++ } })
                return <td key={c[0]} data-c={ci}>
                  <div className="colbar">{CHARTED.map(s => cs[s] ? <i key={s} className={'bg-' + s} style={{ width: cs[s] / rows.length * 100 + '%' }} /> : null)}</div>
                  <div className="colnum num">{t}/{rows.length}</div>
                </td>
              })}
              <td />
            </tr></tfoot>}
          </table>}
        {!M.ghost && rows.length > 0 && <div className="legend sf-pinlegend">
          {SEV.slice(0, 4).map(s => <span key={s}><PinGlyph sev={s} status="confirmed" />{SEV_LABEL[s]}</span>)}
          <span><PinGlyph sev="informational" status="confirmed" />Info</span>
          <span style={{ color: 'var(--fg-4)' }}>Solid pin = confirmed by replay, outline = unverified, slashed = dismissed</span>
        </div>}
      </div>
    </div>
    <Tip ref={tipRef} />
  </>
}

// ---------------------------------------------------------------- list mode

type LGroup = 'origin' | 'category' | 'status'
const CO: Record<string, number> = { reported: 0, needs_follow_up: 1, no_issue_found: 2, ruled_out: 3, not_applicable: 4 }

function CoverageList({ modeSeg }: { modeSeg: ReactNode }) {
  const { detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const [tab, setTab] = useViewState<string>('surface.list.tab', 'all')
  const [group, setGroup] = useViewState<LGroup>('surface.list.group', 'origin')
  const [q, setQ] = useViewState('surface.list.q', '')
  const [collapsed, setCollapsed] = useViewState<Record<string, boolean>>('surface.list.collapsed', {})
  const cov = detail.coverageEntries
  const tabs = useMemo(() => {
    const t: Record<string, number> = { all: cov.length, gaps: cov.filter(x => x.proofGapReason).length, controls: cov.filter(x => x.enforcingControl).length }
    cov.forEach(x => { t[x.status] = (t[x.status] ?? 0) + 1 })
    return ([['all', 'All'], ['reported', 'Reported'], ['needs_follow_up', 'Follow-up'], ['no_issue_found', 'No issue'], ['ruled_out', 'Ruled out'], ['not_applicable', 'N/A'], ['gaps', 'Proof gaps'], ['controls', 'Controls']] as [string, string][])
      .filter(([k]) => t[k]).map(([k, l]) => [k, l, t[k]] as [string, string, number])
  }, [cov])
  const items = useMemo(() => cov.filter(x =>
    (tab === 'all' || (tab === 'gaps' ? !!x.proofGapReason : tab === 'controls' ? !!x.enforcingControl : x.status === tab))
    && matchQ(q, [x.origin, x.category, prettyCat(x.category), x.status, x.summary, x.enforcingControl ?? '', x.proofGapReason ?? ''].join(' '))), [cov, tab, q])
  const groups = useMemo(() => {
    const m = new Map<string, Coverage[]>()
    const key = (x: Coverage) => group === 'origin' ? x.origin : group === 'category' ? x.category : x.status
    items.forEach(x => { const k = key(x); m.set(k, [...(m.get(k) ?? []), x]) })
    const ti = (o: string) => RISK.indexOf((model.risk.get(o)?.riskTier ?? 'unranked') as RiskTier)
    return [...m.entries()].sort(([a], [b]) => group === 'status' ? (CO[a] ?? 9) - (CO[b] ?? 9)
      : group === 'category' ? (CAT_IDX[a] ?? 99) - (CAT_IDX[b] ?? 99) : ti(a) - ti(b) || host(a).localeCompare(host(b)))
      .map(([k, list]) => ({ k, list: list.sort((a, b) => (CAT_IDX[a.category] ?? 99) - (CAT_IDX[b.category] ?? 99) || (CO[a.status] ?? 9) - (CO[b.status] ?? 9)) }))
  }, [items, group, model.risk])
  const ids = useMemo(() => groups.flatMap(g => collapsed[group + ':' + g.k] ? [] : g.list.map(x => cellKey(x.origin, x.category))), [groups, collapsed, group])
  const { index } = useListNav({ ids, kind: 'cell' })
  useShortcuts([{ key: 'G', run: () => setGroup(group === 'origin' ? 'category' : group === 'category' ? 'status' : 'origin') }])
  const listRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (index < 0) return
    listRef.current?.querySelector(`.row[data-id="${CSS.escape(ids[index])}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [index, ids])
  const selId = nav.sel?.kind === 'cell' ? nav.sel.id : null
  const M = model.surface

  return <>
    <div className="toolbar">
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <span className="tb-sp" />
      <FilterBox value={q} onChange={setQ} onEnter={() => ids[0] && nav.select({ kind: 'cell', id: ids[0] })} />
      <Dropdown icon="sliders" title="Grouping (⇧G cycles)" label={<><span className="dim">Group</span><span>{group === 'origin' ? 'Origin' : group === 'category' ? 'Category' : 'Status'}</span></>}>
        <div className="dd-sec">Grouping<span className="kbd-group" style={{ marginLeft: 'auto' }}><span className="kbd">⇧</span><span className="kbd">G</span></span></div>
        <Seg<LGroup> value={group} onChange={setGroup} options={[{ value: 'origin', label: 'Origin' }, { value: 'category', label: 'Category' }, { value: 'status', label: 'Status' }]} />
      </Dropdown>
      {modeSeg}
    </div>
    <div className="list" ref={listRef} tabIndex={-1}>
      {!items.length ? <EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter or switch tabs.</EmptyState> : groups.map(g => {
        const ck = group + ':' + g.k
        const col = !!collapsed[ck]
        return <div key={ck}>
          <div className={'ghead' + (col ? ' collapsed' : '')} role="button" tabIndex={-1} onClick={() => setCollapsed(c => ({ ...c, [ck]: !col }))}>
            <Icon name="chev" />
            <span className="g">{group === 'status' ? <CovSwatch status={g.k} size={[16, 12]} /> : group === 'origin' ? <TierBars tier={(model.risk.get(g.k)?.riskTier ?? 'unranked') as RiskTier} /> : <Icon name="surface" />}</span>
            <span>{group === 'origin' ? host(g.k) : group === 'category' ? prettyCat(g.k) : COV_L[g.k] ?? g.k}</span>
            <span className="ct num">{g.list.length}</span>
          </div>
          {!col && g.list.map(x => {
            const id = cellKey(x.origin, x.category)
            const nfc = (M.findingsByCell[id] ?? []).length
            return <div key={x.id} className={'row' + (selId === id ? ' cur' : '')} data-id={id} onClick={() => nav.select({ kind: 'cell', id })}>
              <span className="g" title={COV_L[x.status]}><CovSwatch status={x.status} size={[16, 12]} /></span>
              {group !== 'category' && <span className="c-tag sf-cat"><Tag>{prettyCat(x.category)}</Tag></span>}
              {group !== 'origin' && <span className="mono muted sf-host">{host(x.origin)}</span>}
              <span className="title sf-sum">{x.summary}</span>
              {x.enforcingControl && <span className="sf-mark" title={'Enforcing control: ' + x.enforcingControl}><Icon name="shield" /></span>}
              {x.proofGapReason && <span className="sf-mark warn" title={'Proof gap: ' + x.proofGapReason}><Icon name="alert" /></span>}
              {nfc > 0 && <span className="nbadge f num" title="Findings in this cell"><SevGlyph sev={M.findingsByCell[id][0].severity} />{nfc}</span>}
            </div>
          })}
        </div>
      })}
    </div>
  </>
}

// ---------------------------------------------------------------- inspectors

/** F's 11-cell locator strip: click a category to move within the origin. */
function Locator({ origin, current }: { origin: string; current: string | null }) {
  const M = useRunModel().surface
  const nav = useNav()
  return <>
    <div className="locator">{CATS.map(c => {
      const st = cellStatus(M, origin, c[0])
      return <button key={c[0]} type="button" className={'st-' + st + (current === c[0] ? ' on' : '')} title={`${c[1]}: ${COV_L[st]}`}
        onClick={() => nav.select({ kind: 'cell', id: cellKey(origin, c[0]) }, { push: nav.sel?.kind === 'host' })}><span className={'gl gl-' + st} /></button>
    })}</div>
    <div className="locator-l">{CATS.map(c => <span key={c[0]}>{c[2]}</span>)}</div>
  </>
}

function ExchangeLinks({ origin, max }: { origin: string; max: number }) {
  const model = useRunModel()
  const links = useLinks()
  const xl = model.exchangesByOrigin.get(origin) ?? []
  const [, setOrigin] = useViewState<string>('exchanges.origin', '')
  if (!xl.length) return null
  return <Section title="Exchanges against origin" right={fmtN(xl.length)}>
    {xl.slice(0, max).map(e => <ExchangeLink key={e.id} id={e.id} showHost={false} />)}
    <LinkRow icon="exchanges" onClick={() => { setOrigin(origin); links.view('exchanges') }}>Show every exchange for {host(origin)}</LinkRow>
  </Section>
}

function CellInspector({ sel }: InspectorProps) {
  const model = useRunModel()
  const links = useLinks()
  const nav = useNav()
  const M = model.surface
  const i = sel.id.lastIndexOf('|')
  const o = sel.id.slice(0, i), cat = sel.id.slice(i + 1)
  const ci = CAT_IDX[cat]
  if (ci == null) return <><PaneHeader title="Cell" /><PaneBody><EmptyState icon="surface" title="Unknown category">{cat}</EmptyState></PaneBody></>
  const cc = CATS[ci]
  const r: Coverage | undefined = M.cov[o]?.[cat]
  const st = (r?.status ?? 'untested') as CoverageStatus
  const all = M.findingsByCell[sel.id] ?? []
  const mapped = st === 'untested'
  const rec = r?.assignmentId ? model.workerById.get(r.assignmentId) : undefined
  const wl = [...(M.workersByOrigin[o] ?? [])].map(w => model.workerById.get(w)!).filter(w => w && w !== rec).sort((a, b) => b.createdAt - a.createdAt)
  const linked = r?.linkedFindingId ? model.findingById.get(r.linkedFindingId) : undefined
  return <>
    <PaneHeader title="Cell" sub={<><span className="mono">{host(o)}</span> · {cc[2]}</>} />
    <PaneBody><div className="d">
      <h2 style={{ marginBottom: 8 }}>{cc[1]}</h2>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <span className={'pill st-' + st}><span className={'gl gl-' + st} />{COV_L[st]}</span>
        <button type="button" className="linkbtn" style={{ margin: 0 }} onClick={() => nav.select({ kind: 'host', id: o }, { push: true })}>
          <span className="mono">{host(o)}</span><Icon name="arrowR" />
        </button>
      </div>
      <Locator origin={o} current={cat} />
      <Section title="Coverage summary">
        {r ? <p>{r.summary}</p> : <p>This cell hasn’t been charted. No worker has reported on {cc[1].toLowerCase()} for this origin yet.</p>}
        {r && (r.enforcingControl || r.proofGapReason || r.updatedAt) && <Props rows={[
          ...(r.enforcingControl ? [['Control', <span className="sf-wrap">{r.enforcingControl}</span>] as [ReactNode, ReactNode]] : []),
          ...(r.proofGapReason ? [['Proof gap', <span className="sf-wrap sf-gap">{r.proofGapReason}</span>] as [ReactNode, ReactNode]] : []),
          ['Updated', fmtDate(r.updatedAt)],
        ]} />}
      </Section>
      {all.length > 0 && <Section title="Findings in this cell" right={all.length}>
        {all.map(f => <LinkRow key={f.id} glyph={<><SevGlyph sev={f.severity} /></>} onClick={() => links.finding(f.id)}
          title={`${SEV_LABEL[f.severity] ?? f.severity} · ${stLabel(normFStatus(f.status))}`}>
          <span className="sf-fst"><StatusGlyph status={normFStatus(f.status)} /></span>{f.title}{linked?.id === f.id && <span className="muted"> · linked</span>}
        </LinkRow>)}
        {mapped && <p className="sf-note">Mapped from the finding’s category; no coverage note was recorded for this cell.</p>}
      </Section>}
      {rec && <Section title="Recorded by">
        <LinkRow glyph={<StatusGlyph status={rec.status} />} trailing="workflow" onClick={() => links.worker(rec.id)}>{rec.title}</LinkRow>
      </Section>}
      {wl.length > 0 && <Section title="Other workers on this origin" right={wl.length}>
        {wl.slice(0, 5).map(w => <LinkRow key={w.id} glyph={<StatusGlyph status={w.status} />} right={PHASE_LABEL[w.phase] ?? w.phase} trailing={null} onClick={() => links.worker(w.id)}>{w.title}</LinkRow>)}
        {wl.length > 5 && <p className="sf-note">+{wl.length - 5} more · open the origin for the full list</p>}
      </Section>}
      <ExchangeLinks origin={o} max={6} />
    </div></PaneBody>
  </>
}

function HostInspector({ sel }: InspectorProps) {
  const { detail } = useRun()
  const model = useRunModel()
  const links = useLinks()
  const M = model.surface
  const o = sel.id
  const om: SurfaceOrigin | undefined = M.origins.find(x => x.origin === o)
  const fl = M.findingsByOrigin[o] ?? []
  const wl = [...(M.workersByOrigin[o] ?? [])].map(w => model.workerById.get(w)!).filter(Boolean).sort((a, b) => a.createdAt - b.createdAt)
  const aps = (M.approvalsByOrigin[o] ?? []).slice().sort((a, b) => Number(b.status === 'pending') - Number(a.status === 'pending') || b.createdAt - a.createdAt)
  const tm = model.risk.get(o)
  const ranked = detail.threatModel?.entries ?? []
  const rank = ranked.findIndex(e => e.origin === o)
  const notes = Object.values(M.cov[o] ?? {}).filter(x => x.proofGapReason || x.enforcingControl)
  const cs: Record<string, number> = {}
  CATS.forEach(c => { const s = cellStatus(M, o, c[0]); cs[s] = (cs[s] ?? 0) + 1 })
  const tier = om?.tier ?? 'unranked'
  return <>
    <PaneHeader title="Origin" sub={om ? <span className="num">{plural(om.ncov, 'category', 'categories')} charted</span> : undefined} />
    <PaneBody><div className="d">
      <div className="d-meta">
        <span className="tag"><TierBars tier={tier} />{RISKL[tier]}</span>
        {(om?.tags ?? []).slice(0, 4).map(t => <Tag key={t}>{t}</Tag>)}
      </div>
      <h2 className="mono" style={{ fontSize: 14 }}>{host(o)}</h2>
      <Locator origin={o} current={null} />
      <div className="legend num sf-cs">
        {COV_ST.filter(s => cs[s[0]]).map(s => <span key={s[0]}><CovSwatch status={s[0]} size={[14, 11]} />{s[1]} <span className="muted">{cs[s[0]]}</span></span>)}
      </div>
      {tm && <Section title="Threat model" right={rank >= 0 ? `#${rank + 1} of ${ranked.length}` : undefined}>
        <p>{tm.rationale}</p>
        {tm.surfaceTags.length > 4 && <div className="chip-row">{tm.surfaceTags.slice(4).map(t => <Tag key={t}>{t}</Tag>)}</div>}
      </Section>}
      {aps.length > 0 && <Section title="Approvals" right={aps.filter(a => a.status === 'pending').length ? aps.filter(a => a.status === 'pending').length + ' pending' : aps.length}>
        {aps.slice(0, 6).map(a => <LinkRow key={a.id} glyph={<StatusGlyph status={a.status === 'pending' ? 'waiting_approval' : a.status} />} right={stLabel(a.status)}
          trailing="queue" onClick={() => links.queueItem('ap:' + a.id)}><span className="mono">{a.method} {a.pathAndQuery}</span></LinkRow>)}
      </Section>}
      {notes.length > 0 && <Section title="Controls and proof gaps" right={notes.length}>
        {notes.map(x => <LinkRow key={x.id} glyph={<CovSwatch status={x.status} size={[14, 11]} />} trailing={null}
          sub={x.proofGapReason ? 'Proof gap: ' + x.proofGapReason : 'Control: ' + x.enforcingControl}
          onClick={() => links.cell(o, x.category)}>{prettyCat(x.category)}</LinkRow>)}
      </Section>}
      {fl.length > 0 && <Section title="Findings" right={fl.length}>
        {fl.slice(0, 12).map(f => <LinkRow key={f.id} glyph={<SevGlyph sev={f.severity} />} onClick={() => links.finding(f.id)}>
          <span className="sf-fst"><StatusGlyph status={normFStatus(f.status)} /></span>{f.title}
        </LinkRow>)}
        {fl.length > 12 && <p className="sf-note">+{fl.length - 12} more in Findings</p>}
      </Section>}
      {wl.length > 0 && <Section title="Workers" right={wl.length}>
        {wl.slice(0, 8).map(w => <LinkRow key={w.id} glyph={<StatusGlyph status={w.status} />} right={PHASE_LABEL[w.phase] ?? w.phase} trailing={null} onClick={() => links.worker(w.id)}>{w.title}</LinkRow>)}
        {wl.length > 8 && <p className="sf-note">+{wl.length - 8} more</p>}
      </Section>}
      <ExchangeLinks origin={o} max={4} />
      {!om && <p className="sf-note">This origin isn’t on the current surface map.</p>}
    </div></PaneBody>
  </>
}

/** Inspectors this view owns, keyed by selection kind. */
export const surfaceInspectors: InspectorMap = {
  cell: CellInspector,
  host: HostInspector,
  endpoint: EndpointInspector,
}
