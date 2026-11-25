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
import { EmptyState, HostLabel, KbdGroup, LinkRow, Props, Section, Seg, Tag } from '../display.tsx'
import { fmtDate, fmtN, host, plural, readRunUrlParam, syncRunUrlParam } from '../format.ts'
import { CovGlyph, CovSwatch, PinGlyph, SevGlyph, StatusGlyph, TierBars } from '../glyphs.tsx'
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
import { cn, covBarBgClass, covHoverBorderClass, covTileClass, runBtn, RW } from '../tw.ts'
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

  // Crosshair: toggle data-hr / data-hc attributes (no re-render while hovering).
  const cross = (r: number, c: number) => {
    const mx = tableRef.current
    if (!mx) return
    const [pr, pc] = xh.current
    if (pr === r && pc === c) return
    if (pr >= 0) mx.querySelector(`tbody tr[data-r="${pr}"]`)?.removeAttribute('data-hr')
    if (pc >= 0) mx.querySelectorAll(`[data-c="${pc}"]`).forEach(el => el.removeAttribute('data-hc'))
    xh.current = [r, c]
    if (r >= 0) mx.querySelector(`tbody tr[data-r="${r}"]`)?.setAttribute('data-hr', '')
    if (c >= 0) mx.querySelectorAll(`[data-c="${c}"]`).forEach(el => el.setAttribute('data-hc', ''))
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
    tableRef.current?.querySelector(`td[data-cell][data-r="${r}"][data-c="${c}"]`)?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
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
    const td = (e.target as HTMLElement).closest('td[data-cell]') as HTMLElement | null
    const th = (e.target as HTMLElement).closest('tbody th') as HTMLElement | null
    if (td) {
      const r = Number(td.dataset.r), c = Number(td.dataset.c)
      cross(r, c)
      const o = rows[r], cat = CATS[c]
      const st = cellStatus(M, o.origin, cat[0])
      const fl = M.findingsByCell[cellKey(o.origin, cat[0])] ?? []
      tipRef.current?.show(<>
        <b>{cat[1]}</b> <span className="text-fg-subtle">· {o.host}</span><br />
        <span className="inline-flex items-center gap-1.5"><CovSwatch status={st} size={[14, 11]} />{COV_L[st]}</span>
        {fl.length > 0 && <span className="text-fg-subtle"> · {plural(fl.length, 'finding')}{st === 'untested' ? ' (mapped)' : ''}</span>}
      </>, e.clientX, e.clientY)
    } else {
      tipRef.current?.hide()
      cross(th ? Number(th.parentElement?.dataset.r ?? -1) : -1, -1)
    }
  }

  const legend = <div className="flex min-w-0 gap-0.5 overflow-hidden">
    {COV_ST.map(([k, l]) => {
      const on = filter === k
      return <button
        key={k}
        type="button"
        className={cn(
          'inline-flex h-[26px] flex-none cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 pl-[5px] pr-1.5 text-[12px] font-normal shadow-none transition-[background-color,opacity,color] duration-[var(--d1)] disabled:cursor-default disabled:opacity-35 disabled:hover:bg-transparent',
          on ? 'bg-press text-fg hover:bg-press' : 'bg-transparent text-fg-muted hover:bg-hover hover:text-fg',
          filter && !on && 'opacity-50',
        )}
        disabled={!counts[k]}
        aria-pressed={on}
        title={`${l}: show only these cells (click again to clear)`}
        onClick={() => setFilter(on ? '' : k)}
      >
        <CovSwatch status={k} size={[16, 12]} />
        <span className="@max-[780px]/mxbar:hidden">{SHORT[k]}</span>
        <span className="tabular-nums text-fg-subtle">{fmtN(counts[k])}</span>
      </button>
    })}
  </div>

  let lastTier: RiskTier | null = null
  const body: ReactNode[] = []
  if (M.ghost && rows.length) {
    body.push(<tr key="g-ghost">
      <th colSpan={CATS.length + 2} className="bg-panel pb-[5px] pt-2 text-left text-[11.5px] font-medium text-fg-subtle">
        <span className="sticky left-0 inline-flex items-center gap-2">
          Project seeds · awaiting consent<span className="font-normal tabular-nums text-fg-faint">{rows.length}</span>
        </span>
      </th>
    </tr>)
  }
  rows.forEach((o, ri) => {
    if (grouped && o.tier !== lastTier) {
      const firstGroup = lastTier === null
      lastTier = o.tier
      const ct = rows.filter(x => x.tier === o.tier).length
      body.push(<tr key={'g-' + o.tier}>
        <th colSpan={CATS.length + 2} className={cn('bg-panel pb-[5px] text-left text-[11.5px] font-medium text-fg-subtle', firstGroup ? 'pt-2' : 'pt-3.5')}>
          <span className="sticky left-0 inline-flex items-center gap-2">
            <TierBars tier={o.tier} />{RISKL[o.tier]}<span className="font-normal tabular-nums text-fg-faint">{ct}</span>
          </span>
        </th>
      </tr>)
    }
    const fl = M.findingsByOrigin[o.origin] ?? []
    const ap = (M.approvalsByOrigin[o.origin] ?? []).filter(a => a.status === 'pending').length
    const selRow = selHost === o.origin || (!!selCell && selCell.startsWith(o.origin + '|'))
    body.push(<tr key={o.origin} data-r={ri} className="group/row">
      <th className="sticky left-0 z-[2] bg-panel p-0 pr-2 text-left font-normal">
        <div
          className={cn(
            'flex h-7 w-[170px] min-w-0 cursor-pointer items-center gap-2 rounded-[5px] pl-1.5 pr-2 transition-colors duration-[var(--d1)] group-data-[hr]/row:bg-hover',
            selHost === o.origin && 'bg-sel shadow-[inset_2px_0_0_var(--sel-line)] group-data-[hr]/row:bg-sel',
            selRow && !selHost && 'bg-hover',
          )}
          role="button"
          tabIndex={-1}
          title={o.host}
          onClick={() => nav.select({ kind: 'host', id: o.origin })}
        >
          <span className="flex min-w-0 flex-1 whitespace-nowrap text-[12.5px]"><HostLabel host={o.host} apex={M.apex} /></span>
          {ap > 0 && <span className="flex flex-none text-warn" title={`${ap} pending approval${ap > 1 ? 's' : ''}`}><Icon name="lock" /></span>}
          {!M.ghost && !grouped && <TierBars tier={o.tier} className="ml-auto" />}
        </div>
      </th>
      {CATS.map((c, ci) => {
        const st = cellStatus(M, o.origin, c[0])
        const k = cellKey(o.origin, c[0])
        const fc = st === 'untested' ? 0 : (M.findingsByCell[k] ?? []).length
        const isSel = selCell === k
        const isCur = !!cur && cur[0] === ri && cur[1] === ci
        return <td
          key={c[0]}
          data-cell=""
          data-r={ri}
          data-c={ci}
          className="group/cell relative h-7 w-[42px] cursor-pointer p-0 after:pointer-events-none after:absolute after:inset-0 after:bg-hover after:opacity-0 after:transition-opacity after:duration-[var(--d2)] after:ease-kovo group-data-[hr]/row:after:opacity-100 data-[hc]:after:opacity-100"
          onClick={() => { setCur([ri, ci]); nav.select({ kind: 'cell', id: k }) }}
        >
          <span
            className={cn(
              'absolute inset-0.5 grid place-items-center rounded-[4px] border transition-[transform,box-shadow,border-color,opacity] duration-[var(--d1)] ease-kovo',
              covTileClass(st, { borderless: !isSel }),
              covHoverBorderClass(st),
              'group-hover/cell:z-[1] group-hover/cell:shadow-[0_0_0_1px_var(--fg-3)]',
              isSel && isCur && 'z-[2] shadow-[0_0_0_2px_var(--accent)] group-hover/cell:shadow-[0_0_0_2px_var(--accent)]',
              isSel && !isCur && 'z-[2] shadow-[0_0_0_1.5px_var(--accent)] group-hover/cell:shadow-[0_0_0_1.5px_var(--accent)]',
              !isSel && isCur && 'shadow-[0_0_0_1.5px_var(--fg),0_0_0_3px_var(--panel)]',
              filter && filter !== st && 'opacity-[0.16]',
            )}
          >
            <CovGlyph status={st} />
            {fc > 0 && <span className="pointer-events-none absolute bottom-[3px] right-[3px] z-[3] text-[9px] font-semibold leading-[9px] tabular-nums text-current opacity-85">{fc}</span>}
          </span>
        </td>
      })}
      <td className="p-0"><div className="flex h-7 w-[118px] min-w-0 items-center gap-0.5 pl-3">{!M.ghost && <>
        {fl.slice(0, 5).map(f => <span key={f.id} className="grid size-3.5 flex-none cursor-pointer place-items-center rounded-[3px] transition-colors duration-[var(--d1)] hover:bg-press" title={`${SEV_LABEL[f.severity] ?? f.severity} · ${stLabel(normFStatus(f.status))}: ${f.title}`}
          onClick={() => links.finding(f.id)}><PinGlyph sev={f.severity} status={f.status} /></span>)}
        {fl.length ? <span className="ml-1 text-[11px] tabular-nums text-fg-subtle">{fl.length > 5 ? '+' + (fl.length - 5) : ''}</span> : <span className="h-px w-3 bg-line-2" />}
      </>}</div></td>
    </tr>)
  })

  return <>
    <div className={cn(RW.toolbar, '@container/mxbar gap-2 pl-3 tabular-nums')}>
      {legend}
      <span className="inline-flex flex-none items-center gap-1 whitespace-nowrap text-[12px] text-fg-subtle @max-[960px]/mxbar:hidden" title={`${plural(rows.length, M.ghost ? 'seed host' : 'origin')} × ${CATS.length} categories · ${plural(nf, 'finding')}${nf ? ', ' + conf + ' confirmed' : ''}`}>
        {plural(rows.length, M.ghost ? 'seed' : 'origin')}
        {gaps > 0 && <> · <button type="button" className={runBtn({ variant: 'link', size: 'none' })} title="Coverage notes the coordinator could not prove either way"
          onClick={onGaps}>{plural(gaps, 'gap')}<Icon name="arrowR" /></button></>}
      </span>
      <span className="min-w-2 flex-1" />
      {!M.ghost && <Seg<Sort> label="Sort" value={sort} onChange={setSort} options={[{ value: 'risk', label: 'Risk' }, { value: 'findings', label: 'Findings' }, { value: 'az', label: 'A–Z' }]} />}
      {modeSeg}
    </div>
    <div className="relative min-h-0 flex-1 overflow-auto outline-none focus-visible:shadow-[inset_0_0_0_2px_var(--accent-line)]" id="sf" tabIndex={0} aria-label="Surface map: arrow keys move the cell cursor, Enter opens the cell">
      <div className="w-max min-w-full pb-10 pl-4 pr-3.5">
        {M.ghost && <div className="mb-1 mt-3 flex max-w-[720px] items-center gap-2 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line)]">
          <StatusGlyph status="waiting" />
          <span>Uncharted. Nothing has been probed; the map fills in as workers report coverage after you approve scope.</span>
          <button type="button" className={cn(runBtn(), 'ml-auto')} onClick={() => nav.setView('overview')}>Review scope</button>
        </div>}
        {!rows.length ? <EmptyState icon="surface" title="No hosts yet">The map lists every candidate host, then fills in as workers report coverage.</EmptyState> :
          <table ref={tableRef} className="border-separate border-spacing-0 text-[12px]" onMouseOver={onOver} onMouseMove={e => tipRef.current?.move(e.clientX, e.clientY)}
            onMouseLeave={() => { tipRef.current?.hide(); cross(-1, -1) }}>
            <thead><tr>
              <th className="sticky left-0 top-0 z-[4] w-[178px] border-b border-line bg-panel pb-1.5 pr-2 text-left align-bottom font-medium text-fg-subtle">
                <div className="flex h-10 items-end pl-1.5 text-[11.5px] text-fg-muted">Origin</div>
              </th>
              {CATS.map((c, ci) => <th key={c[0]} className="group/col sticky top-0 z-[3] w-[42px] border-b border-line bg-panel pb-1.5 pt-2.5 text-left align-bottom font-medium text-fg-subtle" data-c={ci}>
                <span className="block px-1 pb-0.5 text-[10px] font-medium text-fg-faint">{c[2]}</span>
                <span className="flex h-7 items-end whitespace-normal rounded-[4px] px-1 text-[11px] leading-[13px] text-fg-muted transition-[background-color,color] duration-[var(--d1)] group-data-[hc]/col:bg-hover group-data-[hc]/col:text-fg" title={c[1]}>{c[3]}</span>
              </th>)}
              <th className="sticky top-0 z-[3] w-[118px] border-b border-line bg-panel pb-1.5 pl-3 text-left align-bottom font-medium text-fg-subtle">
                <span className="block px-1 pb-0.5 text-[10px] font-medium text-fg-faint">&nbsp;</span>
                <span className="text-[11px] text-fg-muted">Findings</span>
              </th>
            </tr></thead>
            <tbody>{body}</tbody>
            {!M.ghost && <tfoot><tr>
              <th className="sticky left-0 z-[2] border-t border-line bg-panel pl-1.5 pt-2.5 text-left align-top text-[11.5px] font-medium text-fg-subtle">Charted</th>
              {CATS.map((c, ci) => {
                const cs: Record<string, number> = {}
                let t = 0
                rows.forEach(o => { const s = cellStatus(M, o.origin, c[0]); if (s !== 'untested') { cs[s] = (cs[s] ?? 0) + 1; t++ } })
                return <td key={c[0]} data-c={ci} className="border-t border-line p-0 pt-2.5 align-top">
                  <div className="mx-[3px] flex h-[5px] overflow-hidden rounded-[2px] bg-line">{CHARTED.map(s => cs[s] ? <i key={s} className={cn('block h-full', covBarBgClass(s))} style={{ width: cs[s] / rows.length * 100 + '%' }} /> : null)}</div>
                  <div className="mx-[3px] mt-1 text-[10.5px] tabular-nums text-fg-subtle">{t}/{rows.length}</div>
                </td>
              })}
              <td className="border-t border-line p-0 pt-2.5 align-top" />
            </tr></tfoot>}
          </table>}
        {!M.ghost && rows.length > 0 && <div className="mt-3.5 flex flex-wrap gap-x-3.5 gap-y-1.5 text-[11.5px] text-fg-subtle">
          {SEV.slice(0, 4).map(s => <span key={s} className="inline-flex items-center gap-1.5"><PinGlyph sev={s} status="confirmed" />{SEV_LABEL[s]}</span>)}
          <span className="inline-flex items-center gap-1.5"><PinGlyph sev="informational" status="confirmed" />Info</span>
          <span className="inline-flex items-center gap-1.5 text-fg-faint">Solid pin = confirmed by replay, outline = unverified, slashed = dismissed</span>
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
    listRef.current?.querySelector(`[data-id="${CSS.escape(ids[index])}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [index, ids])
  const selId = nav.sel?.kind === 'cell' ? nav.sel.id : null
  const M = model.surface

  return <>
    <div className={RW.toolbar}>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <FilterBox value={q} onChange={setQ} onEnter={() => ids[0] && nav.select({ kind: 'cell', id: ids[0] })} />
      <Dropdown icon="sliders" title="Grouping (⇧G cycles)" label={<><span className="text-fg-subtle">Group</span><span>{group === 'origin' ? 'Origin' : group === 'category' ? 'Category' : 'Status'}</span></>}>
        <div className={RW.ddSec}>Grouping<KbdGroup keys={['⇧', 'G']} className="ml-auto" /></div>
        <Seg<LGroup> fullWidth value={group} onChange={setGroup} options={[{ value: 'origin', label: 'Origin' }, { value: 'category', label: 'Category' }, { value: 'status', label: 'Status' }]} />
      </Dropdown>
      {modeSeg}
    </div>
    <div className={RW.list} ref={listRef} tabIndex={-1}>
      {!items.length ? <EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter or switch tabs.</EmptyState> : groups.map(g => {
        const ck = group + ':' + g.k
        const col = !!collapsed[ck]
        return <div key={ck}>
          <div className={RW.ghead} role="button" tabIndex={-1} onClick={() => setCollapsed(c => ({ ...c, [ck]: !col }))}>
            <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', col && '-rotate-90')} />
            <span className="inline-flex size-3.5 flex-none items-center justify-center">{group === 'status' ? <CovSwatch status={g.k} size={[16, 12]} /> : group === 'origin' ? <TierBars tier={(model.risk.get(g.k)?.riskTier ?? 'unranked') as RiskTier} /> : <Icon name="surface" />}</span>
            <span>{group === 'origin' ? host(g.k) : group === 'category' ? prettyCat(g.k) : COV_L[g.k] ?? g.k}</span>
            <span className="font-normal tabular-nums text-fg-subtle">{g.list.length}</span>
          </div>
          {!col && g.list.map(x => {
            const id = cellKey(x.origin, x.category)
            const nfc = (M.findingsByCell[id] ?? []).length
            return <div key={x.id} className={cn(RW.row, selId === id && RW.rowCur)} data-id={id} onClick={() => nav.select({ kind: 'cell', id })}>
              <span className="inline-flex size-3.5 flex-none items-center justify-center" title={COV_L[x.status]}><CovSwatch status={x.status} size={[16, 12]} /></span>
              {group !== 'category' && <span className="w-[150px] flex-none truncate"><Tag>{prettyCat(x.category)}</Tag></span>}
              {group !== 'origin' && <span className="w-[160px] flex-none truncate font-mono text-[12px] text-fg-subtle">{host(x.origin)}</span>}
              <span className="min-w-0 flex-1 truncate text-fg-muted">{x.summary}</span>
              {x.enforcingControl && <span className="inline-flex flex-none text-fg-subtle" title={'Enforcing control: ' + x.enforcingControl}><Icon name="shield" /></span>}
              {x.proofGapReason && <span className="inline-flex flex-none text-warn" title={'Proof gap: ' + x.proofGapReason}><Icon name="alert" /></span>}
              {nfc > 0 && <span className="inline-flex h-[17px] flex-none items-center gap-1 rounded-[9px] bg-panel px-1.5 text-[11px] font-medium tabular-nums text-fg shadow-[inset_0_0_0_1px_var(--line-2)]" title="Findings in this cell"><SevGlyph sev={M.findingsByCell[id][0].severity} />{nfc}</span>}
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
    <div className="mb-0.5 mt-2.5 grid grid-cols-11 gap-[3px]">{CATS.map(c => {
      const st = cellStatus(M, origin, c[0])
      return <button
        key={c[0]}
        type="button"
        className="h-[22px] w-full cursor-pointer border-0 bg-transparent p-0 shadow-none transition-transform duration-[var(--d1)] ease-kovo hover:-translate-y-px hover:bg-transparent"
        title={`${c[1]}: ${COV_L[st]}`}
        onClick={() => nav.select({ kind: 'cell', id: cellKey(origin, c[0]) }, { push: nav.sel?.kind === 'host' })}
      >
        <span className={cn(
          'grid size-full place-items-center rounded-[4px] border',
          covTileClass(st),
          st === 'untested' && 'border-line-2',
          current === c[0] && 'shadow-[0_0_0_2px_var(--accent)]',
        )}>
          <CovGlyph status={st} />
        </span>
      </button>
    })}</div>
    <div className="mb-3 grid grid-cols-11 gap-[3px] text-center text-[9.5px] text-fg-subtle">{CATS.map(c => <span key={c[0]}>{c[2]}</span>)}</div>
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
    <PaneHeader title="Cell" sub={<><span className="font-mono text-[12px]">{host(o)}</span> · {cc[2]}</>} />
    <PaneBody><div className={RW.detail}>
      <h2 className="m-0 mb-2 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">{cc[1]}</h2>
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn('inline-flex h-[22px] items-center gap-1.5 rounded-[5px] border pl-[7px] pr-2 text-[12px] font-medium', covTileClass(st), st === 'untested' && 'border-line-2 text-fg-subtle')}>
          <CovGlyph status={st} />{COV_L[st]}
        </span>
        <button type="button" className={runBtn({ variant: 'link', size: 'none' })} onClick={() => nav.select({ kind: 'host', id: o }, { push: true })}>
          <span className="font-mono text-[12px]">{host(o)}</span><Icon name="arrowR" />
        </button>
      </div>
      <Locator origin={o} current={cat} />
      <Section title="Coverage summary">
        {r ? <p>{r.summary}</p> : <p>This cell hasn’t been charted. No worker has reported on {cc[1].toLowerCase()} for this origin yet.</p>}
        {r && (r.enforcingControl || r.proofGapReason || r.updatedAt) && <Props rows={[
          ...(r.enforcingControl ? [['Control', <span className="rw-wrap whitespace-normal break-words leading-[18px]">{r.enforcingControl}</span>] as [ReactNode, ReactNode]] : []),
          ...(r.proofGapReason ? [['Proof gap', <span className="rw-wrap whitespace-normal break-words leading-[18px] text-warn">{r.proofGapReason}</span>] as [ReactNode, ReactNode]] : []),
          ['Updated', fmtDate(r.updatedAt)],
        ]} />}
      </Section>
      {all.length > 0 && <Section title="Findings in this cell" right={all.length}>
        {all.map(f => <LinkRow key={f.id} glyph={<><SevGlyph sev={f.severity} /></>} onClick={() => links.finding(f.id)}
          title={`${SEV_LABEL[f.severity] ?? f.severity} · ${stLabel(normFStatus(f.status))}`}>
          <span className="mr-1.5 inline-flex align-[-2px]"><StatusGlyph status={normFStatus(f.status)} /></span>{f.title}{linked?.id === f.id && <span className="text-fg-subtle"> · linked</span>}
        </LinkRow>)}
        {mapped && <p className="mb-2! mt-1.5! flex items-center gap-1.5 text-[12px]! leading-[18px]! text-fg-subtle!">Mapped from the finding’s category; no coverage note was recorded for this cell.</p>}
      </Section>}
      {rec && <Section title="Recorded by">
        <LinkRow glyph={<StatusGlyph status={rec.status} />} trailing="workflow" onClick={() => links.worker(rec.id)}>{rec.title}</LinkRow>
      </Section>}
      {wl.length > 0 && <Section title="Other workers on this origin" right={wl.length}>
        {wl.slice(0, 5).map(w => <LinkRow key={w.id} glyph={<StatusGlyph status={w.status} />} right={PHASE_LABEL[w.phase] ?? w.phase} trailing={null} onClick={() => links.worker(w.id)}>{w.title}</LinkRow>)}
        {wl.length > 5 && <p className="mb-2! mt-1.5! flex items-center gap-1.5 text-[12px]! leading-[18px]! text-fg-subtle!">+{wl.length - 5} more · open the origin for the full list</p>}
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
    <PaneHeader title="Origin" sub={om ? <span className="tabular-nums">{plural(om.ncov, 'category', 'categories')} charted</span> : undefined} />
    <PaneBody><div className={RW.detail}>
      <div className="mb-2.5 flex flex-wrap gap-1.5">
        <Tag><TierBars tier={tier} />{RISKL[tier]}</Tag>
        {(om?.tags ?? []).slice(0, 4).map(t => <Tag key={t}>{t}</Tag>)}
      </div>
      <h2 className="m-0 mb-3 break-words font-mono text-[14px] font-semibold leading-[22px] text-fg">{host(o)}</h2>
      <Locator origin={o} current={null} />
      <div className="mb-3 flex flex-wrap gap-x-3 gap-y-1.5 text-[12px] tabular-nums text-fg-muted">
        {COV_ST.filter(s => cs[s[0]]).map(s => <span key={s[0]} className="inline-flex items-center gap-1.5"><CovSwatch status={s[0]} size={[14, 11]} />{s[1]} <span className="text-fg-subtle">{cs[s[0]]}</span></span>)}
      </div>
      {tm && <Section title="Threat model" right={rank >= 0 ? `#${rank + 1} of ${ranked.length}` : undefined}>
        <p>{tm.rationale}</p>
        {tm.surfaceTags.length > 4 && <div className="mb-2.5 flex flex-wrap gap-[5px]">{tm.surfaceTags.slice(4).map(t => <Tag key={t}>{t}</Tag>)}</div>}
      </Section>}
      {aps.length > 0 && <Section title="Approvals" right={aps.filter(a => a.status === 'pending').length ? aps.filter(a => a.status === 'pending').length + ' pending' : aps.length}>
        {aps.slice(0, 6).map(a => <LinkRow key={a.id} glyph={<StatusGlyph status={a.status === 'pending' ? 'waiting_approval' : a.status} />} right={stLabel(a.status)}
          trailing="queue" onClick={() => links.queueItem('ap:' + a.id)}><span className="font-mono text-[12px]">{a.method} {a.pathAndQuery}</span></LinkRow>)}
      </Section>}
      {notes.length > 0 && <Section title="Controls and proof gaps" right={notes.length}>
        {notes.map(x => <LinkRow key={x.id} glyph={<CovSwatch status={x.status} size={[14, 11]} />} trailing={null}
          sub={x.proofGapReason ? 'Proof gap: ' + x.proofGapReason : 'Control: ' + x.enforcingControl}
          onClick={() => links.cell(o, x.category)}>{prettyCat(x.category)}</LinkRow>)}
      </Section>}
      {fl.length > 0 && <Section title="Findings" right={fl.length}>
        {fl.slice(0, 12).map(f => <LinkRow key={f.id} glyph={<SevGlyph sev={f.severity} />} onClick={() => links.finding(f.id)}>
          <span className="mr-1.5 inline-flex align-[-2px]"><StatusGlyph status={normFStatus(f.status)} /></span>{f.title}
        </LinkRow>)}
        {fl.length > 12 && <p className="mb-2! mt-1.5! flex items-center gap-1.5 text-[12px]! leading-[18px]! text-fg-subtle!">+{fl.length - 12} more in Findings</p>}
      </Section>}
      {wl.length > 0 && <Section title="Workers" right={wl.length}>
        {wl.slice(0, 8).map(w => <LinkRow key={w.id} glyph={<StatusGlyph status={w.status} />} right={PHASE_LABEL[w.phase] ?? w.phase} trailing={null} onClick={() => links.worker(w.id)}>{w.title}</LinkRow>)}
        {wl.length > 8 && <p className="mb-2! mt-1.5! flex items-center gap-1.5 text-[12px]! leading-[18px]! text-fg-subtle!">+{wl.length - 8} more</p>}
      </Section>}
      <ExchangeLinks origin={o} max={4} />
      {!om && <p className="my-1.5 mb-2 flex items-center gap-1.5 text-[12px] leading-[18px] text-fg-subtle">This origin isn’t on the current surface map.</p>}
    </div></PaneBody>
  </>
}

/** Inspectors this view owns, keyed by selection kind. */
export const surfaceInspectors: InspectorMap = {
  cell: CellInspector,
  host: HostInspector,
  endpoint: EndpointInspector,
}
