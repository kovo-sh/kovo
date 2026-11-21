import { useMemo, useRef, useState } from 'react'
import type { RefObject } from 'react'
import { Link } from '@tanstack/react-router'
import { readGraphDigest } from '../actions.ts'
import { Status } from './common.tsx'
import { workerPhaseNames, workerPhases } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { Input } from './ui/input.tsx'

const cardWidth = 300
const cardHeight = 96
const columnGap = 56
const headerHeight = 52
const laneGap = 14
const rowGap = 12
const rowStep = cardHeight + rowGap

type TraceMode = 'list' | 'graph'
type TraceFilter = 'all' | 'running' | 'complete' | 'findings'

function edgePath(fromX: number, fromY: number, toX: number, toY: number) {
  const start = fromX + cardWidth
  const middle = (start + toX) / 2
  return `M ${start} ${fromY} C ${middle} ${fromY}, ${middle} ${toY}, ${toX} ${toY}`
}

function sameColEdgePath(fromX: number, fromY: number, toX: number, toY: number) {
  const right = fromX + cardWidth
  const bulge = right + 26
  return `M ${right} ${fromY} C ${bulge} ${fromY}, ${bulge} ${toY}, ${toX + cardWidth} ${toY}`
}

function safeHost(origin: string) {
  try {
    const u = new URL(origin)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch {
    return origin
  }
}

export function WorkflowTrace({ detail, history, workerId, query, setQuery, zoom, setZoom, fitGraph, viewport, searchRef }: {
  detail: RunDetail
  history: ReadonlyMap<string, string>
  workerId?: string
  query: string
  setQuery: (next: string) => void
  zoom: number
  setZoom: (updater: number | ((v: number) => number)) => void
  fitGraph: () => void
  viewport: RefObject<HTMLDivElement | null>
  searchRef: RefObject<HTMLInputElement | null>
}) {
  const drag = useRef<{ pointer: number; x: number; y: number; left: number; top: number } | null>(null)
  const [traceMode, setTraceMode] = useState<TraceMode>('list')
  const [traceFilter, setTraceFilter] = useState<TraceFilter>('all')
  const [hoveredWorkerId, setHoveredWorkerId] = useState<string | null>(null)
  const [digestsOpen, setDigestsOpen] = useState(false)
  const [expandedDigests, setExpandedDigests] = useState<Record<string, Awaited<ReturnType<typeof readGraphDigest>> | 'loading' | 'error'>>({})

  const search = query.trim().toLowerCase()

  const activeFacts = useMemo(() => detail.facts.filter(f => !f.tainted), [detail.facts])
  const { factCountByWorker, factAuthorById } = useMemo(() => {
    const counts = new Map<string, number>()
    const authors = new Map<string, string>()
    for (const fact of activeFacts) {
      counts.set(fact.assignmentId, (counts.get(fact.assignmentId) ?? 0) + 1)
      authors.set(fact.id, fact.assignmentId)
    }
    return { factCountByWorker: counts, factAuthorById: authors }
  }, [activeFacts])

  const findingCountByWorker = useMemo(() => {
    const counts = new Map<string, number>()
    const evToWorker = new Map(detail.evidence.map(ev => [ev.id, ev.assignmentId]))
    const exToWorker = new Map(detail.exchangesSummary.map(ex => [ex.id, ex.assignmentId]))
    for (const finding of detail.findings) {
      if (finding.status !== 'confirmed' && finding.status !== 'static_verified') continue
      const authors = new Set<string>()
      for (const eid of finding.evidenceIds) {
        const w = evToWorker.get(eid)
        if (w) authors.add(w)
      }
      for (const exid of finding.exchangeIds ?? []) {
        const w = exToWorker.get(exid)
        if (w) authors.add(w)
      }
      for (const w of authors) {
        counts.set(w, (counts.get(w) ?? 0) + 1)
      }
    }
    return counts
  }, [detail.findings, detail.evidence, detail.exchangesSummary])

  const stepById = useMemo(() => new Map(detail.chainSteps.map(step => [step.id, step])), [detail.chainSteps])
  const stepByWorkerId = useMemo(
    () => new Map(detail.chainSteps.filter(step => step.assignedWorkerId).map(step => [step.assignedWorkerId!, step])),
    [detail.chainSteps],
  )

  const filterCounts = useMemo(() => {
    let running = 0
    let complete = 0
    let withFindings = 0
    for (const w of detail.assignments) {
      if (w.status === 'running' || w.status === 'waiting_approval') running += 1
      if (w.status === 'complete') complete += 1
      if ((findingCountByWorker.get(w.id) ?? 0) > 0) withFindings += 1
    }
    return { all: detail.assignments.length, running, complete, findings: withFindings }
  }, [detail.assignments, findingCountByWorker])

  function matchesFilter(w: RunDetail['assignments'][number]) {
    if (traceFilter === 'running') return w.status === 'running' || w.status === 'waiting_approval'
    if (traceFilter === 'complete') return w.status === 'complete'
    if (traceFilter === 'findings') return (findingCountByWorker.get(w.id) ?? 0) > 0
    return true
  }

  const rows = new Map<string, number>()
  const groups = workerPhases.map((phase, index) => {
    const workers = detail.assignments
      .filter(worker => worker.phase === phase)
      .filter(matchesFilter)
    const inputRow = (id: string | null) => (id ? rows.get(id) : undefined) ?? detail.assignments.length
    workers.sort((a, b) => inputRow(a.inputAssignmentId) - inputRow(b.inputAssignmentId))
    const nodes = workers.map((worker, row) => {
      rows.set(worker.id, row)
      const step = worker.stepId ? stepById.get(worker.stepId) : stepByWorkerId.get(worker.id)
      const host = worker.sourceOrigins[0] ? safeHost(worker.sourceOrigins[0]) : ''
      const haystack = `${worker.title} ${step?.title ?? ''} ${step?.category ?? ''} ${host}`.toLowerCase()
      return {
        worker,
        step,
        host,
        factCount: factCountByWorker.get(worker.id) ?? 0,
        findingCount: findingCountByWorker.get(worker.id) ?? 0,
        row,
        x: index * (cardWidth + columnGap),
        y: headerHeight + laneGap + row * rowStep + cardHeight / 2,
        matches: !search || haystack.includes(search),
      }
    })
    return { phase, nodes }
  })

  const nodes = groups.flatMap(group => group.nodes)
  const nodeById = new Map(nodes.map(node => [node.worker.id, node]))

  const edgeKeys = new Set<string>()
  const edges: { from: typeof nodes[number]; to: typeof nodes[number]; causal?: boolean }[] = []
  function addEdge(fromId: string | null | undefined, toNode: typeof nodes[number], causal = false) {
    if (!fromId || fromId === toNode.worker.id) return
    const from = nodeById.get(fromId)
    if (!from) return
    if (from.x > toNode.x) return
    if (from.x === toNode.x && from.row >= toNode.row) return
    const key = `${from.worker.id}->${toNode.worker.id}`
    if (edgeKeys.has(key)) return
    edgeKeys.add(key)
    edges.push({ from, to: toNode, causal })
  }

  for (const to of nodes) {
    addEdge(to.worker.inputAssignmentId, to, false)
    for (const parentFactId of to.worker.parentFactIds ?? []) {
      addEdge(factAuthorById.get(parentFactId), to, true)
    }
    if (to.step) {
      for (const depStepId of to.step.dependsOnStepIds) {
        addEdge(stepById.get(depStepId)?.assignedWorkerId, to, true)
      }
      for (const depFactId of to.step.dependsOnFactIds) {
        addEdge(factAuthorById.get(depFactId), to, true)
      }
    }
  }

  const focusId = hoveredWorkerId || workerId
  const relatedNodes = new Set<string>()
  if (focusId) {
    relatedNodes.add(focusId)
    for (const { from, to } of edges) {
      if (from.worker.id === focusId) relatedNodes.add(to.worker.id)
      if (to.worker.id === focusId) relatedNodes.add(from.worker.id)
    }
  }

  const latestReport = detail.reports[0]
  const reportEvidence = new Set(latestReport?.body.coverage.map(host => host.evidenceId).filter(Boolean))
  const reportInputs = new Set(detail.evidence
    .filter(item => (item.kind === 'verification' || item.kind === 'replay') && (reportEvidence.has(item.id) || detail.findings.some(f => f.evidenceIds.includes(item.id))))
    .map(item => item.assignmentId))
  const reportX = groups.length * (cardWidth + columnGap)
  const reportY = headerHeight + laneGap + cardHeight / 2

  const completedSteps = detail.chainSteps.filter(s => s.status === 'complete').length
  const unassignedSteps = detail.chainSteps.filter(s => !s.assignedWorkerId)
  const activeDigests = detail.digests.filter(d => d.active)

  const listWorkers = useMemo(() => {
    const phaseOrder = new Map<string, number>([
      ['discovery', 0], ['threat_model', 1], ['investigation', 2], ['verification', 3], ['retest', 4],
    ])
    return detail.assignments
      .filter(matchesFilter)
      .map(worker => {
        const step = worker.stepId ? stepById.get(worker.stepId) : stepByWorkerId.get(worker.id)
        const host = worker.sourceOrigins[0] ? safeHost(worker.sourceOrigins[0]) : ''
        const haystack = `${worker.title} ${step?.title ?? ''} ${step?.category ?? ''} ${host}`.toLowerCase()
        return {
          worker,
          step,
          host,
          factCount: factCountByWorker.get(worker.id) ?? 0,
          findingCount: findingCountByWorker.get(worker.id) ?? 0,
          matches: !search || haystack.includes(search),
          phaseIdx: phaseOrder.get(worker.phase) ?? 2,
        }
      })
      .filter(item => item.matches)
      .sort((a, b) => a.worker.createdAt - b.worker.createdAt)
  }, [detail.assignments, traceFilter, search, stepById, stepByWorkerId, factCountByWorker, findingCountByWorker])

  async function expandDigest(digestId: string) {
    if (expandedDigests[digestId] && expandedDigests[digestId] !== 'error') return
    setExpandedDigests(prev => ({ ...prev, [digestId]: 'loading' }))
    try {
      const result = await readGraphDigest({ data: { runId: detail.run.id, digestId } })
      setExpandedDigests(prev => ({ ...prev, [digestId]: result }))
    } catch {
      setExpandedDigests(prev => ({ ...prev, [digestId]: 'error' }))
    }
  }

  return <div className="trace-workspace">
    <div className="trace-toolbar">
      <div className="filter-chips" role="group" aria-label="Filter workers">
        <button type="button" className={`filter-chip${traceFilter === 'all' ? ' active' : ''}`}
          onClick={() => setTraceFilter('all')}>All <span className="mono">{filterCounts.all}</span></button>
        <button type="button" className={`filter-chip${traceFilter === 'running' ? ' active' : ''}`}
          onClick={() => setTraceFilter('running')}>Running <span className="mono">{filterCounts.running}</span></button>
        <button type="button" className={`filter-chip${traceFilter === 'complete' ? ' active' : ''}`}
          onClick={() => setTraceFilter('complete')}>Complete <span className="mono">{filterCounts.complete}</span></button>
        <button type="button" className={`filter-chip${traceFilter === 'findings' ? ' active' : ''}`}
          onClick={() => setTraceFilter('findings')}>With Findings <span className="mono">{filterCounts.findings}</span></button>
      </div>

      <div className="trace-toolbar-right">
        <label className="worker-search"><span className="sr-only">Find worker</span>
          <Input ref={searchRef} value={query} onChange={event => setQuery(event.target.value)} placeholder="Find worker…" />
          <kbd aria-hidden="true">/</kbd>
        </label>

        {detail.digests.length > 0 && <button
          type="button"
          className={`filter-chip${digestsOpen ? ' active' : ''}`}
          onClick={() => setDigestsOpen(v => !v)}
          title="LSM-compacted cold graph digests"
        >
          Cold digests <span className="mono">{activeDigests.length || detail.digests.length}</span> {digestsOpen ? '▴' : '▾'}
        </button>}

        {traceMode === 'graph' && <div className="toolbar zoom">
          <Button variant="ghost" aria-label="Zoom out" disabled={zoom <= 0.35} onClick={() => setZoom(v => Math.max(0.35, Number((v - 0.1).toFixed(2))))}>−</Button>
          <Button variant="ghost" onClick={fitGraph}>Fit</Button>
          <Button variant="ghost" aria-label="Zoom in" onClick={() => setZoom(v => Math.min(1.5, Number((v + 0.1).toFixed(2))))}>+</Button>
        </div>}

        <div className="segmented-toggle" role="group" aria-label="Trace view mode">
          <button type="button" className={`seg-btn${traceMode === 'list' ? ' active' : ''}`}
            onClick={() => setTraceMode('list')}>List</button>
          <button type="button" className={`seg-btn${traceMode === 'graph' ? ' active' : ''}`}
            onClick={() => setTraceMode('graph')}>Graph</button>
        </div>
      </div>
    </div>

    <div className="trace-topline">
      <span><strong>Scope</strong> {detail.run.scopeRevision ? `Rev ${detail.run.scopeRevision} · ${detail.run.approved.length} approved` : 'Awaiting approval'}</span>
      <span><strong>Round</strong> {detail.run.roundNo}</span>
      <span><strong>Chain steps</strong> {completedSteps}/{detail.chainSteps.length}</span>
      <span><strong>Facts</strong> {activeFacts.length}</span>
      <span><strong>Exchanges</strong> {detail.exchangesSummary.length}</span>
    </div>

    {digestsOpen && detail.digests.length > 0 && <section className="trace-digests-drawer" aria-label="Cold graph digests">
      <div className="section-heading">
        <strong>Cold-graph digests ({detail.digests.length})</strong>
        <Button type="button" variant="ghost" onClick={() => setDigestsOpen(false)}>Close</Button>
      </div>
      <div className="trace-digests-list">
        {detail.digests.map(digest => {
          const expanded = expandedDigests[digest.id]
          return <details key={digest.id}>
            <summary>
              Round {digest.roundNo} · {digest.level} digest · {digest.coveredFactIds.length} facts · {digest.coveredAssignmentIds.length} workers
              {!digest.active && ' (superseded)'}
            </summary>
            <p className="muted">{digest.summary}</p>
            <div style={{ marginTop: 6 }}>
              {!expanded && <Button variant="ghost" onClick={() => void expandDigest(digest.id)}>Load covered facts</Button>}
              {expanded === 'loading' && <span className="muted">Loading facts…</span>}
              {expanded === 'error' && <span className="profile-error">Could not load digest facts.</span>}
              {expanded && typeof expanded === 'object' && <ul className="project-list">
                {expanded.facts.map(fact => <li key={fact.id}>
                  <div className="list-row">
                    <span><strong>[{fact.kind}]</strong> {fact.summary}</span>
                    <span className="muted">{safeHost(fact.origin)}</span>
                  </div>
                </li>)}
              </ul>}
            </div>
          </details>
        })}
      </div>
    </section>}

    {traceMode === 'list' ? <div className="trace-list-scroll" aria-label="Worker timeline list">
      {listWorkers.length === 0 ? <div className="empty-panel">
        <p className="muted">No workers match the active filter.</p>
      </div> : <div className="trace-list">
        {listWorkers.map(({ worker, step, host, factCount, findingCount, phaseIdx }, idx) => {
          const selected = worker.id === workerId
          const historyLabel = history.get(worker.id)
          const startPct = Math.min(72, phaseIdx * 18 + (idx % 3) * 2)
          const widthPct = Math.max(12, Math.min(30, Math.round((Math.max(1, worker.turnsUsed) / Math.max(10, worker.maxTurns)) * 42) + 12))
          return <Link
            key={worker.id}
            to="/runs/$runId/workers/$workerId"
            params={{ runId: detail.run.id, workerId: worker.id }}
            search={{ view: 'trace' }}
            className={`trace-list-row${selected ? ' selected' : ''}`}
            data-match="true"
            data-worker-status={worker.status}
          >
            <div className="tl-left">
              <div className="tl-top">
                <span className={`w-dot st-${worker.status}`} aria-hidden="true" />
                {step && <span className="mono muted xs">#{step.seq}</span>}
                <strong className="tl-title">{worker.title}</strong>
                {findingCount > 0 && <span className="badge badge-attention">{findingCount} finding{findingCount > 1 ? 's' : ''}</span>}
                {historyLabel && <span className="badge">{historyLabel}</span>}
              </div>
              <div className="tl-sub">
                <span className="badge">{workerPhaseNames[worker.phase]}</span>
                {host && <span className="mono muted xs">{host}</span>}
                {step?.category && <span className="muted xs">· {step.category}</span>}
                {step && <span className="mono muted xs">· P{step.priority}</span>}
              </div>
            </div>
            <div className="tl-gantt" aria-hidden="true">
              <div className="gantt-track">
                <div className={`gantt-bar st-${worker.status}${findingCount > 0 ? ' has-finding' : ''}`}
                  style={{ left: `${startPct}%`, width: `${widthPct}%` }} />
              </div>
            </div>
            <div className="tl-chips mono tabular">
              <span className="tl-chip">{worker.turnsUsed}t</span>
              <span className="tl-chip">{worker.requestsUsed} req</span>
              <span className="tl-chip">{factCount} facts</span>
              <Status status={worker.status} />
            </div>
          </Link>
        })}
      </div>}
    </div> : <div ref={viewport} className="trace-viewport" aria-label="Worker graph" tabIndex={0}
      onPointerDown={event => {
        if (event.pointerType === 'touch' || event.button !== 0 || (event.target as Element).closest('a, button, input, summary')) return
        drag.current = {
          pointer: event.pointerId, x: event.clientX, y: event.clientY,
          left: event.currentTarget.scrollLeft, top: event.currentTarget.scrollTop,
        }
        event.currentTarget.setPointerCapture(event.pointerId)
      }}
      onPointerMove={event => {
        if (!drag.current || drag.current.pointer !== event.pointerId) return
        event.currentTarget.scrollLeft = drag.current.left + drag.current.x - event.clientX
        event.currentTarget.scrollTop = drag.current.top + drag.current.y - event.clientY
      }}
      onLostPointerCapture={() => { drag.current = null }}>
      <div className="trace-canvas" style={{ transform: `scale(${zoom})`, transformOrigin: '0 0' }}>
        <div className="trace-groups" style={{ gap: columnGap }}>
          <svg className="trace-lines" width="100%" height="100%" data-has-selection={Boolean(focusId)} aria-hidden="true">
            {edges.map(({ from, to }) => {
              const fromId = from.worker.id
              const toId = to.worker.id
              const isHot = Boolean(focusId && (fromId === focusId || toId === focusId))
              const isDim = Boolean(hoveredWorkerId && !isHot)
              const path = from.x === to.x
                ? sameColEdgePath(from.x, from.y, to.x, to.y)
                : edgePath(from.x, from.y, to.x, to.y)
              return <path key={`${fromId}-${toId}`} className="trace-edge"
                data-from={fromId} data-to={toId}
                data-selected={isHot}
                data-dim={isDim}
                data-historical={history.has(fromId) || history.has(toId)}
                data-matches={from.matches || to.matches}
                data-running={to.worker.status === 'running'}
                d={path} />
            })}
            {latestReport && nodes.filter(node => node.worker.phase === 'verification' && (reportInputs.size === 0 || reportInputs.has(node.worker.id))).map(node =>
              <path key={'report-' + node.worker.id} className="trace-edge" data-from={node.worker.id} data-to={latestReport.id}
                data-report="true" data-selected={focusId === node.worker.id} data-running={false}
                data-matches={node.matches} d={edgePath(node.x, node.y, reportX, reportY)} />)}
          </svg>
          {groups.map(({ phase, nodes: phaseNodes }) => {
            const current = phaseNodes.filter(({ worker }) => !history.has(worker.id))
            const completed = current.filter(({ worker }) => worker.status === 'complete').length
            return <section className="trace-group" key={phase} style={{ width: cardWidth }}
              data-active={detail.run.phase === phase} aria-label={workerPhaseNames[phase]}>
              <header style={{ height: headerHeight }}>
                <h2>{workerPhaseNames[phase]}</h2>
                <small>{completed} of {current.length} complete</small>
              </header>
              <div className="trace-lane" style={{ height: Math.max(1, phaseNodes.length) * rowStep, marginTop: laneGap }}>
                {phaseNodes.map(({ worker, step, host, factCount, findingCount, row, matches }) => {
                  const historyLabel = history.get(worker.id)
                  const isDim = Boolean(hoveredWorkerId && !relatedNodes.has(worker.id))
                  return <Link key={worker.id} to="/runs/$runId/workers/$workerId"
                    params={{ runId: detail.run.id, workerId: worker.id }} search={{ view: 'trace' }}
                    className={`trace-node trace-card-node${isDim ? ' dim' : ''}`}
                    aria-label={[worker.title, worker.status, historyLabel].filter(Boolean).join(', ')}
                    data-match={matches} data-selected={workerId === worker.id} data-worker-status={worker.status}
                    data-historical={Boolean(historyLabel)}
                    style={{ top: row * rowStep, height: cardHeight }}
                    onMouseEnter={() => setHoveredWorkerId(worker.id)}
                    onMouseLeave={() => setHoveredWorkerId(curr => curr === worker.id ? null : curr)}
                    tabIndex={matches ? 0 : -1}>
                    <div className="trace-card-top">
                      <span className="trace-card-id mono">
                        <span className={`w-dot st-${worker.status}`} aria-hidden="true" />
                        {step ? `#${step.seq} · P${step.priority}` : workerPhaseNames[worker.phase]}
                      </span>
                      <div className="inline-badges">
                        {findingCount > 0 && <span className="badge badge-attention">{findingCount} finding{findingCount > 1 ? 's' : ''}</span>}
                        {host && <span className="mono muted xs truncate" style={{ maxWidth: 120 }}>{host}</span>}
                      </div>
                    </div>
                    <div className="trace-card-title">{worker.title}</div>
                    <div className="trace-card-chips mono tabular">
                      <span className="tl-chip">{worker.turnsUsed}t</span>
                      <span className="tl-chip">{worker.requestsUsed} req</span>
                      <span className="tl-chip">{factCount} facts</span>
                    </div>
                  </Link>
                })}
                {phaseNodes.length === 0 && <p className="trace-empty">Awaiting assignments</p>}
              </div>
              {phase === 'investigation' && unassignedSteps.length > 0 && <div className="trace-step-lane" aria-label="Queued chain steps">
                {unassignedSteps.slice(0, 8).map(step => <div key={step.id} className="trace-step-card" data-status={step.status}>
                  <div className="section-heading">
                    <strong>#{step.seq} {step.title}</strong>
                    <Status status={step.status} />
                  </div>
                  <span className="muted">{step.category}</span>
                </div>)}
              </div>}
            </section>
          })}
          {latestReport && <section className="trace-group" style={{ width: cardWidth }} aria-label="Report output">
            <header style={{ height: headerHeight }}>
              <h2>Report</h2>
              <small>Version {latestReport.version}{latestReport.partial ? ' · Partial' : ''}</small>
            </header>
            <div className="trace-lane" style={{ height: rowStep, marginTop: laneGap }}>
              <Link className="trace-node trace-card-node" style={{ top: 0, height: cardHeight }} data-worker-status="complete"
                to="/runs/$runId" params={{ runId: detail.run.id }} search={{ view: 'report' }}>
                <div className="trace-card-top">
                  <span className="trace-card-id mono"><span className="w-dot st-complete" />Report v{latestReport.version}</span>
                </div>
                <div className="trace-card-title">{latestReport.partial ? 'Partial report' : 'Complete report'}</div>
                <div className="trace-card-chips mono">
                  <span className="tl-chip">Open full report →</span>
                </div>
              </Link>
            </div>
          </section>}
        </div>
      </div>
    </div>}

    <div className="trace-footer">
      <Status status="complete" />
      <Status status="queued" />
      <Status status="running" />
      <Status status="waiting_approval" />
      <span>{traceMode === 'graph' ? 'Hover card to isolate causal edges · Drag canvas to pan' : 'Click any worker row to open 4-tab Inspector'}</span>
    </div>
  </div>
}
