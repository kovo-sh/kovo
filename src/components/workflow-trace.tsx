import { useRef, useState } from 'react'
import type { RefObject } from 'react'
import { Link } from '@tanstack/react-router'
import { readGraphDigest } from '../actions.ts'
import { Status } from './common.tsx'
import { workerPhaseNames, workerPhases } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { TraceIcon, TraceLine, TraceTitle } from './ui/trace.tsx'

const columnWidth = 236
const columnGap = 62
const headerHeight = 56
const laneGap = 16
const rowHeight = 42
const nodeHeight = 33

function edgePath(fromX: number, fromY: number, toX: number, toY: number) {
  const start = fromX + columnWidth
  const middle = (start + toX) / 2
  return `M ${start} ${fromY} C ${middle} ${fromY}, ${middle} ${toY}, ${toX} ${toY}`
}

function sameColEdgePath(fromX: number, fromY: number, toX: number, toY: number) {
  const left = fromX + columnWidth
  const bulge = left + 26
  return `M ${left} ${fromY} C ${bulge} ${fromY}, ${bulge} ${toY}, ${toX + columnWidth} ${toY}`
}

export function WorkflowTrace({ detail, history, workerId, query, zoom, viewport }: {
  detail: RunDetail
  history: ReadonlyMap<string, string>
  workerId?: string
  query: string
  zoom: number
  viewport: RefObject<HTMLDivElement | null>
}) {
  const drag = useRef<{ pointer: number; x: number; y: number; left: number; top: number } | null>(null)
  const [expandedDigests, setExpandedDigests] = useState<Record<string, Awaited<ReturnType<typeof readGraphDigest>> | 'loading' | 'error'>>({})
  const search = query.trim().toLowerCase()

  const activeFacts = detail.facts.filter(f => !f.tainted)
  const factCountByWorker = new Map<string, number>()
  const factAuthorById = new Map<string, string>()
  for (const fact of activeFacts) {
    factCountByWorker.set(fact.assignmentId, (factCountByWorker.get(fact.assignmentId) ?? 0) + 1)
    factAuthorById.set(fact.id, fact.assignmentId)
  }

  const stepById = new Map(detail.chainSteps.map(step => [step.id, step]))
  const stepByWorkerId = new Map(
    detail.chainSteps.filter(step => step.assignedWorkerId).map(step => [step.assignedWorkerId!, step]),
  )

  const rows = new Map<string, number>()
  const groups = workerPhases.map((phase, index) => {
    const workers = detail.assignments.filter(worker => worker.phase === phase)
    const inputRow = (id: string | null) => (id ? rows.get(id) : undefined) ?? detail.assignments.length
    workers.sort((a, b) => inputRow(a.inputAssignmentId) - inputRow(b.inputAssignmentId))
    const nodes = workers.map((worker, row) => {
      rows.set(worker.id, row)
      const step = worker.stepId ? stepById.get(worker.stepId) : stepByWorkerId.get(worker.id)
      const haystack = `${worker.title} ${step?.title ?? ''} ${step?.category ?? ''}`.toLowerCase()
      return {
        worker,
        step,
        factCount: factCountByWorker.get(worker.id) ?? 0,
        row,
        x: index * (columnWidth + columnGap),
        y: headerHeight + laneGap + row * rowHeight + nodeHeight / 2,
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

  const incomingByTarget = new Map<string, string[]>()
  for (const { from, to } of edges) {
    const list = incomingByTarget.get(to.worker.id) ?? []
    list.push(from.worker.id)
    incomingByTarget.set(to.worker.id, list)
  }
  const ancestors = new Set<string>()
  if (workerId) {
    const queue = [workerId]
    while (queue.length) {
      const id = queue.shift()!
      if (ancestors.has(id)) continue
      ancestors.add(id)
      for (const parent of incomingByTarget.get(id) ?? []) queue.push(parent)
    }
  }
  const descendants = new Set<string>(workerId ? [workerId] : [])
  let grew = true
  while (grew) {
    grew = false
    for (const { from, to } of edges) {
      if (descendants.has(from.worker.id) && !descendants.has(to.worker.id)) {
        descendants.add(to.worker.id)
        grew = true
      }
    }
  }

  const latestReport = detail.reports[0]
  const reportEvidence = new Set(latestReport?.body.coverage.map(host => host.evidenceId).filter(Boolean))
  const reportInputs = new Set(detail.evidence
    .filter(item => (item.kind === 'verification' || item.kind === 'replay') && (reportEvidence.has(item.id) || detail.findings.some(f => f.evidenceIds.includes(item.id))))
    .map(item => item.assignmentId))
  const reportX = groups.length * (columnWidth + columnGap)
  const reportY = headerHeight + laneGap + nodeHeight / 2

  const completedSteps = detail.chainSteps.filter(s => s.status === 'complete').length
  const unassignedSteps = detail.chainSteps.filter(s => !s.assignedWorkerId)
  const activeDigests = detail.digests.filter(d => d.active)

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
    <div className="trace-topline">
      <span><strong>Scope</strong> {detail.run.scopeRevision ? `Rev ${detail.run.scopeRevision} · ${detail.run.approved.length} approved` : 'Awaiting approval'}</span>
      {detail.run.goalRevision > 0 && <span><strong>Goal</strong> Rev {detail.run.goalRevision}</span>}
      <span><strong>Round</strong> {detail.run.roundNo}</span>
      <span><strong>Chain steps</strong> {completedSteps}/{detail.chainSteps.length}</span>
      <span><strong>Facts</strong> {activeFacts.length}</span>
      <span><strong>Exchanges</strong> {detail.exchangesSummary.length}</span>
      {activeDigests.length > 0 && <span><strong>Cold digests</strong> {activeDigests.length}</span>}
    </div>
    <div ref={viewport} className="trace-viewport" aria-label="Worker graph" tabIndex={0}
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
      <div className="trace-canvas" style={{ zoom }}>
        <div className="trace-groups" style={{ gap: columnGap }}>
          <svg className="trace-lines" width="100%" height="100%" data-has-selection={Boolean(workerId)} aria-hidden="true">
            {edges.map(({ from, to }) => {
              const fromId = from.worker.id
              const toId = to.worker.id
              const selected = (ancestors.has(fromId) && ancestors.has(toId)) ||
                (descendants.has(fromId) && descendants.has(toId))
              const path = from.x === to.x
                ? sameColEdgePath(from.x, from.y, to.x, to.y)
                : edgePath(from.x, from.y, to.x, to.y)
              return <path key={`${fromId}-${toId}`} className="trace-edge" data-from={fromId} data-to={toId} data-selected={selected}
                data-historical={history.has(fromId) || history.has(toId)}
                data-matches={from.matches || to.matches} data-running={to.worker.status === 'running'}
                d={path} />
            })}
            {latestReport && nodes.filter(node => node.worker.phase === 'verification' && (reportInputs.size === 0 || reportInputs.has(node.worker.id))).map(node =>
              <path key={'report-' + node.worker.id} className="trace-edge" data-from={node.worker.id} data-to={latestReport.id}
                data-report="true" data-selected={descendants.has(node.worker.id)} data-running={false}
                data-matches={node.matches} d={edgePath(node.x, node.y, reportX, reportY)} />)}
          </svg>
          {groups.map(({ phase, nodes: phaseNodes }) => {
            const current = phaseNodes.filter(({ worker }) => !history.has(worker.id))
            const earlier = phaseNodes.length - current.length
            const completed = current.filter(({ worker }) => worker.status === 'complete').length
            const canceled = current.filter(({ worker }) => worker.status === 'canceled').length
            return <section className="trace-group" key={phase} style={{ width: columnWidth }}
              data-active={detail.run.phase === phase} aria-label={workerPhaseNames[phase]}>
              <header style={{ height: headerHeight }}>
                <h2>{workerPhaseNames[phase]}</h2>
                <small>
                  {completed} of {current.length} complete
                  {canceled > 0 && ` · ${canceled} canceled`}
                  {earlier > 0 && ` · ${earlier} earlier`}
                  {phase === 'threat_model' && detail.threatModel ? ` · ${detail.threatModel.entries.length} ranked` : ''}
                </small>
              </header>
              <div className="trace-lane" style={{ height: Math.max(1, phaseNodes.length) * rowHeight, marginTop: laneGap }}>
                {phaseNodes.map(({ worker, factCount, row, matches }) => {
                  const historyLabel = history.get(worker.id)
                  return <Link key={worker.id} to="/runs/$runId/workers/$workerId"
                    params={{ runId: detail.run.id, workerId: worker.id }} search={{ view: 'trace' }}
                    className="trace-node" aria-label={[worker.title, worker.status, historyLabel].filter(Boolean).join(', ')}
                    title={`${worker.title} (${worker.turnsUsed}/${worker.maxTurns} turns · ${worker.requestsUsed} reqs · ${factCount} facts)${historyLabel ? `\n${historyLabel}` : ''}`}
                    data-match={matches} data-selected={workerId === worker.id} data-worker-status={worker.status}
                    data-historical={Boolean(historyLabel)}
                    style={{ top: row * rowHeight, height: nodeHeight }}
                    tabIndex={matches ? 0 : -1}>
                    <TraceLine>
                      <TraceTitle>{worker.title}</TraceTitle>
                      <span className="trace-node-meta">
                        {worker.turnsUsed > 0 && <span>{worker.turnsUsed}t</span>}
                        {factCount > 0 && <span>{factCount}f</span>}
                        <TraceIcon className={historyLabel ? 'trace-history' : undefined}>{historyLabel ? '↶' : <i />}</TraceIcon>
                      </span>
                    </TraceLine>
                  </Link>
                })}
                {phaseNodes.length === 0 && <p className="trace-empty">Awaiting assignments</p>}
              </div>
              {phase === 'investigation' && unassignedSteps.length > 0 && <div className="trace-step-lane" aria-label="Queued chain steps">
                {unassignedSteps.slice(0, 12).map(step => <div key={step.id} className="trace-step-card" data-status={step.status}>
                  <div className="section-heading">
                    <strong>#{step.seq} {step.title}</strong>
                    <Status status={step.status} />
                  </div>
                  <span className="muted">{step.category}</span>
                </div>)}
              </div>}
            </section>
          })}
          {latestReport && <section className="trace-group" style={{ width: columnWidth }} aria-label="Report output">
            <header style={{ height: headerHeight }}>
              <h2>Report</h2>
              <small>Version {latestReport.version}{latestReport.partial ? ' · Partial' : ''}</small>
            </header>
            <div className="trace-lane" style={{ height: rowHeight, marginTop: laneGap }}>
              <Link className="trace-node" style={{ top: 0, height: nodeHeight }} data-worker-status="complete"
                to="/runs/$runId" params={{ runId: detail.run.id }} search={{ view: 'report' }}>
                <TraceLine>
                  <TraceTitle>{latestReport.partial ? 'Partial report' : 'Complete report'}</TraceTitle>
                  <TraceIcon><i /></TraceIcon>
                </TraceLine>
              </Link>
            </div>
          </section>}
        </div>
      </div>
    </div>

    {detail.digests.length > 0 && <section className="trace-digests" aria-label="Cold graph digests">
      <div className="section-heading">
        <strong>Cold-graph digests ({detail.digests.length})</strong>
        <span className="muted">LSM-compacted inactive branches</span>
      </div>
      {detail.digests.map(digest => {
        const expanded = expandedDigests[digest.id]
        return <details key={digest.id}>
          <summary>
            Round {digest.roundNo} · {digest.level} digest · {digest.coveredFactIds.length} facts · {digest.coveredAssignmentIds.length} workers
            {!digest.active && ' (superseded)'}
          </summary>
          <p>{digest.summary}</p>
          <div style={{ marginTop: 8 }}>
            {!expanded && <Button variant="ghost" onClick={() => void expandDigest(digest.id)}>Load covered facts</Button>}
            {expanded === 'loading' && <span className="muted">Loading facts…</span>}
            {expanded === 'error' && <span className="profile-error">Could not load digest facts.</span>}
            {expanded && typeof expanded === 'object' && <ul className="project-list">
              {expanded.facts.map(fact => <li key={fact.id}>
                <div className="list-row">
                  <span><strong>[{fact.kind}]</strong> {fact.summary}</span>
                  <span className="muted">{new URL(fact.origin).hostname}</span>
                </div>
              </li>)}
              {expanded.facts.length === 0 && <li><div className="list-row"><span className="muted">No untainted facts remain in this digest.</span></div></li>}
            </ul>}
          </div>
        </details>
      })}
    </section>}

    <div className="trace-footer">
      <Status status="complete" />
      <Status status="queued" />
      <Status status="running" />
      <Status status="waiting_approval" />
      <span>Drag to pan</span>
    </div>
  </div>
}
