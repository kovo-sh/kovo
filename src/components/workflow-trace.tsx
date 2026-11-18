import { useRef } from 'react'
import type { RefObject } from 'react'
import { Link } from '@tanstack/react-router'
import { Status } from './common.tsx'
import { phaseNames, workerPhases } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { TraceIcon, TraceLine, TraceTitle } from './ui/trace.tsx'

const columnWidth = 220
const columnGap = 66
const headerHeight = 54
const laneGap = 16
const rowHeight = 40
const nodeHeight = 31

function edgePath(fromX: number, fromY: number, toX: number, toY: number) {
  const start = fromX + columnWidth
  const middle = (start + toX) / 2
  return `M ${start} ${fromY} C ${middle} ${fromY}, ${middle} ${toY}, ${toX} ${toY}`
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
  const search = query.trim().toLowerCase()
  const rows = new Map<string, number>()
  const groups = workerPhases.map((phase, index) => {
    const workers = detail.assignments.filter(worker => worker.phase === phase)
    const inputRow = (id: string | null) => (id ? rows.get(id) : undefined) ?? detail.assignments.length
    workers.sort((a, b) => inputRow(a.inputAssignmentId) - inputRow(b.inputAssignmentId))
    const nodes = workers.map((worker, row) => {
      rows.set(worker.id, row)
      return {
        worker, row, x: index * (columnWidth + columnGap), y: headerHeight + laneGap + row * rowHeight + nodeHeight / 2,
        matches: !search || worker.title.toLowerCase().includes(search),
      }
    })
    return { phase, nodes }
  })
  const nodes = groups.flatMap(group => group.nodes)
  const nodeById = new Map(nodes.map(node => [node.worker.id, node]))
  const edges = nodes.flatMap(to => {
    const inputId = to.worker.inputAssignmentId
    const from = inputId ? nodeById.get(inputId) : undefined
    return from && from.x < to.x ? [{ from, to }] : []
  })
  const inputs = new Map(edges.map(({ from, to }) => [to.worker.id, from.worker.id]))
  const ancestors = new Set<string>()
  for (let id = workerId; id; id = inputs.get(id)) ancestors.add(id)
  const descendants = new Set(workerId ? [workerId] : [])
  for (const { from, to } of edges) {
    if (descendants.has(from.worker.id)) descendants.add(to.worker.id)
  }
  const latest = detail.reports[0]
  const report = latest?.partial === false ? latest : undefined
  const reportEvidence = new Set(report?.body.coverage.map(host => host.evidenceId))
  const reportInputs = new Set(detail.evidence.filter(item => item.kind === 'verification' && reportEvidence.has(item.id))
    .map(item => item.assignmentId))
  const reportX = groups.length * (columnWidth + columnGap)
  const reportY = headerHeight + laneGap + nodeHeight / 2

  return <div className="trace-workspace">
    <div className="trace-topline">
      <span><strong>Scope</strong> {detail.run.scopeRevision ? `Revision ${detail.run.scopeRevision} · ${detail.run.approved.length} approved` : 'Awaiting approval'}</span>
      {detail.run.goalRevision > 0 && <span><strong>Goal</strong> Revision {detail.run.goalRevision}</span>}
    </div>
    <div ref={viewport} className="trace-viewport" aria-label="Worker graph" tabIndex={0}
      onPointerDown={event => {
        if (event.pointerType === 'touch' || event.button !== 0 || (event.target as Element).closest('a, button, input')) return
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
              return <path key={toId} className="trace-edge" data-from={fromId} data-to={toId} data-selected={selected}
                data-historical={history.has(fromId) || history.has(toId)}
                data-matches={from.matches || to.matches} data-running={to.worker.status === 'running'}
                d={edgePath(from.x, from.y, to.x, to.y)} />
            })}
            {report && nodes.filter(node => node.worker.phase === 'verification' && reportInputs.has(node.worker.id)).map(node =>
              <path key={'report-' + node.worker.id} className="trace-edge" data-from={node.worker.id} data-to={report.id}
                data-report="true" data-selected={descendants.has(node.worker.id)} data-running={false}
                data-matches={node.matches} d={edgePath(node.x, node.y, reportX, reportY)} />)}
          </svg>
          {groups.map(({ phase, nodes }) => {
            const current = nodes.filter(({ worker }) => !history.has(worker.id))
            const earlier = nodes.length - current.length
            const completed = current.filter(({ worker }) => worker.status === 'complete').length
            const canceled = current.filter(({ worker }) => worker.status === 'canceled').length
            return <section className="trace-group" key={phase} style={{ width: columnWidth }}
              data-active={detail.run.phase === phase} aria-label={phaseNames[phase]}>
              <header style={{ height: headerHeight }}><h2>{phaseNames[phase]}</h2>
                <small>{completed} of {current.length} complete
                  {canceled > 0 && ` · ${canceled} canceled`}{earlier > 0 && ` · ${earlier} earlier`}</small>
              </header>
              <div className="trace-lane" style={{ height: Math.max(1, nodes.length) * rowHeight, marginTop: laneGap }}>
                {nodes.map(({ worker, row, matches }) => {
                  const historyLabel = history.get(worker.id)
                  return <Link key={worker.id} to="/runs/$runId/workers/$workerId"
                    params={{ runId: detail.run.id, workerId: worker.id }} search={{ view: 'trace' }}
                    className="trace-node" aria-label={[worker.title, worker.status, historyLabel].filter(Boolean).join(', ')}
                    title={historyLabel ? `${worker.title}\n${historyLabel}` : undefined}
                    data-match={matches} data-selected={workerId === worker.id} data-worker-status={worker.status}
                    data-historical={Boolean(historyLabel)}
                    style={{ top: row * rowHeight, height: nodeHeight }}
                    tabIndex={matches ? 0 : -1}>
                    <TraceLine><TraceTitle>{worker.title}</TraceTitle>
                      <TraceIcon className={historyLabel ? 'trace-history' : undefined}>{historyLabel ? '↶' : <i />}</TraceIcon>
                    </TraceLine>
                  </Link>
                })}
                {nodes.length === 0 && <p className="trace-empty">Awaiting assignments</p>}
              </div>
            </section>
          })}
          {report && <section className="trace-group" style={{ width: columnWidth }} aria-label="Report output">
            <header style={{ height: headerHeight }}><h2>Report</h2><small>Version {report.version}</small></header>
            <div className="trace-lane" style={{ height: rowHeight, marginTop: laneGap }}>
              <Link className="trace-node" style={{ top: 0, height: nodeHeight }} data-worker-status="complete"
                to="/runs/$runId" params={{ runId: detail.run.id }} search={{ view: 'report' }}>
                <TraceLine><TraceTitle>Complete report</TraceTitle><TraceIcon><i /></TraceIcon></TraceLine>
              </Link>
            </div>
          </section>}
        </div>
      </div>
    </div>
    <div className="trace-footer"><Status status="complete" /><Status status="queued" /><Status status="running" /><span>Drag to pan</span></div>
  </div>
}
