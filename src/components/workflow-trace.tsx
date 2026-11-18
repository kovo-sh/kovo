import { useRef } from 'react'
import type { RefObject } from 'react'
import { Link } from '@tanstack/react-router'
import { Status } from './common.tsx'
import { phaseNames, workerPhases } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { TraceIcon, TraceLine, TraceTitle } from './ui/trace.tsx'

export function WorkflowTrace({ detail, workerId, query, zoom, viewport }: {
  detail: RunDetail
  workerId?: string
  query: string
  zoom: number
  viewport: RefObject<HTMLDivElement | null>
}) {
  const drag = useRef<{ pointer: number; x: number; y: number; left: number; top: number } | null>(null)
  const groups = workerPhases.map(phase => {
    const workers = detail.assignments.filter(worker => worker.phase === phase)
    const columns = workers.length > 10 ? 2 : 1
    return { phase, workers, columns, rowCount: Math.ceil(workers.length / columns) }
  })
  return <div className="trace-workspace">
    <div className="trace-topline">
      <span><strong>Scope</strong> {detail.run.scopeRevision ? `Revision ${detail.run.scopeRevision} · ${detail.run.approved.length} approved` : 'Awaiting approval'}</span>
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
      <div className="trace-groups" style={{ zoom }}>
        {groups.map(({ phase, workers, columns, rowCount }, index) => {
          const completed = workers.filter(worker => worker.status === 'complete').length
          const canceled = workers.filter(worker => worker.status === 'canceled').length
          const rows = Math.max(1, rowCount)
          const colWidth = 218
          const rowHeight = 38
          const width = columns * colWidth
          const height = rows * rowHeight + 28
          return <section className="trace-group" key={phase} style={{ width }}
            data-active={detail.run.phase === phase} aria-label={phaseNames[phase]}>
            <header><h2>{phaseNames[phase]}</h2><small>{completed} of {workers.length} complete{canceled > 0 && ` · ${canceled} canceled`}</small></header>
            {index < groups.length - 1 && <span className="phase-arrow" aria-hidden="true">→</span>}
            <div className="trace-lane" style={{ height }}>
              <svg className="trace-lines" width={width} height={height} aria-hidden="true">
                <path d={`M8 5 H${width - 8} M8 5 V${height - 8} H${width - 8} V5`} />
                {workers.map((worker, i) => {
                  const left = Math.floor(i / rows) * colWidth + 8
                  const top = i % rows * rowHeight + 30
                  return <path key={worker.id} data-selected={worker.id === workerId}
                    d={`M${left} 5 V${top} h11 M${left + colWidth - 31} ${top} h15 V${height - 8}`} />
                })}
                <circle cx="8" cy="5" r="3" /><circle cx={width - 8} cy="5" r="3" />
              </svg>
              {workers.map((worker, i) => {
                const match = !query || worker.title.toLowerCase().includes(query.trim().toLowerCase())
                return <Link key={worker.id} to="/runs/$runId/workers/$workerId"
                  params={{ runId: detail.run.id, workerId: worker.id }} search={{ view: 'trace' }}
                  className="trace-node" aria-label={`${worker.title}, ${worker.status}`}
                  data-match={match} data-selected={workerId === worker.id} data-worker-status={worker.status}
                  style={{ left: Math.floor(i / rows) * colWidth + 18, top: (i % rows) * rowHeight + 15 }}
                  tabIndex={match ? 0 : -1}>
                  <TraceLine><TraceTitle>{worker.title}</TraceTitle><TraceIcon><i /></TraceIcon></TraceLine>
                </Link>
              })}
              {workers.length === 0 && <p className="trace-empty">Awaiting assignments</p>}
            </div>
          </section>
        })}
      </div>
    </div>
    <div className="trace-footer"><Status status="complete" /><Status status="queued" /><Status status="running" /><span>Drag to pan</span></div>
  </div>
}
