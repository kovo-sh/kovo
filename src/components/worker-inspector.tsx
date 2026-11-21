import { useEffect, useMemo, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { readWorkerSessionAction } from '../actions.ts'
import type { WorkerSessionData } from '../server/worker-session-reader.ts'
import { Status, timeText } from './common.tsx'
import { RunExchanges } from './run-exchanges.tsx'
import { workerPhaseNames } from './run-state.ts'
import type { RunDetail, Worker } from './run-state.ts'
import { Button } from './ui/button.tsx'

type InspectorTab = 'timeline' | 'exchanges' | 'facts' | 'shell'

function safeHost(origin: string) {
  try {
    const u = new URL(origin)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch {
    return origin
  }
}

export function WorkerInspector({
  detail,
  worker,
  historyLabel,
  openEvidence,
}: {
  detail: RunDetail
  worker: Worker
  historyLabel?: string
  openEvidence: (id: string) => void
}) {
  const [tab, setTab] = useState<InspectorTab>('timeline')
  const [session, setSession] = useState<WorkerSessionData | null>(null)
  const [loadingSession, setLoadingSession] = useState(false)
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({})
  const [expandedFacts, setExpandedFacts] = useState<Record<string, boolean>>({})
  const [expandedShell, setExpandedShell] = useState<Record<string, boolean>>({})
  const [focusExchangeId, setFocusExchangeId] = useState<string | undefined>()

  const step = useMemo(
    () => detail.chainSteps.find(s => s.id === worker.stepId || s.assignedWorkerId === worker.id),
    [detail.chainSteps, worker.stepId, worker.id],
  )
  const inputWorker = useMemo(
    () => worker.inputAssignmentId ? detail.assignments.find(a => a.id === worker.inputAssignmentId) : undefined,
    [detail.assignments, worker.inputAssignmentId],
  )
  const workerExchanges = useMemo(
    () => detail.exchangesSummary.filter(ex => ex.assignmentId === worker.id),
    [detail.exchangesSummary, worker.id],
  )
  const workerFacts = useMemo(
    () => detail.facts.filter(f => f.assignmentId === worker.id),
    [detail.facts, worker.id],
  )
  const workerAttachments = useMemo(
    () => detail.evidence.filter(ev => ev.assignmentId === worker.id && ev.operationId !== 'assignment'),
    [detail.evidence, worker.id],
  )
  const workerMessages = useMemo(
    () => detail.messages.filter(m => m.threadId === worker.id),
    [detail.messages, worker.id],
  )

  useEffect(() => {
    let active = true
    setLoadingSession(true)
    setSession(null)
    setFocusExchangeId(undefined)
    readWorkerSessionAction({ data: { runId: detail.run.id, workerId: worker.id } })
      .then(data => {
        if (!active) return
        setSession(data)
        if (data.artifacts.length > 0) {
          setExpandedShell({ [data.artifacts[0].id]: true })
        }
      })
      .catch(() => {
        if (active) setSession({ workerId: worker.id, sessionId: worker.sessionId, turns: [], artifacts: [] })
      })
      .finally(() => {
        if (active) setLoadingSession(false)
      })
    return () => { active = false }
  }, [detail.run.id, worker.id, worker.sessionId, worker.turnsUsed, worker.status])

  const turns = session?.turns ?? []
  const artifacts = session?.artifacts ?? []
  const artifactCount = artifacts.length || workerAttachments.length

  function jumpToExchange(exchangeId: string) {
    setFocusExchangeId(exchangeId)
    setTab('exchanges')
  }

  return <div className="worker-inspector">
    <header className="worker-inspector-head">
      <div className="worker-inspector-meta-top">
        <div className="inline-badges">
          {step && <span className="mono muted xs">#{step.seq}</span>}
          <Status status={worker.status} />
          <span className="badge">{workerPhaseNames[worker.phase]}</span>
          {step && <span className="badge badge-trace">P{step.priority}</span>}
          {step?.category && <span className="badge">{step.category}</span>}
        </div>
      </div>

      <h2 className="worker-inspector-title">{worker.title}</h2>

      <div className="worker-metrics mono">
        <span>{worker.turnsUsed} / {worker.maxTurns} turns</span>
        <span>·</span>
        <span>{worker.requestsUsed} reqs</span>
        <span>·</span>
        <span>{workerFacts.length} facts</span>
        <span>·</span>
        <span>{artifactCount} artifacts</span>
      </div>

      {step && step.skills.length > 0 && <div className="skill-chips">
        {step.skills.map(skill => <span key={skill} className="skill-chip mono">{skill}</span>)}
      </div>}

      {historyLabel && <p className="muted xs">{historyLabel}</p>}
      {inputWorker && <p className="muted xs worker-input">
        Input from <Link to="/runs/$runId/workers/$workerId"
          params={{ runId: detail.run.id, workerId: inputWorker.id }}
          search={{ view: 'trace' }}>{inputWorker.title}</Link>
      </p>}

      <div className="insp-tabs" role="tablist" aria-label="Worker inspector sections">
        <button type="button" role="tab" aria-selected={tab === 'timeline'}
          className={`insp-tab${tab === 'timeline' ? ' active' : ''}`}
          onClick={() => setTab('timeline')}>
          Timeline <span className="mono">{turns.length || worker.turnsUsed}</span>
        </button>
        <button type="button" role="tab" aria-selected={tab === 'exchanges'}
          className={`insp-tab${tab === 'exchanges' ? ' active' : ''}`}
          onClick={() => setTab('exchanges')}>
          Exchanges <span className="mono">{workerExchanges.length}</span>
        </button>
        <button type="button" role="tab" aria-selected={tab === 'facts'}
          className={`insp-tab${tab === 'facts' ? ' active' : ''}`}
          onClick={() => setTab('facts')}>
          Facts <span className="mono">{workerFacts.length}</span>
        </button>
        <button type="button" role="tab" aria-selected={tab === 'shell'}
          className={`insp-tab${tab === 'shell' ? ' active' : ''}`}
          onClick={() => setTab('shell')}>
          Shell / Artifacts <span className="mono">{artifactCount}</span>
        </button>
      </div>
    </header>

    <div className="worker-inspector-body">
      {tab === 'timeline' && <div className="insp-timeline">
        <details className="insp-objective-box" open={turns.length === 0}>
          <summary>Assignment objective</summary>
          <p className="muted">{worker.objective}</p>
        </details>

        {worker.outcome && <div className="outcome-card">
          <div className="pane-kicker">Outcome</div>
          <p>{worker.outcome}</p>
        </div>}

        {loadingSession && turns.length === 0 && <p className="muted xs">Loading durable session timeline…</p>}

        {turns.length > 0 ? turns.map(turn => <div key={turn.turn} className="timeline-turn">
          <div className="timeline-turn-head">
            <span className="mono turn-num">Turn {turn.turn}</span>
            {turn.durationMs !== undefined && <span className="muted mono xs">{(turn.durationMs / 1000).toFixed(1)}s</span>}
            {turn.timestamp && <span className="muted xs" style={{ marginLeft: 'auto' }}>{timeText(turn.timestamp)}</span>}
          </div>
          {turn.thinking && <p className="turn-thought">{turn.thinking}</p>}
          {turn.text && turn.text !== worker.outcome && <p className="turn-text">{turn.text}</p>}
          {turn.tools.length > 0 && <div className="tool-cards">
            {turn.tools.map(tc => {
              const isExpanded = Boolean(expandedTools[tc.id])
              return <div key={tc.id} className={`tool-card${tc.status === 'finding' ? ' is-finding' : tc.status === 'error' ? ' is-error' : ''}`}>
                <div className="tool-card-top mono">
                  <span className="tool-name">{tc.name}</span>
                  <span className={`tool-status st-${tc.status}`}>{tc.status}</span>
                  {tc.durationMs !== undefined && <span className="muted xs" style={{ marginLeft: 'auto' }}>{tc.durationMs}ms</span>}
                </div>
                {tc.argsPreview && <div className="tool-args mono">{tc.argsPreview}</div>}
                {tc.resultPreview && <>
                  <button
                    type="button"
                    className="text-button xs"
                    onClick={() => setExpandedTools(prev => ({ ...prev, [tc.id]: !prev[tc.id] }))}
                  >
                    {isExpanded ? 'Hide tool result ▴' : 'Show tool result ▾'}
                  </button>
                  {isExpanded && <pre className="code-block tool-result-pre">{tc.resultPreview}</pre>}
                </>}
              </div>
            })}
          </div>}
        </div>) : (!loadingSession && workerMessages.length > 0 && <div className="timeline-fallback">
          {workerMessages
            .filter(m => m.content.trim() !== (worker.outcome ?? '').trim())
            .map(m => <div key={m.id} className="timeline-turn">
              <div className="timeline-turn-head">
                <span className="turn-num">{m.role}</span>
                <span className="muted xs" style={{ marginLeft: 'auto' }}>{timeText(m.createdAt)}</span>
              </div>
              <p className="turn-text">{m.content}</p>
            </div>)}
        </div>)}
      </div>}

      {tab === 'exchanges' && <RunExchanges
        key={`${worker.id}-${focusExchangeId ?? ''}`}
        runId={detail.run.id}
        exchanges={workerExchanges}
        compact
        initialExpandedId={focusExchangeId}
      />}

      {tab === 'facts' && <div className="insp-facts">
        {workerFacts.length === 0 ? <p className="muted">No structured facts recorded by this worker yet.</p>
          : workerFacts.map(fact => {
            const open = Boolean(expandedFacts[fact.id])
            return <article key={fact.id} className={`fact-card${fact.tainted ? ' tainted' : ''}`}>
              <div className="fact-card-top">
                <span className="badge badge-trace mono">{fact.kind}</span>
                <span className="mono muted xs">{safeHost(fact.origin)}</span>
                {fact.tainted && <span className="badge badge-danger">tainted</span>}
              </div>
              <p className="fact-summary">{fact.summary}</p>
              <div className="fact-card-foot">
                <div className="inline-badges">
                  {fact.exchangeIds.map(exId => <button
                    key={exId}
                    type="button"
                    className="chip-link mono"
                    onClick={() => jumpToExchange(exId)}
                  >
                    ex:{exId.slice(0, 8)} →
                  </button>)}
                  {fact.evidenceIds.map(evId => <button
                    key={evId}
                    type="button"
                    className="chip-link mono"
                    onClick={() => openEvidence(evId)}
                  >
                    ev:{evId.slice(0, 8)} ↗
                  </button>)}
                </div>
                <button
                  type="button"
                  className="text-button xs"
                  onClick={() => setExpandedFacts(prev => ({ ...prev, [fact.id]: !prev[fact.id] }))}
                >
                  {open ? 'Hide JSON ▴' : 'View JSON ▾'}
                </button>
              </div>
              {open && <pre className="code-block">{JSON.stringify(fact.data, null, 2)}</pre>}
            </article>
          })}
      </div>}

      {tab === 'shell' && <div className="insp-shell">
        {loadingSession && artifacts.length === 0 && <p className="muted xs">Loading shell commands &amp; artifacts…</p>}
        {!loadingSession && artifacts.length === 0 && workerAttachments.length === 0 &&
          <p className="muted">No shell runs or evidence artifacts recorded by this worker.</p>}
        {artifacts.map(art => {
          const open = Boolean(expandedShell[art.id])
          const hasShell = Boolean(art.command)
          return <div key={art.id} className={`shell-card${open ? ' open' : ''}`}>
            <button
              type="button"
              className="shell-card-head"
              onClick={() => setExpandedShell(prev => ({ ...prev, [art.id]: !prev[art.id] }))}
            >
              {hasShell
                ? <span className={`exit-badge ${art.exitStatus === 0 ? 'ok' : 'nonzero'} mono`}>
                    exit {art.exitStatus ?? 0}
                  </span>
                : <span className="badge">{art.kind}</span>}
              <code className="shell-cmd">{hasShell ? art.command : art.title}</code>
              <span className="disclosure-chevron-inline" aria-hidden="true">{open ? '▾' : '▸'}</span>
            </button>
            {open && <div className="shell-card-body">
              <div className="shell-card-bar">
                <span className="muted xs">{art.title} · {timeText(art.createdAt)}</span>
                <Button type="button" variant="ghost" onClick={() => openEvidence(art.id)}>Open full artifact ↗</Button>
              </div>
              {hasShell ? <>
                {art.stdout && <pre className="code-block">{art.stdout}</pre>}
                {art.stderr && <pre className="code-block code-stderr">{art.stderr}</pre>}
                {!art.stdout && !art.stderr && <p className="muted xs">(no stdout/stderr output)</p>}
              </> : <pre className="code-block">{art.preview || '(empty artifact)'}</pre>}
            </div>}
          </div>
        })}
      </div>}
    </div>
  </div>
}
