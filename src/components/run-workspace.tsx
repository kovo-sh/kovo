import { Link, useNavigate } from '@tanstack/react-router'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { commandRun, runData } from '../actions.ts'
import { maxBudgetRequests, workerHistory } from '../domain.ts'
import { FormError, Status, useAction } from './common.tsx'
import { EvidenceDialog } from './evidence-dialog.tsx'
import { RunOverview } from './run-overview.tsx'
import type { Command } from './run-overview.tsx'
import { RunReport } from './run-report.tsx'
import { capabilityTierMeta, formatUsd, phaseNames, workerPhaseNames } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { ThreadTranscript } from './thread-transcript.tsx'
import { Button } from './ui/button.tsx'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from './ui/dropdown-menu.tsx'
import { Input, Textarea } from './ui/input.tsx'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupTextarea } from './ui/input-group.tsx'
import { WorkflowTrace } from './workflow-trace.tsx'

type View = 'overview' | 'trace' | 'report'

export function RunWorkspace({ detail: routeDetail, view, workerId }: {
  detail: RunDetail
  view: View
  workerId?: string
}) {
  const [snapshot, setSnapshot] = useState<RunDetail>()
  const detail = snapshot && snapshot.cursor >= routeDetail.cursor ? snapshot : routeDetail
  const { run, project, assignments, approvals, facts } = detail
  const history = useMemo(() => workerHistory(run, assignments), [run, assignments])
  const navigate = useNavigate()
  const runId = run.id
  const refreshRun = useCallback(async () => {
    try {
      const latest = await runData({ data: { runId } })
      setSnapshot(previous => !previous || latest.cursor >= previous.cursor ? latest : previous)
    } catch {
      // Keep the last committed view while the local server is restarting.
    }
  }, [runId])
  const action = useAction(refreshRun)
  const reducedMotion = useReducedMotion()
  const [reconnecting, setReconnecting] = useState(false)
  const [chatOpen, setChatOpen] = useState(true)
  const [showCoordinator, setShowCoordinator] = useState(false)
  const [revising, setRevising] = useState(false)
  const [draft, setDraft] = useState('')
  const [query, setQuery] = useState('')
  const [zoom, setZoom] = useState(1)
  const [artifact, setArtifact] = useState<string>()
  const search = useRef<HTMLInputElement>(null)
  const viewport = useRef<HTMLDivElement>(null)
  const cursor = useRef(detail.cursor)
  cursor.current = Math.max(cursor.current, detail.cursor)
  const selectedWorker = assignments.find(item => item.id === workerId)
  const worker = showCoordinator ? undefined : selectedWorker
  const inputWorker = worker?.inputAssignmentId
    ? assignments.find(item => item.id === worker.inputAssignmentId)
    : undefined
  const threadId = worker?.id ?? run.coordinatorId
  const messages = detail.messages.filter(item => item.threadId === threadId)
  const attachments = detail.evidence.filter(item => item.assignmentId === worker?.id)
  const workerFacts = worker ? facts.filter(fact => fact.assignmentId === worker.id) : undefined
  const workerHistoryLabel = worker && history.get(worker.id)
  const artifactWorkerId = artifact && detail.evidence.find(item => item.id === artifact)?.assignmentId
  const pendingApprovals = approvals.filter(item => item.status === 'pending')

  useEffect(() => {
    const events = new EventSource(`/api/runs/${runId}/events?since=${cursor.current}`)
    let refreshing = false
    let refreshAgain = false
    let disposed = false
    function requestRefresh() {
      if (refreshing) {
        refreshAgain = true
        return
      }
      refreshing = true
      void refreshRun().finally(() => {
        refreshing = false
        if (disposed || !refreshAgain) return
        refreshAgain = false
        requestRefresh()
      })
    }
    events.onopen = () => {
      setReconnecting(false)
      requestRefresh()
    }
    events.onerror = () => setReconnecting(true)
    events.onmessage = event => {
      if (Number(event.lastEventId) <= cursor.current) return
      cursor.current = Number(event.lastEventId)
      requestRefresh()
    }
    return () => {
      disposed = true
      events.close()
    }
  }, [refreshRun, runId])
  useEffect(() => {
    if (workerId) {
      setChatOpen(true)
      setShowCoordinator(false)
    }
  }, [workerId])
  useEffect(() => {
    const keyboard = (event: KeyboardEvent) => {
      if (event.defaultPrevented || artifact || (event.target instanceof HTMLElement && event.target.closest('[role=menu]'))) return
      const typing = event.target instanceof HTMLElement &&
        Boolean(event.target.closest('input, textarea, select, [contenteditable]'))
      if (event.key === '/' && !typing && search.current) {
        event.preventDefault()
        search.current.focus()
      }
      if (event.key === 'Escape' && chatOpen && workerId) closeWorker()
      if (view !== 'trace' || !(event.target instanceof HTMLElement)) return
      const searchFocused = event.target === search.current
      const workerFocused = event.target.matches('.trace-node')
      if (!searchFocused && !workerFocused) return
      const links = Array.from(document.querySelectorAll<HTMLAnchorElement>('.trace-node[data-match=true]'))
      if (!links.length) return
      if (event.key === 'Enter' && searchFocused) {
        event.preventDefault()
        links[0].click()
      } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault()
        const current = links.indexOf(event.target as HTMLAnchorElement)
        const next = current < 0 ? (event.key === 'ArrowUp' ? links.length - 1 : 0)
          : (current + (event.key === 'ArrowUp' ? -1 : 1) + links.length) % links.length
        links[next].focus()
      }
    }
    window.addEventListener('keydown', keyboard)
    return () => window.removeEventListener('keydown', keyboard)
  }, [workerId, chatOpen, artifact, view])

  function execute(command: Command, onSuccess?: () => void) {
    void action.submit(async () => {
      try {
        return await commandRun({ data: { ...command, runId: run.id, requestId: crypto.randomUUID() } })
      } catch (error) {
        if (command.action === 'scope') await refreshRun()
        throw error
      }
    }, onSuccess)
  }

  function closeWorker() {
    void navigate({ to: '/runs/$runId', params: { runId: run.id }, search: { view } })
  }

  function fitGraph() {
    const pane = viewport.current
    const graph = pane?.firstElementChild
    if (!pane || !(graph instanceof HTMLElement) || !graph.offsetWidth || !graph.offsetHeight) return
    setZoom(Math.min(1, pane.clientWidth / graph.offsetWidth, pane.clientHeight / graph.offsetHeight))
    pane.scrollTo(0, 0)
  }

  const needsModel = !detail.hasModel && run.approved.length > 0 && ['threat_model', 'investigation', 'verification'].includes(run.phase)
  const phaseLabel = run.status === 'budget_paused' ? 'budget_paused'
    : ['paused', 'failed', 'stopped'].includes(run.status) ? run.status
      : needsModel ? 'Waiting for model' : phaseNames[run.phase]

  const usdRatio = run.budgetUsd > 0 ? Math.min(1, run.spentUsd / run.budgetUsd) : 0
  const reqRatio = run.budgetRequests > 0 ? Math.min(1, run.spentRequests / run.budgetRequests) : 0
  const maxRatio = Math.max(usdRatio, reqRatio)
  const meterLevel = maxRatio >= 0.95 ? 'critical' : maxRatio >= 0.75 ? 'warn' : 'ok'
  const suggestedBudgetUsd = Math.min(500, Math.max(run.budgetUsd + 10, Math.ceil(run.spentUsd + 10)))
  const suggestedBudgetReqs = Math.min(maxBudgetRequests, Math.max(run.budgetRequests + 1000, run.spentRequests + 500))

  return <main className="run-page">
    <header className="run-heading">
      <div className="run-title">
        <Link to="/projects/$projectId" params={{ projectId: project.id }}>{project.name}</Link>
        <h1>Security assessment</h1>
        <div className="run-meta">
          <code>{project.seeds.map(seed => new URL(seed).hostname).join(', ')}</code>
          <span className="badge badge-trace">{capabilityTierMeta[run.capabilityTier].short}</span>
          <Status status={phaseLabel} />
          {pendingApprovals.length > 0 && <span className="badge badge-attention">
            {pendingApprovals.length} pending {pendingApprovals.length === 1 ? 'approval' : 'approvals'}
          </span>}
        </div>
      </div>
      <div className="run-header-right">
        <div className="budget-meter" aria-label="Run budget and usage meter">
          <div className="budget-meter-row">
            <span>Turns <strong>{run.turnsUsed}</strong></span>
            <span>Reqs <strong>{run.spentRequests}</strong>/{run.budgetRequests}</span>
            <span>Spend <strong>{formatUsd(run.spentUsd)}</strong>/{formatUsd(run.budgetUsd)}</span>
          </div>
          <div className="meter-track" role="progressbar" aria-label="Budget usage" aria-valuenow={Math.round(maxRatio * 100)} aria-valuemin={0} aria-valuemax={100}>
            <div className="meter-fill" data-level={meterLevel} style={{ width: `${Math.round(maxRatio * 100)}%` }} />
          </div>
        </div>
        <div className="toolbar run-actions">
          {run.status === 'running' && <Button disabled={action.pending} onClick={() => execute({ action: 'pause' })}>Pause</Button>}
          {['paused', 'stopped', 'failed'].includes(run.status) &&
            <Button variant="default" disabled={action.pending} onClick={() => execute({ action: 'resume' })}>Resume</Button>}
          {run.status !== 'complete' && run.status !== 'stopped' && <DropdownMenu>
            <DropdownMenuTrigger render={<Button size="icon" />} aria-label="Run actions">···</DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem disabled={action.pending} onClick={() => setRevising(true)}>Revise goal</DropdownMenuItem>
              <DropdownMenuItem variant="destructive" disabled={action.pending} onClick={() => execute({ action: 'stop' }, () => {
                void navigate({ to: '/runs/$runId', params: { runId: run.id }, search: { view: 'report' } })
              })}>Stop run</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>}
        </div>
      </div>
    </header>

    {run.status === 'budget_paused' && <section className="budget-banner" aria-label="Budget paused">
      <div>
        <h2>Run paused — budget ceiling reached</h2>
        <p className="muted">
          Spent {formatUsd(run.spentUsd)} of {formatUsd(run.budgetUsd)} USD and {run.spentRequests} of {run.budgetRequests} requests.
          A partial report has been saved; raise limits below to resume without repeating completed work.
        </p>
      </div>
      <form className="budget-banner-form" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        execute({
          action: 'raise_budget',
          budgetUsd: Number(form.get('budgetUsd')),
          budgetRequests: Number(form.get('budgetRequests')),
          resume: true,
        })
      }}>
        <label>New USD budget
          <Input name="budgetUsd" type="number" min={0.1} max={500} step="any" required defaultValue={suggestedBudgetUsd} />
        </label>
        <label>New request cap
          <Input name="budgetRequests" type="number" min={1} max={maxBudgetRequests} step={1} required defaultValue={suggestedBudgetReqs} />
        </label>
        <Button type="submit" variant="default" disabled={action.pending}>Raise budget &amp; Resume</Button>
      </form>
    </section>}

    {revising && <form className="revision-form" onSubmit={event => {
      event.preventDefault()
      execute({ action: 'revise', goal: String(new FormData(event.currentTarget).get('goal')) }, () => setRevising(false))
    }}>
      <label>Revise goal<Textarea name="goal" required maxLength={8000} defaultValue={run.goal} /></label>
      <div className="form-actions"><Button onClick={() => setRevising(false)}>Cancel</Button>
        <Button type="submit" variant="default" disabled={action.pending}>Save goal</Button></div>
    </form>}

    <div className="viewbar">
      <nav className="toolbar" aria-label="Run sections">
        <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'overview' }}
          data-active={view !== 'report'}>Workflow</Link>
        <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'report' }}
          data-active={view === 'report'}>Report</Link>
      </nav>
      <div className="toolbar trace-tools">
        {view !== 'report' && <>
          <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'overview' }}
            data-active={view === 'overview'}>Overview</Link>
          <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'trace' }}
            data-active={view === 'trace'}>Trace <small>{assignments.length}</small></Link>
          {view === 'trace' && <>
            <label className="worker-search"><span className="sr-only">Find worker</span>
              <Input ref={search} value={query} onChange={event => setQuery(event.target.value)} placeholder="Find worker…" />
              <kbd aria-hidden="true">/</kbd>
            </label>
            <div className="toolbar zoom">
              <Button variant="ghost" aria-label="Zoom out" disabled={zoom <= 0.35} onClick={() => setZoom(value => Math.max(0.35, value - 0.1))}>−</Button>
              <Button variant="ghost" onClick={fitGraph}>Fit</Button>
              <Button variant="ghost" aria-label="Zoom in" onClick={() => setZoom(value => Math.min(1.5, value + 0.1))}>+</Button>
            </div>
          </>}
        </>}
        <Button variant="ghost" aria-pressed={chatOpen} onClick={() => setChatOpen(!chatOpen)}>Chat</Button>
      </div>
    </div>
    {reconnecting && <p className="run-error muted" role="status">Reconnecting to Guardian…</p>}
    {action.error && <div className="run-error"><FormError error={action.error} /></div>}

    <div className="workbench" data-with-chat={chatOpen}>
      <section className="work-surface" aria-label={view === 'report' ? 'Run report' : 'Workflow'}>
        {view !== 'report' && needsModel && <div className="workflow-callout run-model-callout">
          <div><h2>Connect a model to continue</h2><p>Model settings will return you to this run.</p></div>
          <Link className="action-link primary" to="/settings" search={{ runId }}>Set up model</Link>
        </div>}
        <div hidden={view !== 'overview'}>
          <RunOverview detail={detail} history={history} execute={execute} openEvidence={setArtifact} pending={action.pending} />
        </div>
        <div className="trace-holder" hidden={view !== 'trace'}>
          <WorkflowTrace detail={detail} history={history} workerId={workerId} query={query} zoom={zoom} viewport={viewport} />
        </div>
        {view === 'report' && <RunReport detail={detail} execute={execute} pending={action.pending} openEvidence={setArtifact} />}
      </section>
      <AnimatePresence initial={false}>
        {chatOpen && <motion.section className="chat-pane" aria-label={worker ? 'Worker thread' : 'Coordinator chat'}
          initial={{ opacity: 0, x: reducedMotion ? 0 : 8 }} animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: reducedMotion ? 0 : 8 }} transition={{ duration: 0.19 }}>
          <div className="chat-header">
            {worker ? <Button variant="ghost" onClick={() => setShowCoordinator(true)}>Coordinator</Button> : <strong>Coordinator</strong>}
            {worker ? <strong>Worker</strong> : selectedWorker &&
              <Button variant="ghost" onClick={() => setShowCoordinator(false)}>Worker</Button>}
            <Button variant="ghost" size="icon" className="close-pane" onClick={() => setChatOpen(false)} aria-label="Close chat">×</Button>
          </div>
          {!worker && pendingApprovals.length > 0 && <div aria-label="Coordinator approval prompts">
            {pendingApprovals.map(item => <div key={item.id} className="approval-card approval-card-compact">
              <div className="inline-badges">
                <strong>Tier 3 approval</strong>
                <span className="badge badge-attention">{item.method}</span>
              </div>
              <p className="approval-target"><code>{item.origin}{item.pathAndQuery}</code></p>
              <p className="muted">{item.rationale}</p>
              <div className="approval-actions">
                <Button className="btn-danger" disabled={action.pending} onClick={() => {
                  execute({ action: 'decide_approval', approvalId: item.id, decision: 'denied' })
                }}>Deny</Button>
                <Button variant="default" disabled={action.pending} onClick={() => {
                  execute({ action: 'decide_approval', approvalId: item.id, decision: 'approved' })
                }}>Approve</Button>
              </div>
            </div>)}
          </div>}
          <AnimatePresence initial={false} mode="sync">
            <motion.div className="thread-content" key={threadId}
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, position: 'absolute', visibility: 'hidden' }}
              transition={{ duration: reducedMotion ? 0 : 0.18 }}>
              {worker && <header className="worker-intro">
                <h2>{worker.title}</h2>
                <p className="muted">{workerPhaseNames[worker.phase]} · <Status status={worker.status} /></p>
                <div className="worker-metrics">
                  <span>{worker.turnsUsed} / {worker.maxTurns} turns</span>
                  <span>{worker.requestsUsed} reqs</span>
                  {workerFacts && workerFacts.length > 0 && <span>{workerFacts.length} facts</span>}
                </div>
                {workerHistoryLabel && <p className="muted">{workerHistoryLabel}</p>}
                {inputWorker && <p className="muted worker-input">Input from <Link to="/runs/$runId/workers/$workerId"
                  params={{ runId, workerId: inputWorker.id }} search={{ view: 'trace' }}>{inputWorker.title}</Link></p>}
                {worker.outcome && <p className="outcome">{worker.outcome}</p>}
              </header>}
              <ThreadTranscript messages={messages} worker={worker} workerFacts={workerFacts} attachments={attachments} openEvidence={setArtifact} />
            </motion.div>
          </AnimatePresence>
          {!worker && <form className="composer" onSubmit={event => {
            event.preventDefault()
            if (draft.trim()) execute({ action: 'message', message: draft }, () => setDraft(''))
          }}>
            <InputGroup>
              <InputGroupTextarea rows={1} value={draft} onChange={event => setDraft(event.target.value)} aria-label="Message coordinator"
                placeholder="Message coordinator or steer investigation…" maxLength={8000} onKeyDown={event => {
                  if (event.key !== 'Enter' || event.shiftKey || event.nativeEvent.isComposing) return
                  event.preventDefault()
                  event.currentTarget.form?.requestSubmit()
                }} />
              <InputGroupAddon><InputGroupButton type="submit" variant="default" aria-label="Send message"
                disabled={action.pending || !draft.trim()}>↑</InputGroupButton></InputGroupAddon>
            </InputGroup>
          </form>}
        </motion.section>}
      </AnimatePresence>
    </div>
    {artifact && <EvidenceDialog runId={run.id} artifactId={artifact}
      historyLabel={artifactWorkerId ? history.get(artifactWorkerId) : undefined} close={() => setArtifact(undefined)} />}
  </main>
}
