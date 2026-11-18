import { Link, useNavigate } from '@tanstack/react-router'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { commandRun, runData } from '../actions.ts'
import { FormError, Status, useAction } from './common.tsx'
import { EvidenceDialog } from './evidence-dialog.tsx'
import { RunOverview } from './run-overview.tsx'
import type { Command } from './run-overview.tsx'
import { RunReport } from './run-report.tsx'
import { phaseNames } from './run-state.ts'
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
  const { run, project, assignments } = detail
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
  const threadId = worker?.id ?? run.coordinatorId
  const messages = detail.messages.filter(item => item.threadId === threadId)
  const attachments = detail.evidence.filter(item => item.assignmentId === worker?.id)

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
    if (!pane || !(graph instanceof HTMLElement) || !graph.offsetWidth) return
    setZoom(Math.min(1, pane.clientWidth / graph.offsetWidth))
    pane.scrollTo(0, 0)
  }

  const phaseLabel = ['paused', 'failed', 'stopped'].includes(run.status) ? run.status : phaseNames[run.phase]

  return <main className="run-page">
    <header className="run-heading">
      <div className="run-title">
        <Link to="/projects/$projectId" params={{ projectId: project.id }}>{project.name}</Link>
        <h1>Website review</h1>
        <div className="run-meta"><code>{project.seeds.map(seed => new URL(seed).hostname).join(', ')}</code>
          <Status status={phaseLabel} /></div>
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
    </header>
    {revising && <form className="revision-form" onSubmit={event => {
      event.preventDefault()
      execute({ action: 'revise', goal: String(new FormData(event.currentTarget).get('goal')) }, () => setRevising(false))
    }}>
      <label>Revise goal<Textarea name="goal" required maxLength={1500} defaultValue={run.goal} /></label>
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
        <div hidden={view !== 'overview'}>
          <RunOverview detail={detail} execute={execute} openEvidence={setArtifact} pending={action.pending} />
        </div>
        <div className="trace-holder" hidden={view !== 'trace'}>
          <WorkflowTrace detail={detail} workerId={workerId} query={query} zoom={zoom} viewport={viewport} />
        </div>
        {view === 'report' && <RunReport detail={detail} openEvidence={setArtifact} />}
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
          <AnimatePresence initial={false} mode="sync">
            <motion.div className="thread-content" key={threadId}
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, position: 'absolute', visibility: 'hidden' }}
              transition={{ duration: reducedMotion ? 0 : 0.18 }}>
              {worker && <header className="worker-intro">
                <h2>{worker.title}</h2><p className="muted">{phaseNames[worker.phase]} · <Status status={worker.status} /></p>
                {worker.outcome && <p className="outcome">{worker.outcome}</p>}
              </header>}
              <ThreadTranscript messages={messages} worker={worker} attachments={attachments} openEvidence={setArtifact} />
            </motion.div>
          </AnimatePresence>
          {!worker && <form className="composer" onSubmit={event => {
            event.preventDefault()
            if (draft.trim()) execute({ action: 'message', message: draft }, () => setDraft(''))
          }}>
            <InputGroup>
              <InputGroupTextarea rows={1} value={draft} onChange={event => setDraft(event.target.value)} aria-label="Message coordinator"
                placeholder="Message coordinator…" maxLength={1500} onKeyDown={event => {
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
    {artifact && <EvidenceDialog runId={run.id} artifactId={artifact} close={() => setArtifact(undefined)} />}
  </main>
}
