import { Link, useNavigate, useRouter } from '@tanstack/react-router'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { useEffect, useRef, useState } from 'react'
import { commandRun } from '../actions.ts'
import { FormError, Status, timeText, useAction } from './common.tsx'
import { EvidenceDialog } from './evidence-dialog.tsx'
import { RunOverview } from './run-overview.tsx'
import type { Command } from './run-overview.tsx'
import { RunReport } from './run-report.tsx'
import { phaseNames } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { WorkflowTrace } from './workflow-trace.tsx'

type View = 'overview' | 'trace' | 'report'

export function RunWorkspace({ detail, view, workerId }: {
  detail: RunDetail
  view: View
  workerId?: string
}) {
  const { run, project, assignments } = detail
  const router = useRouter()
  const navigate = useNavigate()
  const action = useAction()
  const reducedMotion = useReducedMotion()
  const [chatOpen, setChatOpen] = useState(true)
  const [review, setReview] = useState(false)
  const [revising, setRevising] = useState(false)
  const [draft, setDraft] = useState('')
  const [query, setQuery] = useState('')
  const [zoom, setZoom] = useState(1)
  const [artifact, setArtifact] = useState<string>()
  const search = useRef<HTMLInputElement>(null)
  const transcript = useRef<HTMLDivElement>(null)
  const cursor = useRef(detail.cursor)
  cursor.current = Math.max(cursor.current, detail.cursor)
  const worker = assignments.find(item => item.id === workerId)
  const threadId = worker?.id ?? run.coordinatorId
  const messages = detail.messages.filter(item => item.threadId === threadId)
  const attachments = detail.evidence.filter(item => item.assignmentId === worker?.id)

  useEffect(() => {
    const events = new EventSource(`/api/runs/${run.id}/events?since=${cursor.current}`)
    events.onmessage = event => {
      if (Number(event.lastEventId) <= cursor.current) return
      cursor.current = Number(event.lastEventId)
      void router.invalidate()
    }
    return () => events.close()
  }, [router, run.id])
  useEffect(() => {
    if (workerId) setChatOpen(true)
  }, [workerId])
  useEffect(() => {
    if (!worker && transcript.current) transcript.current.scrollTop = transcript.current.scrollHeight
  }, [messages.length, worker])
  useEffect(() => {
    const keyboard = (event: KeyboardEvent) => {
      const typing = event.target instanceof HTMLElement &&
        Boolean(event.target.closest('input, textarea, select, [contenteditable]'))
      if (event.key === '/' && !typing && search.current) {
        event.preventDefault()
        search.current.focus()
      }
      if (event.key === 'Escape' && !artifact && chatOpen && workerId) closeWorker()
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
    void action.submit(() => commandRun({ data: { ...command, runId: run.id, requestId: crypto.randomUUID() } }), onSuccess)
  }

  function closeWorker() {
    void navigate({ to: '/runs/$runId', params: { runId: run.id }, search: { view } })
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
        {run.status === 'running' && <button disabled={action.pending} onClick={() => execute({ action: 'pause' })}>Pause</button>}
        {['paused', 'stopped', 'failed'].includes(run.status) &&
          <button className="primary" disabled={action.pending} onClick={() => execute({ action: 'resume' })}>Resume</button>}
        {run.status !== 'complete' && run.status !== 'stopped' && <details className="top-menu">
          <summary aria-label="Run actions">•••</summary>
          <div className="menu-surface">
            <button disabled={action.pending} onClick={() => setRevising(!revising)}>Revise goal</button>
            <button disabled={action.pending} onClick={() => execute({ action: 'stop' }, () => {
              void navigate({ to: '/runs/$runId', params: { runId: run.id }, search: { view: 'report' } })
            })}>Stop run</button>
          </div>
        </details>}
      </div>
    </header>
    {revising && <form className="revision-form" onSubmit={event => {
      event.preventDefault()
      execute({ action: 'revise', goal: String(new FormData(event.currentTarget).get('goal')) }, () => setRevising(false))
    }}>
      <label>Revise goal<textarea name="goal" required maxLength={1500} defaultValue={run.goal} /></label>
      <div className="form-actions"><button type="button" onClick={() => setRevising(false)}>Cancel</button>
        <button className="primary" disabled={action.pending}>Save goal</button></div>
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
              <input ref={search} value={query} onChange={event => setQuery(event.target.value)} placeholder="Find worker…" />
              <kbd aria-hidden="true">/</kbd>
            </label>
            <div className="toolbar zoom">
              <button type="button" aria-label="Zoom out" onClick={() => setZoom(value => Math.max(0.55, value - 0.1))}>−</button>
              <button type="button" onClick={() => setZoom(1)}>Fit</button>
              <button type="button" aria-label="Zoom in" onClick={() => setZoom(value => Math.min(1.5, value + 0.1))}>+</button>
            </div>
          </>}
        </>}
        <button aria-pressed={chatOpen} onClick={() => setChatOpen(!chatOpen)}>Chat</button>
      </div>
    </div>
    {action.error && <div className="run-error"><FormError error={action.error} /></div>}
    <div className="workbench" data-with-chat={chatOpen}>
      <section className="work-surface" aria-label={view === 'report' ? 'Run report' : 'Workflow'}>
        <div hidden={view !== 'overview'}>
          <RunOverview detail={detail} execute={execute} openEvidence={setArtifact} pending={action.pending}
            review={review} setReview={setReview} />
        </div>
        <div className="trace-holder" hidden={view !== 'trace'}>
          <WorkflowTrace detail={detail} workerId={workerId} query={query} zoom={zoom} />
        </div>
        {view === 'report' && <RunReport detail={detail} openEvidence={setArtifact} />}
      </section>
      <AnimatePresence initial={false}>
        {chatOpen && <motion.section className="chat-pane" aria-label={worker ? 'Worker thread' : 'Coordinator chat'}
          initial={{ opacity: 0, x: reducedMotion ? 0 : 8 }} animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: reducedMotion ? 0 : 8 }} transition={{ duration: 0.19 }}>
          <div className="chat-header">
            {worker ? <button onClick={closeWorker}>Coordinator</button> : <strong>Coordinator</strong>}
            {worker && <strong>Worker</strong>}
            <button className="close-pane" onClick={() => setChatOpen(false)} aria-label="Close chat">×</button>
          </div>
          <AnimatePresence initial={false} mode="sync">
            <motion.div className="thread-content" key={threadId}
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, position: 'absolute', visibility: 'hidden' }}
              transition={{ duration: reducedMotion ? 0 : 0.18 }}>
              {worker && <header className="worker-intro">
                <h2>{worker.title}</h2><p className="muted">{phaseNames[worker.phase]} · <Status status={worker.status} /></p>
                {worker.outcome && <p className="outcome">{worker.outcome}</p>}
              </header>}
              <div className="transcript" ref={transcript}>
                {worker && <article className="message"><header>Assignment</header><p>{worker.objective}</p></article>}
                {messages.map(message => <article key={message.id} className="message" data-role={message.role}>
                  <header>{message.role === 'operator' ? 'You' : message.role === 'worker' ? 'Worker' : 'Coordinator'}
                    <time>{timeText(message.createdAt)}</time></header>
                  <p>{message.content}</p>
                </article>)}
                {attachments.map(item => <button type="button" className="attachment" key={item.id} onClick={() => setArtifact(item.id)}>
                  <span>Evidence</span><strong>{item.title}</strong><span aria-hidden="true">↗</span>
                </button>)}
              </div>
            </motion.div>
          </AnimatePresence>
          {!worker && <form className="composer" onSubmit={event => {
            event.preventDefault()
            if (draft.trim()) execute({ action: 'message', message: draft }, () => setDraft(''))
          }}>
            <input value={draft} onChange={event => setDraft(event.target.value)} aria-label="Message coordinator"
              placeholder="Message coordinator…" maxLength={1500} />
            <button className="primary" aria-label="Send message" disabled={action.pending || !draft.trim()}>↑</button>
          </form>}
        </motion.section>}
      </AnimatePresence>
    </div>
    {artifact && <EvidenceDialog runId={run.id} artifactId={artifact} close={() => setArtifact(undefined)} />}
  </main>
}
