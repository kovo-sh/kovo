import { Link, useNavigate } from '@tanstack/react-router'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { commandRun, runData } from '../actions.ts'
import { approvalPolicies, maxBudgetRequests, maxRpsPerOriginCeiling, workerHistory } from '../domain.ts'
import type { ApprovalPolicy } from '../domain.ts'
import { FormError, Status, useAction } from './common.tsx'
import { EvidenceDialog } from './evidence-dialog.tsx'
import { RunExchanges } from './run-exchanges.tsx'
import { RunOverview } from './run-overview.tsx'
import type { Command } from './run-overview.tsx'
import { RunReport } from './run-report.tsx'
import { approvalPolicyMeta, capabilityTierMeta, formatUsd, phaseNames } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { ThreadTranscript } from './thread-transcript.tsx'
import { Button } from './ui/button.tsx'
import { Checkbox } from './ui/checkbox.tsx'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from './ui/dropdown-menu.tsx'
import { Input, Textarea } from './ui/input.tsx'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupTextarea } from './ui/input-group.tsx'
import { WorkerInspector } from './worker-inspector.tsx'
import { WorkflowTrace } from './workflow-trace.tsx'

type View = 'overview' | 'trace' | 'exchanges' | 'report'

const DEFAULT_PANEL_WIDTH = 440
const MIN_PANEL_WIDTH = 320
const WIDTH_STORAGE_KEY = 'guardian-inspector-width'

function safeHost(origin: string) {
  try {
    const u = new URL(origin)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch {
    return origin
  }
}

export function RunWorkspace({ detail: routeDetail, view, workerId }: {
  detail: RunDetail
  view: View
  workerId?: string
}) {
  const [snapshot, setSnapshot] = useState<RunDetail>()
  const detail = snapshot && snapshot.cursor >= routeDetail.cursor ? snapshot : routeDetail
  const { run, project, assignments, approvals } = detail
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

  const [reconnecting, setReconnecting] = useState(false)
  const [chatOpen, setChatOpen] = useState(true)
  const [showCoordinator, setShowCoordinator] = useState(false)
  const [panelWidth, setPanelWidth] = useState(DEFAULT_PANEL_WIDTH)
  const [draggingSplit, setDraggingSplit] = useState(false)

  const [revising, setRevising] = useState(false)
  const [draft, setDraft] = useState('')
  const [query, setQuery] = useState('')
  const [zoom, setZoom] = useState(1)
  const [artifact, setArtifact] = useState<string>()

  // Popovers (Host list + Live Budget editor + Tier 3 Approval Policy switcher)
  const [hostPopoverOpen, setHostPopoverOpen] = useState(false)
  const [budgetPopoverOpen, setBudgetPopoverOpen] = useState(false)
  const [policyPopoverOpen, setPolicyPopoverOpen] = useState(false)
  const [liveUsd, setLiveUsd] = useState(run.budgetUsd)
  const [liveRps, setLiveRps] = useState(run.maxRpsPerOrigin)
  const [liveReqUnlimited, setLiveReqUnlimited] = useState(run.budgetRequests === 0)
  const [liveReqCap, setLiveReqCap] = useState(run.budgetRequests > 0 ? run.budgetRequests : Math.max(run.spentRequests + 1000, 2500))

  const search = useRef<HTMLInputElement>(null)
  const viewport = useRef<HTMLDivElement>(null)
  const cursor = useRef(detail.cursor)
  cursor.current = Math.max(cursor.current, detail.cursor)

  const selectedWorker = assignments.find(item => item.id === workerId)
  const worker = showCoordinator ? undefined : selectedWorker
  const threadId = worker?.id ?? run.coordinatorId
  const coordinatorMessages = detail.messages.filter(item => item.threadId === run.coordinatorId)
  const workerHistoryLabel = worker && history.get(worker.id)
  const artifactWorkerId = artifact && detail.evidence.find(item => item.id === artifact)?.assignmentId
  const pendingApprovals = approvals.filter(item => item.status === 'pending')
  const verifiedFindingCount = detail.findings.filter(
    f => (f.status === 'confirmed' || f.status === 'static_verified') && !f.supersededByFindingId,
  ).length

  // Restore saved inspector width
  useEffect(() => {
    try {
      const saved = Number(localStorage.getItem(WIDTH_STORAGE_KEY))
      if (Number.isFinite(saved) && saved >= MIN_PANEL_WIDTH) {
        setPanelWidth(Math.min(Math.floor(window.innerWidth * 0.65), saved))
      }
    } catch { /* ignore */ }
  }, [])

  // Sync budget popover defaults when opening
  function openBudgetPopover() {
    setHostPopoverOpen(false)
    setPolicyPopoverOpen(false)
    if (!budgetPopoverOpen) {
      setLiveUsd(run.budgetUsd)
      setLiveRps(run.maxRpsPerOrigin)
      setLiveReqUnlimited(run.budgetRequests === 0)
      setLiveReqCap(run.budgetRequests > 0 ? run.budgetRequests : Math.max(run.spentRequests + 1000, 2500))
    }
    setBudgetPopoverOpen(v => !v)
  }

  // Close popovers on outside click
  useEffect(() => {
    if (!hostPopoverOpen && !budgetPopoverOpen && !policyPopoverOpen) return
    const onDown = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null
      if (target?.closest('.popover-anchor')) return
      setHostPopoverOpen(false)
      setBudgetPopoverOpen(false)
      setPolicyPopoverOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [hostPopoverOpen, budgetPopoverOpen, policyPopoverOpen])

  // Pointer drag for vertical splitter
  useEffect(() => {
    if (!draggingSplit) return
    const onMove = (event: PointerEvent) => {
      const maxPx = Math.floor(window.innerWidth * 0.65)
      const next = Math.max(MIN_PANEL_WIDTH, Math.min(maxPx, Math.round(window.innerWidth - event.clientX)))
      setPanelWidth(next)
      try { localStorage.setItem(WIDTH_STORAGE_KEY, String(next)) } catch { /* ignore */ }
    }
    const onUp = () => {
      setDraggingSplit(false)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
    window.addEventListener('pointercancel', onUp)
    return () => {
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
      window.removeEventListener('pointercancel', onUp)
    }
  }, [draggingSplit])

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
      if ((event.metaKey || event.ctrlKey) && event.key === '\\') {
        event.preventDefault()
        setChatOpen(v => !v)
        return
      }
      if (event.defaultPrevented || artifact || (event.target instanceof HTMLElement && event.target.closest('[role=menu]'))) return
      const typing = event.target instanceof HTMLElement &&
        Boolean(event.target.closest('input, textarea, select, [contenteditable]'))
      if (event.key === '/' && !typing && search.current) {
        event.preventDefault()
        search.current.focus()
      }
      if (event.key === 'Escape') {
        if (hostPopoverOpen || budgetPopoverOpen || policyPopoverOpen) {
          setHostPopoverOpen(false)
          setBudgetPopoverOpen(false)
          setPolicyPopoverOpen(false)
          return
        }
        if (chatOpen && workerId) closeWorker()
      }
    }
    window.addEventListener('keydown', keyboard)
    return () => window.removeEventListener('keydown', keyboard)
  }, [workerId, chatOpen, artifact, hostPopoverOpen, budgetPopoverOpen, policyPopoverOpen])

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

  // Collapsed host pill ("academy.dyad.sh" or "dyad.sh + 29 hosts")
  const approvedHosts = useMemo(() => {
    const approvedSet = new Set(run.approved)
    const fromApproved = run.candidates.filter(c => approvedSet.has(c.id)).map(c => c.origin)
    return fromApproved.length ? fromApproved : project.seeds
  }, [run.approved, run.candidates, project.seeds])

  const hostPillLabel = approvedHosts.length <= 1
    ? safeHost(approvedHosts[0] ?? '')
    : `${safeHost(approvedHosts[0])} + ${approvedHosts.length - 1} ${approvedHosts.length - 1 === 1 ? 'host' : 'hosts'}`

  const canEditBudget = !['complete', 'stopped', 'failed'].includes(run.status)
  const currentPolicy: ApprovalPolicy = run.approvalPolicy ?? 'auto_review'

  return <main className="run-page">
    {/* Unified Run Workspace Header Bar (Midnight-Navy Chrome in D3, Slate-Cobalt in D4) */}
    <header className="run-chrome">
      <div className="run-chrome-left">
        <div className="run-identity">
          <Link to="/projects/$projectId" params={{ projectId: project.id }} className="run-workspace-title-link" title={`${project.name} — ${run.goal}`}>
            <h1 className="run-workspace-title">{project.name}</h1>
          </Link>
          <span className="run-chrome-badge">{capabilityTierMeta[run.capabilityTier].short}</span>
          <Status status={phaseLabel} />
          {pendingApprovals.length > 0 && <span className="badge badge-attention">
            {pendingApprovals.length} approval{pendingApprovals.length === 1 ? '' : 's'}
          </span>}
        </div>

        <nav className="run-tabs" aria-label="Run views">
          <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'overview' }}
            className="run-tab" data-active={view === 'overview'}>
            Overview
          </Link>
          <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'trace' }}
            className="run-tab" data-active={view === 'trace'}>
            Trace <span className="run-tab-count" aria-hidden="true">{assignments.length}</span>
          </Link>
          <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'exchanges' }}
            className="run-tab" data-active={view === 'exchanges'}>
            Exchanges <span className="run-tab-count" aria-hidden="true">{detail.exchangesSummary.length}</span>
          </Link>
          <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'report' }}
            className="run-tab" data-active={view === 'report'}>
            Report {verifiedFindingCount > 0 && <span className="run-tab-count" aria-hidden="true">{verifiedFindingCount}</span>}
          </Link>
        </nav>
      </div>

      <div className="run-chrome-right">
        {/* Live Tier 3 Approval Policy Switcher Pill */}
        {run.capabilityTier === 3 && <div className="popover-anchor">
          <button
            type="button"
            className={`chrome-pill policy-pill${policyPopoverOpen ? ' open' : ''}`}
            onClick={() => {
              setHostPopoverOpen(false)
              setBudgetPopoverOpen(false)
              setPolicyPopoverOpen(v => !v)
            }}
            aria-label="Tier 3 approval policy"
            title="Switch Tier 3 approval policy live mid-run"
          >
            <span>Policy: <strong>{approvalPolicyMeta[currentPolicy].short}</strong></span>
            <span aria-hidden="true">▾</span>
          </button>
          {policyPopoverOpen && <div className="chrome-popover policy-popover" role="dialog" aria-label="Tier 3 approval policy switcher">
            <div className="popover-head">
              <strong>Tier 3 Approval Policy</strong>
              <span className="badge badge-complete">{canEditBudget ? 'Live switch' : run.status}</span>
            </div>
            <div className="policy-popover-list">
              {approvalPolicies.map(policy => {
                const meta = approvalPolicyMeta[policy]
                const isSelected = currentPolicy === policy
                return <button
                  key={policy}
                  type="button"
                  className={`policy-popover-item${isSelected ? ' active' : ''}`}
                  disabled={!canEditBudget || action.pending || isSelected}
                  onClick={() => execute({ action: 'set_approval_policy', approvalPolicy: policy }, () => setPolicyPopoverOpen(false))}
                >
                  <div className="policy-option-head">
                    <strong>{meta.optionLabel}</strong>
                    {isSelected && <span className="badge badge-complete">Active</span>}
                  </div>
                  <span className="muted xs">{meta.summary}</span>
                </button>
              })}
            </div>
          </div>}
        </div>}

        {/* Collapsed Host Pill + Popover */}
        <div className="popover-anchor">
          <button
            type="button"
            className={`chrome-pill${hostPopoverOpen ? ' open' : ''}`}
            onClick={() => { setBudgetPopoverOpen(false); setPolicyPopoverOpen(false); setHostPopoverOpen(v => !v) }}
            title="Inspect approved scope hosts"
          >
            <span className={`chrome-dot st-${run.status}`} aria-hidden="true" />
            <span className="mono">{hostPillLabel}</span>
            <span aria-hidden="true">▾</span>
          </button>
          {hostPopoverOpen && <div className="chrome-popover" role="dialog" aria-label="Scope hosts">
            <div className="popover-head">
              <strong>Approved Scope Hosts</strong>
              <span className="mono muted xs">{approvedHosts.length} {approvedHosts.length === 1 ? 'origin' : 'origins'}</span>
            </div>
            <div className="popover-host-list">
              {approvedHosts.map(origin => {
                const tm = detail.threatModel?.entries.find(e => e.origin === origin)
                return <div key={origin} className="popover-host-row">
                  <span className="mono truncate">{safeHost(origin)}</span>
                  {tm && <span className={`badge ${tm.riskTier === 'critical' || tm.riskTier === 'high' ? 'badge-attention' : 'badge-trace'}`}>{tm.riskTier}</span>}
                </div>
              })}
            </div>
          </div>}
        </div>

        {/* Clickable Live Budget Pill + Inline Editor Popover */}
        <div className="popover-anchor">
          <button
            type="button"
            className={`chrome-pill budget-pill${budgetPopoverOpen ? ' open' : ''}`}
            onClick={openBudgetPopover}
            aria-label="Edit live run budget"
            title={canEditBudget ? 'Click to edit live USD cap, RPS, or request cap' : 'Run budget usage'}
          >
            <span className="chrome-budget-bar" aria-hidden="true">
              <span data-level={meterLevel} style={{ width: `${Math.round(maxRatio * 100)}%` }} />
            </span>
            <span className="mono tabular">{formatUsd(run.spentUsd)} / {formatUsd(run.budgetUsd)}</span>
            <span className="chrome-sep">·</span>
            <span className="mono tabular">{run.maxRpsPerOrigin} rps</span>
            <span className="chrome-sep">·</span>
            <span className="mono tabular">Reqs {run.budgetRequests === 0 ? '∞' : `${run.spentRequests}/${run.budgetRequests}`}</span>
          </button>

          {budgetPopoverOpen && <form className="chrome-popover budget-popover" role="dialog" aria-label="Live run budget editor"
            onSubmit={event => {
              event.preventDefault()
              const nextReqs = liveReqUnlimited ? 0 : Math.max(run.spentRequests + 1, Math.min(maxBudgetRequests, Math.round(liveReqCap)))
              execute({
                action: 'raise_budget',
                budgetUsd: liveUsd,
                budgetRequests: nextReqs,
                maxRpsPerOrigin: liveRps,
                resume: run.status === 'budget_paused',
              }, () => setBudgetPopoverOpen(false))
            }}>
            <div className="popover-head">
              <strong>Live Run Budget</strong>
              <span className="badge badge-complete">{canEditBudget ? 'Hot-reload' : run.status}</span>
            </div>
            <p className="muted xs" style={{ marginBottom: 10 }}>
              Spent {formatUsd(run.spentUsd)} · {run.spentRequests} reqs · {run.turnsUsed} turns. Updates apply immediately without restarting workers.
            </p>
            <div className="field-grid">
              <label>USD Spend Cap
                <Input type="number" min={Math.max(0.1, Number((run.spentUsd + 0.1).toFixed(2)))} max={500} step="any"
                  disabled={!canEditBudget || action.pending}
                  value={liveUsd} onChange={e => setLiveUsd(Number(e.target.value))} />
              </label>
              <label>Rate Limit ({liveRps} RPS / origin)
                <input type="range" min={1} max={maxRpsPerOriginCeiling} step={1}
                  disabled={!canEditBudget || action.pending}
                  value={liveRps} onChange={e => setLiveRps(Number(e.target.value))} />
              </label>
              <label className="checkbox">
                <Checkbox
                  checked={liveReqUnlimited}
                  disabled={!canEditBudget || action.pending}
                  aria-label="Unlimited requests"
                  onCheckedChange={checked => setLiveReqUnlimited(Boolean(checked))}
                />
                <span>Unlimited max requests (<code>∞</code>)</span>
              </label>
              {!liveReqUnlimited && <label>Max request cap
                <Input type="number" min={run.spentRequests + 1} max={maxBudgetRequests} step={1}
                  disabled={!canEditBudget || action.pending}
                  value={liveReqCap} onChange={e => setLiveReqCap(Number(e.target.value))} />
              </label>}
            </div>
            <div className="form-actions" style={{ marginTop: 12 }}>
              <Button type="button" variant="ghost" onClick={() => setBudgetPopoverOpen(false)}>Cancel</Button>
              {canEditBudget && <Button type="submit" variant="default" disabled={action.pending}>
                {run.status === 'budget_paused' ? 'Update & Resume' : 'Update Live'}
              </Button>}
            </div>
          </form>}
        </div>

        {/* Run Controls */}
        <div className="run-chrome-actions">
          {run.status === 'running' && <Button className="chrome-action-btn" disabled={action.pending} onClick={() => execute({ action: 'pause' })}>Pause</Button>}
          {['paused', 'stopped', 'failed'].includes(run.status) &&
            <Button variant="default" className="btn-nowrap" disabled={action.pending} onClick={() => execute({ action: 'resume' })}>Resume</Button>}
          {run.status !== 'complete' && run.status !== 'stopped' && <DropdownMenu>
            <DropdownMenuTrigger render={<Button size="icon" className="chrome-icon-btn" />} aria-label="Run actions">···</DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem disabled={action.pending} onClick={() => setRevising(true)}>Revise goal</DropdownMenuItem>
              <DropdownMenuItem variant="destructive" disabled={action.pending} onClick={() => execute({ action: 'stop' }, () => {
                void navigate({ to: '/runs/$runId', params: { runId: run.id }, search: { view: 'report' } })
              })}>Stop run</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>}

          <button
            type="button"
            className={`chrome-icon-btn${chatOpen ? ' active' : ''}`}
            aria-pressed={chatOpen}
            onClick={() => setChatOpen(v => !v)}
            title="Toggle Inspector / Coordinator panel (Cmd+\)"
            aria-label="Toggle Inspector panel"
          >
            <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <rect x="1.5" y="2.5" width="13" height="11" rx="2" stroke="currentColor" strokeWidth="1.3" />
              <line x1="10.2" y1="2.5" x2="10.2" y2="13.5" stroke="currentColor" strokeWidth="1.3" />
            </svg>
          </button>
        </div>
      </div>
    </header>

    {run.status === 'budget_paused' && <section className="budget-banner" aria-label="Budget paused">
      <div>
        <h2>Run paused — budget ceiling reached</h2>
        <p className="muted">
          Spent {formatUsd(run.spentUsd)} of {formatUsd(run.budgetUsd)} USD and {run.spentRequests} of {run.budgetRequests === 0 ? '∞' : run.budgetRequests} requests.
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
        <label>New request cap (0 = ∞)
          <Input name="budgetRequests" type="number" min={0} max={maxBudgetRequests} step={1} required defaultValue={0} />
        </label>
        <Button type="submit" variant="default" disabled={action.pending}>Raise budget &amp; Resume</Button>
      </form>
    </section>}

    {revising && <form className="revision-form" onSubmit={event => {
      event.preventDefault()
      execute({ action: 'revise', goal: String(new FormData(event.currentTarget).get('goal')) }, () => setRevising(false))
    }}>
      <label>Revise goal<Textarea name="goal" required maxLength={8000} defaultValue={run.goal} /></label>
      <div className="form-actions"><Button type="button" onClick={() => setRevising(false)}>Cancel</Button>
        <Button type="submit" variant="default" disabled={action.pending}>Save goal</Button></div>
    </form>}

    {reconnecting && <p className="run-error muted" role="status">Reconnecting to Guardian…</p>}
    {action.error && <div className="run-error"><FormError error={action.error} /></div>}

    {/* Full-Viewport Split Workbench with Draggable Vertical Splitter */}
    <div className="workbench-split">
      <section className="work-surface" aria-label={view === 'report' ? 'Run report' : view === 'exchanges' ? 'Run exchanges' : 'Workflow'}>
        {view !== 'report' && needsModel && <div className="workflow-callout run-model-callout">
          <div><h2>Connect a model to continue</h2><p>Model settings will return you to this run.</p></div>
          <Link className="action-link primary" to="/settings" search={{ runId }}>Set up model</Link>
        </div>}

        <div className="work-scroll" hidden={view !== 'overview'}>
          <RunOverview detail={detail} history={history} execute={execute} openEvidence={setArtifact} pending={action.pending} />
        </div>

        <div className="trace-holder" hidden={view !== 'trace'}>
          <WorkflowTrace
            detail={detail}
            history={history}
            workerId={workerId}
            query={query}
            setQuery={setQuery}
            zoom={zoom}
            setZoom={setZoom}
            fitGraph={fitGraph}
            viewport={viewport}
            searchRef={search}
          />
        </div>

        {view === 'exchanges' && <div className="work-scroll exchanges-page-wrap">
          <div className="exchanges-page-head">
            <div>
              <h2>Brokered HTTP Exchanges</h2>
              <p className="muted">All redacted requests &amp; responses mediated by Guardian’s RequestBroker. Click any row to inspect headers, body, and copy sanitized cURL.</p>
            </div>
            <span className="badge mono">{detail.exchangesSummary.length} recorded</span>
          </div>
          <RunExchanges runId={run.id} exchanges={detail.exchangesSummary} assignments={assignments} />
        </div>}

        {view === 'report' && <div className="work-scroll">
          <RunReport detail={detail} execute={execute} pending={action.pending} openEvidence={setArtifact} />
        </div>}
      </section>

      {chatOpen && <>
        <div
          className={`workbench-splitter${draggingSplit ? ' dragging' : ''}`}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize inspector panel"
          title="Drag to resize · Double-click to reset"
          onPointerDown={e => {
            e.preventDefault()
            setDraggingSplit(true)
          }}
          onDoubleClick={() => {
            setPanelWidth(DEFAULT_PANEL_WIDTH)
            try { localStorage.setItem(WIDTH_STORAGE_KEY, String(DEFAULT_PANEL_WIDTH)) } catch { /* ignore */ }
          }}
        />
        <aside
          className="chat-pane"
          style={{ width: panelWidth }}
          aria-label={worker ? 'Worker inspector' : 'Coordinator chat'}
        >
          <div className="chat-header">
            <div className="panel-mode-tabs">
              <button
                type="button"
                className={`panel-mode-btn${!worker ? ' active' : ''}`}
                onClick={() => setShowCoordinator(true)}
              >
                Coordinator
              </button>
              {selectedWorker && <button
                type="button"
                className={`panel-mode-btn${Boolean(worker) ? ' active' : ''}`}
                onClick={() => setShowCoordinator(false)}
              >
                Worker Inspector
              </button>}
            </div>
            <Button variant="ghost" size="icon" className="close-pane" onClick={() => setChatOpen(false)} aria-label="Close panel">×</Button>
          </div>

          {worker ? <WorkerInspector
            detail={detail}
            worker={worker}
            historyLabel={workerHistoryLabel}
            openEvidence={setArtifact}
          /> : <div className="coordinator-pane">
            {pendingApprovals.length > 0 && <div aria-label="Coordinator approval prompts" className="coord-approvals">
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
                  <Button variant="ghost" disabled={action.pending} onClick={() => {
                    execute({ action: 'approve_similar_endpoint', approvalId: item.id })
                  }}>Approve similar</Button>
                  <Button variant="default" disabled={action.pending} onClick={() => {
                    execute({ action: 'decide_approval', approvalId: item.id, decision: 'approved' })
                  }}>Approve</Button>
                </div>
              </div>)}
            </div>}
            <div className="thread-content" key={threadId}>
              <ThreadTranscript messages={coordinatorMessages} attachments={[]} openEvidence={setArtifact} />
            </div>
            <form className="composer" onSubmit={event => {
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
            </form>
          </div>}
        </aside>
      </>}
    </div>

    {artifact && <EvidenceDialog runId={run.id} artifactId={artifact}
      historyLabel={artifactWorkerId ? history.get(artifactWorkerId) : undefined} close={() => setArtifact(undefined)} />}
  </main>
}
