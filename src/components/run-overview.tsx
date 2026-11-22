import { Fragment, useMemo, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { checkRunLabHealthAction, exportSarifAction, startRunLabAction, stopRunLabAction } from '../actions.ts'
import {
  approvalPolicies,
  assessmentCheckTitles,
  canReviewScope,
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
  maxScopeHosts,
} from '../domain.ts'
import type { ApprovalPolicy, CapabilityTier, Finding, RunCommand } from '../domain.ts'
import {
  callerCompatibilityLabels,
  dynamicRetestLabels,
  findingVerificationTier,
  owaspCategoryTitles,
  patchStatusLabels,
  verificationTierLabels,
} from '../report-summary.ts'
import { Status } from './common.tsx'
import { approvalPolicyMeta, capabilityTierMeta, formatUsd, workerPhaseNames, workerPhases } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { Checkbox } from './ui/checkbox.tsx'
import { Input, NativeSelect } from './ui/input.tsx'

export type Command = RunCommand extends infer C
  ? C extends RunCommand ? Omit<C, 'requestId' | 'runId'> : never
  : never

interface ScopeDraft {
  scopeRevision: number
  assetIds: string[]
  capabilityTier: CapabilityTier
  approvalPolicy: ApprovalPolicy
  approvedPersonaIds: string[]
  budgetUsd: number
  budgetRequests: number
  maxRpsPerOrigin: number
}

function autoApprovalBadge(decidedBy: string | null | undefined): { label: string; className: string } {
  if (decidedBy === 'auto-review:judge') return { label: 'Safety Judge', className: 'badge badge-trace' }
  if (decidedBy === 'auto-yolo') return { label: 'YOLO', className: 'badge badge-attention' }
  return { label: 'Auto-Rule', className: 'badge badge-complete' }
}

function riskBadgeClass(riskTier: 'critical' | 'high' | 'medium' | 'low') {
  if (riskTier === 'critical') return 'badge badge-danger'
  if (riskTier === 'high') return 'badge badge-attention'
  if (riskTier === 'medium') return 'badge badge-running'
  return 'badge'
}

function sevPillClass(severity: string) {
  if (severity === 'critical') return 'sev-pill sev-critical'
  if (severity === 'high') return 'sev-pill sev-high'
  if (severity === 'medium') return 'sev-pill sev-medium'
  return 'sev-pill sev-low'
}

function downloadSarifBlob(content: string, filename: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/sarif+json; charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function safeHost(origin: string) {
  try {
    const url = new URL(origin)
    return url.port ? `${url.hostname}:${url.port}` : url.hostname
  } catch {
    return origin
  }
}

function isHeaderHygiene(f: Finding) {
  return f.findingKind === 'baseline_check' && (f.severity === 'low' || f.severity === 'informational')
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }

export function RunOverview({ detail, history, execute, openEvidence, pending, refreshRun }: {
  detail: RunDetail
  history: ReadonlyMap<string, string>
  execute: (command: Command, onSuccess?: () => void) => void
  openEvidence: (id: string) => void
  pending: boolean
  refreshRun?: () => Promise<void>
}) {
  const { run, project, assignments, evidence, approvals, personas, threatModel } = detail
  const plan = run.reviewPlan
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState<ScopeDraft>()
  const [exportingSarif, setExportingSarif] = useState(false)
  const [labPending, setLabPending] = useState(false)
  const [labStatusMsg, setLabStatusMsg] = useState('')
  const [labErrorMsg, setLabErrorMsg] = useState('')
  const [hygieneOpen, setHygieneOpen] = useState(false)
  const [auditLogOpen, setAuditLogOpen] = useState(false)
  const [threatOpen, setThreatOpen] = useState(false)
  const [showAllThreat, setShowAllThreat] = useState(false)
  const [scopeOpenManual, setScopeOpenManual] = useState<boolean | null>(null)

  const verifiedFindings = useMemo(
    () => detail.findings
      .filter(f => (f.status === 'confirmed' || f.status === 'static_verified') && !f.supersededByFindingId)
      .sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9)),
    [detail.findings],
  )
  const hygieneFindings = useMemo(() => verifiedFindings.filter(isHeaderHygiene), [verifiedFindings])
  const primaryFindings = useMemo(() => verifiedFindings.filter(f => !isHeaderHygiene(f)), [verifiedFindings])

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const f of primaryFindings) {
      if (f.severity === 'critical') c.critical += 1
      else if (f.severity === 'high') c.high += 1
      else if (f.severity === 'medium') c.medium += 1
      else c.low += 1
    }
    return c
  }, [primaryFindings])

  const runtimeConfirmedCount = detail.findings.filter(f => f.status === 'confirmed').length
  const staticVerifiedCount = detail.findings.filter(f => f.status === 'static_verified').length
  const openProofGaps = detail.openProofGaps ?? []
  const patchProposals = detail.patchProposals ?? []
  const findingTitleById = new Map(detail.findings.map(f => [f.id, f.title]))
  const replaySpecByFinding = new Map(detail.replaySpecs.map(r => [r.findingId, r]))
  const activeRetestFindingIds = new Set(
    assignments
      .filter(a => a.phase === 'retest' && (a.status === 'queued' || a.status === 'running'))
      .map(a => a.objective),
  )

  const currentWorkers = assignments.filter(w => !history.has(w.id))
  const completedWorkers = currentWorkers.filter(w => w.status === 'complete').length
  const runningWorkers = currentWorkers.filter(w => w.status === 'running' || w.status === 'waiting_approval').length

  async function handleDownloadSarif() {
    setExportingSarif(true)
    try {
      const res = await exportSarifAction({ data: { runId: run.id, reportId: detail.reports[0]?.id } })
      downloadSarifBlob(res.content, res.filename)
    } finally {
      setExportingSarif(false)
    }
  }

  async function handleLabStart() {
    setLabPending(true)
    setLabErrorMsg('')
    setLabStatusMsg('')
    try {
      const res = await startRunLabAction({ data: { runId: run.id } })
      setLabStatusMsg(res.target ? `Lab running at ${res.target.origin}` : 'Lab started.')
      await refreshRun?.()
    } catch (err) {
      setLabErrorMsg(err instanceof Error ? err.message : 'Failed to start lab stack.')
    } finally {
      setLabPending(false)
    }
  }

  async function handleLabStop() {
    setLabPending(true)
    setLabErrorMsg('')
    setLabStatusMsg('')
    try {
      await stopRunLabAction({ data: { runId: run.id } })
      setLabStatusMsg('Lab stack stopped (0 orphan containers).')
      await refreshRun?.()
    } catch (err) {
      setLabErrorMsg(err instanceof Error ? err.message : 'Failed to stop lab stack.')
    } finally {
      setLabPending(false)
    }
  }

  async function handleLabHealth() {
    setLabPending(true)
    setLabErrorMsg('')
    try {
      const res = await checkRunLabHealthAction({ data: { runId: run.id } })
      setLabStatusMsg(res.message)
      await refreshRun?.()
    } catch (err) {
      setLabErrorMsg(err instanceof Error ? err.message : 'Health check failed.')
    } finally {
      setLabPending(false)
    }
  }

  const afterApproval = ['threat_model', 'investigation', 'verification'].includes(run.phase)
  const canReview = canReviewScope(run.phase, run.status)
  const review = canReview ? draft : undefined
  const stale = Boolean(review && review.scopeRevision !== run.scopeRevision)
  const selected = review?.assetIds ?? []
  const overLimit = selected.length > maxScopeHosts
  const inventoryIds = new Set(evidence.filter(item => item.kind === 'inventory').map(item => item.id))
  const pendingApprovals = approvals.filter(item => item.status === 'pending')
  const autoApprovedApprovals = approvals.filter(item =>
    item.status === 'approved' &&
    typeof item.decidedBy === 'string' &&
    item.decidedBy.startsWith('auto-'),
  )
  const suggestedCandidates = run.scopeRevision > 0
    ? run.candidates.filter(asset => !run.approved.includes(asset.id) && !asset.thirdParty)
    : []

  // Scope Inventory defaults OPEN during scope review / editing, and COLLAPSED once approved!
  const scopeInventoryOpen = Boolean(review) || run.phase === 'review' || (scopeOpenManual ?? run.scopeRevision === 0)

  function beginReview(extraAssetId?: string) {
    const baseIds = run.scopeRevision > 0 ? [...run.approved]
      : run.candidates.filter(asset => !asset.thirdParty && (project.defaultScope.length
        ? project.defaultScope.includes(asset.origin) : !asset.dnsSource)).map(asset => asset.id)
    const assetIds = extraAssetId && !baseIds.includes(extraAssetId) ? [...baseIds, extraAssetId] : baseIds
    setDraft({
      scopeRevision: run.scopeRevision,
      assetIds,
      capabilityTier: run.capabilityTier,
      approvalPolicy: run.approvalPolicy ?? 'auto_review',
      approvedPersonaIds: [...run.approvedPersonaIds],
      budgetUsd: run.budgetUsd,
      budgetRequests: run.budgetRequests,
      maxRpsPerOrigin: run.maxRpsPerOrigin,
    })
  }

  function toggleReview() {
    if (review) setDraft(undefined)
    else beginReview()
  }

  return <div className="overview-body">
    {/* 1. Compact KPI & Severity Strip */}
    <section className="kpi-strip" aria-label="Run KPI and severity summary">
      <div className={`kpi-card sev-critical${sevCounts.critical > 0 ? ' has-items' : ''}`}>
        <span className="kpi-label">Critical</span>
        <span className="kpi-val tabular mono">{sevCounts.critical}</span>
      </div>
      <div className={`kpi-card sev-high${sevCounts.high > 0 ? ' has-items' : ''}`}>
        <span className="kpi-label">High</span>
        <span className="kpi-val tabular mono">{sevCounts.high}</span>
      </div>
      <div className={`kpi-card sev-medium${sevCounts.medium > 0 ? ' has-items' : ''}`}>
        <span className="kpi-label">Medium</span>
        <span className="kpi-val tabular mono">{sevCounts.medium}</span>
      </div>
      <div className={`kpi-card sev-low${sevCounts.low > 0 ? ' has-items' : ''}`}>
        <span className="kpi-label">Low</span>
        <span className="kpi-val tabular mono">{sevCounts.low}</span>
      </div>
      <button
        type="button"
        className="kpi-card kpi-hygiene"
        onClick={() => setHygieneOpen(v => !v)}
        aria-expanded={hygieneOpen}
        title="Expand collapsed header hygiene observations"
      >
        <span className="kpi-label">Header Hygiene <span className="mono">({hygieneOpen ? 'open' : 'collapsed'})</span></span>
        <span className="kpi-val-sm tabular">{hygieneFindings.length} info <span className="muted">{hygieneOpen ? '▴' : '▾'}</span></span>
      </button>
      <div className="kpi-card kpi-meta">
        <span className="kpi-label">Activity &amp; Spend</span>
        <span className="kpi-val-sm tabular mono">
          {runningWorkers > 0 ? `${runningWorkers} active · ` : ''}{completedWorkers}/{currentWorkers.length} wk · {detail.exchangesSummary.length} ex · {formatUsd(run.spentUsd)}
        </span>
      </div>
    </section>

    {project.environment === 'local-lab' && <section className="overview-card lab-runner-panel" aria-label="Local lab runner">
      <div className="section-heading">
        <div>
          <div className="inline-badges">
            <h2>Local lab runner</h2>
            <span className={`badge ${detail.labTarget ? 'badge-complete' : project.labConfig?.enabled ? 'badge-trace' : ''}`}>
              {detail.labTarget ? 'Running' : project.labConfig?.enabled ? 'Ready' : 'Disabled'}
            </span>
            <span className={`badge ${project.labConfig?.iastEnabled ? 'badge-complete' : ''}`}>
              {project.labConfig?.iastEnabled ? 'IAST enabled' : 'IAST off'}
            </span>
          </div>
          <p className="muted xs" style={{ marginTop: 4 }}>
            Isolated Docker <code>--internal</code> stack · Port {project.labConfig?.internalPort ?? 8080} · Health <code>{project.labConfig?.healthPath ?? '/health'}</code>
            {project.labConfig?.dockerComposeFile && <> · Compose <code>{project.labConfig.dockerComposeFile}</code></>}
          </p>
        </div>
        <div className="toolbar">
          {detail.labTarget ? <Button type="button" className="btn-danger" disabled={labPending} onClick={() => void handleLabStop()}>
            Stop lab
          </Button> : <Button type="button" variant="default" disabled={labPending || !detail.localLabEnvEnabled || !project.labConfig?.enabled} onClick={() => void handleLabStart()}>
            Start lab
          </Button>}
          <Button type="button" variant="ghost" disabled={labPending} onClick={() => void handleLabHealth()}>
            Health check
          </Button>
          <Button type="button" variant="ghost" disabled={labPending} onClick={() => { void refreshRun?.() }}>
            Refresh
          </Button>
        </div>
      </div>
      <div className="lab-meta-grid">
        {project.labConfig?.services && project.labConfig.services.length > 0 && <div className="lab-meta-item">
          <span className="muted xs">Services </span>
          <div className="inline-badges">
            {project.labConfig.services.map(svc => <span key={svc.name} className="badge badge-trace mono">
              {' '}{svc.name}{svc.internalPort ? `:${svc.internalPort}` : ''}{' '}
            </span>)}
          </div>
        </div>}
        {project.labConfig?.seedCommand && <div className="lab-meta-item">
          <span className="muted xs">Seed command </span>
          <code className="mono xs">{' '}{project.labConfig.seedCommand}{' '}</code>
        </div>}
        {detail.labTarget && <div className="lab-meta-item">
          <span className="muted xs">Loopback origin </span>
          <code className="mono xs">{' '}{detail.labTarget.origin}{' '}</code>
        </div>}
        {(detail.labTelemetry?.length ?? 0) > 0 && <div className="lab-meta-item">
          <span className="muted xs">IAST telemetry </span>
          <span className="badge badge-complete mono">{' '}{detail.labTelemetry.length} traces recorded{' '}</span>
        </div>}
      </div>
      {labStatusMsg && <p role="status" className="muted xs" style={{ marginTop: 6 }}>{labStatusMsg}</p>}
      {labErrorMsg && <p role="alert" className="form-error" style={{ marginTop: 6 }}>{labErrorMsg}</p>}
    </section>}

    {hygieneOpen && hygieneFindings.length > 0 && <section className="overview-card hygiene-drawer">
      <div className="section-heading">
        <div>
          <h3>Header Hygiene &amp; Passive Hardening ({hygieneFindings.length})</h3>
          <p className="muted">Grouped out of primary triage so Medium/High/Critical findings stay above the fold.</p>
        </div>
        <Button type="button" variant="ghost" onClick={() => setHygieneOpen(false)}>Collapse</Button>
      </div>
      <div className="hygiene-grid">
        {hygieneFindings.map(f => <div key={f.id} className="hygiene-item">
          <strong className="mono xs">{f.title}</strong>
          <span className="muted xs">{safeHost(f.origin)} · {f.reason}</span>
        </div>)}
      </div>
    </section>}

    {/* 2. Needs Attention: Blocking Operator Gates + Auto-Approved Audit Trail + Top Verified Findings */}
    {pendingApprovals.length > 0 && <section className="approval-stack" aria-label="Pending Tier 3 approvals">
      <div className="section-heading approval-stack-head">
        <div className="inline-badges">
          <h2>Pending Tier 3 approvals ({pendingApprovals.length})</h2>
          <span className="badge badge-trace">Policy: {approvalPolicyMeta[run.approvalPolicy ?? 'auto_review'].label}</span>
        </div>
        <Button
          type="button"
          variant="default"
          className="btn-nowrap"
          disabled={pending}
          onClick={() => execute({ action: 'approve_all_pending' })}
        >
          Approve all pending ({pendingApprovals.length})
        </Button>
      </div>
      {pendingApprovals.map(item => <article key={item.id} className="approval-card">
        <div className="section-heading">
          <div className="inline-badges">
            <h3>Tier 3 approval required</h3>
            <span className="badge badge-attention">{item.method}</span>
            {item.riskLevel && <span className={`badge ${item.riskLevel === 'high' ? 'badge-danger' : item.riskLevel === 'medium' ? 'badge-attention' : ''}`}>
              risk: {item.riskLevel}
            </span>}
            {item.personaHandle && <span className="badge badge-trace">persona: {item.personaHandle}</span>}
          </div>
          <Status status="waiting_approval" />
        </div>
        <p className="approval-target"><code>{item.method} {item.origin}{item.pathAndQuery}</code></p>
        <p className="muted">{item.rationale}</p>
        {item.policyNote && <p className="muted xs"><strong>Gate note:</strong> {item.policyNote}</p>}
        {item.requestPreview && <pre className="approval-preview">{item.requestPreview}</pre>}
        <div className="approval-actions">
          <Button className="btn-danger" disabled={pending} onClick={() => {
            execute({ action: 'decide_approval', approvalId: item.id, decision: 'denied' })
          }}>Deny</Button>
          <Button variant="ghost" disabled={pending} onClick={() => {
            execute({ action: 'approve_similar_endpoint', approvalId: item.id })
          }}>Approve similar</Button>
          <Button variant="default" disabled={pending} onClick={() => {
            execute({ action: 'decide_approval', approvalId: item.id, decision: 'approved' })
          }}>Approve probe</Button>
        </div>
      </article>)}
    </section>}

    {autoApprovedApprovals.length > 0 && <section className="disclosure-card audit-log-disclosure" aria-label="Auto-approved audit log">
      <button
        type="button"
        className="disclosure-card-trigger"
        aria-expanded={auditLogOpen}
        onClick={() => setAuditLogOpen(v => !v)}
      >
        <div>
          <div className="inline-badges">
            <strong>Auto-approved audit log ({autoApprovedApprovals.length})</strong>
            <span className="badge badge-complete">{approvalPolicyMeta[run.approvalPolicy ?? 'auto_review'].label}</span>
          </div>
          <p className="muted xs" style={{ marginTop: 3 }}>
            Full transparency log of Tier 3 probes auto-approved by deterministic rules, Safety Judge LLM, or YOLO mode.
          </p>
        </div>
        <span className={`disclosure-chevron${auditLogOpen ? ' open' : ''}`} aria-hidden="true">▾</span>
      </button>
      {auditLogOpen && <div className="disclosure-card-body">
        <div className="table-scroll">
          <table className="compact-table audit-log-table">
            <thead>
              <tr>
                <th scope="col">Method</th>
                <th scope="col">Target</th>
                <th scope="col">Approved By</th>
                <th scope="col">Reason</th>
              </tr>
            </thead>
            <tbody>
              {autoApprovedApprovals.map(item => {
                const badge = autoApprovalBadge(item.decidedBy)
                return <tr key={item.id}>
                  <td><span className="badge">{item.method}</span></td>
                  <td className="mono xs"><strong>{safeHost(item.origin)}</strong>{item.pathAndQuery}</td>
                  <td><span className={badge.className}>{badge.label}</span></td>
                  <td className="muted xs">{item.policyNote || item.rationale}</td>
                </tr>
              })}
            </tbody>
          </table>
        </div>
      </div>}
    </section>}

    {run.phase === 'consent' && <form className="workflow-callout" onSubmit={event => {
      event.preventDefault()
      if (new FormData(event.currentTarget).has('discoveryConsent')) execute({ action: 'discover', consent: true })
    }}>
      <div>
        <h2>Discovery consent</h2>
        <p>Review project records, specs, and imported DNS exports for {project.seeds.map(safeHost).join(', ')}.</p>
        <label className="checkbox"><Checkbox name="discoveryConsent" required aria-label="I authorize discovery for these assets." /> I authorize discovery for these assets.</label>
      </div>
      <Button type="submit" variant="default" className="btn-nowrap" disabled={pending || run.status !== 'waiting'}>Start discovery</Button>
    </form>}

    {run.phase === 'review' && <div className="workflow-callout">
      <div>
        <h2>Scope &amp; capability approval</h2>
        <p>{run.candidates.length} candidates · {run.candidates.filter(asset => asset.thirdParty).length} third-party · {capabilityTierMeta[run.capabilityTier].short}</p>
      </div>
      <Button variant="default" className="btn-nowrap" onClick={toggleReview} aria-expanded={Boolean(review)} disabled={!canReview}>
        {review ? 'Close review' : 'Review scope'}
      </Button>
    </div>}

    {primaryFindings.length > 0 && <section className="overview-card attention-findings-card" aria-label="Top verified findings">
      <div className="section-heading">
        <div>
          <h2>Needs Attention · Top Verified Findings</h2>
          <p className="muted">Prioritized by exploitability and replay verification. {hygieneFindings.length > 0 ? `${hygieneFindings.length} passive header hygiene items folded above.` : ''}</p>
        </div>
        <div className="toolbar">
          <Button variant="ghost" disabled={exportingSarif} onClick={() => void handleDownloadSarif()}>
            {exportingSarif ? 'Exporting…' : 'SARIF 2.1.0'}
          </Button>
          <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'report' }} className="action-link primary btn-nowrap">
            Open Report →
          </Link>
        </div>
      </div>

      <div className="findings-stack">
        {primaryFindings.slice(0, 6).map(finding => {
          const tier = findingVerificationTier(finding)
          const replayRow = finding.replaySpecId ? detail.replaySpecs.find(r => r.id === finding.replaySpecId) : replaySpecByFinding.get(finding.id)
          const canRetest = Boolean(finding.status === 'confirmed' && (finding.replaySpecId || replayRow))
          const retestQueued = [...activeRetestFindingIds].some(obj => obj.includes(finding.id))
          return <article key={finding.id} className="finding-summary-row">
            <div className="finding-summary-main">
              <div className="inline-badges">
                <span className={sevPillClass(finding.severity)}>{finding.severity.toUpperCase()}</span>
                <span className="mono muted xs">{safeHost(finding.origin)}</span>
                {finding.cwe && <span className="badge">{finding.cwe}</span>}
                {tier && <span className="badge badge-complete">{verificationTierLabels[tier]}</span>}
                {finding.findingKind === 'multi_step_chain' && <span className="badge badge-trace">Multi-step chain</span>}
              </div>
              <h3 className="finding-summary-title">{finding.title}</h3>
              <p className="muted finding-summary-desc">{finding.reason}</p>
            </div>
            <div className="finding-summary-actions">
              <Link to="/runs/$runId" params={{ runId: run.id }} search={{ view: 'report' }} className="action-link btn-nowrap">
                Inspect in Report
              </Link>
              {canRetest && <Button variant="ghost" className="btn-nowrap" disabled={pending || retestQueued} onClick={() => {
                execute({ action: 'retest_finding', findingId: finding.id })
              }}>
                {retestQueued ? 'Verifying…' : 'Verify Fix'}
              </Button>}
            </div>
          </article>
        })}
      </div>
    </section>}

    {/* Compact Phase Rail */}
    <ol className="phase-rail" aria-label="Run phases">
      {workerPhases.map(phase => {
        const nodes = assignments.filter(worker => worker.phase === phase && !history.has(worker.id))
        const settled = nodes.length > 0 && nodes.every(worker => ['complete', 'canceled'].includes(worker.status))
        const active = run.phase === phase && run.status === 'running' && (phase === 'discovery' || detail.hasModel)
        const waitingApproval = nodes.some(worker => worker.status === 'waiting_approval')
        return <Fragment key={phase}>
          <li>
            <div>
              <h2>{workerPhaseNames[phase]}</h2>
              <span className="muted">{nodes.length} {nodes.length === 1 ? 'worker' : 'workers'}</span>
            </div>
            <div className="phase-segments">{nodes.length
              ? nodes.map(node => <i key={node.id} data-status={node.status} />)
              : <i />}</div>
            <span className="muted">
              {settled ? 'Complete' : waitingApproval ? 'Awaiting approval' : active ? `${workerPhaseNames[phase]} in progress` : 'Queued'}
            </span>
          </li>
          {phase === 'discovery' && <li className="approval-gate" data-approved={run.scopeRevision > 0}
            aria-label={run.scopeRevision ? 'Scope reviewed' : 'Scope approval required'}>
            <span aria-hidden="true">{run.scopeRevision ? '✓' : '◇'}</span>
          </li>}
        </Fragment>
      })}
    </ol>

    {afterApproval && <div className="workflow-callout">
      <div>
        <h2>Approved scope</h2>
        <p>
          {run.approved.length} approved {run.approved.length === 1 ? 'host' : 'hosts'} · Revision {run.scopeRevision} · {capabilityTierMeta[run.capabilityTier].short}
          {run.approvedPersonaIds.length > 0 && ` · ${run.approvedPersonaIds.length} ${run.approvedPersonaIds.length === 1 ? 'persona' : 'personas'}`}
          {` · Budget ${formatUsd(run.budgetUsd)} / ${run.budgetRequests === 0 ? '∞ reqs' : `${run.budgetRequests} reqs`}`}
        </p>
        {plan?.status === 'pending' && <p>{run.status === 'running' && detail.hasModel ? 'Preparing review plan' : 'Review plan pending'}</p>}
        {plan?.status === 'ready' && <p>{plan.source === 'standard' ? 'Standard checks' : 'Planned checks'} · {plan.checks.map(id => assessmentCheckTitles[id]).join(', ')}</p>}
      </div>
      <Button className="btn-nowrap" onClick={toggleReview} aria-expanded={Boolean(review)} disabled={!canReview}>
        {review ? 'Close review' : 'Review scope'}
      </Button>
    </div>}

    {suggestedCandidates.length > 0 && canReview && !review && <section className="candidate-callout" aria-label="Unapproved candidate hosts">
      <div className="section-heading">
        <div>
          <h3>Candidate hosts outside current scope ({suggestedCandidates.length})</h3>
          <p className="muted">Worker-suggested or excluded hosts stay strictly out of scope until explicitly authorized.</p>
        </div>
      </div>
      <ul className="project-list">{suggestedCandidates.slice(0, 8).map(asset => <li key={asset.id}>
        <div className="list-row">
          <span>
            <strong>{safeHost(asset.origin)}</strong>
            <small>{asset.source}</small>
          </span>
          <div className="toolbar">
            <Button variant="ghost" disabled={pending} onClick={() => beginReview(asset.id)}>Review</Button>
            <Button variant="default" className="btn-nowrap" disabled={pending || run.approved.length >= maxScopeHosts} onClick={() => {
              execute({
                action: 'scope',
                assetIds: [...run.approved, asset.id],
                expectedScopeRevision: run.scopeRevision,
                consent: true,
              })
            }}>Promote to scope</Button>
          </div>
        </div>
      </li>)}</ul>
    </section>}

    {(runtimeConfirmedCount > 0 || staticVerifiedCount > 0 || openProofGaps.length > 0 || patchProposals.length > 0) && primaryFindings.length === 0 && <section className="workflow-callout" aria-label="Verification tiers and exports">
      <div>
        <h2>Verification summary</h2>
        <div className="inline-badges">
          <span className="badge badge-complete">Runtime Confirmed: {runtimeConfirmedCount}</span>
          <span className="badge badge-trace">Static Verified: {staticVerifiedCount}</span>
          {openProofGaps.length > 0 && <span className="badge badge-attention">Open Proof Gaps: {openProofGaps.length}</span>}
          {patchProposals.length > 0 && <span className="badge badge-accent">Patch Proposals: {patchProposals.length}</span>}
        </div>
      </div>
      <Button variant="ghost" disabled={exportingSarif} onClick={() => void handleDownloadSarif()}>
        {exportingSarif ? 'Exporting SARIF…' : 'Download SARIF 2.1.0'}
      </Button>
    </section>}

    {openProofGaps.length > 0 && <section className="overview-card" aria-label="Open Proof Gaps">
      <div className="section-heading">
        <h2>Open Proof Gaps</h2>
        <span className="muted">{openProofGaps.length} {openProofGaps.length === 1 ? 'lead' : 'leads'} awaiting follow-up</span>
      </div>
      <div className="threat-grid">
        {openProofGaps.slice(0, 8).map(gap => <div key={gap.id} className="threat-card">
          <div className="threat-card-head">
            <strong>{safeHost(gap.origin)}</strong>
            <span className="badge badge-attention">{owaspCategoryTitles[gap.category] ?? gap.category}</span>
          </div>
          <p>{gap.proofGapReason || gap.summary}</p>
          {gap.proofGapReason && gap.summary !== gap.proofGapReason && <p className="muted">{gap.summary}</p>}
        </div>)}
      </div>
    </section>}

    {patchProposals.length > 0 && <section className="overview-card" aria-label="Verified Patch Diffs">
      <div className="section-heading">
        <h2>Verified Patch Diffs</h2>
        <span className="muted">{patchProposals.length} {patchProposals.length === 1 ? 'patch' : 'patches'}</span>
      </div>
      <div className="threat-grid">
        {patchProposals.slice(0, 6).map(patch => <article key={patch.id} className="threat-card">
          <div className="threat-card-head">
            <strong>{findingTitleById.get(patch.findingId) ?? patch.findingId}</strong>
            <div className="inline-badges">
              <span className={patch.status === 'approved' ? 'badge badge-complete' : patch.status === 'withheld' ? 'badge badge-attention' : 'badge badge-danger'}>
                {patchStatusLabels[patch.status]}
              </span>
              <span className={patch.callerCompatibility === 'attacker_only' ? 'badge badge-complete' : patch.callerCompatibility === 'needs_operator_step' ? 'badge badge-attention' : 'badge badge-danger'}>
                {callerCompatibilityLabels[patch.callerCompatibility]}
              </span>
              <span className={patch.dynamicRetestVerdict === 'fixed' ? 'badge badge-complete' : patch.dynamicRetestVerdict === 'reproduced' ? 'badge badge-danger' : 'badge'}>
                {dynamicRetestLabels[patch.dynamicRetestVerdict]}
              </span>
            </div>
          </div>
          {patch.reviewNotes && <p className="muted">{patch.reviewNotes}</p>}
          {patch.status === 'approved' && patch.diff.trim() && <pre className="approval-preview">{patch.diff}</pre>}
        </article>)}
      </div>
    </section>}

    {/* 3. Collapsible Threat Model */}
    {threatModel && threatModel.entries.length > 0 && <section className="disclosure-card" aria-label="Threat model ranking">
      <button
        type="button"
        className="disclosure-card-trigger"
        aria-expanded={threatOpen}
        onClick={() => setThreatOpen(v => !v)}
      >
        <div>
          <div className="inline-badges">
            <strong>Threat model ranking</strong>
            <span className="badge badge-trace">{threatModel.entries.length} ranked {threatModel.entries.length === 1 ? 'host' : 'hosts'}</span>
          </div>
          {threatModel.summary && <p className="muted xs" style={{ marginTop: 3 }}>{threatModel.summary}</p>}
        </div>
        <span className={`disclosure-chevron${threatOpen ? ' open' : ''}`} aria-hidden="true">▾</span>
      </button>
      {threatOpen && <div className="disclosure-card-body">
        <div className="table-scroll">
          <table className="compact-table">
            <thead>
              <tr>
                <th scope="col">Host</th>
                <th scope="col">Risk</th>
                <th scope="col">Surface tags</th>
                <th scope="col">Rationale</th>
              </tr>
            </thead>
            <tbody>
              {(showAllThreat ? threatModel.entries : threatModel.entries.slice(0, 8)).map(entry => <tr key={entry.origin}>
                <td className="mono"><strong>{safeHost(entry.origin)}</strong></td>
                <td><span className={riskBadgeClass(entry.riskTier)}>{entry.riskTier}</span></td>
                <td><div className="inline-badges">{entry.surfaceTags.slice(0, 4).map(t => <span key={t} className="badge">{t}</span>)}</div></td>
                <td className="muted">{entry.rationale}</td>
              </tr>)}
            </tbody>
          </table>
        </div>
        {threatModel.entries.length > 8 && <div style={{ marginTop: 8 }}>
          <Button type="button" variant="ghost" onClick={() => setShowAllThreat(v => !v)}>
            {showAllThreat ? 'Show top 8' : `Show all ${threatModel.entries.length} ranked hosts`}
          </Button>
        </div>}
      </div>}
    </section>}

    {/* 4. Collapsible Scope Inventory (default collapsed once approved; auto-open during review) */}
    {run.candidates.length > 0 && <section className="disclosure-card inventory-disclosure" aria-label="Scope inventory">
      <button
        type="button"
        className="disclosure-card-trigger"
        aria-expanded={scopeInventoryOpen}
        onClick={() => { if (!review) setScopeOpenManual(v => !(v ?? scopeInventoryOpen)) }}
      >
        <div>
          <div className="inline-badges">
            <strong>Discovery inventory &amp; scope</strong>
            <span className="badge">{run.candidates.length} discovered</span>
            {run.scopeRevision > 0 && <span className="badge badge-complete">{run.approved.length} approved · Rev {run.scopeRevision}</span>}
          </div>
          <p className="muted xs" style={{ marginTop: 3 }}>
            {review ? 'Select approved hosts, tier, limits, and personas below.' : 'Click to inspect discovered hosts and ownership evidence.'}
          </p>
        </div>
        <span className={`disclosure-chevron${scopeInventoryOpen ? ' open' : ''}`} aria-hidden="true">▾</span>
      </button>

      {scopeInventoryOpen && <form className="disclosure-card-body inventory" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        if (!review || stale || !form.has('scopeConsent') || overLimit) return
        execute({
          action: 'scope',
          assetIds: review.assetIds,
          expectedScopeRevision: review.scopeRevision,
          consent: true,
          saveProject: form.has('defaultScope'),
          capabilityTier: review.capabilityTier,
          approvalPolicy: review.approvalPolicy,
          approvedPersonaIds: review.capabilityTier >= 2 ? review.approvedPersonaIds : [],
          budgetUsd: review.budgetUsd,
          budgetRequests: review.budgetRequests,
          maxRpsPerOrigin: review.maxRpsPerOrigin,
        }, () => setDraft(undefined))
      }}>
        {review && <div className="section-heading" style={{ marginBottom: 8 }}>
          <div className="inline-badges">
            <span className="badge badge-accent">{selected.length} / {maxScopeHosts} selected</span>
            <Button type="button" variant="ghost" disabled={stale || pending} onClick={() => setDraft(current => current && {
              ...current,
              assetIds: run.candidates.filter(a => !a.thirdParty).slice(0, maxScopeHosts).map(a => a.id),
            })}>Select first-party</Button>
            <Button type="button" variant="ghost" disabled={stale || pending} onClick={() => setDraft(current => current && {
              ...current, assetIds: [],
            })}>Clear</Button>
          </div>
        </div>}
        <div className="table-scroll"><table>
          <thead><tr>{review && <th scope="col">Include</th>}<th scope="col">Host</th><th scope="col">Ownership evidence</th><th scope="col">Scope</th></tr></thead>
          <tbody>{run.candidates.map(asset => {
            const sourceId = asset.sourceEvidenceId
            return <tr key={asset.id}>
              {review && <td><Checkbox aria-label={`Include ${new URL(asset.origin).hostname}`} checked={selected.includes(asset.id)}
                disabled={stale || pending} onCheckedChange={checked => setDraft(current => current && {
                  ...current, assetIds: checked
                    ? (current.assetIds.includes(asset.id) ? current.assetIds : [...current.assetIds, asset.id])
                    : current.assetIds.filter(item => item !== asset.id),
                })} /></td>}
              <td><strong>{safeHost(asset.origin)}</strong>{asset.thirdParty && <small>Third-party service</small>}
                {asset.accessPolicy && <small>Access policy records</small>}</td>
              <td>{sourceId && inventoryIds.has(sourceId)
                ? <Button variant="ghost" className="text-button" onClick={() => openEvidence(sourceId)}>{asset.source} ↗</Button>
                : asset.source}</td>
              <td><Status status={run.approved.includes(asset.id) ? 'approved'
                : !run.scopeRevision && !asset.thirdParty ? 'proposed' : 'excluded'} /></td>
            </tr>
          })}</tbody>
        </table></div>
        {review && <div className="scope-footer" key={review.scopeRevision}>
          {overLimit && <p role="alert">Choose up to {maxScopeHosts} hosts for this run.</p>}
          {stale ? <>
            <p role="status">This draft uses revision {review.scopeRevision}. The current scope is revision {run.scopeRevision}.</p>
            <Button type="button" onClick={() => beginReview()} disabled={pending}>Review latest scope</Button>
          </> : <>
            <div className="scope-config">
              <label>Capability tier
                <NativeSelect value={review.capabilityTier} disabled={pending} onChange={event => {
                  const nextTier = Number(event.target.value) as CapabilityTier
                  setDraft(current => current && { ...current, capabilityTier: nextTier })
                }}>
                  <option value={0}>{capabilityTierMeta[0].name}</option>
                  <option value={1}>{capabilityTierMeta[1].name}</option>
                  <option value={2}>{capabilityTierMeta[2].name}</option>
                  <option value={3}>{capabilityTierMeta[3].name}</option>
                </NativeSelect>
                <span className="muted">{capabilityTierMeta[review.capabilityTier].summary}</span>
              </label>
              {review.capabilityTier === 3 && <label>Tier 3 Approval Policy
                <NativeSelect value={review.approvalPolicy} disabled={pending} onChange={event => {
                  const nextPolicy = event.target.value as ApprovalPolicy
                  setDraft(current => current && { ...current, approvalPolicy: nextPolicy })
                }}>
                  {approvalPolicies.map(policy => (
                    <option key={policy} value={policy}>{approvalPolicyMeta[policy].optionLabel}</option>
                  ))}
                </NativeSelect>
                <span className="muted">{approvalPolicyMeta[review.approvalPolicy].summary}</span>
              </label>}
              <div className="field-grid-3">
                <label>Budget (USD)
                  <Input type="number" min={0.1} max={500} step="any" disabled={pending}
                    value={review.budgetUsd} onChange={e => setDraft(c => c && { ...c, budgetUsd: Number(e.target.value) })} />
                </label>
                <label>Max requests (0 = ∞)
                  <Input type="number" min={0} max={maxBudgetRequests} step={1} disabled={pending}
                    value={review.budgetRequests} onChange={e => setDraft(c => c && { ...c, budgetRequests: Number(e.target.value) })} />
                </label>
                <label>Max RPS / origin
                  <Input type="number" min={1} max={maxRpsPerOriginCeiling} step={1} disabled={pending}
                    value={review.maxRpsPerOrigin} onChange={e => setDraft(c => c && { ...c, maxRpsPerOrigin: Number(e.target.value) })} />
                </label>
              </div>
              {personas.length > 0 && <div className="persona-binding-list">
                <strong>Bind test personas {review.capabilityTier < 2 && <span className="muted">(requires Tier 2 or Tier 3)</span>}</strong>
                {personas.map(persona => <label key={persona.id} className="checkbox persona-binding-item">
                  <span className="inline-badges">
                    <Checkbox
                      checked={review.approvedPersonaIds.includes(persona.id)}
                      disabled={pending || review.capabilityTier < 2}
                      aria-label={`Bind persona ${persona.handle}`}
                      onCheckedChange={checked => setDraft(current => current && {
                        ...current,
                        approvedPersonaIds: checked
                          ? [...current.approvedPersonaIds, persona.id]
                          : current.approvedPersonaIds.filter(id => id !== persona.id),
                      })}
                    />
                    <span><strong>{persona.handle}</strong> · {persona.roleLabel}</span>
                  </span>
                  <span className="muted">{persona.originAllowlist.map(safeHost).join(', ')}</span>
                </label>)}
              </div>}
            </div>
            {run.phase === 'review' && <p className="muted">The coordinator ranks approved hosts in Threat Model and dispatches multi-step investigation workers.</p>}
            <label className="checkbox"><Checkbox name="scopeConsent" required aria-label="I authorize scoped defensive assessment of the selected hosts." /> I authorize scoped defensive assessment of the selected hosts at {capabilityTierMeta[review.capabilityTier].short}.</label>
            <label className="checkbox"><Checkbox name="defaultScope" aria-label="Save selected hosts as the project default" /> Save selected hosts as the project default</label>
            <Button type="submit" variant="default" className="btn-nowrap" disabled={pending || overLimit || (run.phase === 'review' && selected.length === 0)}>
              {run.phase === 'review' ? 'Approve scope' : 'Save scope revision'}
            </Button>
          </>}
        </div>}
      </form>}
    </section>}

    {run.candidates.length > 0 && run.phase !== 'complete' && <div className="candidate-form">
      <Button onClick={() => setAdding(!adding)} aria-expanded={adding}>Add candidate</Button>
      {adding && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        execute({ action: 'candidate', candidate: {
          origin: String(form.get('origin')), source: String(form.get('source')), thirdParty: form.has('thirdParty'),
        } }, () => setAdding(false))
      }}>
        <label>Host<Input name="origin" required placeholder="docs.example.com" /></label>
        <label>Source<Input name="source" maxLength={160} required placeholder="Service inventory record" /></label>
        <label className="checkbox"><Checkbox name="thirdParty" aria-label="Third-party service" /> Third-party service</label>
        <div className="form-actions"><Button type="submit" variant="default" disabled={pending}>Add for review</Button></div>
      </form>}
    </div>}
  </div>
}
