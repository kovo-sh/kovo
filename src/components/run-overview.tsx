import { Fragment, useState } from 'react'
import { exportSarifAction } from '../actions.ts'
import {
  assessmentCheckTitles,
  canReviewScope,
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
  maxScopeHosts,
} from '../domain.ts'
import type { CapabilityTier, RunCommand } from '../domain.ts'
import {
  callerCompatibilityLabels,
  dynamicRetestLabels,
  owaspCategoryTitles,
  patchStatusLabels,
} from '../report-summary.ts'
import { Status } from './common.tsx'
import { capabilityTierMeta, formatUsd, phaseNames, workerPhaseNames, workerPhases } from './run-state.ts'
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
  approvedPersonaIds: string[]
  budgetUsd: number
  budgetRequests: number
  maxRpsPerOrigin: number
}

function riskBadgeClass(riskTier: 'critical' | 'high' | 'medium' | 'low') {
  if (riskTier === 'critical') return 'badge badge-danger'
  if (riskTier === 'high') return 'badge badge-attention'
  if (riskTier === 'medium') return 'badge badge-running'
  return 'badge'
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

export function RunOverview({ detail, history, execute, openEvidence, pending }: {
  detail: RunDetail
  history: ReadonlyMap<string, string>
  execute: (command: Command, onSuccess?: () => void) => void
  openEvidence: (id: string) => void
  pending: boolean
}) {
  const { run, project, assignments, evidence, approvals, personas, threatModel } = detail
  const plan = run.reviewPlan
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState<ScopeDraft>()
  const [exportingSarif, setExportingSarif] = useState(false)
  const runtimeConfirmedCount = detail.findings.filter(f => f.status === 'confirmed').length
  const staticVerifiedCount = detail.findings.filter(f => f.status === 'static_verified').length
  const openProofGaps = detail.openProofGaps ?? []
  const patchProposals = detail.patchProposals ?? []
  const findingTitleById = new Map(detail.findings.map(f => [f.id, f.title]))

  async function handleDownloadSarif() {
    setExportingSarif(true)
    try {
      const res = await exportSarifAction({ data: { runId: run.id, reportId: detail.reports[0]?.id } })
      downloadSarifBlob(res.content, res.filename)
    } finally {
      setExportingSarif(false)
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
  const suggestedCandidates = run.scopeRevision > 0
    ? run.candidates.filter(asset => !run.approved.includes(asset.id) && !asset.thirdParty)
    : []

  function beginReview(extraAssetId?: string) {
    const baseIds = run.scopeRevision > 0 ? [...run.approved]
      : run.candidates.filter(asset => !asset.thirdParty && (project.defaultScope.length
        ? project.defaultScope.includes(asset.origin) : !asset.dnsSource)).map(asset => asset.id)
    const assetIds = extraAssetId && !baseIds.includes(extraAssetId) ? [...baseIds, extraAssetId] : baseIds
    setDraft({
      scopeRevision: run.scopeRevision,
      assetIds,
      capabilityTier: run.capabilityTier,
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

    {pendingApprovals.length > 0 && <section className="approval-stack" aria-label="Pending Tier 3 approvals">
      {pendingApprovals.map(item => <article key={item.id} className="approval-card">
        <div className="section-heading">
          <div className="inline-badges">
            <h3>Tier 3 approval required</h3>
            <span className="badge badge-attention">{item.method}</span>
            {item.personaHandle && <span className="badge badge-trace">persona: {item.personaHandle}</span>}
          </div>
          <Status status="waiting_approval" />
        </div>
        <p className="approval-target"><code>{item.method} {item.origin}{item.pathAndQuery}</code></p>
        <p className="muted">{item.rationale}</p>
        {item.requestPreview && <pre className="approval-preview">{item.requestPreview}</pre>}
        <div className="approval-actions">
          <Button className="btn-danger" disabled={pending} onClick={() => {
            execute({ action: 'decide_approval', approvalId: item.id, decision: 'denied' })
          }}>Deny</Button>
          <Button variant="default" disabled={pending} onClick={() => {
            execute({ action: 'decide_approval', approvalId: item.id, decision: 'approved' })
          }}>Approve probe</Button>
        </div>
      </article>)}
    </section>}

    {run.phase === 'consent' && <form className="workflow-callout" onSubmit={event => {
      event.preventDefault()
      if (new FormData(event.currentTarget).has('discoveryConsent')) execute({ action: 'discover', consent: true })
    }}>
      <div>
        <h2>Discovery consent</h2>
        <p>Review project records, specs, and imported DNS exports for {project.seeds.map(seed => new URL(seed).hostname).join(', ')}.</p>
        <label className="checkbox"><Checkbox name="discoveryConsent" required aria-label="I authorize discovery for these assets." /> I authorize discovery for these assets.</label>
      </div>
      <Button type="submit" variant="default" disabled={pending || run.status !== 'waiting'}>Start discovery</Button>
    </form>}

    {run.phase === 'review' && <div className="workflow-callout">
      <div>
        <h2>Scope &amp; capability approval</h2>
        <p>{run.candidates.length} candidates · {run.candidates.filter(asset => asset.thirdParty).length} third-party · {capabilityTierMeta[run.capabilityTier].short}</p>
      </div>
      <Button variant="default" onClick={toggleReview} aria-expanded={Boolean(review)} disabled={!canReview}>
        {review ? 'Close review' : 'Review scope'}
      </Button>
    </div>}

    {afterApproval && <div className="workflow-callout">
      <div>
        <h2>Approved scope</h2>
        <p>
          {run.approved.length} approved {run.approved.length === 1 ? 'host' : 'hosts'} · Revision {run.scopeRevision} · {capabilityTierMeta[run.capabilityTier].short}
          {run.approvedPersonaIds.length > 0 && ` · ${run.approvedPersonaIds.length} ${run.approvedPersonaIds.length === 1 ? 'persona' : 'personas'}`}
          {` · Budget ${formatUsd(run.budgetUsd)} / ${run.budgetRequests} reqs`}
        </p>
        {plan?.status === 'pending' && <p>{run.status === 'running' && detail.hasModel ? 'Preparing review plan' : 'Review plan pending'}</p>}
        {plan?.status === 'ready' && <p>{plan.source === 'standard' ? 'Standard checks' : 'Planned checks'} · {plan.checks.map(id => assessmentCheckTitles[id]).join(', ')}</p>}
      </div>
      <Button onClick={toggleReview} aria-expanded={Boolean(review)} disabled={!canReview}>
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
            <strong>{new URL(asset.origin).hostname}</strong>
            <small>{asset.source}</small>
          </span>
          <div className="toolbar">
            <Button variant="ghost" disabled={pending} onClick={() => beginReview(asset.id)}>Review</Button>
            <Button variant="default" disabled={pending || run.approved.length >= maxScopeHosts} onClick={() => {
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

    {threatModel && threatModel.entries.length > 0 && <section className="stacked-section" aria-label="Threat model ranking">
      <div className="section-heading">
        <h2>Threat model ranking</h2>
        <span className="muted">{threatModel.entries.length} ranked {threatModel.entries.length === 1 ? 'host' : 'hosts'}</span>
      </div>
      {threatModel.summary && <p className="muted" style={{ marginTop: 4 }}>{threatModel.summary}</p>}
      <div className="threat-grid">
        {threatModel.entries.slice(0, 8).map(entry => <div key={entry.origin} className="threat-card">
          <div className="threat-card-head">
            <strong>{safeHost(entry.origin)}</strong>
            <div className="inline-badges">
              {entry.surfaceTags.map(tag => <span key={tag} className="badge">{tag}</span>)}
              <span className={riskBadgeClass(entry.riskTier)}>{entry.riskTier}</span>
            </div>
          </div>
          <p className="muted">{entry.rationale}</p>
        </div>)}
      </div>
    </section>}

    {(runtimeConfirmedCount > 0 || staticVerifiedCount > 0 || openProofGaps.length > 0 || patchProposals.length > 0) && <section className="workflow-callout" aria-label="Verification tiers and exports">
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

    {openProofGaps.length > 0 && <section className="stacked-section" aria-label="Open Proof Gaps">
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

    {patchProposals.length > 0 && <section className="stacked-section" aria-label="Verified Patch Diffs">
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

    {run.candidates.length > 0 && <form className="inventory" onSubmit={event => {
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
        approvedPersonaIds: review.capabilityTier >= 2 ? review.approvedPersonaIds : [],
        budgetUsd: review.budgetUsd,
        budgetRequests: review.budgetRequests,
        maxRpsPerOrigin: review.maxRpsPerOrigin,
      }, () => setDraft(undefined))
    }}>
      <div className="section-heading">
        <h2>Discovery inventory</h2>
        <div className="inline-badges">
          <span className="muted">{run.candidates.length} discovered</span>
          {review && <>
            <span className="badge badge-accent">{selected.length} / {maxScopeHosts} selected</span>
            <Button type="button" variant="ghost" disabled={stale || pending} onClick={() => setDraft(current => current && {
              ...current,
              assetIds: run.candidates.filter(a => !a.thirdParty).slice(0, maxScopeHosts).map(a => a.id),
            })}>Select first-party</Button>
            <Button type="button" variant="ghost" disabled={stale || pending} onClick={() => setDraft(current => current && {
              ...current, assetIds: [],
            })}>Clear</Button>
          </>}
        </div>
      </div>
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
            <td><strong>{new URL(asset.origin).hostname}</strong>{asset.thirdParty && <small>Third-party service</small>}
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
            <div className="field-grid-3">
              <label>Budget (USD)
                <Input type="number" min={0.1} max={500} step="any" disabled={pending}
                  value={review.budgetUsd} onChange={e => setDraft(c => c && { ...c, budgetUsd: Number(e.target.value) })} />
              </label>
              <label>Max requests
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
                <span className="muted">{persona.originAllowlist.map(o => new URL(o).hostname).join(', ')}</span>
              </label>)}
            </div>}
          </div>
          {run.phase === 'review' && <p className="muted">The coordinator ranks approved hosts in Threat Model and dispatches multi-step investigation workers.</p>}
          <label className="checkbox"><Checkbox name="scopeConsent" required aria-label="I authorize scoped defensive assessment of the selected hosts." /> I authorize scoped defensive assessment of the selected hosts at {capabilityTierMeta[review.capabilityTier].short}.</label>
          <label className="checkbox"><Checkbox name="defaultScope" aria-label="Save selected hosts as the project default" /> Save selected hosts as the project default</label>
          <Button type="submit" variant="default" disabled={pending || overLimit || (run.phase === 'review' && selected.length === 0)}>
            {run.phase === 'review' ? 'Approve scope' : 'Save scope revision'}
          </Button>
        </>}
      </div>}
    </form>}

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
