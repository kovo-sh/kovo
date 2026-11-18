import { Fragment, useState } from 'react'
import { assessmentCheckTitles, canReviewScope, maxScopeHosts } from '../domain.ts'
import type { RunCommand } from '../domain.ts'
import { Status } from './common.tsx'
import { phaseNames, workerPhases } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { Checkbox } from './ui/checkbox.tsx'
import { Input } from './ui/input.tsx'

export type Command = RunCommand extends infer C
  ? C extends RunCommand ? Omit<C, 'requestId' | 'runId'> : never
  : never

export function RunOverview({ detail, history, execute, openEvidence, pending }: {
  detail: RunDetail
  history: ReadonlyMap<string, string>
  execute: (command: Command, onSuccess?: () => void) => void
  openEvidence: (id: string) => void
  pending: boolean
}) {
  const { run, project, assignments, evidence } = detail
  const plan = run.reviewPlan
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState<{ scopeRevision: number; assetIds: string[] }>()
  const afterApproval = run.phase === 'analysis' || run.phase === 'verification'
  const canReview = canReviewScope(run.phase, run.status)
  const review = canReview ? draft : undefined
  const stale = Boolean(review && review.scopeRevision !== run.scopeRevision)
  const selected = review?.assetIds ?? []
  const overLimit = selected.length > maxScopeHosts
  const inventoryIds = new Set(evidence.filter(item => item.kind === 'inventory').map(item => item.id))

  function beginReview() {
    const assetIds = run.scopeRevision > 0 ? run.approved
      : run.candidates.filter(asset => !asset.thirdParty && (project.defaultScope.length
        ? project.defaultScope.includes(asset.origin) : !asset.dnsSource)).map(asset => asset.id)
    setDraft({ scopeRevision: run.scopeRevision, assetIds })
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
        return <Fragment key={phase}>
          <li>
            <div><h2>{phaseNames[phase]}</h2><span className="muted">{nodes.length} {nodes.length === 1 ? 'worker' : 'workers'}</span></div>
            <div className="phase-segments">{nodes.length
              ? nodes.map(node => <i key={node.id} data-status={node.status} />)
              : <i />}</div>
            <span className="muted">{settled ? 'Complete' : active ? `${phaseNames[phase]} in progress` : 'Queued'}</span>
          </li>
          {phase === 'discovery' && <li className="approval-gate" data-approved={run.scopeRevision > 0}
            aria-label={run.scopeRevision ? 'Scope reviewed' : 'Scope approval required'}>
            <span aria-hidden="true">{run.scopeRevision ? '✓' : '◇'}</span>
          </li>}
        </Fragment>
      })}
    </ol>
    {run.phase === 'consent' && <form className="workflow-callout" onSubmit={event => {
      event.preventDefault()
      if (new FormData(event.currentTarget).has('discoveryConsent')) execute({ action: 'discover', consent: true })
    }}>
      <div>
        <h2>Discovery consent</h2>
        <p>Review project records and imported DNS exports for {project.seeds.map(seed => new URL(seed).hostname).join(', ')}.</p>
        <label className="checkbox"><Checkbox name="discoveryConsent" required aria-label="I authorize discovery for these assets." /> I authorize discovery for these assets.</label>
      </div>
      <Button type="submit" variant="default" disabled={pending || run.status !== 'waiting'}>Start discovery</Button>
    </form>}
    {run.phase === 'review' && <div className="workflow-callout">
      <div><h2>Scope approval</h2>
        <p>{run.candidates.length} candidates · {run.candidates.filter(asset => asset.thirdParty).length} third-party</p></div>
      <Button variant="default" onClick={toggleReview} aria-expanded={Boolean(review)} disabled={!canReview}>
        {review ? 'Close review' : 'Review scope'}
      </Button>
    </div>}
    {afterApproval && <div className="workflow-callout">
      <div>
        <h2>Approved scope</h2><p>{run.approved.length} approved {run.approved.length === 1 ? 'host' : 'hosts'} · Revision {run.scopeRevision}</p>
        {plan?.status === 'pending' && <p>{run.status === 'running' && detail.hasModel ? 'Preparing review plan' : 'Review plan pending'}</p>}
        {plan?.status === 'ready' && <p>{plan.source === 'standard' ? 'Standard checks' : 'Planned checks'} · {plan.checks.map(id => assessmentCheckTitles[id]).join(', ')}</p>}
      </div>
      <Button onClick={toggleReview} aria-expanded={Boolean(review)} disabled={!canReview}>
        {review ? 'Close review' : 'Review scope'}
      </Button>
    </div>}
    {run.candidates.length > 0 && <form className="inventory" onSubmit={event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      if (!review || stale || !form.has('scopeConsent') || overLimit) return
      execute({
        action: 'scope', assetIds: review.assetIds, expectedScopeRevision: review.scopeRevision,
        consent: true, saveProject: form.has('defaultScope'),
      }, () => setDraft(undefined))
    }}>
      <div className="section-heading"><h2>Discovery inventory</h2>
        <span className="muted">{run.candidates.length} discovered</span></div>
      <div className="table-scroll"><table>
        <thead><tr>{review && <th scope="col">Include</th>}<th scope="col">Host</th><th scope="col">Ownership evidence</th><th scope="col">Scope</th></tr></thead>
        <tbody>{run.candidates.map(asset => {
          const sourceId = asset.sourceEvidenceId
          return <tr key={asset.id}>
            {review && <td><Checkbox aria-label={`Include ${new URL(asset.origin).hostname}`} checked={selected.includes(asset.id)}
              disabled={stale || pending} onCheckedChange={checked => setDraft(current => current && {
                ...current, assetIds: checked
                  ? [...current.assetIds, asset.id] : current.assetIds.filter(item => item !== asset.id),
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
          <Button type="button" onClick={beginReview} disabled={pending}>Review latest scope</Button>
        </> : <>
          {run.phase === 'review' && <p className="muted">The coordinator selects checks for your goal from the available evidence.</p>}
          <label className="checkbox"><Checkbox name="scopeConsent" required aria-label="I authorize read-only review of the selected hosts." /> I authorize read-only review of the selected hosts.</label>
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
        <label>Source<Input name="source" maxLength={120} required placeholder="Service inventory record" /></label>
        <label className="checkbox"><Checkbox name="thirdParty" aria-label="Third-party service" /> Third-party service</label>
        <div className="form-actions"><Button type="submit" variant="default" disabled={pending}>Add for review</Button></div>
      </form>}
    </div>}
  </div>
}
