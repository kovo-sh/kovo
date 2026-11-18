import { Fragment, useState } from 'react'
import { maxScopeHosts } from '../domain.ts'
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

export function RunOverview({ detail, execute, openEvidence, pending, review, setReview }: {
  detail: RunDetail
  execute: (command: Command, onSuccess?: () => void) => void
  openEvidence: (id: string) => void
  pending: boolean
  review: boolean
  setReview: (review: boolean) => void
}) {
  const { run, project, assignments, evidence } = detail
  const [adding, setAdding] = useState(false)
  const initialSelection = () => run.scopeRevision > 0 ? run.approved
    : run.candidates.filter(asset => !asset.thirdParty && (project.defaultScope.length
      ? project.defaultScope.includes(asset.origin) : !asset.dnsSource)).map(asset => asset.id)
  const [selection, setSelection] = useState<string[] | null>(null)
  const selected = selection ?? initialSelection()
  const overLimit = selected.length > maxScopeHosts
  const inventory = evidence.find(item => item.kind === 'inventory')

  return <div className="overview-body">
    <ol className="phase-rail" aria-label="Run phases">
      {workerPhases.map(phase => {
        const nodes = assignments.filter(worker => worker.phase === phase)
        const settled = nodes.length > 0 && nodes.every(worker => ['complete', 'canceled'].includes(worker.status))
        return <Fragment key={phase}>
          <li>
            <div><h2>{phaseNames[phase]}</h2><span className="muted">{nodes.length} {nodes.length === 1 ? 'worker' : 'workers'}</span></div>
            <div className="phase-segments">{nodes.length
              ? nodes.map(node => <i key={node.id} data-status={node.status} />)
              : <i />}</div>
            <span className="muted">{settled ? 'Complete' : run.phase === phase ? `${phaseNames[phase]} in progress` : 'Queued'}</span>
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
      <Button variant="default" onClick={() => { setSelection(initialSelection()); setReview(!review) }} aria-expanded={review} disabled={run.status !== 'waiting'}>
        {review ? 'Close review' : 'Review scope'}
      </Button>
    </div>}
    {['analysis', 'verification'].includes(run.phase) && <div className="workflow-callout">
      <div><h2>Approved scope</h2><p>{run.approved.length} approved hosts · Revision {run.scopeRevision}</p></div>
      <Button onClick={() => { setSelection(initialSelection()); setReview(!review) }} aria-expanded={review}>
        {review ? 'Close review' : 'Review scope'}
      </Button>
    </div>}
    {run.candidates.length > 0 && <form className="inventory" onSubmit={event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      if (!form.has('scopeConsent') || overLimit) return
      execute({ action: 'scope', assetIds: selected, consent: true, saveProject: form.has('defaultScope') }, () => {
        setReview(false)
        setSelection(null)
      })
    }}>
      <div className="section-heading"><h2>Discovery inventory</h2>
        <span className="muted">{run.candidates.length} discovered</span></div>
      <div className="table-scroll"><table>
        <thead><tr>{review && <th scope="col">Include</th>}<th scope="col">Host</th><th scope="col">Ownership evidence</th><th scope="col">Scope</th></tr></thead>
        <tbody>{run.candidates.map(asset => <tr key={asset.id}>
          {review && <td><Checkbox aria-label={`Include ${new URL(asset.origin).hostname}`} checked={selected.includes(asset.id)}
            onCheckedChange={checked => setSelection(checked
              ? [...selected, asset.id] : selected.filter(item => item !== asset.id))} /></td>}
          <td><strong>{new URL(asset.origin).hostname}</strong>{asset.thirdParty && <small>Third-party service</small>}</td>
          <td>{inventory ? <Button variant="ghost" className="text-button" onClick={() => openEvidence(inventory.id)}>{asset.source} ↗</Button> : asset.source}</td>
          <td><Status status={run.approved.includes(asset.id) ? 'approved'
            : !run.scopeRevision && !asset.thirdParty ? 'proposed' : 'excluded'} /></td>
        </tr>)}</tbody>
      </table></div>
      {review && <div className="scope-footer">
        {overLimit && <p role="alert">Choose up to {maxScopeHosts} hosts for this run.</p>}
        <label className="checkbox"><Checkbox name="scopeConsent" required aria-label="I authorize read-only review of the selected hosts." /> I authorize read-only review of the selected hosts.</label>
        <label className="checkbox"><Checkbox name="defaultScope" aria-label="Save selected hosts as the project default" /> Save selected hosts as the project default</label>
        <Button type="submit" variant="default" disabled={pending || overLimit || (run.phase === 'review' && selected.length === 0)}>
          {run.phase === 'review' ? 'Approve scope' : 'Save scope revision'}
        </Button>
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
