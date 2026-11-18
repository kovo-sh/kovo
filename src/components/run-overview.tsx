import { useState } from 'react'
import type { RunCommand } from '../domain.ts'
import { Status } from './common.tsx'
import { phaseNames, workerPhases } from './run-state.ts'
import type { RunDetail } from './run-state.ts'

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
    : run.candidates.filter(asset => !asset.thirdParty && (!project.defaultScope.length ||
      project.defaultScope.includes(asset.origin))).map(asset => asset.id)
  const [selection, setSelection] = useState<string[] | null>(null)
  const selected = selection ?? initialSelection()
  const inventory = evidence.find(item => item.kind === 'inventory')

  return <div className="overview-body">
    <ol className="phase-rail" aria-label="Run phases">
      {workerPhases.map(phase => {
        const nodes = assignments.filter(worker => worker.phase === phase)
        const done = nodes.filter(worker => worker.status === 'complete').length
        return <li key={phase}>
          <div><h2>{phaseNames[phase]}</h2><span className="muted">{nodes.length} {nodes.length === 1 ? 'worker' : 'workers'}</span></div>
          <div className="phase-segments">{nodes.length
            ? nodes.map(node => <i key={node.id} data-status={node.status} />)
            : <i />}</div>
          <span className="muted">{nodes.length && done === nodes.length ? 'Complete' : run.phase === phase ? phaseNames[phase] + ' in progress' : 'Queued'}</span>
        </li>
      })}
    </ol>
    {run.phase === 'consent' && <form className="workflow-callout" onSubmit={event => {
      event.preventDefault()
      execute({ action: 'discover', consent: true })
    }}>
      <div>
        <h2>Discovery consent</h2>
        <p>Review supplied project records for {project.seeds.map(seed => new URL(seed).hostname).join(', ')}.</p>
        <label className="checkbox"><input type="checkbox" required /> I authorize discovery for these assets.</label>
      </div>
      <button className="primary" disabled={pending || run.status !== 'waiting'}>Start discovery</button>
    </form>}
    {run.phase === 'review' && <div className="workflow-callout">
      <div><h2>Scope approval</h2>
        <p>{run.candidates.length} candidates · {run.candidates.filter(asset => asset.thirdParty).length} third-party</p></div>
      <button className="primary" onClick={() => { setSelection(initialSelection()); setReview(!review) }} aria-expanded={review} disabled={run.status !== 'waiting'}>
        {review ? 'Close review' : 'Review scope'}
      </button>
    </div>}
    {['analysis', 'verification'].includes(run.phase) && <div className="workflow-callout">
      <div><h2>Approved scope</h2><p>{run.approved.length} approved hosts · Revision {run.scopeRevision}</p></div>
      <button onClick={() => { setSelection(initialSelection()); setReview(!review) }} aria-expanded={review}>
        {review ? 'Close review' : 'Review scope'}
      </button>
    </div>}
    {run.candidates.length > 0 && <form className="inventory" onSubmit={event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
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
          {review && <td><input type="checkbox" aria-label={`Include ${new URL(asset.origin).hostname}`} checked={selected.includes(asset.id)}
            onChange={event => setSelection(event.target.checked
              ? [...selected, asset.id] : selected.filter(item => item !== asset.id))} /></td>}
          <td><strong>{new URL(asset.origin).hostname}</strong>{asset.thirdParty && <small>Third-party service</small>}</td>
          <td>{inventory ? <button type="button" className="text-button" onClick={() => openEvidence(inventory.id)}>{asset.source} ↗</button> : asset.source}</td>
          <td><Status status={run.approved.includes(asset.id) ? 'approved'
            : !run.scopeRevision && !asset.thirdParty ? 'proposed' : 'excluded'} /></td>
        </tr>)}</tbody>
      </table></div>
      {review && <div className="scope-footer">
        <label className="checkbox"><input required type="checkbox" /> I authorize read-only review of the selected hosts.</label>
        <label className="checkbox"><input name="defaultScope" type="checkbox" /> Save selected hosts as the project default</label>
        <button className="primary" disabled={pending || (run.phase === 'review' && selected.length === 0)}>
          {run.phase === 'review' ? 'Approve scope' : 'Save scope revision'}
        </button>
      </div>}
    </form>}
    {run.candidates.length > 0 && run.phase !== 'complete' && <div className="candidate-form">
      <button type="button" onClick={() => setAdding(!adding)} aria-expanded={adding}>Add candidate</button>
      {adding && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        execute({ action: 'candidate', candidate: {
          origin: String(form.get('origin')), source: String(form.get('source')), thirdParty: form.has('thirdParty'),
        } }, () => setAdding(false))
      }}>
        <label>Host<input name="origin" required placeholder="docs.example.com" /></label>
        <label>Source<input name="source" maxLength={120} required placeholder="Service inventory record" /></label>
        <label className="checkbox"><input name="thirdParty" type="checkbox" /> Third-party service</label>
        <div className="form-actions"><button className="primary" disabled={pending}>Add for review</button></div>
      </form>}
    </div>}
  </div>
}
