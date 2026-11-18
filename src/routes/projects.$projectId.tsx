import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { addProjectAsset, createRun, projectData } from '../actions.ts'
import { FormError, Status, timeText, useAction } from '../components/common.tsx'

export const Route = createFileRoute('/projects/$projectId')({
  loader: ({ params }) => projectData({ data: { projectId: params.projectId } }),
  component: ProjectPage,
})

function ProjectPage() {
  const { project, assets, runs } = Route.useLoaderData()
  const navigate = useNavigate()
  const [adding, setAdding] = useState(false)
  const [starting, setStarting] = useState(runs.length === 0)
  const action = useAction()
  const inventoryAction = useAction()
  return <main className="workspace-page">
    <Link className="back-link" to="/">← Projects</Link>
    <div className="page-title">
      <div><h1>{project.name}</h1><p className="muted">{project.seeds.map(seed => new URL(seed).hostname).join(', ')}</p></div>
      {!starting && <button className="primary" onClick={() => setStarting(true)}>New run</button>}
    </div>
    {starting && <form className="form-card" onSubmit={event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      void action.submit(() => createRun({ data: {
        requestId: crypto.randomUUID(), projectId: project.id, goal: String(form.get('goal')),
        sourceMode: form.has('live') ? 'public' : 'prepared',
      } }), async result => { await navigate({ to: '/runs/$runId', params: { runId: result.id } }) })
    }}>
      <h2>Start a run</h2>
      <label>Run goal<textarea name="goal" rows={3} maxLength={1500} required placeholder="Review the evidence for our public website." /></label>
      <label className="checkbox"><input type="checkbox" name="live" /> Read approved public pages during this run</label>
      <FormError error={action.error} />
      <div className="form-actions"><button className="primary" disabled={action.pending}>Create run</button></div>
    </form>}
    {runs.length > 0 && <section aria-label="Run history" className="stacked-section">
      <h2>Run history</h2>
      <ul className="project-list">{runs.map(run => <li key={run.id}>
        <Link to="/runs/$runId" params={{ runId: run.id }}>
          <span><strong>{run.goal}</strong><small>{timeText(run.createdAt)}</small></span><Status status={run.status} />
        </Link>
      </li>)}</ul>
    </section>}
    <section className="stacked-section">
      <div className="section-heading"><h2>Project inventory</h2>
        <button onClick={() => setAdding(value => !value)} aria-expanded={adding}>Add candidate</button>
      </div>
      {adding && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        let prepared: unknown
        if (String(form.get('prepared')).trim()) {
          try {
            prepared = JSON.parse(String(form.get('prepared')))
          } catch {
            void inventoryAction.submit(async () => { throw new Error('Prepared evidence must be valid JSON.') })
            return
          }
        }
        void inventoryAction.submit(() => addProjectAsset({ data: {
          requestId: crypto.randomUUID(), projectId: project.id,
          origin: String(form.get('origin')), source: String(form.get('source')), thirdParty: form.has('thirdParty'),
          prepared: prepared as Parameters<typeof addProjectAsset>[0]['data']['prepared'],
        } }), () => setAdding(false))
      }}>
        <label>Host<input name="origin" placeholder="docs.example.com" required /></label>
        <label>Source<input name="source" placeholder="Service ownership inventory" required maxLength={120} /></label>
        <label className="checkbox"><input name="thirdParty" type="checkbox" /> Third-party service</label>
        <details className="provider-advanced"><summary>Supply prepared evidence</summary>
          <label>Prepared response metadata
            <textarea name="prepared" rows={4} placeholder={'{"status":200,"mediaType":"text/html","transportMaxAge":31536000,"includeSubDomains":false}'} />
          </label>
        </details>
        <FormError error={inventoryAction.error} />
        <div className="form-actions"><button className="primary" disabled={inventoryAction.pending}>Add to project</button></div>
      </form>}
      <ul className="project-list">{assets.map(asset => <li key={asset.id}>
        <div className="list-row"><span><strong>{new URL(asset.origin).hostname}</strong><small>{asset.source}</small></span>
          <span className="muted">{asset.thirdParty ? 'Third party' : project.defaultScope.includes(asset.origin) ? 'Project default' : 'Candidate'}</span>
        </div>
      </li>)}</ul>
    </section>
  </main>
}
