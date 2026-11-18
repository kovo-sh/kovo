import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { addProjectAsset, createRun, projectData } from '../actions.ts'
import { FormError, Status, timeText, useAction } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible.tsx'
import { Input, Textarea } from '../components/ui/input.tsx'

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
      {!starting && <Button variant="default" onClick={() => setStarting(true)}>New run</Button>}
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
      <label>Run goal<Textarea name="goal" rows={3} maxLength={1500} required placeholder="Review the evidence for our public website." /></label>
      <label className="checkbox"><Checkbox name="live" aria-label="Read approved public pages during this run" /> Read approved public pages during this run</label>
      <FormError error={action.error} />
      <div className="form-actions"><Button type="submit" variant="default" disabled={action.pending}>Create run</Button></div>
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
        <Button onClick={() => setAdding(value => !value)} aria-expanded={adding}>Add candidate</Button>
      </div>
      {adding && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        let prepared: unknown
        const supplied = String(form.get('prepared') ?? '').trim()
        if (supplied) {
          try {
            prepared = JSON.parse(supplied)
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
        <label>Host<Input name="origin" placeholder="docs.example.com" required /></label>
        <label>Source<Input name="source" placeholder="Service ownership inventory" required maxLength={120} /></label>
        <label className="checkbox"><Checkbox name="thirdParty" aria-label="Third-party service" /> Third-party service</label>
        <Collapsible className="provider-advanced">
          <CollapsibleTrigger render={<Button variant="ghost" />}>Supply prepared evidence</CollapsibleTrigger>
          <CollapsibleContent keepMounted>
            <label>Prepared response metadata
              <Textarea name="prepared" rows={4} placeholder={'{"status":200,"mediaType":"text/html","transportMaxAge":31536000,"includeSubDomains":false}'} />
            </label>
          </CollapsibleContent>
        </Collapsible>
        <FormError error={inventoryAction.error} />
        <div className="form-actions"><Button type="submit" variant="default" disabled={inventoryAction.pending}>Add to project</Button></div>
      </form>}
      <ul className="project-list">{assets.map(asset => <li key={asset.id}>
        <div className="list-row"><span><strong>{new URL(asset.origin).hostname}</strong><small>{asset.source}</small></span>
          <span className="muted">{asset.thirdParty ? 'Third party' : project.defaultScope.includes(asset.origin) ? 'Project default' : 'Candidate'}</span>
        </div>
      </li>)}</ul>
    </section>
  </main>
}
