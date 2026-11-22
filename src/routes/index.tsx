import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { createProject, workspaceData } from '../actions.ts'
import { FormError, useAction } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import { Input, NativeSelect, Textarea } from '../components/ui/input.tsx'

export const Route = createFileRoute('/')({
  loader: () => workspaceData(),
  component: Workspace,
})

function Workspace() {
  const { workspace, projects, hasModel } = Route.useLoaderData()
  const navigate = useNavigate()
  const [creating, setCreating] = useState<boolean | null>(null)
  const isCreating = creating ?? projects.length === 0
  const action = useAction()

  return <main className="workspace-page">
    <div className="page-title">
      <div><p className="eyebrow">{workspace.name}</p><h1>Projects</h1></div>
      {!isCreating && <Button variant="default" onClick={() => setCreating(true)}>New project</Button>}
    </div>
    {!hasModel && <div className="model-callout">
      <div><h2>Connect a model</h2><p className="muted">Configure one or more OpenRouter or compatible LLM profiles for coordinator and worker reviews.</p></div>
      <Link className="action-link primary" to="/settings">Set up model</Link>
    </div>}
    {isCreating && <form className="form-card" onSubmit={event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      const environment = form.get('environment') === 'local-lab' ? 'local-lab' as const : 'public' as const
      void action.submit(() => createProject({ data: {
        requestId: crypto.randomUUID(),
        name: String(form.get('name')),
        seeds: String(form.get('seeds')).split(/[\s,]+/).filter(Boolean),
        environment,
      } }), async project => {
        setCreating(false)
        await navigate({ to: '/projects/$projectId', params: { projectId: project.id } })
      })
    }}>
      <h2>Create a project</h2>
      <label>Project name<Input name="name" placeholder="Product website" required maxLength={160} /></label>
      <label>Target environment
        <NativeSelect name="environment" defaultValue="public">
          <option value="public">Public HTTPS (global unicast IPs only)</option>
          <option value="local-lab">Local Lab (opt-in loopback/private staging when enabled)</option>
        </NativeSelect>
        <span className="muted">Local lab requires server-side GUARDIAN_ALLOW_LOCAL_LAB=1 to permit loopback or RFC1918 targets.</span>
      </label>
      <label>Seed hosts
        <Textarea name="seeds" rows={3} placeholder={'example.com\ndocs.example.com'} required />
        <span className="muted">Enter up to 100 related hosts you own or have written authorization to assess.</span>
      </label>
      <FormError error={action.error} />
      <div className="form-actions">
        {projects.length > 0 && <Button onClick={() => setCreating(false)}>Cancel</Button>}
        <Button type="submit" variant="default" disabled={action.pending}>Create project</Button>
      </div>
    </form>}
    {projects.length > 0 && <ul className="project-list">
      {projects.map(project => <li key={project.id}>
        <Link to="/projects/$projectId" params={{ projectId: project.id }}>
          <span>
            <span className="inline-badges">
              <strong>{project.name}</strong>
              {project.environment === 'local-lab' && <span className="badge badge-attention">Local lab</span>}
            </span>
            <small>{project.seeds.map(seed => new URL(seed).hostname).join(', ')}</small>
          </span>
          <span aria-hidden="true">→</span>
        </Link>
      </li>)}
    </ul>}
  </main>
}
