import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { createProject, workspaceData } from '../actions.ts'
import { FormError, useAction } from '../components/common.tsx'

export const Route = createFileRoute('/')({
  loader: () => workspaceData(),
  component: Workspace,
})

function Workspace() {
  const { workspace, projects } = Route.useLoaderData()
  const navigate = useNavigate()
  const [creating, setCreating] = useState(projects.length === 0)
  const action = useAction()

  return <main className="workspace-page">
    <div className="page-title">
      <div><p className="eyebrow">{workspace.name}</p><h1>Projects</h1></div>
      {!creating && <button type="button" className="primary" onClick={() => setCreating(true)}>New project</button>}
    </div>
    {creating && <form className="form-card" onSubmit={event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      void action.submit(() => createProject({ data: {
        requestId: crypto.randomUUID(),
        name: String(form.get('name')),
        seeds: String(form.get('seeds')).split(/[\s,]+/).filter(Boolean),
      } }), async project => { await navigate({ to: '/projects/$projectId', params: { projectId: project.id } }) })
    }}>
      <h2>Create a project</h2>
      <label>Project name<input name="name" placeholder="Product website" required maxLength={120} /></label>
      <label>Seed hosts
        <textarea name="seeds" rows={3} placeholder={'example.com\ndocs.example.com'} required />
        <span className="muted">Enter related hosts you own or have permission to review.</span>
      </label>
      <FormError error={action.error} />
      <div className="form-actions">
        {projects.length > 0 && <button type="button" onClick={() => setCreating(false)}>Cancel</button>}
        <button className="primary" disabled={action.pending}>Create project</button>
      </div>
    </form>}
    {projects.length > 0 && <ul className="project-list">
      {projects.map(project => <li key={project.id}>
        <Link to="/projects/$projectId" params={{ projectId: project.id }}>
          <span><strong>{project.name}</strong><small>{project.seeds.map(seed => new URL(seed).hostname).join(', ')}</small></span>
          <span aria-hidden="true">→</span>
        </Link>
      </li>)}
    </ul>}
  </main>
}
