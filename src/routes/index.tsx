import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { createProject, workspaceData } from '../actions.ts'
import { FormError, useAction } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Input, NativeSelect, Textarea } from '../components/ui/input.tsx'

export const Route = createFileRoute('/')({
  loader: () => workspaceData(),
  component: Workspace,
})

function Workspace() {
  const { workspace, projects, hasModel } = Route.useLoaderData()
  const navigate = useNavigate()
  const [creating, setCreating] = useState<boolean | null>(null)
  const [environment, setEnvironment] = useState<'public' | 'local-lab'>('public')
  const [includeSubdomains, setIncludeSubdomains] = useState(false)
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
      const nextEnv = form.get('environment') === 'local-lab' ? 'local-lab' as const : 'public' as const
      void action.submit(() => createProject({ data: {
        requestId: crypto.randomUUID(),
        name: String(form.get('name')),
        seeds: String(form.get('seeds')).split(/[\s,]+/).filter(Boolean),
        environment: nextEnv,
        includeSubdomains: nextEnv === 'public' ? includeSubdomains : false,
      } }), async project => {
        setCreating(false)
        setIncludeSubdomains(false)
        await navigate({ to: '/projects/$projectId', params: { projectId: project.id } })
      })
    }}>
      <h2>Create a project</h2>
      <label>Project name<Input name="name" placeholder="Product website" required maxLength={160} /></label>
      <label>Target environment
        <NativeSelect name="environment" value={environment} onChange={e => {
          const next = e.target.value === 'local-lab' ? 'local-lab' : 'public'
          setEnvironment(next)
          if (next !== 'public') setIncludeSubdomains(false)
        }}>
          <option value="public">Public HTTPS (global unicast IPs only)</option>
          <option value="local-lab">Local Lab (opt-in loopback/private staging when enabled)</option>
        </NativeSelect>
        <span className="muted">Local lab requires server-side GUARDIAN_ALLOW_LOCAL_LAB=1 to permit loopback or RFC1918 targets.</span>
      </label>
      <label>Seed hosts
        <Textarea name="seeds" rows={3} placeholder={'example.com\ndocs.example.com'} required />
        <span className="muted">Enter up to 100 related hosts you own or have written authorization to assess.</span>
      </label>
      {environment === 'public' && <div className="field-grid">
        <label className="checkbox">
          <Checkbox
            name="includeSubdomains"
            checked={includeSubdomains}
            aria-label="Include subdomains (*.domain)"
            onCheckedChange={checked => setIncludeSubdomains(Boolean(checked))}
          />
          <span>Include subdomains (<code>*.domain</code>)</span>
        </label>
        <span className="muted small-note">
          Uses passive CT-log discovery + live DNS in Phase 0 to admit live first-party subdomains into scope. Managed third-party SaaS CNAMEs (e.g. GitBook, Webflow, Shopify, Zendesk) stay excluded unless you explicitly approve them.
        </span>
      </div>}
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
