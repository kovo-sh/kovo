import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { createProject, workspaceData } from '../actions.ts'
import { FormError, useAction } from '../components/common.tsx'
import { fmtDate, host, plural } from '../components/run/format.ts'
import { StatusGlyph } from '../components/run/glyphs.tsx'
import { Icon } from '../components/run/icons.tsx'
import { PHASE_LABEL, runStatusLabel } from '../components/run/meta.ts'
import { useShell } from '../components/shell/AppShell.tsx'
import { Button } from '../components/ui/button.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Input, NativeSelect, Textarea } from '../components/ui/input.tsx'

type HomeSearch = { new?: string }

export const Route = createFileRoute('/')({
  validateSearch: (search: Record<string, unknown>): HomeSearch => ({
    new: search.new === '1' || search.new === true ? '1' : undefined,
  }),
  loader: () => workspaceData(),
  component: Workspace,
})

function CreateProjectSheet({
  isModal,
  canCancel,
  onClose,
}: {
  isModal: boolean
  canCancel: boolean
  onClose: () => void
}) {
  const navigate = useNavigate()
  const [environment, setEnvironment] = useState<'public' | 'local-lab'>('public')
  const [includeSubdomains, setIncludeSubdomains] = useState(false)
  const action = useAction()

  useEffect(() => {
    if (!isModal) return
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [isModal, onClose])

  const sheetContent = <form
    className={isModal ? 'sh-modal-sheet' : 'sheet'}
    role={isModal ? 'dialog' : undefined}
    aria-modal={isModal ? 'true' : undefined}
    aria-label={isModal ? 'Create a project' : undefined}
    onSubmit={event => {
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
        setIncludeSubdomains(false)
        onClose()
        await navigate({ to: '/projects/$projectId', params: { projectId: project.id } })
      })
    }}
  >
    <div className="sheet-h">
      <Icon name="plus" />
      <span>Create a project</span>
      <span className="muted">Define authorized seed hosts</span>
      {isModal && <button
        type="button"
        className="sh-icon-btn sh-sheet-close"
        onClick={onClose}
        aria-label="Close modal"
      >
        <Icon name="close" />
      </button>}
    </div>

    <div className="sh-sheet-body">
      <label>
        Project name
        <Input name="name" placeholder="Product website" required maxLength={160} autoFocus={isModal} />
      </label>

      <label>
        Target environment
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

      <label>
        Seed hosts
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
        <span className="sh-hint">
          Uses passive CT-log discovery + live DNS in Phase 0 to admit live first-party subdomains into scope. Managed third-party SaaS CNAMEs (e.g. GitBook, Webflow, Shopify, Zendesk) stay excluded unless you explicitly approve them.
        </span>
      </div>}

      <FormError error={action.error} />
    </div>

    <div className="sheet-f">
      <span className="muted">Scope stays fail-closed until approved.</span>
      {canCancel && <Button type="button" onClick={onClose}>Cancel</Button>}
      <Button type="submit" variant="default" disabled={action.pending}>Create project</Button>
    </div>
  </form>

  if (!isModal) return sheetContent

  return <div className="sh-overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
    {sheetContent}
  </div>
}

function formatRunPhase(status: string, phase: string): string {
  if (status === 'complete') return 'Complete'
  if (status === 'failed' || status === 'paused' || status === 'budget_paused' || status === 'waiting_approval') {
    return runStatusLabel(status)
  }
  return PHASE_LABEL[phase] ?? runStatusLabel(status)
}

function Workspace() {
  const { workspace, projects, hasModel, poolHealth } = Route.useLoaderData()
  const search = Route.useSearch()
  const navigate = useNavigate()
  const shell = useShell()
  const [modalOpen, setModalOpen] = useState(Boolean(search.new))
  const [filter, setFilter] = useState('')

  useEffect(() => {
    if (search.new) {
      setModalOpen(true)
      void navigate({ to: '/', search: {}, replace: true })
    }
  }, [search.new, navigate])

  useEffect(() => {
    if (!shell) return
    shell.registerNewProjectHandler(() => setModalOpen(true))
    return () => shell.registerNewProjectHandler(null)
  }, [shell])

  const visibleProjects = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return projects
    return projects.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.environment.toLowerCase().includes(q) ||
      p.seeds.some(s => host(s).toLowerCase().includes(q)),
    )
  }, [projects, filter])

  return <main className="proj-wrap">
    <header className="sh-hdr">
      <h1 className="sh-hdr-title">Projects</h1>
      <span className="sh-hdr-count num">{projects.length}</span>
      <span className="sh-hdr-sp" />
      <div className="sh-hdr-actions">
        {projects.length > 0 && <div className="sh-filter">
          <Icon name="search" />
          <input
            type="search"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter…"
            aria-label="Filter projects"
          />
          {filter && <button
            type="button"
            className="sh-filter-clear"
            onClick={() => setFilter('')}
            aria-label="Clear filter"
          >
            <Icon name="x" size={12} />
          </button>}
        </div>}
        {projects.length > 0 && (
          <Button variant="default" className="btn primary" onClick={() => setModalOpen(true)}>
            New project
          </Button>
        )}
      </div>
    </header>

    {!hasModel && <div className="rbanner warn" role="status">
      <Icon name="alert" />
      <span className="grow">
        <b>Connect a model to run assessments.</b> Configure one or more OpenRouter or compatible LLM profiles for coordinator and worker reviews.
      </span>
      <Link className="btn" to="/settings" search={{}}>
        Set up model
        <Icon name="arrowR" />
      </Link>
    </div>}

    {hasModel && poolHealth === 'degraded' && <div className="rbanner warn" role="status">
      <Icon name="alert" />
      <span className="grow">
        <b>Model failover pool degraded.</b> One or more enabled profiles have an active circuit breaker cooldown.
      </span>
      <Link className="btn" to="/settings" search={{}}>
        Model settings
        <Icon name="arrowR" />
      </Link>
    </div>}

    {projects.length === 0 ? <div className="sh-onboard">
      <div className="sh-onboard-in">
        <div className="sh-onboard-eyebrow">{workspace.name}</div>
        <h2 className="sh-onboard-display">Start your first project</h2>
        <p className="sh-onboard-lede">
          Register the hosts you own or have written authorization to test. Guardian verifies scope before dispatching any live requests.
        </p>
        <CreateProjectSheet isModal={false} canCancel={false} onClose={() => setModalOpen(false)} />
      </div>
    </div> : <div className="proj-table-wrap">
      <div className="proj-head" role="row">
        <span>Project</span>
        <span>Seed host(s)</span>
        <span>Latest run</span>
        <span className="r">Runs / Findings</span>
      </div>

      {visibleProjects.length === 0 ? <div className="proj-empty-note">
        No projects match “{filter}”.
      </div> : visibleProjects.map(project => {
        const seedHosts = project.seeds.map(host)
        const hostSummary = seedHosts.slice(0, 2).join(', ')
        const extraHosts = Math.max(0, project.hostCount - Math.min(2, seedHosts.length))
        const latest = project.latestRun
        return <div
          key={project.id}
          className="proj-row"
          onClick={e => {
            if ((e.target as HTMLElement).closest('a, button')) return
            void navigate({ to: '/projects/$projectId', params: { projectId: project.id } })
          }}
        >
          <div className="proj-name-col">
            <Link
              to="/projects/$projectId"
              params={{ projectId: project.id }}
              className="proj-name-link"
              title={project.name}
            >
              {project.name}
            </Link>
            {project.environment === 'local-lab'
              ? <span className="tag warn">Local lab</span>
              : <span className="tag">Public</span>}
          </div>

          <div className="proj-hosts-col" title={seedHosts.join(', ')}>
            <span className="proj-hosts-text mono">{hostSummary || '—'}</span>
            {extraHosts > 0 && <span className="tag solid num">+{extraHosts}</span>}
          </div>

          <div className="proj-run-col">
            {latest ? <Link
              to="/runs/$runId"
              params={{ runId: latest.id }}
              search={{}}
              className="proj-run-link"
              title={latest.goal}
            >
              <span className="g"><StatusGlyph status={latest.status} /></span>
              <span className="proj-run-meta">{formatRunPhase(latest.status, latest.phase)}</span>
              <span className="proj-run-time num">{fmtDate(latest.startedAt)}</span>
            </Link> : <span className="muted">No runs yet</span>}
          </div>

          <div className="proj-counts-col num">
            <span className={project.runCount > 0 ? '' : 'dim'}>
              {plural(project.runCount, 'run')}
            </span>
            <span className="dim">·</span>
            <span className={latest && latest.confirmedCount > 0 ? 'hot' : 'dim'}>
              {latest ? `${latest.confirmedCount} confirmed` : '—'}
            </span>
          </div>

          <div className="proj-acts">
            <Link
              to="/projects/$projectId"
              params={{ projectId: project.id }}
              className="btn"
            >
              Open
            </Link>
            <Link
              to="/projects/$projectId"
              params={{ projectId: project.id }}
              hash="new-run"
              className="btn primary"
            >
              New run
            </Link>
          </div>
        </div>
      })}
    </div>}

    {projects.length > 0 && modalOpen && (
      <CreateProjectSheet isModal={true} canCancel={true} onClose={() => setModalOpen(false)} />
    )}
  </main>
}
