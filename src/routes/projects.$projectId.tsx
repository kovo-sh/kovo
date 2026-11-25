import { createFileRoute, Link, useLocation, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { projectData, removeProject, testPersonaAuthAction } from '../actions.ts'
import { Icon } from '../components/run/icons.tsx'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu.tsx'
import { ProjectGuardrailsTab } from '../components/project/ProjectGuardrailsTab.tsx'
import { ProjectInventoryTab } from '../components/project/ProjectInventoryTab.tsx'
import { ProjectNewRunSheet } from '../components/project/ProjectNewRunSheet.tsx'
import { ProjectOverviewTab } from '../components/project/ProjectOverviewTab.tsx'
import { ProjectPersonasTab } from '../components/project/ProjectPersonasTab.tsx'
import { ProjectSourcesTab } from '../components/project/ProjectSourcesTab.tsx'
import type { PersonaTestState, ProjectTabId } from '../components/project/types.ts'
import { isProjectTab, PROJECT_TABS, safeHost } from '../components/project/types.ts'
import '../components/project/project.css'
import type { PublicPersona } from '../domain.ts'

type ProjectSearch = {
  tab?: ProjectTabId
  newRun?: string
}

export const Route = createFileRoute('/projects/$projectId')({
  validateSearch: (search: Record<string, unknown>): ProjectSearch => ({
    ...(isProjectTab(search.tab) ? { tab: search.tab } : {}),
    ...(search.newRun === '1' || search.newRun === 1 || search.newRun === true ? { newRun: '1' } : {}),
  }),
  loader: ({ params }) => projectData({ data: { projectId: params.projectId } }),
  component: ProjectPage,
})

function ProjectPage() {
  const data = Route.useLoaderData()
  const { project, assets, personas, specs, runs } = data
  const search = Route.useSearch()
  const location = useLocation()
  const navigate = useNavigate()
  const router = useRouter()

  const activeTab: ProjectTabId = search.tab ?? 'overview'
  const hashWantsNewRun = location.hash === 'new-run' || location.hash === '#new-run'
  const [newRunOpen, setNewRunOpen] = useState(() => Boolean(search.newRun) || hashWantsNewRun)
  const [deleteProjectOpen, setDeleteProjectOpen] = useState(false)
  const [deletingProject, setDeletingProject] = useState(false)
  const [deleteProjectError, setDeleteProjectError] = useState('')
  const [selectedPersonaIds, setSelectedPersonaIds] = useState<string[]>(() => personas.map(p => p.id))
  const [personaTests, setPersonaTests] = useState<Record<string, PersonaTestState>>({})

  const activeRunsCount = runs.filter(r => r.status === 'running').length
  const totalFindings = runs.reduce((sum, r) => sum + r.findingCount, 0)
  const totalConfirmed = runs.reduce((sum, r) => sum + r.confirmedCount, 0)

  useEffect(() => {
    if (!deleteProjectOpen) return
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !deletingProject) {
        e.preventDefault()
        setDeleteProjectOpen(false)
        setDeleteProjectError('')
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [deleteProjectOpen, deletingProject])

  async function confirmDeleteProject() {
    if (deletingProject) return
    setDeletingProject(true)
    setDeleteProjectError('')
    try {
      await removeProject({ data: { projectId: project.id, stopActive: activeRunsCount > 0 } })
      setDeleteProjectOpen(false)
      await router.invalidate()
      await navigate({ to: '/', replace: true })
    } catch (err) {
      setDeleteProjectError(err instanceof Error ? err.message : 'Could not delete the project.')
      setDeletingProject(false)
    }
  }

  useEffect(() => {
    const openAndCleanUrl = () => {
      setNewRunOpen(true)
      void navigate({
        to: '/projects/$projectId',
        params: { projectId: project.id },
        search: search.tab ? { tab: search.tab } : {},
        hash: '',
        replace: true,
      })
    }
    const windowHashWantsNewRun =
      typeof window !== 'undefined' && window.location.hash === '#new-run'
    if (search.newRun || hashWantsNewRun || windowHashWantsNewRun) {
      openAndCleanUrl()
    }
    if (typeof window === 'undefined') return
    const onHashChange = () => {
      if (window.location.hash === '#new-run') {
        openAndCleanUrl()
      }
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [search.newRun, search.tab, hashWantsNewRun, project.id, navigate])

  function selectTab(next: ProjectTabId) {
    if (next === activeTab) return
    void navigate({
      to: '/projects/$projectId',
      params: { projectId: project.id },
      search: next === 'overview' ? {} : { tab: next },
      replace: false,
    })
  }

  async function handleTestPersonaAuth(persona: PublicPersona) {
    setPersonaTests(prev => ({
      ...prev,
      [persona.id]: {
        status: 'testing',
        message: persona.authKind === 'login' ? 'Signing in and checking access…' : 'Checking access…',
      },
    }))
    try {
      const res = await testPersonaAuthAction({
        data: { projectId: project.id, personaId: persona.id },
      })
      setPersonaTests(prev => ({
        ...prev,
        [persona.id]: {
          status: res.ok ? 'ok' : 'warn',
          message: `HTTP ${res.status} (${res.durationMs}ms) · ${res.authHint}`,
        },
      }))
    } catch (err) {
      setPersonaTests(prev => ({
        ...prev,
        [persona.id]: {
          status: 'error',
          message: err instanceof Error ? err.message : 'Sign-in check failed.',
        },
      }))
    }
  }

  const allowlistCount = (project.sandboxWriteAllowlist ?? []).length
  const tabCounts: Partial<Record<ProjectTabId, number>> = {
    overview: runs.length,
    inventory: assets.length,
    personas: personas.length,
    sources: specs.length,
    ...(allowlistCount > 0 ? { guardrails: allowlistCount } : {}),
  }

  return <main className="pw">
    <header className="pw-hdr">
      <div className="pw-hdr-top">
        <Link className="pw-crumb" to="/">Projects</Link>
        <span className="pw-crumb-sep" aria-hidden="true">/</span>
        <h1 className="pw-title">{project.name}</h1>
        {project.environment === 'local-lab' && <span className="pw-tag warn">Local Lab</span>}
        <span className="pw-hdr-meta mono" title={project.seeds.join(', ')}>
          {project.seeds.map(safeHost).join(', ')}
        </span>
        <div className="pw-hdr-actions">
          <button type="button" className="pw-btn primary" onClick={() => setNewRunOpen(true)}>
            New run
          </button>
          <DropdownMenu>
            <DropdownMenuTrigger className="pw-btn ghost pw-hdr-more" aria-label="Project actions">
              <Icon name="dots" size={15} />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="pw-menu">
              <DropdownMenuItem
                variant="destructive"
                className="pw-menu-item"
                onClick={() => {
                  setDeleteProjectError('')
                  setDeleteProjectOpen(true)
                }}
              >
                <Icon name="trash" size={13} />
                Delete project
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>

    <div className="pw-toolbar">
      <nav className="pw-tabs" role="tablist" aria-label="Project sections">
        {PROJECT_TABS.map(tab => {
          const isActive = activeTab === tab.id
          const count = tabCounts[tab.id]
          return <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            className={`pw-tab${isActive ? ' on' : ''}`}
            onClick={() => selectTab(tab.id)}
          >
            <span>{tab.label}</span>
            {typeof count === 'number' && <span className="ct num">{count}</span>}
          </button>
        })}
      </nav>
    </div>

    <div className="pw-body">
      {activeTab === 'overview' && (
        <ProjectOverviewTab
          data={data}
          onSelectTab={selectTab}
        />
      )}
      {activeTab === 'inventory' && <ProjectInventoryTab data={data} />}
      {activeTab === 'personas' && (
        <ProjectPersonasTab
          data={data}
          personaTests={personaTests}
          onTestPersona={persona => void handleTestPersonaAuth(persona)}
          onPersonaCreated={created => {
            setSelectedPersonaIds(prev => prev.includes(created.id) ? prev : [...prev, created.id])
          }}
        />
      )}
      {activeTab === 'sources' && <ProjectSourcesTab data={data} />}
      {activeTab === 'guardrails' && <ProjectGuardrailsTab data={data} />}
    </div>

    <ProjectNewRunSheet
      open={newRunOpen}
      onClose={() => setNewRunOpen(false)}
      data={data}
      selectedPersonaIds={selectedPersonaIds}
      setSelectedPersonaIds={setSelectedPersonaIds}
      personaTests={personaTests}
      onTestPersona={persona => void handleTestPersonaAuth(persona)}
    />

    {deleteProjectOpen && (
      <div
        className="pw-overlay"
        onMouseDown={e => {
          if (e.target === e.currentTarget && !deletingProject) {
            setDeleteProjectOpen(false)
            setDeleteProjectError('')
          }
        }}
      >
        <div
          className="pw-modal"
          style={{ width: 460 }}
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="pw-del-project-title"
        >
          <div className="pw-modal-hdr">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <Icon name="trash" size={15} style={{ color: 'var(--pw-bad)' }} />
              <span id="pw-del-project-title">Delete project</span>
            </span>
            <button
              type="button"
              className="pw-btn ghost"
              style={{ padding: '0 6px' }}
              disabled={deletingProject}
              onClick={() => { setDeleteProjectOpen(false); setDeleteProjectError('') }}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </button>
          </div>
          <div className="pw-modal-body">
            <p className="dim" style={{ margin: 0, fontSize: 12.5 }}>
              Permanently delete <strong style={{ color: 'var(--pw-fg)' }}>{project.name}</strong> and all associated data, local synced repos, and test account credentials. This cannot be undone.
            </p>
            <div className="pw-confirm-summary">
              <div className="pw-confirm-goal">{project.name}</div>
              <div className="pw-confirm-meta num">
                <span className="pw-tag solid">
                  {runs.length} {runs.length === 1 ? 'run' : 'runs'}
                </span>
                <span className="pw-tag solid">
                  {totalFindings} {totalFindings === 1 ? 'finding' : 'findings'}
                  {totalConfirmed > 0 ? ` (${totalConfirmed} confirmed)` : ''}
                </span>
                {personas.length > 0 && (
                  <span className="pw-tag solid">
                    {personas.length} {personas.length === 1 ? 'test account' : 'test accounts'}
                  </span>
                )}
                {specs.length > 0 && (
                  <span className="pw-tag solid">
                    {specs.length} {specs.length === 1 ? 'spec' : 'specs'}
                  </span>
                )}
              </div>
            </div>
            {activeRunsCount > 0 && (
              <div className="pw-confirm-warn" role="status">
                <Icon name="alert" size={14} />
                <span>
                  {activeRunsCount} {activeRunsCount === 1 ? 'run is' : 'runs are'} currently active. Confirming will stop active runs before deleting the project.
                </span>
              </div>
            )}
            {deleteProjectError && <p className="err" role="alert" style={{ margin: 0 }}>{deleteProjectError}</p>}
          </div>
          <div className="pw-modal-ftr">
            <button
              type="button"
              className="pw-btn ghost"
              disabled={deletingProject}
              onClick={() => { setDeleteProjectOpen(false); setDeleteProjectError('') }}
            >
              Cancel
            </button>
            <button
              type="button"
              className="pw-btn danger-solid"
              disabled={deletingProject}
              onClick={() => void confirmDeleteProject()}
            >
              <Icon name="trash" size={13} />
              {deletingProject
                ? (activeRunsCount > 0 ? 'Stopping & deleting…' : 'Deleting…')
                : (activeRunsCount > 0 ? 'Stop runs & delete project' : 'Delete project')}
            </button>
          </div>
        </div>
      </div>
    )}
  </main>
}
