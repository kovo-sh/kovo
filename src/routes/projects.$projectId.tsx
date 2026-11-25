import { createFileRoute, Link, useLocation, useNavigate } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { projectData, testPersonaAuthAction } from '../actions.ts'
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

  const activeTab: ProjectTabId = search.tab ?? 'overview'
  const hashWantsNewRun = location.hash === 'new-run' || location.hash === '#new-run'
  const [newRunOpen, setNewRunOpen] = useState(() => Boolean(search.newRun) || hashWantsNewRun)
  const [selectedPersonaIds, setSelectedPersonaIds] = useState<string[]>(() => personas.map(p => p.id))
  const [personaTests, setPersonaTests] = useState<Record<string, PersonaTestState>>({})

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
  const showHeaderNewRun = !(activeTab === 'overview' && runs.length === 0)

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
        {showHeaderNewRun && (
          <div className="pw-hdr-actions">
            <button type="button" className="pw-btn primary" onClick={() => setNewRunOpen(true)}>
              New run
            </button>
          </div>
        )}
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
          onOpenNewRun={() => setNewRunOpen(true)}
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
  </main>
}
