import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
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

export const Route = createFileRoute('/projects/$projectId')({
  validateSearch: (search: Record<string, unknown>): { tab?: ProjectTabId } => ({
    ...(isProjectTab(search.tab) ? { tab: search.tab } : {}),
  }),
  loader: ({ params }) => projectData({ data: { projectId: params.projectId } }),
  component: ProjectPage,
})

function ProjectPage() {
  const data = Route.useLoaderData()
  const { project, assets, personas, specs, runs } = data
  const search = Route.useSearch()
  const navigate = useNavigate()

  const activeTab: ProjectTabId = search.tab ?? 'overview'
  const [newRunOpen, setNewRunOpen] = useState(false)
  const [selectedPersonaIds, setSelectedPersonaIds] = useState<string[]>(() => personas.map(p => p.id))
  const [personaTests, setPersonaTests] = useState<Record<string, PersonaTestState>>({})

  function selectTab(next: ProjectTabId) {
    void navigate({
      to: '/projects/$projectId',
      params: { projectId: project.id },
      search: next === 'overview' ? {} : { tab: next },
      replace: true,
    })
  }

  async function handleTestPersonaAuth(persona: PublicPersona) {
    setPersonaTests(prev => ({
      ...prev,
      [persona.id]: {
        status: 'testing',
        message: persona.authKind === 'login' ? 'Logging in & testing GET…' : 'Testing safe GET…',
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
          message: err instanceof Error ? err.message : 'Auth check failed.',
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
        {project.environment === 'local-lab'
          ? <span className="pw-tag warn">Local Lab</span>
          : <span className="pw-tag solid">Public HTTPS</span>}
        <span className="pw-hdr-meta mono" title={project.seeds.join(', ')}>
          {project.seeds.map(safeHost).join(', ')}
        </span>
        <div className="pw-hdr-actions">
          <button type="button" className="pw-btn primary" onClick={() => setNewRunOpen(true)}>
            New run
          </button>
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
