import { createFileRoute, Link, useLocation, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { projectData, removeProject, removeProjectAsset, testPersonaAuthAction } from '../actions.ts'
import { Icon } from '../components/run/icons.tsx'
import { ProjectEditModal } from '../components/project/ProjectEditModal.tsx'
import { ProjectGuardrailsTab } from '../components/project/ProjectGuardrailsTab.tsx'
import { ProjectInventoryTab } from '../components/project/ProjectInventoryTab.tsx'
import { ProjectNewRunSheet } from '../components/project/ProjectNewRunSheet.tsx'
import { ProjectOverviewTab } from '../components/project/ProjectOverviewTab.tsx'
import { ProjectPersonasTab } from '../components/project/ProjectPersonasTab.tsx'
import { ProjectSourcesTab } from '../components/project/ProjectSourcesTab.tsx'
import type { PersonaTestState, ProjectLoaderData, ProjectTabId } from '../components/project/types.ts'
import { isProjectTab, PROJECT_TABS, safeHost } from '../components/project/types.ts'
import { Badge } from '../components/ui/badge.tsx'
import { Button, buttonVariants } from '../components/ui/button.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog.tsx'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu.tsx'
import { type PublicPersona } from '../domain.ts'
import { cn } from '../lib/cn.ts'

type ProjectSearch = {
  tab?: ProjectTabId
  newRun?: string
  syncError?: string
}

export const Route = createFileRoute('/projects/$projectId')({
  validateSearch: (search: Record<string, unknown>): ProjectSearch => ({
    ...(isProjectTab(search.tab) ? { tab: search.tab } : {}),
    ...(search.newRun === '1' || search.newRun === 1 || search.newRun === true ? { newRun: '1' } : {}),
    ...(typeof search.syncError === 'string' && search.syncError.trim().length > 0
      ? { syncError: search.syncError.trim().slice(0, 300) }
      : {}),
  }),
  loader: ({ params }) => projectData({ data: { projectId: params.projectId } }),
  component: ProjectPage,
})

function ProjectPage() {
  const data = Route.useLoaderData()
  return <ProjectPageContent key={data.project.id} data={data} />
}

function ProjectPageContent({ data }: { data: ProjectLoaderData }) {
  const { project, assets, personas, specs, runs } = data
  const search = Route.useSearch()
  const location = useLocation()
  const navigate = useNavigate()
  const router = useRouter()

  const activeTab: ProjectTabId = search.tab ?? 'overview'
  const hashWantsNewRun = location.hash === 'new-run' || location.hash === '#new-run'
  const [newRunOpen, setNewRunOpen] = useState(() => Boolean(search.newRun) || hashWantsNewRun)
  const [syncErrorBanner, setSyncErrorBanner] = useState(() => search.syncError ?? '')
  const [editProjectOpen, setEditProjectOpen] = useState(false)
  const [deleteProjectOpen, setDeleteProjectOpen] = useState(false)
  const [deletingProject, setDeletingProject] = useState(false)
  const [deleteProjectError, setDeleteProjectError] = useState('')
  const [selectedPersonaIds, setSelectedPersonaIds] = useState<string[]>(() => personas.map(p => p.id))
  const [personaTests, setPersonaTests] = useState<Record<string, PersonaTestState>>({})

  const validPersonaIds = useMemo(() => new Set(personas.map(p => p.id)), [personas])
  const activeSelectedPersonaIds = useMemo(
    () => selectedPersonaIds.filter(pid => validPersonaIds.has(pid)),
    [selectedPersonaIds, validPersonaIds],
  )

  useEffect(() => {
    setSelectedPersonaIds(prev => {
      const filtered = prev.filter(pid => validPersonaIds.has(pid))
      return filtered.length === prev.length ? prev : filtered
    })
  }, [validPersonaIds])

  useEffect(() => {
    if (!search.syncError) return
    setSyncErrorBanner(search.syncError)
    void navigate({
      to: '/projects/$projectId',
      params: { projectId: project.id },
      search: {
        ...(search.tab ? { tab: search.tab } : {}),
        ...(search.newRun ? { newRun: search.newRun } : {}),
      },
      replace: true,
    })
  }, [search.syncError, search.tab, search.newRun, project.id, navigate])

  const activeRunsCount = runs.filter(r => r.isActive || r.status === 'running').length
  const totalFindings = runs.reduce((sum, r) => sum + r.findingCount, 0)
  const totalConfirmed = runs.reduce((sum, r) => sum + r.confirmedCount, 0)

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

  return (
    <main className="flex min-h-full flex-col bg-panel font-sans text-base text-fg antialiased">
      <header className="sticky top-0 z-20 border-b border-line bg-panel px-3.5 md:px-[22px]">
        <div className="flex h-11 min-w-0 items-center gap-2">
          <Link className="whitespace-nowrap text-[13px] text-fg-subtle transition-colors hover:text-fg" to="/">
            Projects
          </Link>
          <span className="text-fg-faint" aria-hidden="true">/</span>
          <h1 className="min-w-0 truncate text-[13.5px] font-semibold tracking-[-0.005em] text-fg">
            {project.name}
          </h1>
          {project.environment === 'local-lab' && <Badge variant="warn">Local Lab</Badge>}
          <span
            className="min-w-0 flex-1 truncate font-mono text-[12px] text-fg-subtle"
            title={project.seeds.join(', ')}
          >
            {project.seeds.map(safeHost).join(', ')}
          </span>
          <div className="ml-auto flex flex-none items-center gap-1.5">
            <Button variant="default" onClick={() => setNewRunOpen(true)}>
              New run
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger
                className={cn(
                  buttonVariants({ variant: 'ghost', size: 'icon' }),
                  'size-[26px] border-0 bg-transparent shadow-none hover:bg-hover hover:text-fg',
                )}
                aria-label="Project actions"
              >
                <Icon name="dots" size={15} />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-[168px]">
                <DropdownMenuItem
                  className="justify-start gap-2"
                  onClick={() => setEditProjectOpen(true)}
                >
                  <Icon name="edit" size={13} />
                  Edit project
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  className="justify-start gap-2"
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

      <div className="flex h-10 items-center gap-1.5 overflow-x-auto border-b border-line bg-panel px-3.5 [scrollbar-width:none] md:px-[22px]">
        <nav className="flex items-center gap-0.5" role="tablist" aria-label="Project sections">
          {PROJECT_TABS.map(tab => {
            const isActive = activeTab === tab.id
            const count = tabCounts[tab.id]
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                className={cn(
                  'inline-flex h-[26px] cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 px-[9px] text-[12.5px] font-medium shadow-none transition-colors',
                  isActive
                    ? 'bg-press text-fg hover:bg-press'
                    : 'bg-transparent text-fg-muted hover:bg-hover hover:text-fg',
                )}
                onClick={() => selectTab(tab.id)}
              >
                <span>{tab.label}</span>
                {typeof count === 'number' && (
                  <span className="text-[11.5px] font-normal tabular-nums text-fg-subtle">{count}</span>
                )}
              </button>
            )
          })}
        </nav>
      </div>

      {syncErrorBanner && (
        <div
          role="alert"
          className="flex flex-wrap items-center gap-2.5 border-b border-warn-line bg-warn-soft px-3.5 py-2 text-[12.5px] text-fg md:px-[22px]"
        >
          <Icon name="alert" size={14} className="flex-none text-warn" />
          <span className="min-w-0 flex-1">
            <strong className="font-medium">Initial GitHub repository sync failed:</strong>{' '}
            <span className="text-fg-muted">{syncErrorBanner}</span>
          </span>
          <div className="flex flex-none items-center gap-1.5">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setSyncErrorBanner('')
                selectTab('sources')
              }}
            >
              Retry in Source &amp; Specs
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => setSyncErrorBanner('')}
            >
              Dismiss
            </Button>
          </div>
        </div>
      )}

      <div className="w-full max-w-[1020px] flex-1 px-3.5 pb-12 pt-4 md:px-6 md:pb-16 md:pt-[22px]">
        {activeTab === 'overview' && (
          <ProjectOverviewTab
            key={project.id}
            data={data}
            onSelectTab={selectTab}
          />
        )}
        {activeTab === 'inventory' && (
          <ProjectInventoryTab
            key={project.id}
            data={data}
            onDeleteAsset={assetId =>
              removeProjectAsset({ data: { requestId: crypto.randomUUID(), projectId: project.id, assetId } })
            }
          />
        )}
        {activeTab === 'personas' && (
          <ProjectPersonasTab
            key={project.id}
            data={data}
            personaTests={personaTests}
            onTestPersona={persona => void handleTestPersonaAuth(persona)}
            onPersonaCreated={created => {
              setSelectedPersonaIds(prev => prev.includes(created.id) ? prev : [...prev, created.id])
            }}
            onPersonaUpdated={updated => {
              setPersonaTests(prev => {
                if (!(updated.id in prev)) return prev
                const next = { ...prev }
                delete next[updated.id]
                return next
              })
            }}
          />
        )}
        {activeTab === 'sources' && <ProjectSourcesTab key={project.id} data={data} />}
        {activeTab === 'guardrails' && <ProjectGuardrailsTab key={project.id} data={data} />}
      </div>

      <ProjectNewRunSheet
        key={project.id}
        open={newRunOpen}
        onClose={() => setNewRunOpen(false)}
        data={data}
        selectedPersonaIds={activeSelectedPersonaIds}
        setSelectedPersonaIds={setSelectedPersonaIds}
        personaTests={personaTests}
        onTestPersona={persona => void handleTestPersonaAuth(persona)}
      />

      <ProjectEditModal
        open={editProjectOpen}
        project={project}
        onClose={() => setEditProjectOpen(false)}
      />

      <Dialog
        open={deleteProjectOpen}
        closeOnEscape={!deletingProject}
        onOpenChange={nextOpen => {
          if (!nextOpen && !deletingProject) {
            setDeleteProjectOpen(false)
            setDeleteProjectError('')
          }
        }}
      >
        <DialogContent
          role="alertdialog"
          className="flex max-h-[calc(100vh-56px)] max-w-[460px] flex-col overflow-hidden p-0"
        >
          <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
            <DialogTitle className="inline-flex items-center gap-2 text-[13px] font-semibold text-fg">
              <Icon name="trash" size={15} className="text-danger" />
              <span>Delete project</span>
            </DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px]"
              disabled={deletingProject}
              onClick={() => {
                setDeleteProjectOpen(false)
                setDeleteProjectError('')
              }}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </Button>
          </DialogHeader>
          <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
            <DialogDescription className="text-[12.5px] leading-5 text-fg-muted">
              Permanently delete <strong className="font-semibold text-fg">{project.name}</strong> and all associated data, local synced repos, and test account credentials. This cannot be undone.
            </DialogDescription>
            <div className="flex flex-col gap-2 rounded-lg border border-line bg-sunk px-3 py-2.5">
              <div className="line-clamp-2 text-[13px] font-medium text-fg">{project.name}</div>
              <div className="flex flex-wrap items-center gap-1.5 tabular-nums">
                <Badge variant="neutral" className="bg-panel">
                  {runs.length} {runs.length === 1 ? 'run' : 'runs'}
                </Badge>
                <Badge variant="neutral" className="bg-panel">
                  {totalFindings} {totalFindings === 1 ? 'finding' : 'findings'}
                  {totalConfirmed > 0 ? ` (${totalConfirmed} confirmed)` : ''}
                </Badge>
                {personas.length > 0 && (
                  <Badge variant="neutral" className="bg-panel">
                    {personas.length} {personas.length === 1 ? 'test account' : 'test accounts'}
                  </Badge>
                )}
                {specs.length > 0 && (
                  <Badge variant="neutral" className="bg-panel">
                    {specs.length} {specs.length === 1 ? 'spec' : 'specs'}
                  </Badge>
                )}
              </div>
            </div>
            {activeRunsCount > 0 && (
              <div
                className="flex items-start gap-2 rounded-lg border border-warn-line bg-warn-soft px-3 py-2 text-[12px] leading-[17px] text-fg"
                role="status"
              >
                <Icon name="alert" size={14} className="mt-0.5 flex-none text-warn" />
                <span>
                  {activeRunsCount} {activeRunsCount === 1 ? 'run is' : 'runs are'} currently active. Confirming will stop active runs before deleting the project.
                </span>
              </div>
            )}
            {deleteProjectError && (
              <p className="m-0 text-[12px] text-danger" role="alert">
                {deleteProjectError}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={deletingProject}
              onClick={() => {
                setDeleteProjectOpen(false)
                setDeleteProjectError('')
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="default"
              className="data-[slot=button]:bg-danger data-[slot=button]:text-white data-[slot=button]:hover:bg-danger hover:brightness-[1.08]"
              disabled={deletingProject}
              onClick={() => void confirmDeleteProject()}
            >
              <Icon name="trash" size={13} />
              {deletingProject
                ? (activeRunsCount > 0 ? 'Stopping & deleting…' : 'Deleting…')
                : (activeRunsCount > 0 ? 'Stop runs & delete project' : 'Delete project')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  )
}
