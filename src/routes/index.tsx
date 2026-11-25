import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { createProject, syncGithubRepositories, workspaceData } from '../actions.ts'
import { FormError, useAction } from '../components/common.tsx'
import {
  CreateProjectGithubBlock,
  type GithubPatStatusSummary,
} from '../components/project/CreateProjectGithubBlock.tsx'
import { host, plural } from '../components/run/format.ts'
import { StatusGlyph } from '../components/run/glyphs.tsx'
import { Icon } from '../components/run/icons.tsx'
import { PHASE_LABEL, runStatusLabel } from '../components/run/meta.ts'
import { formatFullDateTime, formatRelativeTime, useNow, useShell } from '../components/shell/AppShell.tsx'
import { Badge } from '../components/ui/badge.tsx'
import { Button, buttonVariants } from '../components/ui/button.tsx'
import { Card } from '../components/ui/card.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Dialog, DialogContent, DialogTitle } from '../components/ui/dialog.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../components/ui/disclosure.tsx'
import { Input, NativeSelect, Textarea } from '../components/ui/input.tsx'
import { cn } from '../lib/cn.ts'

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
  open = true,
  canCancel,
  githubPatStatus,
  onClose,
}: {
  isModal: boolean
  open?: boolean
  canCancel: boolean
  githubPatStatus: GithubPatStatusSummary
  onClose: () => void
}) {
  const navigate = useNavigate()
  const [environment, setEnvironment] = useState<'public' | 'local-lab'>('public')
  const [includeSubdomains, setIncludeSubdomains] = useState(true)
  const [selectedRepos, setSelectedRepos] = useState<string[]>([])
  const [submitStatus, setSubmitStatus] = useState('')
  const action = useAction()

  useEffect(() => {
    if (!isModal || open) return
    setEnvironment('public')
    setIncludeSubdomains(true)
    setSelectedRepos([])
    setSubmitStatus('')
  }, [isModal, open])

  const formContent = (
    <form
      className={cn(isModal && 'flex min-h-0 flex-1 flex-col overflow-hidden')}
      onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        const nextEnv = environment
        const reposToSync = selectedRepos.slice(0, 20)
        setSubmitStatus('Creating project…')
        void action.submit(async () => {
          const project = await createProject({ data: {
            requestId: crypto.randomUUID(),
            name: String(form.get('name')),
            seeds: String(form.get('seeds')).split(/[\s,]+/).filter(Boolean),
            environment: nextEnv,
            includeSubdomains: nextEnv === 'public' ? includeSubdomains : false,
          } })
          if (reposToSync.length > 0) {
            setSubmitStatus(`Syncing ${reposToSync.length} ${reposToSync.length === 1 ? 'repo' : 'repos'}…`)
            try {
              await syncGithubRepositories({ data: { projectId: project.id, repos: reposToSync } })
            } catch {
              // Non-blocking: still open the newly created project cleanly so the user can retry sync if needed.
            }
          }
          return project
        }, async project => {
          setSubmitStatus('')
          setEnvironment('public')
          setIncludeSubdomains(true)
          setSelectedRepos([])
          onClose()
          await navigate({ to: '/projects/$projectId', params: { projectId: project.id } })
        }).finally(() => setSubmitStatus(''))
      }}
    >
      <div className="flex flex-none items-center gap-2.5 border-b border-line px-4 py-[11px] font-medium text-fg">
        <Icon name="plus" />
        {isModal ? (
          <DialogTitle className="text-[13px] font-medium tracking-normal text-fg">New project</DialogTitle>
        ) : (
          <span>New project</span>
        )}
        {isModal && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="ml-auto text-fg-subtle hover:text-fg"
            disabled={action.pending}
            onClick={onClose}
            aria-label="Close modal"
          >
            <Icon name="close" />
          </Button>
        )}
      </div>

      <div
        className={cn(
          'flex flex-col gap-4 px-5 py-[18px]',
          isModal && 'min-h-0 flex-1 overflow-y-auto',
        )}
      >
        <label className="grid gap-1.5 text-[12.5px] font-medium text-fg">
          <span>Project name</span>
          <Input name="name" placeholder="Acme Web" required maxLength={160} autoFocus={isModal} />
        </label>

        <div className="grid gap-[9px]">
          <label className="grid gap-1.5 text-[12.5px] font-medium text-fg">
            <span>Sites</span>
            <Textarea
              name="seeds"
              rows={2}
              placeholder={'https://app.example.com'}
              required
            />
          </label>

          <label
            className={cn(
              'flex select-none items-center gap-2 text-[12.5px] font-[450] text-fg-muted',
              environment !== 'public' ? 'cursor-default opacity-50' : 'cursor-pointer',
            )}
          >
            <Checkbox
              name="includeSubdomains"
              checked={environment === 'public' ? includeSubdomains : false}
              disabled={environment !== 'public' || action.pending}
              aria-label="Include subdomains"
              onCheckedChange={checked => setIncludeSubdomains(Boolean(checked))}
            />
            <span>Include subdomains</span>
            <code className="rounded-[5px] border border-line-2 bg-sunk px-1.5 py-px font-mono text-[11px] text-fg-subtle">
              *.domain
            </code>
          </label>
        </div>

        <CreateProjectGithubBlock
          initialPatStatus={githubPatStatus}
          selectedRepos={selectedRepos}
          onChangeSelectedRepos={setSelectedRepos}
          disabled={action.pending}
        />

        <Disclosure className="border-t border-line pt-2.5">
          <DisclosureTrigger className="h-auto w-auto rounded-sm bg-transparent px-0 py-0.5 text-[12px] font-medium text-fg-subtle shadow-none hover:bg-transparent hover:text-fg-muted">
            <span>Advanced configuration</span>
            {environment === 'local-lab' && <Badge variant="warn">Local Lab</Badge>}
          </DisclosureTrigger>
          <DisclosureContent className="mt-2.5 grid gap-2.5 rounded-lg border border-line bg-sunk px-3 py-[11px]">
            <label className="grid gap-1.5 text-[12.5px] font-medium text-fg">
              <span>Target environment</span>
              <NativeSelect
                name="environment"
                value={environment}
                onChange={e => {
                  const next = e.target.value === 'local-lab' ? 'local-lab' : 'public'
                  setEnvironment(next)
                  if (next !== 'public') setIncludeSubdomains(false)
                  else setIncludeSubdomains(true)
                }}
              >
                <option value="public">Public website</option>
                <option value="local-lab">Local lab (localhost / private staging)</option>
              </NativeSelect>
            </label>
          </DisclosureContent>
        </Disclosure>

        <FormError error={action.error} />
      </div>

      <div className="flex flex-none items-center justify-end gap-2 border-t border-line bg-sunk px-4 py-2.5">
        {submitStatus && <span className="mr-auto text-[12px] text-fg-subtle">{submitStatus}</span>}
        {canCancel && (
          <Button type="button" variant="outline" disabled={action.pending} onClick={onClose}>
            Cancel
          </Button>
        )}
        <Button type="submit" variant="default" disabled={action.pending}>
          {submitStatus || (selectedRepos.length > 0 ? `Create & sync (${selectedRepos.length})` : 'Create project')}
        </Button>
      </div>
    </form>
  )

  if (!isModal) {
    return (
      <Card className="overflow-hidden border-line bg-panel">
        {formContent}
      </Card>
    )
  }

  return (
    <Dialog
      open={open}
      closeOnEscape={!action.pending}
      onOpenChange={(nextOpen, details) => {
        if (!nextOpen) {
          if (action.pending) {
            details.cancel()
            return
          }
          onClose()
        }
      }}
    >
      <DialogContent
        aria-label="New project"
        className="flex max-h-[calc(100vh-56px)] max-w-[540px] flex-col overflow-hidden rounded-2xl border-line-2 bg-panel p-0 [&_svg]:block [&_svg]:flex-none"
      >
        {formContent}
      </DialogContent>
    </Dialog>
  )
}

function formatRunPhase(status: string, phase: string): string {
  if (status === 'complete') return 'Complete'
  if (status === 'failed' || status === 'paused' || status === 'budget_paused' || status === 'waiting_approval') {
    return runStatusLabel(status)
  }
  return PHASE_LABEL[phase] ?? runStatusLabel(status)
}

function Workspace() {
  const { workspace, projects, hasModel, poolHealth, githubPatStatus } = Route.useLoaderData()
  const search = Route.useSearch()
  const navigate = useNavigate()
  const shell = useShell()
  const now = useNow()
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

  return <main className="flex min-h-0 flex-1 flex-col">
    <header className="sticky top-0 z-10 flex h-11 min-w-0 flex-none items-center gap-2.5 border-b border-line bg-panel px-[18px]">
      <h1 className="m-0 whitespace-nowrap text-[13.5px] font-semibold tracking-[-0.01em] text-fg">Projects</h1>
      <span className="text-[12.5px] font-normal tabular-nums text-fg-subtle">{projects.length}</span>
      <span className="min-w-2 flex-1" />
      <div className="flex flex-none items-center gap-1.5">
        {projects.length > 0 && (
          <div className="flex h-[26px] w-[140px] flex-none items-center gap-1.5 rounded-control px-2 text-fg-subtle transition-[width,background-color] duration-[var(--d2)] ease-kovo hover:bg-hover focus-within:w-[210px] focus-within:bg-sunk focus-within:text-fg-muted focus-within:shadow-hairline">
            <Icon name="search" />
            <input
              type="search"
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Filter…"
              aria-label="Filter projects"
              className="h-full min-w-0 flex-1 rounded-none border-0 bg-transparent p-0 text-[12.5px] text-fg shadow-none outline-none placeholder:text-fg-subtle focus:shadow-none focus:outline-none"
            />
            {filter && (
              <button
                type="button"
                className="inline-flex h-auto cursor-pointer items-center justify-center rounded-sm border-0 bg-transparent p-0.5 text-fg-subtle shadow-none hover:bg-hover hover:text-fg"
                onClick={() => setFilter('')}
                aria-label="Clear filter"
              >
                <Icon name="x" size={12} />
              </button>
            )}
          </div>
        )}
        {projects.length > 0 && (
          <Button variant="default" onClick={() => setModalOpen(true)}>
            New project
          </Button>
        )}
      </div>
    </header>

    {!hasModel && (
      <div
        className="flex min-h-10 flex-none items-center gap-2.5 border-b border-warn-line bg-warn-soft py-2 pl-[18px] pr-3.5 text-[12.5px] text-fg-muted"
        role="status"
      >
        <Icon name="alert" className="flex-none text-warn" />
        <span className="min-w-0 flex-1">
          <b className="font-medium text-fg">Connect an AI model to run assessments.</b> Add an OpenRouter or compatible model profile in Settings.
        </span>
        <Link className={buttonVariants({ variant: 'outline' })} to="/settings" search={{}}>
          Set up model
          <Icon name="arrowR" />
        </Link>
      </div>
    )}

    {hasModel && poolHealth === 'degraded' && (
      <div
        className="flex min-h-10 flex-none items-center gap-2.5 border-b border-warn-line bg-warn-soft py-2 pl-[18px] pr-3.5 text-[12.5px] text-fg-muted"
        role="status"
      >
        <Icon name="alert" className="flex-none text-warn" />
        <span className="min-w-0 flex-1">
          <b className="font-medium text-fg">Some model profiles are temporarily unavailable.</b> One or more enabled models are cooling down after recent errors.
        </span>
        <Link className={buttonVariants({ variant: 'outline' })} to="/settings" search={{}}>
          Model settings
          <Icon name="arrowR" />
        </Link>
      </div>
    )}

    {projects.length === 0 ? (
      <div className="flex-1 overflow-auto px-8 pb-14 pt-10">
        <div className="mx-auto max-w-[620px]">
          <div className="inline-flex items-center gap-2 text-[12px] font-medium text-fg-subtle">
            {workspace.name}
          </div>
          <h2 className="mb-1.5 mt-2 text-[22px] font-semibold leading-[29px] tracking-[-0.02em] text-fg">
            Start your first project
          </h2>
          <p className="mb-5 max-w-[520px] text-[13px] leading-5 text-fg-muted">
            Register the hosts you own or have written authorization to test. Kovo Hunter verifies scope before dispatching any live requests.
          </p>
          <CreateProjectSheet
            isModal={false}
            canCancel={false}
            githubPatStatus={githubPatStatus}
            onClose={() => setModalOpen(false)}
          />
        </div>
      </div>
    ) : (
      <div className="min-h-0 flex-1 overflow-auto">
        <div
          className="sticky top-0 z-[2] grid h-8 grid-cols-[minmax(200px,1.45fr)_minmax(160px,1.15fr)_minmax(170px,1fr)_150px] items-center gap-3 border-b border-line bg-sunk px-[18px] text-[11.5px] font-medium text-fg-subtle max-[960px]:grid-cols-[minmax(170px,1.3fr)_minmax(130px,1fr)_140px]"
          role="row"
        >
          <span>Project</span>
          <span className="max-[960px]:hidden">Seed host(s)</span>
          <span>Latest run</span>
          <span className="text-right">Runs / Findings</span>
        </div>

        {visibleProjects.length === 0 ? (
          <div className="px-[18px] py-7 text-center text-[12.5px] text-fg-subtle">
            No projects match “{filter}”.
          </div>
        ) : visibleProjects.map(project => {
          const seedHosts = project.seeds.map(host)
          const hostSummary = seedHosts.slice(0, 2).join(', ')
          const extraHosts = Math.max(0, project.hostCount - Math.min(2, seedHosts.length))
          const latest = project.latestRun
          return (
            <div
              key={project.id}
              className="group/row relative grid min-h-11 cursor-pointer grid-cols-[minmax(200px,1.45fr)_minmax(160px,1.15fr)_minmax(170px,1fr)_150px] items-center gap-3 border-b border-line px-[18px] py-1.5 transition-colors duration-[var(--d1)] hover:bg-hover max-[960px]:grid-cols-[minmax(170px,1.3fr)_minmax(130px,1fr)_140px]"
              onClick={e => {
                if ((e.target as HTMLElement).closest('a, button')) return
                void navigate({ to: '/projects/$projectId', params: { projectId: project.id } })
              }}
            >
              <div className="flex min-w-0 items-center gap-2">
                <Link
                  to="/projects/$projectId"
                  params={{ projectId: project.id }}
                  className="min-w-0 truncate font-medium text-fg decoration-line-strong underline-offset-2 hover:underline"
                  title={project.name}
                >
                  {project.name}
                </Link>
                {project.environment === 'local-lab' && <Badge variant="warn">Local Lab</Badge>}
              </div>

              <div className="flex min-w-0 items-center gap-1.5 text-fg-muted max-[960px]:hidden" title={seedHosts.join(', ')}>
                <span className="min-w-0 truncate font-mono text-[12px]">{hostSummary || '—'}</span>
                {extraHosts > 0 && <Badge className="bg-sunk tabular-nums">+{extraHosts}</Badge>}
              </div>

              <div className="flex min-w-0 items-center gap-[7px] text-[12.5px] text-fg-muted">
                {latest ? (() => {
                  const relTime = formatRelativeTime(latest.startedAt, { compact: false, now })
                  const fullTime = formatFullDateTime(latest.startedAt)
                  return (
                    <Link
                      to="/runs/$runId"
                      params={{ runId: latest.id }}
                      search={{}}
                      className="inline-flex max-w-full min-w-0 items-center gap-[7px] text-fg-muted hover:text-fg"
                      title={`${latest.goal} (${fullTime})`}
                    >
                      <span className="inline-flex size-3.5 flex-none items-center justify-center">
                        <StatusGlyph status={latest.status} />
                      </span>
                      <span className="truncate">{formatRunPhase(latest.status, latest.phase)}</span>
                      <time
                        className="flex-none whitespace-nowrap text-[11.5px] tabular-nums text-fg-subtle"
                        dateTime={new Date(latest.startedAt).toISOString()}
                        title={fullTime}
                        suppressHydrationWarning
                      >
                        {relTime}
                      </time>
                    </Link>
                  )
                })() : <span className="text-fg-subtle">No runs yet</span>}
              </div>

              <div className="flex items-center justify-end gap-2 whitespace-nowrap text-[12px] tabular-nums text-fg-muted transition-opacity duration-[var(--d1)] group-hover/row:opacity-0 group-focus-within/row:opacity-0">
                <span className={project.runCount > 0 ? '' : 'text-fg-subtle'}>
                  {plural(project.runCount, 'run')}
                </span>
                <span className="text-fg-subtle">·</span>
                <span className={latest && latest.confirmedCount > 0 ? 'font-medium text-fg' : 'text-fg-subtle'}>
                  {latest ? `${latest.confirmedCount} confirmed` : '—'}
                </span>
              </div>

              <div className="pointer-events-none absolute right-3.5 top-1/2 flex -translate-y-1/2 translate-x-1 items-center gap-[5px] bg-[linear-gradient(90deg,transparent,var(--row-h)_22px)] pl-7 opacity-0 transition-[opacity,transform] duration-[var(--d2)] ease-kovo group-hover/row:pointer-events-auto group-hover/row:translate-x-0 group-hover/row:opacity-100 group-focus-within/row:pointer-events-auto group-focus-within/row:translate-x-0 group-focus-within/row:opacity-100">
                <Link
                  to="/projects/$projectId"
                  params={{ projectId: project.id }}
                  className={buttonVariants({ variant: 'outline' })}
                >
                  Open
                </Link>
                <Link
                  to="/projects/$projectId"
                  params={{ projectId: project.id }}
                  search={{ newRun: '1' }}
                  className={buttonVariants({ variant: 'default' })}
                >
                  New run
                </Link>
              </div>
            </div>
          )
        })}
      </div>
    )}

    {projects.length > 0 && (
      <CreateProjectSheet
        isModal={true}
        open={modalOpen}
        canCancel={true}
        githubPatStatus={githubPatStatus}
        onClose={() => setModalOpen(false)}
      />
    )}
  </main>
}
