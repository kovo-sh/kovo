import { Link, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { createRun, removeRun } from '../../actions.ts'
import { getRunRerunPresetAction, listProjectRunLabelsAction } from '../../actions-run-controls.ts'
import type { ApprovalPolicy, CapabilityTier } from '../../domain.ts'
import { cn } from '../../lib/cn.ts'
import { assertNever, isRunDeleteBlocked, isRunInProgress } from '../../server/run-status.ts'
import type { RunActivity } from '../../server/run-status.ts'
import { fmtDur } from '../run/format.ts'
import { StatusGlyph } from '../run/glyphs.tsx'
import { Icon } from '../run/icons.tsx'
import { runStatusLabel } from '../run/meta.ts'
import { capabilityTierMeta, formatUsd, phaseNames } from '../run-state.ts'
import { formatFullDateTime, formatRelativeTime, useNow } from '../shell/AppShell.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { EmptyState } from '../ui/empty-state.tsx'
import { Input } from '../ui/input.tsx'
import type { ProjectLoaderData } from './types.ts'

export type RunStatusFilter = 'all' | 'running' | 'completed' | 'stopped' | 'failed'

export const RUN_STATUS_FILTERS: readonly { id: RunStatusFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'running', label: 'Running' },
  { id: 'completed', label: 'Completed' },
  { id: 'stopped', label: 'Stopped' },
  { id: 'failed', label: 'Failed' },
]

export type ProjectRunSummary = ProjectLoaderData['runs'][number]

export function matchesRunStatusFilter(
  run: Pick<ProjectRunSummary, 'status' | 'isActive'> & { activity?: RunActivity },
  filter: RunStatusFilter,
): boolean {
  const lifecycle = run.activity?.lifecycle ?? run.status
  switch (filter) {
    case 'all':
      return true
    case 'running':
      return Boolean(run.isActive) || isRunInProgress(run.activity ?? lifecycle)
    case 'completed':
      return lifecycle === 'complete'
    case 'stopped':
      return lifecycle === 'stopped'
    case 'failed':
      return lifecycle === 'failed'
    default:
      return assertNever(filter, 'Unhandled RunStatusFilter')
  }
}

export function scanModeBadgeInfo(
  run: { capabilityTier: CapabilityTier; approvalPolicy: ApprovalPolicy },
): { label: string; variant: 'neutral' | 'accent' | 'warn' } {
  if (run.capabilityTier === 0) {
    return { label: 'Offline Review', variant: 'neutral' }
  }
  if (run.capabilityTier === 3 && run.approvalPolicy === 'yolo') {
    return { label: 'Autonomous Scan', variant: 'warn' }
  }
  if (run.capabilityTier === 3) {
    return { label: 'Supervised Scan', variant: 'accent' }
  }
  return { label: 'Passive Scan', variant: 'neutral' }
}

export function filterProjectRuns<
  T extends Pick<ProjectRunSummary, 'id' | 'goal' | 'status' | 'phase' | 'capabilityTier' | 'approvalPolicy' | 'isActive'>,
>(
  runs: readonly T[],
  options: { statusFilter: RunStatusFilter; query: string; labels?: Record<string, string | null> },
): T[] {
  const q = options.query.trim().toLowerCase()
  return runs.filter(run => {
    if (!matchesRunStatusFilter(run, options.statusFilter)) return false
    if (!q) return true
    const runLabel = (options.labels?.[run.id] || (run as { label?: string | null }).label || '').toLowerCase()
    const modeLabel = scanModeBadgeInfo(run).label.toLowerCase()
    const statusLabel = runStatusLabel(run.status).toLowerCase()
    const phaseLabel = (phaseNames[run.phase] ?? run.phase).toLowerCase()
    return (
      runLabel.includes(q)
      || run.goal.toLowerCase().includes(q)
      || run.id.toLowerCase().includes(q)
      || modeLabel.includes(q)
      || statusLabel.includes(q)
      || phaseLabel.includes(q)
    )
  })
}

function plural(count: number, singular: string, pluralWord = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralWord}`
}

function statusDotClass(status: string | undefined): string {
  switch (status) {
    case 'complete':
    case 'approved':
    case 'confirmed':
      return 'bg-ok'
    case 'running':
      return 'bg-accent'
    case 'waiting':
    case 'paused':
    case 'budget_paused':
    case 'waiting_approval':
      return 'bg-warn'
    case 'failed':
      return 'bg-danger'
    default:
      return 'bg-fg-faint'
  }
}

interface Props {
  data: ProjectLoaderData
  onNewRun?: () => void
}

export function ProjectRunsTab({ data, onNewRun }: Props) {
  const { project, runs } = data
  const navigate = useNavigate()
  const router = useRouter()
  const now = useNow()

  const [statusFilter, setStatusFilter] = useState<RunStatusFilter>('all')
  const [query, setQuery] = useState('')
  const [runToDelete, setRunToDelete] = useState<ProjectRunSummary | null>(null)
  const [deletingRun, setDeletingRun] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  const [rerunningRunId, setRerunningRunId] = useState<string | null>(null)
  const [rerunError, setRerunError] = useState('')
  const [runLabels, setRunLabels] = useState<Record<string, string | null>>({})
  const runIdsKey = runs.map(r => r.id).join(',')

  useEffect(() => {
    let active = true
    void listProjectRunLabelsAction({ data: { projectId: project.id } }).then(
      labels => {
        if (active) setRunLabels(labels)
      },
      () => {},
    )
    return () => { active = false }
  }, [project.id, runIdsKey])

  const displayRunLabel = (run: ProjectRunSummary): string =>
    runLabels[run.id] || (run as { label?: string | null }).label || run.goal

  async function handleRerun(run: ProjectRunSummary) {
    if (rerunningRunId) return
    setRerunningRunId(run.id)
    setRerunError('')
    try {
      const preset = await getRunRerunPresetAction({ data: { runId: run.id } })
      const created = await createRun({
        data: {
          requestId: crypto.randomUUID(),
          ...preset,
        },
      })
      await navigate({ to: '/runs/$runId', params: { runId: created.id } })
    } catch (err) {
      setRerunError(err instanceof Error ? err.message : 'Could not start a re-run.')
      setRerunningRunId(null)
    }
  }

  const statusCounts = useMemo(() => {
    const counts: Record<RunStatusFilter, number> = {
      all: runs.length,
      running: 0,
      completed: 0,
      stopped: 0,
      failed: 0,
    }
    for (const run of runs) {
      if (matchesRunStatusFilter(run, 'running')) counts.running += 1
      if (matchesRunStatusFilter(run, 'completed')) counts.completed += 1
      if (matchesRunStatusFilter(run, 'stopped')) counts.stopped += 1
      if (matchesRunStatusFilter(run, 'failed')) counts.failed += 1
    }
    return counts
  }, [runs])

  const filteredRuns = useMemo(
    () => filterProjectRuns(runs, { statusFilter, query, labels: runLabels }),
    [runs, statusFilter, query, runLabels],
  )

  function handleNewRun() {
    if (onNewRun) {
      onNewRun()
      return
    }
    void navigate({
      to: '/projects/$projectId',
      params: { projectId: project.id },
      search: { tab: 'runs', newRun: '1' },
    })
  }

  async function confirmDeleteRun() {
    if (!runToDelete || deletingRun) return
    const needsStop = runToDelete.activity
      ? isRunDeleteBlocked(runToDelete.activity)
      : Boolean(runToDelete.isActive)
    setDeletingRun(true)
    setDeleteError('')
    try {
      await removeRun({ data: { runId: runToDelete.id, stopActive: needsStop } })
      setRunToDelete(null)
      await router.invalidate()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Could not delete the run.')
    } finally {
      setDeletingRun(false)
    }
  }

  const isRunToDeleteActive = Boolean(
    runToDelete && (runToDelete.activity ? isRunDeleteBlocked(runToDelete.activity) : runToDelete.isActive),
  )
  const isRunToDeleteParkedOnly = Boolean(
    runToDelete?.activity && !runToDelete.activity.hasLiveWork && runToDelete.activity.hasParkedApprovals,
  )
  const hasFilters = statusFilter !== 'all' || query.trim().length > 0

  return (
    <section aria-label="Project runs">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-baseline gap-2">
          <h2 className="m-0 text-[14px] font-semibold text-fg">Runs</h2>
          <span className="text-[12px] tabular-nums text-fg-subtle">
            {hasFilters ? `${filteredRuns.length} of ${runs.length}` : runs.length}
          </span>
        </div>
        <div className="flex items-center gap-3">
          {rerunError && <span className="text-[12px] text-danger" role="alert">{rerunError}</span>}
          <Button type="button" variant="default" onClick={handleNewRun}>
            <Icon name="plus" size={13} />
            New run
          </Button>
        </div>
      </div>

      {runs.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2.5">
          <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Filter runs by status">
            {RUN_STATUS_FILTERS.map(filter => {
              const active = statusFilter === filter.id
              const count = statusCounts[filter.id]
              return (
                <button
                  key={filter.id}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setStatusFilter(filter.id)}
                  className={cn(
                    'inline-flex h-[26px] cursor-pointer items-center gap-1.5 rounded-full border px-2.5 text-[12px] font-medium shadow-none transition-colors',
                    active
                      ? 'border-accent-line bg-accent-soft text-accent'
                      : 'border-line bg-transparent text-fg-muted hover:bg-hover hover:text-fg',
                  )}
                >
                  <span>{filter.label}</span>
                  <span className={cn('text-[11px] tabular-nums', active ? 'text-accent/80' : 'text-fg-subtle')}>
                    {count}
                  </span>
                </button>
              )
            })}
          </div>

          <div className="relative min-w-[200px] flex-1 sm:max-w-[280px]">
            <Icon
              name="search"
              size={13}
              className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-subtle"
            />
            <Input
              type="search"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search runs…"
              aria-label="Search runs"
              className="h-[28px] w-full pl-7 pr-2.5 text-[12.5px]"
            />
          </div>
        </div>
      )}

      {runs.length === 0 ? (
        <div className="mt-4 rounded-card border border-line bg-sunk">
          <EmptyState
            icon={<Icon name="play" size={20} />}
            title="No runs yet"
            description={`Start a ${capabilityTierMeta[1].name} to map your surface, or run ${capabilityTierMeta[2].name} with test accounts across ${project.name}.`}
            action={
              <Button type="button" variant="default" onClick={handleNewRun}>
                <Icon name="plus" size={13} />
                New run
              </Button>
            }
            className="max-w-[440px] py-9"
          />
        </div>
      ) : filteredRuns.length === 0 ? (
        <div className="mt-4 rounded-card border border-line bg-sunk">
          <EmptyState
            icon={<Icon name="search" size={18} />}
            title="No matching runs"
            description="Try a different status filter or clear your search query."
            action={
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setStatusFilter('all')
                  setQuery('')
                }}
              >
                Clear filters
              </Button>
            }
            className="max-w-[400px] py-8"
          />
        </div>
      ) : (
        <div className="mt-3 border-t border-line">
          {filteredRuns.map(run => {
            const modeBadge = scanModeBadgeInfo(run)
            const active = Boolean(run.activity ? run.activity.hasLiveWork : run.isActive)
            const durationLabel = active ? fmtDur(Math.max(0, now - run.createdAt)) : null
            const runTitle = displayRunLabel(run)

            return (
              <div
                key={run.id}
                className="group flex items-center gap-1 border-b border-line transition-colors hover:bg-hover"
              >
                <Link
                  to="/runs/$runId"
                  params={{ runId: run.id }}
                  className="flex min-h-[48px] min-w-0 flex-1 items-center gap-3 px-2 py-2 text-inherit no-underline"
                >
                  <span className="inline-flex size-3.5 flex-none items-center justify-center">
                    <StatusGlyph status={run.status} />
                  </span>
                  <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="flex min-w-0 flex-wrap items-center gap-2">
                      <span className="truncate font-medium text-fg" title={runTitle !== run.goal ? run.goal : undefined}>
                        {runTitle}
                      </span>
                      <Badge variant={modeBadge.variant}>{modeBadge.label}</Badge>
                    </span>
                    <span className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[12px] tabular-nums text-fg-subtle">
                      <span>{phaseNames[run.phase]}</span>
                      <span aria-hidden="true">·</span>
                      <span>
                        {plural(run.findingCount, 'finding')}
                        {run.confirmedCount > 0 ? ` (${run.confirmedCount} confirmed)` : ''}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>{run.turnsUsed} turns</span>
                      <span aria-hidden="true">·</span>
                      <span>{run.spentRequests} reqs</span>
                      <span aria-hidden="true">·</span>
                      <span>{formatUsd(run.spentUsd)}</span>
                      {durationLabel && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span>{durationLabel} elapsed</span>
                        </>
                      )}
                    </span>
                  </span>
                  <span className="flex flex-none items-center gap-2.5">
                    <Badge variant="neutral" className="bg-sunk">{runStatusLabel(run.status)}</Badge>
                    <time
                      className="text-[12px] tabular-nums text-fg-subtle"
                      dateTime={new Date(run.createdAt).toISOString()}
                      title={formatFullDateTime(run.createdAt)}
                      suppressHydrationWarning
                    >
                      {formatRelativeTime(run.createdAt, { compact: false, now })}
                    </time>
                  </span>
                </Link>
                {run.status === 'complete' && (
                  <Button
                    type="button"
                    variant="ghost"
                    className="h-7 flex-none px-2 text-[12px] text-fg-muted hover:text-fg"
                    disabled={rerunningRunId !== null}
                    aria-label={`Re-run: ${runTitle}`}
                    onClick={() => void handleRerun(run)}
                  >
                    <Icon name="replay" size={12} />
                    {rerunningRunId === run.id ? 'Starting…' : 'Re-run'}
                  </Button>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="mr-1 flex-none text-fg-subtle opacity-55 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
                  title="Delete run"
                  aria-label={`Delete run: ${runTitle}`}
                  onClick={() => {
                    setDeleteError('')
                    setRunToDelete(run)
                  }}
                >
                  <Icon name="trash" size={14} />
                </Button>
              </div>
            )
          })}
        </div>
      )}

      <Dialog
        open={Boolean(runToDelete)}
        closeOnEscape={!deletingRun}
        onOpenChange={nextOpen => {
          if (!nextOpen && !deletingRun) {
            setRunToDelete(null)
            setDeleteError('')
          }
        }}
      >
        <DialogContent
          role="alertdialog"
          className="flex max-h-[calc(100vh-56px)] max-w-[460px] flex-col overflow-hidden p-0"
        >
          {runToDelete && (
            <>
              <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
                <DialogTitle className="inline-flex items-center gap-2 text-[13px] font-semibold text-fg">
                  <Icon name="trash" size={15} className="text-danger" />
                  <span>{isRunToDeleteActive ? 'Stop & delete run' : 'Delete run'}</span>
                </DialogTitle>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[26px]"
                  disabled={deletingRun}
                  onClick={() => {
                    setRunToDelete(null)
                    setDeleteError('')
                  }}
                  aria-label="Close"
                >
                  <Icon name="close" size={14} />
                </Button>
              </DialogHeader>
              <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
                <DialogDescription className="text-[12.5px] leading-5 text-fg-muted">
                  Permanently remove this run and all of its findings, HTTP traffic, reports, and artifacts. This cannot be undone.
                </DialogDescription>
                <div className="flex flex-col gap-2 rounded-lg border border-line bg-sunk px-3 py-2.5">
                  <div className="line-clamp-2 text-[13px] font-medium text-fg" title={runToDelete.goal}>
                    {displayRunLabel(runToDelete)}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 tabular-nums">
                    <Badge variant="neutral" className="bg-panel capitalize">
                      <span
                        className={cn('inline-block size-[7px] flex-none rounded-full', statusDotClass(runToDelete.status))}
                        aria-hidden="true"
                      />
                      {runStatusLabel(runToDelete.status)}
                    </Badge>
                    <Badge variant="neutral" className="bg-panel">
                      {plural(runToDelete.findingCount, 'finding')}
                      {runToDelete.confirmedCount > 0 ? ` (${runToDelete.confirmedCount} confirmed)` : ''}
                    </Badge>
                    <Badge variant="neutral" className="bg-panel">
                      {runToDelete.spentRequests} req · {formatUsd(runToDelete.spentUsd)}
                    </Badge>
                  </div>
                </div>
                {isRunToDeleteActive && (
                  <div
                    className="flex items-start gap-2 rounded-lg border border-warn-line bg-warn-soft px-3 py-2 text-[12px] leading-[17px] text-fg"
                    role="status"
                  >
                    <Icon name="alert" size={14} className="mt-0.5 flex-none text-warn" />
                    <span>
                      {isRunToDeleteParkedOnly
                        ? 'This paused run has parked approval requests awaiting decision. Confirming will cancel parked approvals before deleting.'
                        : 'This run is currently running. Confirming will stop active workers and clean up containers before deleting.'}
                    </span>
                  </div>
                )}
                {deleteError && (
                  <p className="m-0 text-[12px] text-danger" role="alert">
                    {deleteError}
                  </p>
                )}
              </DialogBody>
              <DialogFooter>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={deletingRun}
                  onClick={() => {
                    setRunToDelete(null)
                    setDeleteError('')
                  }}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="default"
                  className="data-[slot=button]:bg-danger data-[slot=button]:text-white data-[slot=button]:hover:bg-danger hover:brightness-[1.08]"
                  disabled={deletingRun}
                  onClick={() => void confirmDeleteRun()}
                >
                  <Icon name="trash" size={13} />
                  {deletingRun
                    ? (isRunToDeleteActive ? 'Stopping & deleting…' : 'Deleting…')
                    : (isRunToDeleteActive ? 'Stop & delete run' : 'Delete run')}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </section>
  )
}
