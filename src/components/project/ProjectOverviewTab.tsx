import { Link, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { createRun, removeRun } from '../../actions.ts'
import { getRunRerunPresetAction, listProjectRunLabelsAction } from '../../actions-run-controls.ts'
import { cn } from '../../lib/cn.ts'
import { isRunDeleteBlocked, isRunInProgress } from '../../server/run-status.ts'
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
import type { ProjectLoaderData, ProjectTabId } from './types.ts'
import { formatGithubPatBadge } from './types.ts'

interface Props {
  data: ProjectLoaderData
  onSelectTab: (tab: ProjectTabId) => void
}

const SETUP_GRID_COLS: Record<number, string> = {
  1: 'sm:grid-cols-1',
  2: 'sm:grid-cols-2',
  3: 'sm:grid-cols-3',
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

function RunsEmptySvg() {
  return (
    <svg
      className="block"
      width="180"
      height="88"
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
    >
      {/* Left card: Target surface radar */}
      <rect
        x="4"
        y="14"
        width="64"
        height="60"
        rx="8"
        fill="var(--panel)"
        stroke="var(--line-2)"
        strokeWidth="1.2"
      />
      <circle cx="36" cy="44" r="18" stroke="var(--line-2)" strokeWidth="1.1" />
      <circle cx="36" cy="44" r="10.5" stroke="var(--line-strong)" strokeWidth="1.1" strokeDasharray="2.5 2.5" />
      <path d="M36 44L48.5 31.5" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="36" cy="44" r="2.6" fill="var(--panel)" stroke="var(--fg-2)" strokeWidth="1.25" />
      <circle cx="48.5" cy="31.5" r="2.6" fill="var(--accent)" />
      <circle cx="25.5" cy="51.5" r="2" fill="var(--fg-3)" />

      {/* Center dashed connector + launch emblem */}
      <line
        x1="68"
        y1="44"
        x2="77"
        y2="44"
        stroke="var(--line-strong)"
        strokeWidth="1.25"
        strokeDasharray="2.5 2.5"
        strokeLinecap="round"
      />
      <line
        x1="103"
        y1="44"
        x2="112"
        y2="44"
        stroke="var(--line-strong)"
        strokeWidth="1.25"
        strokeDasharray="2.5 2.5"
        strokeLinecap="round"
      />
      <circle
        cx="90"
        cy="44"
        r="13"
        fill="var(--panel)"
        stroke="var(--accent)"
        strokeWidth="1.4"
      />
      <circle cx="90" cy="44" r="10.5" fill="var(--accent-soft)" />
      <path
        d="M87.5 39.2L95.2 44L87.5 48.8V39.2Z"
        fill="var(--accent)"
        stroke="var(--accent)"
        strokeWidth="1.1"
        strokeLinejoin="round"
      />

      {/* Right card: Verified findings report */}
      <rect
        x="112"
        y="14"
        width="64"
        height="60"
        rx="8"
        fill="var(--panel)"
        stroke="var(--line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="127"
        cy="30"
        r="6.5"
        fill="var(--ok-soft)"
        stroke="color-mix(in srgb, var(--ok) 45%, transparent)"
        strokeWidth="1.1"
      />
      <path
        d="M124.2 30.1L126.2 32.1L130.1 28.1"
        stroke="var(--ok)"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect x="138" y="27.75" width="28" height="4.5" rx="2.25" fill="var(--line-strong)" />
      <rect x="121" y="45" width="45" height="4.5" rx="2.25" fill="var(--line-2)" />
      <rect x="121" y="54" width="33" height="4.5" rx="2.25" fill="var(--line)" />
    </svg>
  )
}

function PersonasSetupSvg({ ready }: { ready: boolean }) {
  const accent = ready ? 'var(--ok)' : 'var(--accent)'
  const border = ready ? 'color-mix(in srgb, var(--ok) 35%, var(--line-2))' : 'var(--line-2)'
  return (
    <svg width="36" height="26" viewBox="0 0 36 26" fill="none" aria-hidden="true" className="mb-1 block text-fg">
      <rect x="0.75" y="0.75" width="34.5" height="24.5" rx="5.5" fill="var(--sunk)" stroke={border} strokeWidth="1.1" />
      <circle cx="11.5" cy="9.75" r="2.25" stroke="currentColor" strokeWidth="1.25" />
      <path d="M7.5 17.75c.5-2.1 2-3.25 4-3.25s3.5 1.15 4 3.25" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" />
      <path d="M18 6v14" stroke={accent} strokeWidth="1.2" strokeLinecap="round" strokeDasharray="2 2.2" />
      <circle cx="24.5" cy="9.75" r="2.25" fill={ready ? accent : 'var(--panel)'} stroke={accent} strokeWidth="1.25" />
      <path d="M20.5 17.75c.5-2.1 2-3.25 4-3.25s3.5 1.15 4 3.25" stroke={accent} strokeWidth="1.25" strokeLinecap="round" />
    </svg>
  )
}

function GithubSetupSvg({ ready }: { ready: boolean }) {
  const accent = ready ? 'var(--ok)' : 'var(--accent)'
  const border = ready ? 'color-mix(in srgb, var(--ok) 35%, var(--line-2))' : 'var(--line-2)'
  return (
    <svg width="36" height="26" viewBox="0 0 36 26" fill="none" aria-hidden="true" className="mb-1 block text-fg">
      <rect x="0.75" y="0.75" width="34.5" height="24.5" rx="5.5" fill="var(--sunk)" stroke={border} strokeWidth="1.1" />
      <circle cx="10.5" cy="8.5" r="1.75" fill="var(--panel)" stroke="currentColor" strokeWidth="1.25" />
      <circle cx="10.5" cy="17.5" r="1.75" fill="var(--panel)" stroke="currentColor" strokeWidth="1.25" />
      <circle cx="17.5" cy="11" r="1.75" fill={accent} />
      <path d="M10.5 10.25v5.5" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" />
      <path d="M10.5 15.75c0-2.5 7-1.75 7-4.75" stroke={accent} strokeWidth="1.25" strokeLinecap="round" />
      <rect x="22.5" y="12.25" width="7" height="5.5" rx="1.25" fill="var(--panel)" stroke={accent} strokeWidth="1.25" />
      <path d="M24.25 12.25V10.5a1.75 1.75 0 0 1 3.5 0v1.75" stroke={accent} strokeWidth="1.25" strokeLinecap="round" />
    </svg>
  )
}

export function ProjectOverviewTab({ data, onSelectTab }: Props) {
  const { project, assets, personas, specs, runs, githubPatStatus } = data
  const navigate = useNavigate()
  const router = useRouter()
  const now = useNow()
  const [runToDelete, setRunToDelete] = useState<ProjectLoaderData['runs'][number] | null>(null)
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

  const displayRunLabel = (run: ProjectLoaderData['runs'][number]): string =>
    runLabels[run.id] || (run as { label?: string | null }).label || run.goal

  async function handleRerun(run: ProjectLoaderData['runs'][number]) {
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
  const latestRun = runs[0]
  const completedRuns = runs.filter(r => r.status === 'complete').length
  const activeRuns = runs.filter(r => isRunInProgress(r.activity ?? r.status)).length
  const wildcardCount = assets.filter(a => a.includeSubdomains && !a.thirdParty).length
  const thirdPartyCount = assets.filter(a => a.thirdParty).length
  const allowlistCount = (project.sandboxWriteAllowlist ?? []).length

  const setupItems = [
    {
      id: 'personas' as const,
      done: personas.length > 0,
      title: `${plural(personas.length, 'test account')} set up`,
      pending: 'Add test accounts',
      description: 'Scan behind sign-in and catch cross-account access leaks.',
      art: <PersonasSetupSvg ready={false} />,
    },
    {
      id: 'sources' as const,
      done: specs.length > 0,
      title: `${plural(specs.length, 'repo snapshot')} synced`,
      pending: 'Connect GitHub repos',
      description: 'Add source code to enrich vulnerability analysis.',
      art: <GithubSetupSvg ready={false} />,
    },
  ]
  const pendingSetup = setupItems.filter(item => !item.done)
  const completedSetup = setupItems.length - pendingSetup.length
  const postureTitle = runs.length === 0
    ? `Ready to assess ${plural(assets.length, 'host')}`
    : activeRuns > 0
      ? `${plural(activeRuns, 'run')} in progress`
      : `Latest run ${runStatusLabel(latestRun!.status)}`
  const postureSub = latestRun
    ? [
      capabilityTierMeta[latestRun.capabilityTier]?.name ?? 'Standard',
      phaseNames[latestRun.phase],
      plural(completedRuns, 'completed run'),
      formatRelativeTime(latestRun.createdAt, { compact: false, now }),
    ].join(' · ')
    : `No scans yet — start with a ${capabilityTierMeta[1].name} to map the surface.`

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

  return (
    <>
      <section
        className="flex flex-wrap items-center justify-between gap-x-6 gap-y-4 border-y border-line py-3"
        aria-label="Project posture"
      >
        <div className="flex min-w-0 flex-[1_1_320px] items-center gap-2.5">
          <span
            className={cn('inline-block size-2 flex-none rounded-full', statusDotClass(latestRun?.status))}
            aria-hidden="true"
          />
          <div className="flex min-w-0 flex-col gap-0.5">
            <div className="flex flex-wrap items-center gap-2 text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">
              {postureTitle}
              {project.environment === 'local-lab' && <Badge variant="warn">Local Lab</Badge>}
            </div>
            <div className="text-[12px] leading-[18px] text-fg-subtle">{postureSub}</div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-3.5 gap-y-1.5 text-[12px] tabular-nums text-fg-subtle">
          <span>
            <b className="font-semibold text-fg-muted">{assets.length}</b> hosts
            {wildcardCount > 0 ? ` · ${wildcardCount} *.domain` : ''}
          </span>
          <span>
            <b className="font-semibold text-fg-muted">{personas.length}</b> accounts
          </span>
          <span>
            <b className="font-semibold text-fg-muted">{specs.length}</b> specs
          </span>
          {allowlistCount > 0 && (
            <span>
              <b className="font-semibold text-fg-muted">{allowlistCount}</b> write rules
            </span>
          )}
          {thirdPartyCount > 0 && (
            <span>
              <b className="font-semibold text-fg-muted">{thirdPartyCount}</b> third-party
            </span>
          )}
          <span className={githubPatStatus.configured ? 'text-fg-muted' : 'text-fg-subtle'}>
            {formatGithubPatBadge(githubPatStatus)}
          </span>
          {latestRun && latestRun.spentRequests > 0 && (
            <span>
              <b className="font-semibold text-fg-muted">{latestRun.spentRequests}</b> reqs · {formatUsd(latestRun.spentUsd)}
            </span>
          )}
        </div>
      </section>

      {pendingSetup.length > 0 ? (
        <section className="mt-[22px]" aria-label="Setup readiness">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
            <h2 className="m-0 text-[13px] font-semibold text-fg">Finish setup</h2>
            <span className="text-[12px] tabular-nums text-fg-subtle">
              {completedSetup} of {setupItems.length} complete
            </span>
          </div>
          <div
            className={cn(
              'grid grid-cols-1 divide-y divide-line overflow-hidden rounded-lg border border-line bg-panel sm:divide-x sm:divide-y-0',
              SETUP_GRID_COLS[pendingSetup.length] ?? 'sm:grid-cols-3',
            )}
          >
            {pendingSetup.map(item => (
              <button
                key={item.id}
                type="button"
                className="flex h-auto min-h-[60px] cursor-pointer flex-col items-start gap-[3px] whitespace-normal rounded-none border-0 bg-transparent px-3.5 py-3 text-left shadow-none transition-colors hover:bg-hover"
                onClick={() => onSelectTab(item.id)}
              >
                {item.art}
                <span className="flex items-center gap-1.5 text-[13.5px] font-semibold text-fg">
                  {item.pending}
                </span>
                <span className="text-[11.5px] font-normal leading-4 text-fg-subtle">
                  {item.description}
                </span>
              </button>
            ))}
          </div>
        </section>
      ) : (
        <div
          className="mt-[18px] flex flex-wrap items-center gap-x-3.5 gap-y-2 rounded-lg border border-line bg-sunk px-3 py-2 text-[12px] text-fg-muted"
          role="status"
        >
          <span className="inline-flex items-center gap-1.5 font-medium text-fg">
            <Icon name="check" size={13} className="text-fg-subtle" />
            Setup complete
          </span>
          <span className="tabular-nums text-fg-subtle">
            {plural(personas.length, 'test account')} · {plural(specs.length, 'repo snapshot')}
          </span>
          <Button type="button" variant="ghost" className="ml-auto" onClick={() => onSelectTab('personas')}>
            Review
          </Button>
        </div>
      )}

      <section className="mt-[22px]" aria-label="Run history">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
          <h2 className="m-0 text-[13px] font-semibold text-fg">
            Runs <span className="font-normal tabular-nums text-fg-subtle">({runs.length})</span>
          </h2>
          <div className="flex items-center gap-3">
            {rerunError && <span className="text-[12px] text-danger" role="alert">{rerunError}</span>}
            {runs.length > 0 && (
              <Link
                to="/projects/$projectId"
                params={{ projectId: project.id }}
                search={{ tab: 'runs' }}
                className="text-[12px] font-medium text-fg-muted no-underline transition-colors hover:text-fg"
              >
                View all runs ({runs.length}) →
              </Link>
            )}
          </div>
        </div>
        {runs.length > 0 ? (
          <div className="border-t border-line">
            {runs.slice(0, 3).map(run => {
              const runTitle = displayRunLabel(run)
              return (
              <div
                key={run.id}
                className="group flex items-center gap-1 border-b border-line transition-colors hover:bg-hover"
              >
                <Link
                  to="/runs/$runId"
                  params={{ runId: run.id }}
                  className="flex min-h-[42px] min-w-0 flex-1 items-center gap-3 px-1.5 py-[7px] text-inherit no-underline"
                >
                  <span
                    className={cn('inline-block size-[7px] flex-none rounded-full', statusDotClass(run.status))}
                    aria-hidden="true"
                  />
                  <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
                      <span className="truncate" title={runTitle !== run.goal ? run.goal : undefined}>{runTitle}</span>
                    </span>
                    <span className="text-[12px] tabular-nums text-fg-subtle">
                      {capabilityTierMeta[run.capabilityTier]?.name ?? 'Standard'} · {phaseNames[run.phase]}
                      {run.findingCount > 0 ? ` · ${plural(run.findingCount, 'finding')}` : ''}
                      {run.confirmedCount > 0 ? ` (${run.confirmedCount} confirmed)` : ''}
                      {' '}· {run.turnsUsed} turns · {run.spentRequests} reqs · {formatUsd(run.spentUsd)}
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
        ) : (
          <div className="mt-3.5 rounded-card border border-line bg-sunk">
            <EmptyState
              icon={<RunsEmptySvg />}
              title="No runs yet"
              description={`Start a ${capabilityTierMeta[1].name} to map your surface, or run ${capabilityTierMeta[2].name} with test accounts to verify access controls across ${project.name}. Use New run in the header to begin.`}
              className="max-w-[440px] py-9 [&_[data-slot=empty-state-icon]]:size-auto [&_[data-slot=empty-state-icon]>svg]:h-[88px] [&_[data-slot=empty-state-icon]>svg]:w-[180px]"
            />
          </div>
        )}
      </section>

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
    </>
  )
}
