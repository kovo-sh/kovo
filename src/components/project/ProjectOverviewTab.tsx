import { Link, useRouter } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { removeRun } from '../../actions.ts'
import { runStatusLabel } from '../run/meta.ts'
import { Icon } from '../run/icons.tsx'
import { formatFullDateTime, formatRelativeTime, useNow } from '../shell/AppShell.tsx'
import { formatUsd, phaseNames } from '../run-state.ts'
import type { ProjectLoaderData, ProjectTabId } from './types.ts'
import { formatGithubPatBadge } from './types.ts'

interface Props {
  data: ProjectLoaderData
  onSelectTab: (tab: ProjectTabId) => void
}

const RUN_MODE_LABEL: Record<number, string> = {
  0: 'Offline Audit',
  1: 'Safe Audit',
  2: 'Core Pentest',
  3: 'Active Pentest',
}

function plural(count: number, singular: string, pluralWord = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralWord}`
}

function RunsEmptySvg() {
  return (
    <svg
      className="pw-empty-art"
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
        fill="var(--pw-panel)"
        stroke="var(--pw-line-2)"
        strokeWidth="1.2"
      />
      <circle cx="36" cy="44" r="18" stroke="var(--pw-line-2)" strokeWidth="1.1" />
      <circle cx="36" cy="44" r="10.5" stroke="var(--pw-line-strong)" strokeWidth="1.1" strokeDasharray="2.5 2.5" />
      <path d="M36 44L48.5 31.5" stroke="var(--pw-accent)" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="36" cy="44" r="2.6" fill="var(--pw-panel)" stroke="var(--pw-fg-2)" strokeWidth="1.25" />
      <circle cx="48.5" cy="31.5" r="2.6" fill="var(--pw-accent)" />
      <circle cx="25.5" cy="51.5" r="2" fill="var(--pw-fg-3)" />

      {/* Center dashed connector + launch emblem */}
      <line
        x1="68"
        y1="44"
        x2="77"
        y2="44"
        stroke="var(--pw-line-strong)"
        strokeWidth="1.25"
        strokeDasharray="2.5 2.5"
        strokeLinecap="round"
      />
      <line
        x1="103"
        y1="44"
        x2="112"
        y2="44"
        stroke="var(--pw-line-strong)"
        strokeWidth="1.25"
        strokeDasharray="2.5 2.5"
        strokeLinecap="round"
      />
      <circle
        cx="90"
        cy="44"
        r="13"
        fill="var(--pw-panel)"
        stroke="var(--pw-accent)"
        strokeWidth="1.4"
      />
      <circle cx="90" cy="44" r="10.5" fill="var(--pw-accent-soft)" />
      <path
        d="M87.5 39.2L95.2 44L87.5 48.8V39.2Z"
        fill="var(--pw-accent)"
        stroke="var(--pw-accent)"
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
        fill="var(--pw-panel)"
        stroke="var(--pw-line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="127"
        cy="30"
        r="6.5"
        fill="var(--pw-ok-soft)"
        stroke="color-mix(in srgb, var(--pw-ok) 45%, transparent)"
        strokeWidth="1.1"
      />
      <path
        d="M124.2 30.1L126.2 32.1L130.1 28.1"
        stroke="var(--pw-ok)"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect x="138" y="27.75" width="28" height="4.5" rx="2.25" fill="var(--pw-line-strong)" />
      <rect x="121" y="45" width="45" height="4.5" rx="2.25" fill="var(--pw-line-2)" />
      <rect x="121" y="54" width="33" height="4.5" rx="2.25" fill="var(--pw-line)" />
    </svg>
  )
}

function PersonasSetupSvg({ ready }: { ready: boolean }) {
  const accent = ready ? 'var(--pw-ok)' : 'var(--pw-accent)'
  const border = ready ? 'color-mix(in srgb, var(--pw-ok) 35%, var(--pw-line-2))' : 'var(--pw-line-2)'
  return (
    <svg width="36" height="26" viewBox="0 0 36 26" fill="none" aria-hidden="true" style={{ display: 'block', marginBottom: 4, color: 'var(--pw-fg)' }}>
      <rect x="0.75" y="0.75" width="34.5" height="24.5" rx="5.5" fill="var(--pw-sunk)" stroke={border} strokeWidth="1.1" />
      <circle cx="11.5" cy="9.75" r="2.25" stroke="currentColor" strokeWidth="1.25" />
      <path d="M7.5 17.75c.5-2.1 2-3.25 4-3.25s3.5 1.15 4 3.25" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" />
      <path d="M18 6v14" stroke={accent} strokeWidth="1.2" strokeLinecap="round" strokeDasharray="2 2.2" />
      <circle cx="24.5" cy="9.75" r="2.25" fill={ready ? accent : 'var(--pw-panel)'} stroke={accent} strokeWidth="1.25" />
      <path d="M20.5 17.75c.5-2.1 2-3.25 4-3.25s3.5 1.15 4 3.25" stroke={accent} strokeWidth="1.25" strokeLinecap="round" />
    </svg>
  )
}

function GithubSetupSvg({ ready }: { ready: boolean }) {
  const accent = ready ? 'var(--pw-ok)' : 'var(--pw-accent)'
  const border = ready ? 'color-mix(in srgb, var(--pw-ok) 35%, var(--pw-line-2))' : 'var(--pw-line-2)'
  return (
    <svg width="36" height="26" viewBox="0 0 36 26" fill="none" aria-hidden="true" style={{ display: 'block', marginBottom: 4, color: 'var(--pw-fg)' }}>
      <rect x="0.75" y="0.75" width="34.5" height="24.5" rx="5.5" fill="var(--pw-sunk)" stroke={border} strokeWidth="1.1" />
      <circle cx="10.5" cy="8.5" r="1.75" fill="var(--pw-panel)" stroke="currentColor" strokeWidth="1.25" />
      <circle cx="10.5" cy="17.5" r="1.75" fill="var(--pw-panel)" stroke="currentColor" strokeWidth="1.25" />
      <circle cx="17.5" cy="11" r="1.75" fill={accent} />
      <path d="M10.5 10.25v5.5" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" />
      <path d="M10.5 15.75c0-2.5 7-1.75 7-4.75" stroke={accent} strokeWidth="1.25" strokeLinecap="round" />
      <rect x="22.5" y="12.25" width="7" height="5.5" rx="1.25" fill="var(--pw-panel)" stroke={accent} strokeWidth="1.25" />
      <path d="M24.25 12.25V10.5a1.75 1.75 0 0 1 3.5 0v1.75" stroke={accent} strokeWidth="1.25" strokeLinecap="round" />
    </svg>
  )
}

function AllowlistSetupSvg({ ready }: { ready: boolean }) {
  const accent = ready ? 'var(--pw-ok)' : 'var(--pw-accent)'
  const border = ready ? 'color-mix(in srgb, var(--pw-ok) 35%, var(--pw-line-2))' : 'var(--pw-line-2)'
  return (
    <svg width="36" height="26" viewBox="0 0 36 26" fill="none" aria-hidden="true" style={{ display: 'block', marginBottom: 4, color: 'var(--pw-fg)' }}>
      <rect x="0.75" y="0.75" width="34.5" height="24.5" rx="5.5" fill="var(--pw-sunk)" stroke={border} strokeWidth="1.1" />
      <path d="M7.5 9.25h9.5M7.5 13h7.5M7.5 16.75h9.5" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" />
      <circle cx="24.5" cy="13" r="5" fill="var(--pw-panel)" stroke={accent} strokeWidth="1.3" />
      <path d="M22.3 13.1 23.8 14.6 26.8 11.4" stroke={accent} strokeWidth="1.35" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function ProjectOverviewTab({ data, onSelectTab }: Props) {
  const { project, assets, personas, specs, runs, githubPatStatus } = data
  const router = useRouter()
  const now = useNow()
  const [runToDelete, setRunToDelete] = useState<ProjectLoaderData['runs'][number] | null>(null)
  const [deletingRun, setDeletingRun] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  const latestRun = runs[0]
  const completedRuns = runs.filter(r => r.status === 'complete').length
  const activeRuns = runs.filter(r => r.status === 'running' || r.status === 'waiting' || r.status === 'paused' || r.status === 'budget_paused').length
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
    {
      id: 'guardrails' as const,
      done: allowlistCount > 0,
      title: plural(allowlistCount, 'approved write rule'),
      pending: 'Approve write rules',
      description: 'Allow safe test mutations on staging without risking real data.',
      art: <AllowlistSetupSvg ready={false} />,
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
      RUN_MODE_LABEL[latestRun.capabilityTier] ?? 'Standard',
      phaseNames[latestRun.phase],
      plural(completedRuns, 'completed run'),
      formatRelativeTime(latestRun.createdAt, { compact: false, now }),
    ].join(' · ')
    : 'No scans yet — start with a Safe Audit to map the surface.'

  useEffect(() => {
    if (!runToDelete) return
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !deletingRun) {
        e.preventDefault()
        setRunToDelete(null)
        setDeleteError('')
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [runToDelete, deletingRun])

  async function confirmDeleteRun() {
    if (!runToDelete || deletingRun) return
    const isActive = runToDelete.status === 'running'
    setDeletingRun(true)
    setDeleteError('')
    try {
      await removeRun({ data: { runId: runToDelete.id, stopActive: isActive } })
      setRunToDelete(null)
      await router.invalidate()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Could not delete the run.')
    } finally {
      setDeletingRun(false)
    }
  }

  return <>
    <section className="pw-posture" aria-label="Project posture">
      <div className="pw-posture-main">
        <span className="pw-dot" data-status={latestRun?.status ?? 'ready'} aria-hidden="true" />
        <div className="pw-posture-copy">
          <div className="pw-posture-title">
            {postureTitle}
            {project.environment === 'local-lab' && <span className="pw-tag warn">Local Lab</span>}
          </div>
          <div className="pw-posture-sub">{postureSub}</div>
        </div>
      </div>
      <div className="pw-posture-facts num">
        <span><b>{assets.length}</b> hosts{wildcardCount > 0 ? ` · ${wildcardCount} *.domain` : ''}</span>
        <span><b>{personas.length}</b> accounts</span>
        <span><b>{specs.length}</b> specs</span>
        <span><b>{allowlistCount}</b> write rules</span>
        {thirdPartyCount > 0 && <span><b>{thirdPartyCount}</b> third-party</span>}
        <span className={githubPatStatus.configured ? 'pw-posture-linked' : 'muted'}>{formatGithubPatBadge(githubPatStatus)}</span>
        {latestRun && latestRun.spentRequests > 0 && (
          <span><b>{latestRun.spentRequests}</b> reqs · {formatUsd(latestRun.spentUsd)}</span>
        )}
      </div>
    </section>

    {pendingSetup.length > 0 ? (
      <section className="pw-sec" aria-label="Setup readiness">
        <div className="pw-sec-head">
          <h2>Finish setup</h2>
          <span className="muted num">{completedSetup} of {setupItems.length} complete</span>
        </div>
        <div
          className="pw-needs"
          style={{ gridTemplateColumns: `repeat(${pendingSetup.length}, minmax(0, 1fr))` }}
        >
          {pendingSetup.map(item => (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectTab(item.id)}
            >
              {item.art}
              <span className="n">{item.pending}</span>
              <span className="l">{item.description}</span>
            </button>
          ))}
        </div>
      </section>
    ) : (
      <div className="pw-setup-done" role="status">
        <span className="pw-setup-done-label">
          <Icon name="check" size={13} />
          Setup complete
        </span>
        <span className="pw-setup-done-meta num">
          {plural(personas.length, 'test account')} · {plural(specs.length, 'repo snapshot')} · {plural(allowlistCount, 'approved write rule')}
        </span>
        <button type="button" className="pw-btn ghost" onClick={() => onSelectTab('guardrails')}>
          Review
        </button>
      </div>
    )}

    <section className="pw-sec" aria-label="Run history">
      <div className="pw-sec-head">
        <div>
          <h2>Runs <span className="muted num">({runs.length})</span></h2>
        </div>
      </div>
      {runs.length > 0 ? (
        <div className="pw-table-wrap">
          {runs.map(run => (
            <div key={run.id} className="pw-run-row">
              <Link to="/runs/$runId" params={{ runId: run.id }} className="pw-row-link">
                <span className="pw-dot" data-status={run.status} aria-hidden="true" />
                <span className="pw-row-main">
                  <span className="pw-row-title">
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{run.goal}</span>
                  </span>
                  <span className="pw-row-sub num">
                    {RUN_MODE_LABEL[run.capabilityTier] ?? 'Standard'} · {phaseNames[run.phase]}
                    {run.findingCount > 0 ? ` · ${plural(run.findingCount, 'finding')}` : ''}
                    {run.confirmedCount > 0 ? ` (${run.confirmedCount} confirmed)` : ''}
                    {' '}· {run.turnsUsed} turns · {run.spentRequests} reqs · {formatUsd(run.spentUsd)}
                  </span>
                </span>
                <span className="pw-row-right">
                  <span className="pw-tag solid">{runStatusLabel(run.status)}</span>
                  <time
                    className="muted num"
                    style={{ fontSize: 12 }}
                    dateTime={new Date(run.createdAt).toISOString()}
                    title={formatFullDateTime(run.createdAt)}
                    suppressHydrationWarning
                  >
                    {formatRelativeTime(run.createdAt, { compact: false, now })}
                  </time>
                </span>
              </Link>
              <button
                type="button"
                className="pw-row-del"
                title="Delete run"
                aria-label={`Delete run: ${run.goal}`}
                onClick={() => {
                  setDeleteError('')
                  setRunToDelete(run)
                }}
              >
                <Icon name="trash" size={14} />
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="pw-empty-card">
          <RunsEmptySvg />
          <h3>No runs yet</h3>
          <p>Start a Safe Audit to map your surface, or run a Core Pentest with test accounts to verify access controls across {project.name}. Use New run in the header to begin.</p>
        </div>
      )}
    </section>

    {runToDelete && (() => {
      const isActive = runToDelete.status === 'running'
      return (
        <div
          className="pw-overlay"
          onMouseDown={e => {
            if (e.target === e.currentTarget && !deletingRun) {
              setRunToDelete(null)
              setDeleteError('')
            }
          }}
        >
          <div
            className="pw-modal"
            style={{ width: 460 }}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="pw-del-run-title"
          >
            <div className="pw-modal-hdr">
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                <Icon name="trash" size={15} style={{ color: 'var(--pw-bad)' }} />
                <span id="pw-del-run-title">{isActive ? 'Stop & delete run' : 'Delete run'}</span>
              </span>
              <button
                type="button"
                className="pw-btn ghost"
                style={{ padding: '0 6px' }}
                disabled={deletingRun}
                onClick={() => { setRunToDelete(null); setDeleteError('') }}
                aria-label="Close"
              >
                <Icon name="close" size={14} />
              </button>
            </div>
            <div className="pw-modal-body">
              <p className="dim" style={{ margin: 0, fontSize: 12.5 }}>
                Permanently remove this run and all of its findings, HTTP traffic, reports, and artifacts. This cannot be undone.
              </p>
              <div className="pw-confirm-summary">
                <div className="pw-confirm-goal" title={runToDelete.goal}>{runToDelete.goal}</div>
                <div className="pw-confirm-meta num">
                  <span className="pw-tag solid" style={{ textTransform: 'capitalize' }}>
                    <span className="pw-dot" data-status={runToDelete.status} />
                    {runStatusLabel(runToDelete.status)}
                  </span>
                  <span className="pw-tag solid">
                    {plural(runToDelete.findingCount, 'finding')}
                    {runToDelete.confirmedCount > 0 ? ` (${runToDelete.confirmedCount} confirmed)` : ''}
                  </span>
                  <span className="pw-tag solid">{runToDelete.spentRequests} req · {formatUsd(runToDelete.spentUsd)}</span>
                </div>
              </div>
              {isActive && (
                <div className="pw-confirm-warn" role="status">
                  <Icon name="alert" size={14} />
                  <span>This run is currently running. Confirming will stop active workers and clean up containers before deleting.</span>
                </div>
              )}
              {deleteError && <p className="err" role="alert" style={{ margin: 0 }}>{deleteError}</p>}
            </div>
            <div className="pw-modal-ftr">
              <button
                type="button"
                className="pw-btn ghost"
                disabled={deletingRun}
                onClick={() => { setRunToDelete(null); setDeleteError('') }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="pw-btn danger-solid"
                disabled={deletingRun}
                onClick={() => void confirmDeleteRun()}
              >
                <Icon name="trash" size={13} />
                {deletingRun ? (isActive ? 'Stopping & deleting…' : 'Deleting…') : (isActive ? 'Stop & delete run' : 'Delete run')}
              </button>
            </div>
          </div>
        </div>
      )
    })()}
  </>
}
