import { Link } from '@tanstack/react-router'
import { formatFullDateTime, formatRelativeTime, useNow } from '../shell/AppShell.tsx'
import { formatUsd, phaseNames } from '../run-state.ts'
import type { ProjectLoaderData, ProjectTabId } from './types.ts'
import { formatGithubPatBadge } from './types.ts'

interface Props {
  data: ProjectLoaderData
  onSelectTab: (tab: ProjectTabId) => void
  onOpenNewRun: () => void
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

export function ProjectOverviewTab({ data, onSelectTab, onOpenNewRun }: Props) {
  const { project, assets, personas, specs, runs, githubPatStatus } = data
  const now = useNow()
  const latestRun = runs[0]
  const completedRuns = runs.filter(r => r.status === 'complete').length
  const activeRuns = runs.filter(r => r.status === 'running' || r.status === 'waiting' || r.status === 'paused' || r.status === 'budget_paused').length
  const wildcardCount = assets.filter(a => a.includeSubdomains && !a.thirdParty).length
  const thirdPartyCount = assets.filter(a => a.thirdParty).length
  const allowlistCount = (project.sandboxWriteAllowlist ?? []).length

  const postureHeadline = runs.length === 0
    ? `Ready for your first assessment across ${plural(assets.length, 'host')}`
    : activeRuns > 0
      ? `${plural(activeRuns, 'active run')} in progress across ${plural(assets.length, 'host')} — ${plural(completedRuns, 'completed run')} on record`
      : `${plural(completedRuns, 'completed run')} across ${plural(assets.length, 'host')} — latest ${phaseNames[latestRun!.phase].toLowerCase()} (${latestRun!.status.replaceAll('_', ' ')})`

  return <>
    <div className="pw-eyebrow">
      {project.environment === 'local-lab' && <><span>Local Lab</span><span>·</span></>}
      <span className="num">{plural(assets.length, 'host')}</span>
      {wildcardCount > 0 && <><span>·</span><span>{plural(wildcardCount, '*.domain scope')}</span></>}
    </div>
    <h2 className="pw-hed">{postureHeadline}</h2>

    <div className="pw-trio">
      <div>
        <h3>Scope &amp; Surface</h3>
        <div className="big num">{plural(assets.length, 'host')}</div>
        <p>
          {plural(project.seeds.length, 'seed')}
          {wildcardCount > 0 ? ` · ${wildcardCount} *.domain` : ''}
          {thirdPartyCount > 0 ? ` · ${plural(thirdPartyCount, 'third-party host')}` : ''}
        </p>
      </div>
      <div>
        <h3>Accounts &amp; Context</h3>
        <div className="big num">{plural(personas.length, 'test account')} · {plural(specs.length, 'snapshot')}</div>
        <p>{formatGithubPatBadge(githubPatStatus)} · {plural(allowlistCount, 'write allowlist rule')}</p>
      </div>
      <div>
        <h3>Latest Run</h3>
        {latestRun ? <>
          <div className="big" style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span className="pw-dot" data-status={latestRun.status} />
            <span style={{ textTransform: 'capitalize' }}>{latestRun.status.replaceAll('_', ' ')}</span>
          </div>
          <p className="num">
            {RUN_MODE_LABEL[latestRun.capabilityTier] ?? 'Standard'} · {phaseNames[latestRun.phase]} · {latestRun.spentRequests} reqs · {formatUsd(latestRun.spentUsd)}
          </p>
        </> : <>
          <div className="big">No runs yet</div>
          <p>Launch a Safe Audit or Core Pentest in one click.</p>
        </>}
      </div>
    </div>

    <section className="pw-sec" aria-label="Setup readiness">
      <div className="pw-sec-head">
        <h2>Readiness &amp; setup</h2>
      </div>
      <div className="pw-needs">
        <button
          type="button"
          className={personas.length > 0 ? 'ready' : ''}
          onClick={() => onSelectTab('personas')}
        >
          <PersonasSetupSvg ready={personas.length > 0} />
          <span className="n">{personas.length > 0 ? `${plural(personas.length, 'test account')} ready` : 'Add Test Accounts'}</span>
          <span className="l">
            Scan behind sign-in and catch cross-account access leaks.
          </span>
        </button>
        <button
          type="button"
          className={specs.length > 0 ? 'ready' : ''}
          onClick={() => onSelectTab('sources')}
        >
          <GithubSetupSvg ready={specs.length > 0} />
          <span className="n">{specs.length > 0 ? `${plural(specs.length, 'repo snapshot')} synced` : 'Connect GitHub Repos'}</span>
          <span className="l">
            Add source code to enrich vulnerability analysis.
          </span>
        </button>
        <button
          type="button"
          className={allowlistCount > 0 ? 'ready' : ''}
          onClick={() => onSelectTab('guardrails')}
        >
          <AllowlistSetupSvg ready={allowlistCount > 0} />
          <span className="n">{allowlistCount > 0 ? `${plural(allowlistCount, 'allowlist rule')}` : 'Configure Write Allowlist'}</span>
          <span className="l">
            Allow safe test mutations on staging without risking real data.
          </span>
        </button>
      </div>
    </section>

    <section className="pw-sec" aria-label="Run history">
      <div className="pw-sec-head">
        <div>
          <h2>Runs <span className="muted num">({runs.length})</span></h2>
        </div>
        {runs.length > 0 && (
          <button type="button" className="pw-btn" onClick={onOpenNewRun}>New run</button>
        )}
      </div>
      {runs.length > 0 ? (
        <div className="pw-table-wrap">
          {runs.map(run => (
            <Link key={run.id} to="/runs/$runId" params={{ runId: run.id }} className="pw-row-link">
              <span className="pw-dot" data-status={run.status} aria-hidden="true" />
              <span className="pw-row-main">
                <span className="pw-row-title">
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{run.goal}</span>
                </span>
                <span className="pw-row-sub num">
                  {RUN_MODE_LABEL[run.capabilityTier] ?? 'Standard'} · {phaseNames[run.phase]} · {run.turnsUsed} turns · {run.spentRequests} reqs · {formatUsd(run.spentUsd)}
                </span>
              </span>
              <span className="pw-row-right">
                <span className="pw-tag solid" style={{ textTransform: 'capitalize' }}>{run.status.replaceAll('_', ' ')}</span>
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
          ))}
        </div>
      ) : (
        <div className="pw-empty-card">
          <RunsEmptySvg />
          <h3>No runs yet</h3>
          <p>Start a Safe Audit to map your surface, or run a Core Pentest with test accounts to verify access controls across {project.name}.</p>
          <button type="button" className="pw-btn primary" onClick={onOpenNewRun}>Start first run</button>
        </div>
      )}
    </section>
  </>
}
