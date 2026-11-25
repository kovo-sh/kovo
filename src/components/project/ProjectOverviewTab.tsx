import { Link } from '@tanstack/react-router'
import { timeText } from '../common.tsx'
import { capabilityTierMeta, formatUsd, phaseNames } from '../run-state.ts'
import type { ProjectLoaderData, ProjectTabId } from './types.ts'
import { formatGithubPatBadge } from './types.ts'

interface Props {
  data: ProjectLoaderData
  onSelectTab: (tab: ProjectTabId) => void
  onOpenNewRun: () => void
}

function plural(count: number, singular: string, pluralWord = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralWord}`
}

export function ProjectOverviewTab({ data, onSelectTab, onOpenNewRun }: Props) {
  const { project, assets, personas, specs, runs, githubPatStatus } = data
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
      : `${plural(completedRuns, 'completed run')} across ${plural(assets.length, 'host')} — latest ${phaseNames[latestRun!.phase].toLowerCase()} (${latestRun!.status})`

  return <>
    <div className="pw-eyebrow">
      <span>{project.environment === 'local-lab' ? 'Local Lab project' : 'Public HTTPS project'}</span>
      <span>·</span>
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
          {thirdPartyCount > 0 ? ` · ${thirdPartyCount} third-party CNAME` : ''}
        </p>
      </div>
      <div>
        <h3>Auth &amp; Context</h3>
        <div className="big num">{plural(personas.length, 'persona')} · {plural(specs.length, 'snapshot')}</div>
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
            {capabilityTierMeta[latestRun.capabilityTier].short} · {phaseNames[latestRun.phase]} · {latestRun.spentRequests} reqs · {formatUsd(latestRun.spentUsd)}
          </p>
        </> : <>
          <div className="big">No runs yet</div>
          <p>Launch a Passive Recon or Authenticated BOLA run in one click.</p>
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
          <span className="n">{personas.length > 0 ? `${plural(personas.length, 'persona')} ready` : 'Add Personas'}</span>
          <span className="l">
            {personas.length > 0
              ? 'Vault accounts configured for Tier 2/3 BOLA checks.'
              : 'Configure User A & User B for cross-tenant authorization testing.'}
          </span>
        </button>
        <button
          type="button"
          className={specs.length > 0 ? 'ready' : githubPatStatus.configured ? '' : ''}
          onClick={() => onSelectTab('sources')}
        >
          <span className="n">{specs.length > 0 ? `${plural(specs.length, 'repo snapshot')} synced` : 'Connect GitHub Repos'}</span>
          <span className="l">
            {githubPatStatus.configured
              ? 'PAT connected — discover & sync repos read-only for grey-box context.'
              : 'Optional Fine-Grained PAT for read-only code, schema & CVE context.'}
          </span>
        </button>
        <button
          type="button"
          className={allowlistCount > 0 ? 'ready' : ''}
          onClick={() => onSelectTab('guardrails')}
        >
          <span className="n">{allowlistCount > 0 ? `${plural(allowlistCount, 'allowlist rule')}` : 'Configure Write Allowlist'}</span>
          <span className="l">
            {allowlistCount > 0
              ? 'Explicit Tier-2 sandbox write allowlist active.'
              : 'Fail-closed empty list; optionally allow non-destructive staging POSTs.'}
          </span>
        </button>
      </div>
    </section>

    <section className="pw-sec" aria-label="Run history">
      <div className="pw-sec-head">
        <div>
          <h2>Runs <span className="muted num">({runs.length})</span></h2>
        </div>
        <button type="button" className="pw-btn primary" onClick={onOpenNewRun}>New run</button>
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
                  {capabilityTierMeta[run.capabilityTier].short} · {phaseNames[run.phase]} · {run.turnsUsed} turns · {run.spentRequests} reqs · {formatUsd(run.spentUsd)}
                </span>
              </span>
              <span className="pw-row-right">
                <span className="pw-tag solid" style={{ textTransform: 'capitalize' }}>{run.status.replaceAll('_', ' ')}</span>
                <span className="muted num" style={{ fontSize: 12 }}>{timeText(run.createdAt)}</span>
              </span>
            </Link>
          ))}
        </div>
      ) : (
        <div className="pw-empty">
          <p>No assessment runs yet for {project.name}.</p>
          <button type="button" className="pw-btn primary" onClick={onOpenNewRun}>Start first run</button>
        </div>
      )}
    </section>
  </>
}
