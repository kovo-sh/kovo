import { useCallback, useEffect, useRef, useState } from 'react'
import type { GithubAppInstallationSummary, GithubAuthKind, GithubPatKind } from '../../server/github-connector.ts'
import '../settings/settings.css'

export interface GithubInstallBannerProps {
  authKind?: GithubAuthKind | null
  tokenKind?: GithubPatKind | null
  login?: string | null
  installUrl?: string | null
  installations?: GithubAppInstallationSummary[]
  privateRepoCount?: number
  needsAppInstall?: boolean
  loading?: boolean
  onRefresh: () => void
  compact?: boolean
}

function OrgRepoLockIcon() {
  return (
    <svg
      className="gh-inst-icon"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M3 2.75A1.25 1.25 0 0 1 4.25 1.5h5.5A1.25 1.25 0 0 1 11 2.75v3.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <path
        d="M3 2.75v9.5A1.25 1.25 0 0 0 4.25 13.5h2.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <path d="M5.25 4.75h3.5M5.25 7.25h2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
      <rect
        x="8.75"
        y="9"
        width="5.5"
        height="4.75"
        rx="1.2"
        stroke="currentColor"
        strokeWidth="1.35"
      />
      <path
        d="M10 9V7.85a1.5 1.5 0 0 1 3 0V9"
        stroke="currentColor"
        strokeWidth="1.35"
        strokeLinecap="round"
      />
    </svg>
  )
}

function formatSelectionLabel(selection: GithubAppInstallationSummary['repositorySelection']): string {
  if (selection === 'all') return 'all repos'
  if (selection === 'selected') return 'selected repos'
  return 'installed'
}

export function GithubInstallBanner({
  authKind,
  tokenKind,
  login,
  installUrl,
  installations,
  privateRepoCount,
  needsAppInstall,
  loading = false,
  onRefresh,
  compact = false,
}: GithubInstallBannerProps) {
  const [awaitingReturn, setAwaitingReturn] = useState(false)
  const onRefreshRef = useRef(onRefresh)
  const cleanupRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    onRefreshRef.current = onRefresh
  }, [onRefresh])

  useEffect(() => {
    return () => {
      cleanupRef.current?.()
      cleanupRef.current = null
    }
  }, [])

  const armAutoRefreshOnReturn = useCallback(() => {
    if (typeof window === 'undefined' || typeof document === 'undefined') return
    cleanupRef.current?.()
    cleanupRef.current = null

    let fired = false
    let sawLeave = false
    const armedAt = Date.now()
    setAwaitingReturn(true)

    const cleanup = () => {
      window.removeEventListener('blur', handleBlur)
      window.removeEventListener('focus', handleReturn)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      if (cleanupRef.current === cleanup) {
        cleanupRef.current = null
      }
    }

    const triggerOnce = () => {
      if (fired) return
      if (!sawLeave && Date.now() - armedAt < 300) return
      fired = true
      cleanup()
      setAwaitingReturn(false)
      onRefreshRef.current()
    }

    const handleBlur = () => {
      sawLeave = true
    }

    const handleReturn = () => {
      triggerOnce()
    }

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        sawLeave = true
      } else if (document.visibilityState === 'visible') {
        triggerOnce()
      }
    }

    window.addEventListener('blur', handleBlur)
    window.addEventListener('focus', handleReturn)
    document.addEventListener('visibilitychange', handleVisibilityChange)
    cleanupRef.current = cleanup
  }, [])

  const isGithubApp = authKind === 'github_app_device' || tokenKind === 'github_app'
  const installedList = Array.isArray(installations) ? installations : []

  if (needsAppInstall) {
    return (
      <div
        className={`gh-inst-banner${compact ? ' gh-inst-compact' : ''}`}
        role="region"
        aria-label="GitHub App repository access"
        data-testid="github-install-banner"
      >
        <div className="gh-inst-head">
          <span className="gh-inst-icon-badge" aria-hidden="true">
            <OrgRepoLockIcon />
          </span>
          <div className="gh-inst-copy">
            <strong className="gh-inst-title">Missing private repos or orgs?</strong>
            <p className="gh-inst-body">
              {login ? (
                <>
                  You&apos;re signed in as <code className="gh-inst-login">@{login}</code>, but the GitHub App isn&apos;t installed on any account or organization yet — so only public repos appear.
                </>
              ) : (
                <>
                  You&apos;re signed in with GitHub, but the GitHub App isn&apos;t installed on any account or organization yet — so only public repos appear.
                </>
              )}
            </p>
          </div>
        </div>
        <div className="gh-inst-actions">
          {installUrl && (
            <a
              className="gh-inst-btn primary"
              href={installUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={armAutoRefreshOnReturn}
            >
              Choose orgs &amp; repos on GitHub ↗
            </a>
          )}
          <button
            type="button"
            className="gh-inst-btn"
            disabled={loading}
            onClick={() => {
              cleanupRef.current?.()
              setAwaitingReturn(false)
              onRefresh()
            }}
          >
            {loading ? 'Refreshing…' : 'Refresh repos'}
          </button>
          {awaitingReturn && !loading && (
            <span className="gh-inst-hint" role="status">
              Will refresh automatically when you return from GitHub.
            </span>
          )}
        </div>
      </div>
    )
  }

  if (installedList.length > 0) {
    return (
      <div
        className={`gh-inst-bar${compact ? ' gh-inst-compact' : ''}`}
        role="region"
        aria-label="Installed GitHub accounts and organizations"
        data-testid="github-install-bar"
      >
        <div className="gh-inst-chips">
          <span className="gh-inst-bar-label">
            <OrgRepoLockIcon />
            <span>Installed on</span>
          </span>
          {installedList.map(inst => {
            const label = `${inst.accountLogin} · ${formatSelectionLabel(inst.repositorySelection)}`
            const title = `${inst.accountType}: ${inst.accountLogin} (${formatSelectionLabel(inst.repositorySelection)})`
            return inst.htmlUrl ? (
              <a
                key={inst.id}
                className="gh-inst-chip gh-inst-chip-link"
                href={inst.htmlUrl}
                target="_blank"
                rel="noopener noreferrer"
                title={title}
                onClick={armAutoRefreshOnReturn}
              >
                {label}
              </a>
            ) : (
              <span key={inst.id} className="gh-inst-chip" title={title}>
                {label}
              </span>
            )
          })}
          {typeof privateRepoCount === 'number' && privateRepoCount > 0 && (
            <span className="gh-inst-private-count">
              {privateRepoCount} private
            </span>
          )}
        </div>
        <div className="gh-inst-bar-actions">
          {installUrl && (
            <a
              className="gh-inst-link"
              href={installUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={armAutoRefreshOnReturn}
            >
              Manage orgs &amp; repos on GitHub ↗
            </a>
          )}
          <button
            type="button"
            className="gh-inst-btn ghost"
            disabled={loading}
            onClick={() => {
              cleanupRef.current?.()
              setAwaitingReturn(false)
              onRefresh()
            }}
          >
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>
    )
  }

  if (isGithubApp && (installUrl || loading)) {
    return (
      <div
        className={`gh-inst-bar${compact ? ' gh-inst-compact' : ''}`}
        role="region"
        aria-label="GitHub App repository access"
        data-testid="github-install-bar"
      >
        <div className="gh-inst-chips">
          <span className="gh-inst-bar-label">
            <OrgRepoLockIcon />
            <span>
              {loading
                ? 'Checking installed accounts & organizations…'
                : 'Choose which personal or organization repositories Kovo Hunter can read.'}
            </span>
          </span>
        </div>
        <div className="gh-inst-bar-actions">
          {installUrl && (
            <a
              className="gh-inst-link"
              href={installUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={armAutoRefreshOnReturn}
            >
              Choose orgs &amp; repos on GitHub ↗
            </a>
          )}
          <button
            type="button"
            className="gh-inst-btn ghost"
            disabled={loading}
            onClick={() => {
              cleanupRef.current?.()
              setAwaitingReturn(false)
              onRefresh()
            }}
          >
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>
    )
  }

  return null
}
