import { useCallback, useEffect, useRef, useState } from 'react'
import { cn } from '../../lib/cn.ts'
import type { GithubAppInstallationSummary, GithubAuthKind, GithubPatKind } from '../../server/github-connector.ts'
import { Badge } from '../ui/badge.tsx'
import { Button, buttonVariants } from '../ui/button.tsx'

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
  flush?: boolean
}

function OrgRepoLockIcon() {
  return (
    <svg
      className="block shrink-0"
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
  flush = false,
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

  const flushSurfaceClasses =
    'rounded-none border-0 border-t border-line [.pw-repo-sheet_&]:border-t-0 [.pw-repo-sheet_&]:border-b [.pw-repo-sheet_&]:border-line'

  if (needsAppInstall) {
    return (
      <div
        className={cn(
          'flex flex-col bg-sunk text-fg',
          compact ? 'gap-2 px-3 py-2.5' : 'gap-2.5 px-3.5 py-3',
          flush ? flushSurfaceClasses : 'rounded-lg border border-line-2',
        )}
        role="region"
        aria-label="GitHub App repository access"
        data-testid="github-install-banner"
      >
        <div className="flex min-w-0 items-start gap-2.5">
          <span
            className="inline-flex size-7 flex-none items-center justify-center rounded-[7px] border border-line-2 bg-panel text-fg-muted"
            aria-hidden="true"
          >
            <OrgRepoLockIcon />
          </span>
          <div className="flex min-w-0 flex-1 flex-col gap-0.5">
            <strong className="text-[13px] font-semibold leading-[18px] text-fg">
              Missing private repos or orgs?
            </strong>
            <p className="m-0 text-[12px] leading-[18px] text-fg-muted">
              {login ? (
                <>
                  You&apos;re signed in as{' '}
                  <code className="rounded-sm border border-line-2 bg-panel px-[5px] py-px font-mono text-[11.5px] text-fg">
                    @{login}
                  </code>
                  , but the GitHub App isn&apos;t installed on any account or organization yet — so only public repos appear.
                </>
              ) : (
                <>
                  You&apos;re signed in with GitHub, but the GitHub App isn&apos;t installed on any account or organization yet — so only public repos appear.
                </>
              )}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {installUrl && (
            <a
              className={cn(buttonVariants({ variant: 'default' }), 'px-2.5 text-[12px] no-underline')}
              href={installUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={armAutoRefreshOnReturn}
            >
              Choose orgs &amp; repos on GitHub ↗
            </a>
          )}
          {/* The flush (picker) surface owns a single Refresh in its header. */}
          {!flush && (
            <Button
              type="button"
              variant="outline"
              className="px-2.5 text-[12px]"
              disabled={loading}
              onClick={() => {
                cleanupRef.current?.()
                setAwaitingReturn(false)
                onRefresh()
              }}
            >
              {loading ? 'Refreshing…' : 'Refresh repos'}
            </Button>
          )}
          {awaitingReturn && !loading && (
            <span className="text-[11.5px] text-fg-subtle" role="status">
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
        className={cn(
          'flex flex-wrap items-center justify-between gap-2.5 bg-sunk text-[12px] text-fg-muted',
          compact ? 'px-2.5 py-1.5' : 'px-[11px] py-2',
          flush ? flushSurfaceClasses : 'rounded-lg border border-line',
        )}
        role="region"
        aria-label="Installed GitHub accounts and organizations"
        data-testid="github-install-bar"
      >
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
          <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-fg-subtle">
            <OrgRepoLockIcon />
            <span>Installed on</span>
          </span>
          {installedList.map(inst => {
            const label = `${inst.accountLogin} · ${formatSelectionLabel(inst.repositorySelection)}`
            const title = `${inst.accountType}: ${inst.accountLogin} (${formatSelectionLabel(inst.repositorySelection)})`
            return inst.htmlUrl ? (
              <a
                key={inst.id}
                className="inline-flex h-[22px] items-center gap-1 whitespace-nowrap rounded-full border border-line-2 bg-panel px-2 text-[11.5px] font-medium text-fg no-underline transition-colors hover:border-accent-line hover:text-accent"
                href={inst.htmlUrl}
                target="_blank"
                rel="noopener noreferrer"
                title={title}
                onClick={armAutoRefreshOnReturn}
              >
                {label}
              </a>
            ) : (
              <Badge
                key={inst.id}
                variant="neutral"
                className="h-[22px] bg-panel px-2 font-medium text-fg"
                title={title}
              >
                {label}
              </Badge>
            )
          })}
          {typeof privateRepoCount === 'number' && privateRepoCount > 0 && (
            <Badge
              variant="neutral"
              className="bg-panel text-[11px] font-medium tabular-nums text-fg-muted"
            >
              {privateRepoCount} private
            </Badge>
          )}
        </div>
        <div className="flex flex-none flex-wrap items-center gap-2">
          {installUrl && (
            <a
              className="whitespace-nowrap text-[12px] font-medium text-accent no-underline hover:underline"
              href={installUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={armAutoRefreshOnReturn}
            >
              Manage orgs &amp; repos on GitHub ↗
            </a>
          )}
          {/* The flush (picker) surface owns a single Refresh in its header. */}
          {!flush && (
            <Button
              type="button"
              variant="ghost"
              className="h-6 px-[7px] text-[12px]"
              disabled={loading}
              onClick={() => {
                cleanupRef.current?.()
                setAwaitingReturn(false)
                onRefresh()
              }}
            >
              {loading ? 'Refreshing…' : 'Refresh'}
            </Button>
          )}
        </div>
      </div>
    )
  }

  if (isGithubApp && (installUrl || loading)) {
    return (
      <div
        className={cn(
          'flex flex-wrap items-center justify-between gap-2.5 bg-sunk text-[12px] text-fg-muted',
          compact ? 'px-2.5 py-1.5' : 'px-[11px] py-2',
          flush ? flushSurfaceClasses : 'rounded-lg border border-line',
        )}
        role="region"
        aria-label="GitHub App repository access"
        data-testid="github-install-bar"
      >
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
          <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-fg-subtle">
            <OrgRepoLockIcon />
            <span>
              {loading
                ? 'Checking installed accounts & organizations…'
                : 'Choose which personal or organization repositories Kovo can read.'}
            </span>
          </span>
        </div>
        <div className="flex flex-none flex-wrap items-center gap-2">
          {installUrl && (
            <a
              className="whitespace-nowrap text-[12px] font-medium text-accent no-underline hover:underline"
              href={installUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={armAutoRefreshOnReturn}
            >
              Choose orgs &amp; repos on GitHub ↗
            </a>
          )}
          {/* The flush (picker) surface owns a single Refresh in its header. */}
          {!flush && (
            <Button
              type="button"
              variant="ghost"
              className="h-6 px-[7px] text-[12px]"
              disabled={loading}
              onClick={() => {
                cleanupRef.current?.()
                setAwaitingReturn(false)
                onRefresh()
              }}
            >
              {loading ? 'Refreshing…' : 'Refresh'}
            </Button>
          )}
        </div>
      </div>
    )
  }

  return null
}
