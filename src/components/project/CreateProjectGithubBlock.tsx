import { useEffect, useState } from 'react'
import { listGithubRepositories, saveGithubToken } from '../../actions.ts'
import { useGithubDeviceFlow } from '../github/useGithubDeviceFlow.ts'
import { Icon } from '../run/icons.tsx'
import { Input } from '../ui/input.tsx'
import type { GithubAppInstallationSummary } from '../../server/github-connector.ts'
import { GithubInstallBanner } from './GithubInstallBanner.tsx'
import { GroupedRepoPicker } from './GroupedRepoPicker.tsx'
import type { DiscoveredGithubRepo } from './types.ts'

export interface GithubPatStatusSummary {
  configured: boolean
  source: 'vault' | 'fixture' | null
  tokenKind: 'fine_grained' | 'classic' | 'github_app' | 'unknown' | null
  authKind?: 'github_app_device' | 'pat' | null
  login?: string | null
  expiresAt?: string | null
  githubDeviceFlowConfigured?: boolean
  clientIdSource?: 'env' | 'vault' | null
  appSlug?: string | null
  installUrl?: string | null
  installations?: GithubAppInstallationSummary[]
  privateRepoCount?: number
  needsAppInstall?: boolean
}

interface Props {
  initialPatStatus: GithubPatStatusSummary
  selectedRepos: string[]
  onChangeSelectedRepos: (repos: string[]) => void
  disabled?: boolean
}

const MAX_SYNC_REPOS = 20

function connectionBadge(status: GithubPatStatusSummary): string {
  if (status.login) return `@${status.login}`
  return 'Connected'
}

/** Crisp 16px monochrome GitHub mark for compact connected header bar. */
function GithubMarkIcon() {
  return (
    <svg
      className="cp-gh-mark"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M8 1C4.13 1 1 4.13 1 8c0 3.09 2.01 5.71 4.79 6.64.35.06.48-.15.48-.34 0-.17-.01-.72-.01-1.31-1.76.32-2.21-.43-2.35-.83-.08-.2-.42-.83-.72-.99-.24-.13-.59-.46-.01-.47.55-.01.94.51 1.07.72.63 1.05 1.63.76 2.03.58.06-.45.25-.76.45-.93-1.56-.18-3.19-.78-3.19-3.47 0-.76.27-1.39.72-1.88-.07-.18-.32-.89.07-1.85 0 0 .59-.19 1.93.72a6.7 6.7 0 0 1 3.51 0c1.34-.91 1.93-.72 1.93-.72.39.96.14 1.67.07 1.85.45.49.72 1.11.72 1.88 0 2.7-1.64 3.29-3.2 3.47.25.22.47.64.47 1.3 0 .94-.01 1.69-.01 1.93 0 .19.13.41.48.34A7.002 7.002 0 0 0 15 8c0-3.87-3.13-7-7-7Z"
      />
    </svg>
  )
}

/** Refined neutral-ink repo + branch + security lens illustration (light & dark). */
function GithubBannerSvg() {
  return (
    <svg
      className="cp-gh-art"
      width="54"
      height="40"
      viewBox="0 0 58 44"
      fill="none"
      aria-hidden="true"
    >
      {/* Repository code card */}
      <rect
        x="1"
        y="3"
        width="40"
        height="34"
        rx="7"
        fill="var(--panel)"
        stroke="var(--line-2)"
        strokeWidth="1.25"
      />
      {/* Window header bar */}
      <path d="M1.6 11.5H40.4" stroke="var(--line)" strokeWidth="1.1" />
      <circle cx="7" cy="7.5" r="1.3" fill="var(--fg-4)" />
      <circle cx="11.5" cy="7.5" r="1.3" fill="var(--fg-4)" />
      <circle cx="16" cy="7.5" r="1.3" fill="var(--fg-4)" />

      {/* Git branch graph inside repo card */}
      <circle cx="11.5" cy="18.5" r="2.1" fill="var(--panel)" stroke="currentColor" strokeWidth="1.35" />
      <circle cx="11.5" cy="30" r="2.1" fill="var(--panel)" stroke="currentColor" strokeWidth="1.35" />
      <path d="M11.5 20.6V27.9" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" />
      <path d="M11.5 27.9C11.5 24.4 21.5 25.2 21.5 23.1" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" />
      <circle cx="21.5" cy="21" r="2.2" fill="var(--accent)" />

      {/* Subtle code lines */}
      <rect x="27" y="17.5" width="9" height="2.2" rx="1.1" fill="var(--line-strong)" />
      <rect x="27" y="23" width="7" height="2.2" rx="1.1" fill="var(--line-2)" />
      <rect x="27" y="28.5" width="8.5" height="2.2" rx="1.1" fill="var(--line-2)" />

      {/* Overlapping neutral security lens badge */}
      <circle
        cx="43"
        cy="28"
        r="11.5"
        fill="var(--panel)"
        stroke="var(--line-strong)"
        strokeWidth="1.25"
      />
      <circle cx="43" cy="28" r="9" fill="var(--sunk)" />
      <circle cx="41.8" cy="26.8" r="3.9" stroke="var(--fg-2)" strokeWidth="1.55" />
      <path d="M44.7 29.7L47.5 32.5" stroke="var(--fg-2)" strokeWidth="1.65" strokeLinecap="round" />
    </svg>
  )
}

export function CreateProjectGithubBlock({
  initialPatStatus,
  selectedRepos,
  onChangeSelectedRepos,
  disabled = false,
}: Props) {
  const [patStatus, setPatStatus] = useState<GithubPatStatusSummary>(initialPatStatus)
  const [expandedConnect, setExpandedConnect] = useState(false)
  const [tokenInput, setTokenInput] = useState('')
  const [savingToken, setSavingToken] = useState(false)
  const [loadingRepos, setLoadingRepos] = useState(false)
  const [repos, setRepos] = useState<DiscoveredGithubRepo[]>([])
  const [reposLoaded, setReposLoaded] = useState(false)
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')

  const device = useGithubDeviceFlow({
    configured: Boolean(patStatus.githubDeviceFlowConfigured),
    disabled: disabled || savingToken,
    onAuthorized: result => {
      setPatStatus(result.accountStatus)
      setReposLoaded(false)
      setExpandedConnect(false)
      setError('')
    },
  })
  const { flow: deviceFlow, starting: startingDeviceFlow, error: deviceFlowError, clientId: clientIdInput, setClientId: setClientIdInput, codeCopied } = device

  useEffect(() => {
    if (!patStatus.configured || reposLoaded) return
    let cancelled = false
    setLoadingRepos(true)
    setError('')
    void listGithubRepositories()
      .then(result => {
        if (cancelled) return
        setPatStatus(result.status)
        setRepos(result.repos)
        setReposLoaded(true)
        if (result.repos.length === 1) {
          onChangeSelectedRepos([result.repos[0]!.fullName])
        }
      })
      .catch(err => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : 'Could not load GitHub repositories.')
      })
      .finally(() => {
        if (!cancelled) setLoadingRepos(false)
      })
    return () => { cancelled = true }
  }, [patStatus.configured, reposLoaded, onChangeSelectedRepos])

  async function handleRefresh() {
    if (loadingRepos || disabled) return
    setLoadingRepos(true)
    setError('')
    try {
      const result = await listGithubRepositories()
      setPatStatus(result.status)
      setRepos(result.repos)
      setReposLoaded(true)
      if (result.repos.length === 1 && selectedRepos.length === 0) {
        onChangeSelectedRepos([result.repos[0]!.fullName])
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not refresh repositories.')
    } finally {
      setLoadingRepos(false)
    }
  }

  async function handleSaveToken() {
    const trimmed = tokenInput.trim()
    if (trimmed.length < 10 || savingToken || disabled) return
    setSavingToken(true)
    setError('')
    try {
      const result = await saveGithubToken({ data: { token: trimmed } })
      setTokenInput('')
      setPatStatus(result.status)
      setRepos(result.repos)
      setReposLoaded(true)
      setExpandedConnect(false)
      setSearch('')
      onChangeSelectedRepos(result.repos.length === 1 ? [result.repos[0]!.fullName] : [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not connect GitHub.')
    } finally {
      setSavingToken(false)
    }
  }

  if (!patStatus.configured) {
    return (
      <div className={`cp-gh-card${expandedConnect ? ' open' : ''}`}>
        <button
          type="button"
          className="cp-gh-banner"
          onClick={() => {
            setExpandedConnect(v => !v)
            setError('')
          }}
          aria-expanded={expandedConnect}
          disabled={disabled}
        >
          <GithubBannerSvg />
          <span className="cp-gh-copy">
            <span className="cp-gh-title-row">
              <strong>Connect GitHub</strong>
              <span className="cp-gh-rec-badge">Recommended</span>
            </span>
            <span className="cp-gh-sub">
              Add source code to find deeper vulnerabilities
            </span>
          </span>
          <span className="cp-gh-chev" aria-hidden="true">
            <Icon name={expandedConnect ? 'chevU' : 'chevR'} size={14} />
          </span>
        </button>

        {expandedConnect && (
          <div className="cp-gh-panel">
            {!deviceFlow ? (
              <div className="cp-gh-flow-row">
                {patStatus.githubDeviceFlowConfigured ? (
                  <button
                    type="button"
                    className="btn primary"
                    disabled={startingDeviceFlow || savingToken || disabled}
                    onClick={() => void device.start()}
                  >
                    {startingDeviceFlow ? 'Starting…' : 'Sign in with GitHub'}
                  </button>
                ) : (
                  <div className="cp-gh-input-row">
                    <Input
                      type="text"
                      value={clientIdInput}
                      onChange={e => { setClientIdInput(e.target.value); setError('') }}
                      onKeyDown={e => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          void device.start()
                        }
                      }}
                      placeholder="GitHub App Client ID"
                      autoComplete="off"
                      disabled={startingDeviceFlow || savingToken || disabled}
                      aria-label="GitHub App Client ID"
                      style={{ flex: 1 }}
                    />
                    <button
                      type="button"
                      className="btn primary"
                      disabled={startingDeviceFlow || savingToken || disabled || clientIdInput.trim().length < 6}
                      onClick={() => void device.start()}
                    >
                      {startingDeviceFlow ? 'Starting…' : 'Sign in'}
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="cp-gh-device">
                <div className="cp-gh-code-row">
                  <span className="cp-gh-code mono">{deviceFlow.userCode}</span>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => void device.copyCode()}
                  >
                    {codeCopied ? 'Copied' : 'Copy code'}
                  </button>
                  <a
                    className="btn primary"
                    href={deviceFlow.verificationUri}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Open GitHub ↗
                  </a>
                </div>
                <div className="cp-gh-poll-row">
                  <span role="status" className="muted num">
                    Waiting for approval…
                  </span>
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={() => void device.cancel()}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {(error || deviceFlowError) && <p role="alert" className="cp-gh-err">{error || deviceFlowError}</p>}

            <details className="cp-gh-alt">
              <summary>Or connect with an access token</summary>
              <div className="cp-gh-alt-body">
                <div className="cp-gh-input-row">
                  <Input
                    type="password"
                    value={tokenInput}
                    onChange={e => setTokenInput(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        e.preventDefault()
                        void handleSaveToken()
                      }
                    }}
                    placeholder="Paste read-only GitHub token"
                    autoComplete="off"
                    disabled={savingToken || disabled}
                    aria-label="Read-only GitHub access token"
                    style={{ flex: 1 }}
                  />
                  <button
                    type="button"
                    className="btn primary"
                    disabled={savingToken || disabled || tokenInput.trim().length < 10}
                    onClick={() => void handleSaveToken()}
                  >
                    {savingToken ? 'Connecting…' : 'Connect'}
                  </button>
                </div>
                <a
                  className="cp-gh-token-link"
                  href="https://github.com/settings/personal-access-tokens/new"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Create a read-only token on GitHub ↗
                </a>
              </div>
            </details>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="cp-gh-card connected">
      <div className="cp-gh-connected-bar">
        <div className="cp-gh-connected-left">
          <GithubMarkIcon />
          <strong className="cp-gh-connected-title">GitHub</strong>
          <span className="cp-gh-login-pill">{connectionBadge(patStatus)}</span>
          {selectedRepos.length > 0 && (
            <span className="cp-gh-sel-pill num">{selectedRepos.length} selected</span>
          )}
        </div>
        <button
          type="button"
          className="btn ghost cp-gh-refresh-btn"
          disabled={loadingRepos || disabled}
          onClick={() => void handleRefresh()}
        >
          {loadingRepos ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      <GithubInstallBanner
        authKind={patStatus.authKind}
        tokenKind={patStatus.tokenKind}
        login={patStatus.login}
        installUrl={patStatus.installUrl}
        installations={patStatus.installations}
        privateRepoCount={patStatus.privateRepoCount}
        needsAppInstall={patStatus.needsAppInstall}
        loading={loadingRepos}
        onRefresh={() => void handleRefresh()}
        compact
        flush
      />

      <div className="cp-gh-connected-body">
        {loadingRepos && !reposLoaded ? (
          <div className="cp-gh-state">
            <span className="muted">Loading repositories…</span>
          </div>
        ) : error ? (
          <div className="cp-gh-state cp-gh-state-err">
            <span role="alert" className="cp-gh-err">{error}</span>
            <button type="button" className="btn ghost" onClick={() => void handleRefresh()}>Retry</button>
          </div>
        ) : (
          <GroupedRepoPicker
            repos={repos}
            selectedRepos={selectedRepos}
            onChangeSelectedRepos={onChangeSelectedRepos}
            search={search}
            onSearchChange={setSearch}
            maxSelectable={MAX_SYNC_REPOS}
            disabled={disabled}
            variant="compact"
            emptyMessage="No repositories found. You can sync repos later in the project."
          />
        )}
      </div>
    </div>
  )
}
