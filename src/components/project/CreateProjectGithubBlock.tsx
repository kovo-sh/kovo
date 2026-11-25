import { useEffect, useMemo, useRef, useState } from 'react'
import {
  cancelGithubDeviceFlowAction,
  listGithubRepositories,
  pollGithubDeviceFlowAction,
  saveGithubToken,
  startGithubDeviceFlowAction,
} from '../../actions.ts'
import { Icon } from '../run/icons.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import { Input } from '../ui/input.tsx'
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
}

interface ActiveDeviceFlow {
  flowId: string
  userCode: string
  verificationUri: string
  expiresIn: number
  intervalSec: number
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

async function copyText(text: string): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) return false
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** Theme-aware repo + code-branch + security lens illustration (light & dark). */
function GithubBannerSvg({ connected }: { connected: boolean }) {
  const accent = connected ? 'var(--ok)' : 'var(--accent)'
  const accentSoft = connected ? 'var(--ok-soft)' : 'var(--accent-soft)'
  const accentLine = connected
    ? 'color-mix(in srgb, var(--ok) 45%, transparent)'
    : 'var(--accent-line)'
  return (
    <svg
      className="cp-gh-art"
      width="58"
      height="44"
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
      <circle cx="7" cy="7.5" r="1.4" fill="var(--fg-4)" />
      <circle cx="11.5" cy="7.5" r="1.4" fill="var(--fg-4)" />
      <circle cx="16" cy="7.5" r="1.4" fill="var(--fg-4)" />

      {/* Git branch graph inside repo card */}
      <circle cx="11.5" cy="18.5" r="2.2" fill="var(--panel)" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="11.5" cy="30" r="2.2" fill="var(--panel)" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="21.5" cy="21" r="2.2" fill={accent} />
      <path d="M11.5 20.7V27.8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <path d="M11.5 27.8C11.5 24.4 21.5 25.2 21.5 23.2" stroke={accent} strokeWidth="1.4" strokeLinecap="round" />

      {/* Subtle code lines */}
      <rect x="27" y="17.5" width="9" height="2.4" rx="1.2" fill="var(--line-strong)" />
      <rect x="27" y="23" width="7" height="2.4" rx="1.2" fill="var(--line-2)" />
      <rect x="27" y="28.5" width="8.5" height="2.4" rx="1.2" fill="var(--line-2)" />

      {/* Overlapping shield / security magnifier badge */}
      <circle
        cx="43"
        cy="28"
        r="12.5"
        fill="var(--panel)"
        stroke={accentLine}
        strokeWidth="1.35"
      />
      <circle cx="43" cy="28" r="10" fill={accentSoft} />
      {connected ? (
        <path
          d="M38.8 28.2L41.6 31L47.4 25.1"
          stroke={accent}
          strokeWidth="1.9"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      ) : (
        <>
          <circle cx="41.8" cy="26.8" r="4.1" stroke={accent} strokeWidth="1.65" />
          <path d="M44.9 29.9L47.8 32.8" stroke={accent} strokeWidth="1.75" strokeLinecap="round" />
        </>
      )}
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

  // GitHub App Device Flow state
  const [clientIdInput, setClientIdInput] = useState('')
  const [deviceFlow, setDeviceFlow] = useState<ActiveDeviceFlow | null>(null)
  const [startingDeviceFlow, setStartingDeviceFlow] = useState(false)
  const [codeCopied, setCodeCopied] = useState(false)
  const activeFlowIdRef = useRef<string | null>(null)

  useEffect(() => {
    activeFlowIdRef.current = deviceFlow?.flowId ?? null
  }, [deviceFlow?.flowId])

  useEffect(() => {
    if (!deviceFlow) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const flowId = deviceFlow.flowId

    const scheduleNext = (delaySec: number) => {
      if (cancelled) return
      timer = setTimeout(() => {
        void pollOnce()
      }, Math.max(1, delaySec) * 1000)
    }

    const pollOnce = async () => {
      if (cancelled || activeFlowIdRef.current !== flowId) return
      try {
        const res = await pollGithubDeviceFlowAction({ data: { flowId } })
        if (cancelled || activeFlowIdRef.current !== flowId) return
        if (res.status === 'pending') {
          scheduleNext(res.intervalSec)
          return
        }
        if (res.status === 'slow_down') {
          setDeviceFlow(prev => (prev && prev.flowId === flowId ? { ...prev, intervalSec: res.intervalSec } : prev))
          scheduleNext(res.intervalSec)
          return
        }
        if (res.status === 'authorized') {
          setDeviceFlow(null)
          setCodeCopied(false)
          setClientIdInput('')
          setExpandedConnect(false)
          setError('')
          setPatStatus(res.accountStatus)
          setReposLoaded(false)
          return
        }
        setDeviceFlow(null)
        setError(res.error || 'GitHub sign-in did not complete.')
      } catch (err) {
        if (cancelled || activeFlowIdRef.current !== flowId) return
        setDeviceFlow(null)
        setError(err instanceof Error ? err.message : 'GitHub sign-in polling failed.')
      }
    }

    scheduleNext(deviceFlow.intervalSec)
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [deviceFlow?.flowId])

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

  const filteredRepos = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return repos
    return repos.filter(r =>
      r.fullName.toLowerCase().includes(q) ||
      r.defaultBranch.toLowerCase().includes(q) ||
      (r.description?.toLowerCase().includes(q) ?? false),
    )
  }, [repos, search])

  async function handleStartDeviceFlow() {
    if (startingDeviceFlow || savingToken || disabled) return
    const trimmedClientId = clientIdInput.trim()
    if (!patStatus.githubDeviceFlowConfigured && trimmedClientId.length < 6) {
      setError('Enter your GitHub App Client ID to start sign-in.')
      return
    }
    setStartingDeviceFlow(true)
    setError('')
    setCodeCopied(false)
    try {
      const started = await startGithubDeviceFlowAction({
        data: trimmedClientId ? { clientId: trimmedClientId } : undefined,
      })
      setDeviceFlow(started)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start GitHub sign-in.')
    } finally {
      setStartingDeviceFlow(false)
    }
  }

  async function handleCancelDeviceFlow() {
    const flowId = deviceFlow?.flowId
    setDeviceFlow(null)
    setCodeCopied(false)
    setError('')
    if (flowId) {
      try {
        await cancelGithubDeviceFlowAction({ data: { flowId } })
      } catch {
        // Best-effort
      }
    }
  }

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

  function toggleRepo(fullName: string, checked: boolean) {
    if (checked) {
      if (selectedRepos.includes(fullName)) return
      if (selectedRepos.length >= MAX_SYNC_REPOS) return
      onChangeSelectedRepos([...selectedRepos, fullName])
    } else {
      onChangeSelectedRepos(selectedRepos.filter(n => n !== fullName))
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
          <GithubBannerSvg connected={false} />
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
                    onClick={() => void handleStartDeviceFlow()}
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
                          void handleStartDeviceFlow()
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
                      onClick={() => void handleStartDeviceFlow()}
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
                    onClick={() => void copyText(deviceFlow.userCode).then(ok => setCodeCopied(ok))}
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
                    onClick={() => void handleCancelDeviceFlow()}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {error && <p role="alert" className="cp-gh-err">{error}</p>}

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
      <div className="cp-gh-connected-head">
        <GithubBannerSvg connected={true} />
        <div className="cp-gh-copy">
          <div className="cp-gh-title-row">
            <strong>GitHub repositories</strong>
            <span className="tag ok">{connectionBadge(patStatus)}</span>
            {selectedRepos.length > 0 && (
              <span className="tag accent num">{selectedRepos.length} selected</span>
            )}
          </div>
          <span className="cp-gh-sub">
            Select repos to include in security analysis
          </span>
        </div>
        <button
          type="button"
          className="btn ghost"
          disabled={loadingRepos || disabled}
          onClick={() => void handleRefresh()}
        >
          {loadingRepos ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      <div className="cp-gh-panel">
        {loadingRepos && !reposLoaded ? (
          <span className="muted">Loading repositories…</span>
        ) : error ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
            <span role="alert" className="cp-gh-err">{error}</span>
            <button type="button" className="btn ghost" onClick={() => void handleRefresh()}>Retry</button>
          </div>
        ) : repos.length === 0 ? (
          <span className="muted">No repositories found. You can sync repos later in the project.</span>
        ) : (
          <>
            {repos.length > 1 && (
              <div className="cp-gh-input-row">
                <Input
                  type="search"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Filter repositories…"
                  aria-label="Filter GitHub repositories"
                  disabled={disabled}
                  style={{ flex: 1, minWidth: 150 }}
                />
                <button
                  type="button"
                  className="btn ghost"
                  disabled={disabled || filteredRepos.length === 0}
                  onClick={() => onChangeSelectedRepos(filteredRepos.slice(0, MAX_SYNC_REPOS).map(r => r.fullName))}
                >
                  Select all
                </button>
                {selectedRepos.length > 0 && (
                  <button
                    type="button"
                    className="btn ghost"
                    disabled={disabled}
                    onClick={() => onChangeSelectedRepos([])}
                  >
                    Clear
                  </button>
                )}
              </div>
            )}

            <div className="cp-gh-repo-list" role="group" aria-label="Accessible GitHub repositories">
              {filteredRepos.length === 0 ? (
                <div className="cp-gh-repo-empty">No repositories match “{search.trim()}”.</div>
              ) : filteredRepos.map((repo, idx) => {
                const checked = selectedRepos.includes(repo.fullName)
                const atCap = !checked && selectedRepos.length >= MAX_SYNC_REPOS
                return (
                  <label
                    key={repo.fullName}
                    className={`checkbox cp-gh-repo-item${checked ? ' on' : ''}`}
                    style={{
                      borderTop: idx === 0 ? 'none' : '1px solid var(--line)',
                      cursor: atCap || disabled ? 'default' : 'pointer',
                      opacity: atCap ? 0.55 : 1,
                    }}
                  >
                    <Checkbox
                      checked={checked}
                      disabled={disabled || atCap}
                      aria-label={`Select repository ${repo.fullName}`}
                      onCheckedChange={next => toggleRepo(repo.fullName, Boolean(next))}
                    />
                    <span className="mono cp-gh-repo-name">{repo.fullName}</span>
                    <span className="tag solid">{repo.private ? 'private' : 'public'}</span>
                  </label>
                )
              })}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
