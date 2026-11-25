import { useRouter } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import {
  cancelGithubDeviceFlowAction,
  clearGithubToken,
  importSpec,
  listGithubRepositories,
  pollGithubDeviceFlowAction,
  removeProjectSpec,
  saveGithubToken,
  startGithubDeviceFlowAction,
  syncGithubRepositories,
} from '../../actions.ts'
import { maxSpecBytes } from '../../domain.ts'
import { formatHumanTime, FormError, useAction } from '../common.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import { GithubInstallBanner } from './GithubInstallBanner.tsx'
import type { DiscoveredGithubRepo, ProjectLoaderData } from './types.ts'
import { safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
}

interface ActiveDeviceFlow {
  flowId: string
  userCode: string
  verificationUri: string
  expiresIn: number
  intervalSec: number
}

function SourcesEmptyIllustration() {
  return (
    <svg
      width="180"
      height="88"
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
      style={{ display: 'block', color: 'var(--pw-fg)' }}
    >
      <rect x="6" y="8" width="168" height="72" rx="10" fill="var(--pw-sunk)" stroke="var(--pw-line-2)" strokeWidth="1.2" />
      <rect x="22" y="22" width="46" height="44" rx="6" fill="var(--pw-panel)" stroke="var(--pw-line-strong)" strokeWidth="1.2" />
      <circle cx="34" cy="34" r="3" fill="var(--pw-accent)" />
      <circle cx="34" cy="54" r="3" fill="var(--pw-panel)" stroke="var(--pw-accent)" strokeWidth="1.4" />
      <circle cx="52" cy="44" r="3" fill="var(--pw-panel)" stroke="currentColor" strokeWidth="1.4" />
      <path d="M34 37v14M37 35.5c5 0 6 8.5 12 8.5" stroke="var(--pw-accent)" strokeWidth="1.4" strokeLinecap="round" />
      <path d="M74 44h30" stroke="var(--pw-line-strong)" strokeWidth="1.4" strokeLinecap="round" strokeDasharray="3 3" />
      <path d="M99 39.5 104.5 44 99 48.5" stroke="var(--pw-accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="112" y="22" width="46" height="44" rx="6" fill="var(--pw-panel)" stroke="var(--pw-accent)" strokeWidth="1.4" />
      <path d="M122 34h26M122 43h18M122 52h22" stroke="var(--pw-fg-3)" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="147" cy="43" r="2.2" fill="var(--pw-accent)" />
    </svg>
  )
}

async function copyCodeToClipboard(text: string): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) return false
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

function formatGithubConnectionBadge(status: ProjectLoaderData['githubPatStatus']): string {
  if (!status.configured) return 'Optional · Not connected'
  if (status.authKind === 'github_app_device') {
    return status.login ? `Connected via GitHub App · @${status.login}` : 'Connected via GitHub App'
  }
  const kindLabel = status.tokenKind === 'fine_grained'
    ? 'Read-only token'
    : status.tokenKind === 'classic'
      ? 'Classic token'
      : 'GitHub token'
  return status.source === 'fixture' ? `${kindLabel} · local preset` : `${kindLabel} saved`
}

export function ProjectSourcesTab({ data }: Props) {
  const { project, specs, githubPatStatus } = data
  const router = useRouter()
  const [liveGithubStatus, setLiveGithubStatus] = useState(githubPatStatus)
  const [githubTokenInput, setGithubTokenInput] = useState('')
  const [editingGithubToken, setEditingGithubToken] = useState(false)
  const [repoPickerOpen, setRepoPickerOpen] = useState(false)
  const [discoveredRepos, setDiscoveredRepos] = useState<DiscoveredGithubRepo[]>([])
  const [reposLoaded, setReposLoaded] = useState(false)
  const [reposTruncated, setReposTruncated] = useState(false)
  const [repoSearch, setRepoSearch] = useState('')
  const [selectedRepos, setSelectedRepos] = useState<string[]>([])
  const [githubNotice, setGithubNotice] = useState('')
  const [specNotice, setSpecNotice] = useState('')
  const [specName, setSpecName] = useState('')
  const [specContent, setSpecContent] = useState('')

  // GitHub App Device Flow state
  const [clientIdInput, setClientIdInput] = useState('')
  const [deviceFlow, setDeviceFlow] = useState<ActiveDeviceFlow | null>(null)
  const [deviceFlowStarting, setDeviceFlowStarting] = useState(false)
  const [deviceFlowError, setDeviceFlowError] = useState('')
  const [codeCopied, setCodeCopied] = useState(false)
  const activeFlowIdRef = useRef<string | null>(null)

  const githubAction = useAction()
  const specAction = useAction()

  useEffect(() => {
    setLiveGithubStatus(githubPatStatus)
  }, [githubPatStatus])

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
          setDeviceFlowError('')
          setEditingGithubToken(false)
          setCodeCopied(false)
          setClientIdInput('')
          setLiveGithubStatus(res.accountStatus)
          const who = res.login ? ` · @${res.login}` : ''
          setGithubNotice(`Connected via GitHub App${who}. Found ${res.repoCount} accessible ${res.repoCount === 1 ? 'repository' : 'repositories'}.`)
          await router.invalidate()
          loadGithubRepos()
          return
        }
        setDeviceFlow(null)
        setDeviceFlowError(res.error || 'GitHub sign-in did not complete. Please try again.')
      } catch (err) {
        if (cancelled || activeFlowIdRef.current !== flowId) return
        setDeviceFlow(null)
        setDeviceFlowError(err instanceof Error ? err.message : 'GitHub sign-in polling failed.')
      }
    }

    scheduleNext(deviceFlow.intervalSec)
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [deviceFlow?.flowId])

  async function handleStartDeviceFlow() {
    if (deviceFlowStarting || githubAction.pending) return
    const trimmedClientId = clientIdInput.trim()
    if (!githubPatStatus.githubDeviceFlowConfigured && trimmedClientId.length < 6) {
      setDeviceFlowError('Enter your GitHub App Client ID to start sign-in.')
      return
    }
    setDeviceFlowStarting(true)
    setDeviceFlowError('')
    setGithubNotice('')
    setCodeCopied(false)
    try {
      const started = await startGithubDeviceFlowAction({
        data: trimmedClientId ? { clientId: trimmedClientId } : undefined,
      })
      setDeviceFlow(started)
    } catch (err) {
      setDeviceFlowError(err instanceof Error ? err.message : 'Could not start GitHub Device Flow.')
    } finally {
      setDeviceFlowStarting(false)
    }
  }

  async function handleCancelDeviceFlow() {
    const flowId = deviceFlow?.flowId
    setDeviceFlow(null)
    setDeviceFlowError('')
    setCodeCopied(false)
    if (flowId) {
      try {
        await cancelGithubDeviceFlowAction({ data: { flowId } })
      } catch {
        // Best-effort cleanup
      }
    }
  }

  async function handleCopyUserCode() {
    if (!deviceFlow) return
    const copied = await copyCodeToClipboard(deviceFlow.userCode)
    setCodeCopied(copied)
  }

  function loadGithubRepos() {
    setGithubNotice('')
    void githubAction.submit(() => listGithubRepositories(), result => {
      setLiveGithubStatus(result.status)
      setDiscoveredRepos(result.repos)
      setSelectedRepos(result.defaultSelected)
      setReposTruncated(result.truncated)
      setReposLoaded(true)
      setRepoPickerOpen(true)
      setEditingGithubToken(false)
    })
  }

  function openRepoPicker() {
    setEditingGithubToken(false)
    setGithubNotice('')
    if (repoPickerOpen && reposLoaded) {
      setRepoPickerOpen(false)
      return
    }
    setRepoPickerOpen(true)
    if (!reposLoaded) loadGithubRepos()
  }

  function toggleSelectedRepo(fullName: string, checked: boolean) {
    setSelectedRepos(prev =>
      checked
        ? (prev.includes(fullName) ? prev : [...prev, fullName])
        : prev.filter(name => name !== fullName),
    )
  }

  async function onSpecFileSelected(file: File | undefined) {
    if (!file) return
    if (file.size > maxSpecBytes) {
      setSpecNotice(`File exceeds the ${Math.round(maxSpecBytes / (1024 * 1024))} MiB spec limit.`)
      return
    }
    const text = await file.text()
    setSpecName(current => current || file.name.slice(0, 160))
    setSpecContent(text)
  }

  const needle = repoSearch.trim().toLowerCase()
  const filteredRepos = needle
    ? discoveredRepos.filter(r =>
      r.fullName.toLowerCase().includes(needle) ||
      (r.description?.toLowerCase().includes(needle) ?? false) ||
      r.defaultBranch.toLowerCase().includes(needle),
    )
    : discoveredRepos
  const maxSyncBatch = 20
  const showBroadNote = discoveredRepos.length > 10 || githubPatStatus.tokenKind === 'classic'

  return <section aria-label="Source repositories">
    <div className="pw-sec-head">
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <h2>Source repositories (read-only)</h2>
          <span className={githubPatStatus.configured ? 'pw-tag ok' : 'pw-tag solid'}>
            {formatGithubConnectionBadge(githubPatStatus)}
          </span>
        </div>
        <p title="Credentials are stored locally in an owner-only (0600) credential file and never echoed back">
          Optional read-only GitHub sync for source code, API schemas, and dependency checks. Credentials stay stored privately on your machine and are never shown again.
        </p>
      </div>
      {githubPatStatus.configured && <div className="pw-sec-actions">
        <button
          type="button"
          className="pw-btn primary"
          disabled={githubAction.pending}
          onClick={openRepoPicker}
          aria-expanded={repoPickerOpen}
        >
          {repoPickerOpen ? 'Hide repos' : 'Discover & sync repos'}
        </button>
        <button
          type="button"
          className="pw-btn ghost"
          disabled={githubAction.pending}
          onClick={() => {
            setEditingGithubToken(v => !v)
            setGithubNotice('')
            setDeviceFlowError('')
          }}
          aria-expanded={editingGithubToken}
        >
          {editingGithubToken ? 'Cancel' : 'Change connection'}
        </button>
      </div>}
    </div>

    {githubNotice && <p role="status" className="notice">{githubNotice}</p>}
    {specNotice && <p role="status" className="notice">{specNotice}</p>}

    {(!githubPatStatus.configured || editingGithubToken) && <div className="pw-sheet" style={{ marginBottom: 16 }}>
      <div className="pw-sheet-h">
        <span>{githubPatStatus.configured ? 'Reconnect GitHub account' : 'Sign in with GitHub'}</span>
        <span className="pw-tag solid">Read-only · Auto-refresh</span>
      </div>
      <div className="pw-sheet-b pw-gh-device">
        {!deviceFlow ? (
          <>
            <p
              className="muted"
              style={{ margin: 0, fontSize: 12 }}
              title="Uses GitHub App Device Flow (Contents: Read-only, Metadata: Read-only) with automatic refresh in a local 0600 file"
            >
              Sign in to Kovo Hunter with read-only GitHub App access (code and metadata only). Expiring tokens refresh automatically and stay stored privately on your machine.
            </p>
            {!githubPatStatus.githubDeviceFlowConfigured && (
              <label className="pw-fld">
                GitHub App Client ID
                <div className="pw-gh-client-row">
                  <input
                    className="pw-in mono"
                    type="text"
                    value={clientIdInput}
                    onChange={e => { setClientIdInput(e.target.value); setDeviceFlowError('') }}
                    placeholder="Iv23li…"
                    autoComplete="off"
                    disabled={deviceFlowStarting || githubAction.pending}
                  />
                </div>
                <span
                  className="hint"
                  title="Server administrators can set GUARDIAN_GITHUB_CLIENT_ID in the environment for one-click sign-in. Saved locally with 0600 permissions."
                >
                  Entered once for one-click GitHub sign-in and stored privately on your machine.
                </span>
              </label>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <button
                type="button"
                className="pw-btn primary"
                disabled={deviceFlowStarting || githubAction.pending || (!githubPatStatus.githubDeviceFlowConfigured && clientIdInput.trim().length < 6)}
                onClick={() => void handleStartDeviceFlow()}
              >
                {deviceFlowStarting ? 'Starting GitHub sign-in…' : 'Sign in with GitHub'}
              </button>
              {githubPatStatus.configured && (
                <button
                  type="button"
                  className="pw-btn ghost"
                  onClick={() => { setEditingGithubToken(false); setGithubTokenInput(''); setDeviceFlowError('') }}
                >
                  Cancel
                </button>
              )}
            </div>
          </>
        ) : (
          <>
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              Copy this one-time verification code, open GitHub, and approve read-only access. This page updates automatically.
            </p>
            <div className="pw-gh-code-box" role="region" aria-label="GitHub device verification code">
              <span className="pw-gh-user-code" data-testid="github-device-user-code">{deviceFlow.userCode}</span>
              <button
                type="button"
                className="pw-btn"
                onClick={() => void handleCopyUserCode()}
              >
                {codeCopied ? 'Copied code' : 'Copy code'}
              </button>
              <a
                className="pw-btn primary"
                href={deviceFlow.verificationUri}
                target="_blank"
                rel="noopener noreferrer"
              >
                Open GitHub verification ↗
              </a>
            </div>
            <div className="pw-gh-poll-row">
              <span className="pw-gh-poll-status" role="status">
                <span className="pw-gh-pulse" aria-hidden="true" />
                Waiting for GitHub approval… polling every <span className="num">{deviceFlow.intervalSec}s</span>
              </span>
              <button
                type="button"
                className="pw-btn ghost"
                onClick={() => void handleCancelDeviceFlow()}
              >
                Cancel
              </button>
            </div>
          </>
        )}

        {deviceFlowError && <p role="alert" className="err" style={{ margin: 0 }}>{deviceFlowError}</p>}

        <details className="pw-disclosure" style={{ marginTop: 4 }}>
          <summary>Or connect with a read-only GitHub token</summary>
          <div className="pw-disclosure-body">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
              <ol className="pw-steps" style={{ flex: 1 }}>
                <li>Under <strong>Repository access</strong>, choose <strong>Only select repositories</strong> and pick the repos you want Kovo Hunter to inspect.</li>
                <li>Under <strong>Repository permissions</strong>, set <strong>Contents: Read-only</strong>.</li>
                <li>Click <strong>Generate token</strong> and paste it below — <span title="Saved locally in an owner-only (0600) credential file">stored privately on your machine</span>.</li>
              </ol>
              <a
                className="pw-btn"
                href="https://github.com/settings/personal-access-tokens/new"
                target="_blank"
                rel="noopener noreferrer"
              >
                Create read-only token on GitHub ↗
              </a>
            </div>
            <form
              style={{ display: 'grid', gap: 8 }}
              onSubmit={event => {
                event.preventDefault()
                const token = githubTokenInput.trim()
                if (!token) return
                setGithubNotice('')
                setDeviceFlowError('')
                void githubAction.submit(() => saveGithubToken({ data: { token } }), result => {
                  setLiveGithubStatus(result.status)
                  setGithubTokenInput('')
                  setEditingGithubToken(false)
                  setDiscoveredRepos(result.repos)
                  setSelectedRepos(result.defaultSelected)
                  setReposTruncated(result.truncated)
                  setReposLoaded(true)
                  setRepoPickerOpen(true)
                  setRepoSearch('')
                  setGithubNotice(`Read-only token saved privately on your machine. Found ${result.repos.length} accessible ${result.repos.length === 1 ? 'repository' : 'repositories'}.`)
                })
              }}
            >
              <label className="pw-fld">Read-only GitHub access token
                <input
                  className="pw-in mono"
                  name="githubPat"
                  type="password"
                  required
                  minLength={10}
                  maxLength={512}
                  autoComplete="off"
                  value={githubTokenInput}
                  onChange={e => setGithubTokenInput(e.target.value)}
                  placeholder="github_pat_…"
                />
              </label>
              <FormError error={githubAction.error} />
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                <span className="hint">Read-only access; token stays stored privately on your machine.</span>
                <button type="submit" className="pw-btn primary" disabled={githubAction.pending || githubTokenInput.trim().length < 10}>
                  {githubAction.pending ? 'Saving & discovering…' : 'Save token & discover repos'}
                </button>
              </div>
            </form>
          </div>
        </details>
      </div>
    </div>}

    {githubPatStatus.configured && !editingGithubToken && repoPickerOpen && <div className="pw-sheet" style={{ marginBottom: 16 }}>
      <div className="pw-sheet-h">
        <span>Select repositories to sync</span>
        <div className="pw-sec-actions">
          <button type="button" className="pw-btn ghost" disabled={githubAction.pending} onClick={loadGithubRepos}>
            {githubAction.pending && !reposLoaded ? 'Loading…' : 'Refresh'}
          </button>
          {githubPatStatus.source === 'vault' && (
            <button
              type="button"
              className="pw-btn ghost danger"
              disabled={githubAction.pending}
              onClick={() => {
                setGithubNotice('')
                void githubAction.submit(() => clearGithubToken(), result => {
                  setLiveGithubStatus(result.status)
                  setDiscoveredRepos([])
                  setSelectedRepos([])
                  setReposLoaded(false)
                  setRepoPickerOpen(false)
                  setRepoSearch('')
                  setGithubNotice(result.status.configured
                    ? 'Removed your saved credential (a local fallback token is still active).'
                    : 'Disconnected GitHub and removed the saved credential from this machine.')
                })
              }}
            >
              {githubPatStatus.authKind === 'github_app_device' ? 'Disconnect GitHub' : 'Remove saved token'}
            </button>
          )}
        </div>
      </div>
      <div className="pw-sheet-b">
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Read-only shallow clone + automatic OpenAPI, GraphQL, route, and lockfile extraction.
          {reposTruncated && ' Showing the 200 most recently updated repositories.'}
        </p>

        <GithubInstallBanner
          authKind={liveGithubStatus.authKind}
          tokenKind={liveGithubStatus.tokenKind}
          login={liveGithubStatus.login}
          installUrl={liveGithubStatus.installUrl}
          installations={liveGithubStatus.installations}
          privateRepoCount={liveGithubStatus.privateRepoCount}
          needsAppInstall={liveGithubStatus.needsAppInstall}
          loading={githubAction.pending}
          onRefresh={loadGithubRepos}
        />

        {githubPatStatus.source === 'fixture' && (
          <p
            className="muted"
            style={{ margin: 0, fontSize: 11.5 }}
            title="Loaded from local fallback token file (~/.config/guardian-fixtures/github.pat)"
          >
            Using a local fallback GitHub token. Click <strong>Change connection</strong> to sign in with GitHub or save your own read-only token instead.
          </p>
        )}

        {showBroadNote && discoveredRepos.length > 0 && <div className="pw-broad-note">
          <span>
            {githubPatStatus.tokenKind === 'classic'
              ? `Classic GitHub token detected (${discoveredRepos.length} accessible repos).`
              : `Found ${discoveredRepos.length} accessible repos.`}{' '}
            {discoveredRepos.length > 10
              ? 'Nothing was pre-selected so you do not accidentally clone everything.'
              : 'Consider scoping a read-only token or GitHub App installation to only the target repositories.'}
          </span>
        </div>}

        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            className="pw-in"
            style={{ flex: 1, minWidth: 200 }}
            type="search"
            value={repoSearch}
            onChange={e => setRepoSearch(e.target.value)}
            placeholder="Filter repositories by name, branch, or description…"
            aria-label="Filter GitHub repositories"
          />
          <button
            type="button"
            className="pw-btn ghost"
            disabled={githubAction.pending || filteredRepos.length === 0}
            onClick={() => setSelectedRepos(filteredRepos.slice(0, maxSyncBatch).map(r => r.fullName))}
          >
            Select all{filteredRepos.length > maxSyncBatch ? ` (first ${maxSyncBatch})` : filteredRepos.length > 0 ? ` (${filteredRepos.length})` : ''}
          </button>
          <button
            type="button"
            className="pw-btn ghost"
            disabled={githubAction.pending || selectedRepos.length === 0}
            onClick={() => setSelectedRepos([])}
          >
            Clear
          </button>
        </div>

        {githubAction.pending && !reposLoaded ? (
          <p className="muted" style={{ margin: 0 }}>Discovering accessible repositories…</p>
        ) : filteredRepos.length > 0 ? (
          <ul className="pw-repo-list" aria-label="Accessible GitHub repositories">
            {filteredRepos.map(repo => {
              const checked = selectedRepos.includes(repo.fullName)
              const updated = formatHumanTime(repo.updatedAt)
              return <li key={repo.fullName} className="pw-repo-row">
                <label className="pw-repo-label">
                  <Checkbox
                    checked={checked}
                    aria-label={`Select repository ${repo.fullName}`}
                    onCheckedChange={next => toggleSelectedRepo(repo.fullName, Boolean(next))}
                  />
                  <span className="pw-repo-meta">
                    <span className="pw-row-title">
                      <strong className="mono">{repo.fullName}</strong>
                      <span className="pw-tag solid">{repo.private ? 'private' : 'public'}</span>
                      <span className="pw-tag accent">{repo.defaultBranch}</span>
                      {updated.label && (
                        <span className="muted num" style={{ fontSize: 11.5 }} title={updated.full}>
                          Updated {updated.label}
                        </span>
                      )}
                    </span>
                    {repo.description && <small className="muted" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{repo.description}</small>}
                  </span>
                </label>
              </li>
            })}
          </ul>
        ) : (
          <p className="muted" style={{ margin: 0 }}>
            {discoveredRepos.length === 0
              ? 'No repositories were returned for this account. Verify the GitHub App installation or token grants Contents: Read-only on at least one repository.'
              : `No repositories match "${repoSearch.trim()}".`}
          </p>
        )}

        {selectedRepos.length > maxSyncBatch && (
          <p role="alert" className="err" style={{ margin: 0 }}>Select at most {maxSyncBatch} repositories per sync batch.</p>
        )}
        <FormError error={githubAction.error} />
      </div>
      <div className="pw-sheet-f">
        <span className="hint num">{selectedRepos.length} of {discoveredRepos.length} selected</span>
        <button type="button" className="pw-btn ghost" onClick={() => setRepoPickerOpen(false)}>Close</button>
        <button
          type="button"
          className="pw-btn primary"
          disabled={githubAction.pending || selectedRepos.length === 0 || selectedRepos.length > maxSyncBatch}
          onClick={() => {
            setGithubNotice('')
            void githubAction.submit(
              () => syncGithubRepositories({ data: { projectId: project.id, repos: selectedRepos } }),
              result => {
                setRepoPickerOpen(false)
                const warnText = result.warnings.length ? ` Warnings: ${result.warnings.join('; ')}` : ''
                setGithubNotice(`Synced ${result.repos.length} ${result.repos.length === 1 ? 'repo' : 'repos'}: ${result.specsImported} specs imported, ${result.dependenciesExtracted} dependencies extracted.${warnText}`)
              },
            )
          }}
        >
          {githubAction.pending ? 'Syncing…' : `Sync selected (${selectedRepos.length})`}
        </button>
      </div>
    </div>}

    <div className="pw-sec-head" style={{ marginTop: 18 }}>
      <h2>Synced snapshots &amp; specs <span className="muted num">({specs.length})</span></h2>
    </div>
    {specs.length > 0 ? (
      <div className="pw-table-wrap">
        {specs.map(spec => {
          const imported = formatHumanTime(spec.createdAt)
          return <div key={spec.id} className="pw-row">
            <div className="pw-row-main">
              <div className="pw-row-title">
                <strong className="mono">{spec.name}</strong>
                <span className="pw-tag solid">{spec.kind}</span>
                {spec.origin && <span className="pw-tag accent">{safeHost(spec.origin)}</span>}
              </div>
              <div className="pw-row-sub num">
                {Math.max(1, Math.round(spec.bytes / 1024))} KiB
                {imported.label && (
                  <>
                    {' · '}
                    <span title={imported.full}>Imported {imported.label}</span>
                  </>
                )}
              </div>
            </div>
            <div className="pw-row-right">
              <button
                type="button"
                className="pw-btn ghost danger"
                disabled={specAction.pending}
                onClick={() => {
                  void specAction.submit(() => removeProjectSpec({ data: {
                    requestId: crypto.randomUUID(),
                    projectId: project.id,
                    specId: spec.id,
                  } }), () => setSpecNotice(`Removed spec "${spec.name}".`))
                }}
              >
                Delete
              </button>
            </div>
          </div>
        })}
      </div>
    ) : (
      <div className="pw-empty" style={{ padding: '32px 20px', gap: 12 }}>
        <SourcesEmptyIllustration />
        <div style={{ display: 'grid', gap: 4 }}>
          <strong style={{ color: 'var(--pw-fg)', fontSize: 13.5 }}>No repositories or specs synced yet</strong>
          <p style={{ margin: 0, maxWidth: 440 }}>
            Connect GitHub above to pull read-only code and dependency context, or upload an OpenAPI or GraphQL schema manually below.
          </p>
        </div>
      </div>
    )}

    <details className="pw-disclosure">
      <summary>Advanced: upload schemas or lockfiles manually</summary>
      <div className="pw-disclosure-body">
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Kovo Hunter automatically discovers runtime schemas and extracts OpenAPI, GraphQL, and lockfile specs from synced repositories. Use manual upload only when you need to supply an extra schema or lockfile directly.
        </p>
        <form
          className="pw-sheet"
          onSubmit={event => {
            event.preventDefault()
            const form = new FormData(event.currentTarget)
            const originVal = String(form.get('origin') ?? '').trim()
            const kindRaw = String(form.get('kind') ?? 'openapi')
            const kind = (['openapi', 'graphql', 'routes', 'notes'] as const).includes(kindRaw as 'openapi')
              ? kindRaw as 'openapi' | 'graphql' | 'routes' | 'notes' : 'notes'
            void specAction.submit(() => importSpec({ data: {
              requestId: crypto.randomUUID(),
              projectId: project.id,
              name: specName.trim() || String(form.get('name') ?? '').trim(),
              kind,
              ...(originVal ? { origin: originVal } : {}),
              content: specContent,
            } }), saved => {
              setSpecName('')
              setSpecContent('')
              setSpecNotice(`Imported spec "${saved.name}" (${saved.kind}).`)
            })
          }}
        >
          <div className="pw-sheet-h"><span>Upload OpenAPI, GraphQL, or lockfile</span></div>
          <div className="pw-sheet-b">
            <div className="pw-grid-2">
              <label className="pw-fld">Name
                <input className="pw-in" name="name" required maxLength={160} value={specName} onChange={e => setSpecName(e.target.value)}
                  placeholder="openapi.yaml or package-lock.json" />
              </label>
              <label className="pw-fld">Kind
                <select className="pw-select" name="kind" defaultValue="openapi">
                  <option value="openapi">OpenAPI / Swagger</option>
                  <option value="graphql">GraphQL schema</option>
                  <option value="routes">Route map / Server handlers</option>
                  <option value="notes">Lockfile / Dependencies / Notes</option>
                </select>
              </label>
            </div>
            <div className="pw-grid-2">
              <label className="pw-fld">Target origin (optional)
                <input className="pw-in" name="origin" placeholder={project.seeds[0] ?? 'https://api.example.com'} />
              </label>
              <label className="pw-fld">Load from file (optional, up to 2 MiB)
                <input className="pw-in" style={{ paddingTop: 3 }} type="file" accept=".json,.yaml,.yml,.graphql,.gql,.txt,.md,.lock" onChange={e => {
                  void onSpecFileSelected(e.target.files?.[0])
                }} />
              </label>
            </div>
            <label className="pw-fld">Content
              <textarea className="pw-textarea mono" name="content" rows={6} required value={specContent} onChange={e => setSpecContent(e.target.value)}
                placeholder="Paste OpenAPI, GraphQL SDL, lockfile JSON, or route notes…" />
            </label>
            <FormError error={specAction.error} />
          </div>
          <div className="pw-sheet-f">
            <button type="submit" className="pw-btn primary" disabled={specAction.pending || !specContent.trim()}>Import spec</button>
          </div>
        </form>
      </div>
    </details>
  </section>
}
