import { createFileRoute, Link, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import {
  clearGithubToken,
  getGithubStatus,
  listGithubRepositories,
  listModels,
  removeModelProfile,
  saveGithubToken,
  testModel,
  toggleModelProfile,
} from '../actions.ts'
import { formatHumanTime, useAction } from '../components/common.tsx'
import { useGithubDeviceFlow } from '../components/github/useGithubDeviceFlow.ts'
import { GithubInstallBanner } from '../components/project/GithubInstallBanner.tsx'
import { ModelProfileSheet } from '../components/settings/ModelProfileSheet.tsx'
import '../components/settings/settings.css'
import { Icon } from '../components/run/icons.tsx'
import { id } from '../domain.ts'
import type { PublicModelProfile } from '../domain.ts'

function ModelProfilesEmptyIllustration() {
  return (
    <svg
      width="180"
      height="88"
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
      style={{ display: 'block', color: 'var(--sw-fg)' }}
    >
      <rect x="6" y="8" width="168" height="72" rx="10" fill="var(--sw-sunk)" stroke="var(--sw-line-2)" strokeWidth="1.2" />
      <rect x="20" y="29" width="34" height="30" rx="6" fill="var(--sw-panel)" stroke="var(--sw-line-strong)" strokeWidth="1.2" />
      <path d="M29 41h16M29 48h10" stroke="var(--sw-fg-3)" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M54 44h22c8 0 10-16 20-16h18" stroke="var(--sw-accent)" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M54 44h22c8 0 10 16 20 16h18" stroke="var(--sw-line-strong)" strokeWidth="1.4" strokeLinecap="round" strokeDasharray="3 3" />
      <circle cx="54" cy="44" r="3" fill="var(--sw-panel)" stroke="currentColor" strokeWidth="1.4" />
      <rect x="114" y="17" width="46" height="22" rx="5" fill="var(--sw-panel)" stroke="var(--sw-accent)" strokeWidth="1.4" />
      <circle cx="124" cy="28" r="3" fill="var(--sw-accent)" />
      <path d="M132 28h18" stroke="var(--sw-fg-2)" strokeWidth="1.5" strokeLinecap="round" />
      <rect x="114" y="49" width="46" height="22" rx="5" fill="var(--sw-panel)" stroke="var(--sw-line-strong)" strokeWidth="1.2" />
      <circle cx="124" cy="60" r="3" fill="var(--sw-panel)" stroke="var(--sw-fg-3)" strokeWidth="1.4" />
      <path d="M132 60h18" stroke="var(--sw-fg-3)" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  )
}

export const Route = createFileRoute('/settings')({
  validateSearch: (search): { runId?: string } => ({ runId: id.safeParse(search.runId).data }),
  loader: async () => {
    const [profiles, githubStatus] = await Promise.all([listModels(), getGithubStatus()])
    return { profiles, githubStatus }
  },
  component: SettingsWorkbenchPage,
})

type GithubStatusData = Awaited<ReturnType<typeof getGithubStatus>>

function githubConnectionSummary(status: GithubStatusData): { label: string; tone: 'ok' | 'solid' } {
  if (!status.configured) return { label: 'Not connected', tone: 'solid' }
  return {
    label: status.login ? `GitHub connected · @${status.login}` : 'GitHub connected',
    tone: 'ok',
  }
}

function GithubConnectionBand({ initialStatus }: { initialStatus: GithubStatusData }) {
  const router = useRouter()
  const [status, setStatus] = useState<GithubStatusData>(initialStatus)
  const [reconnecting, setReconnecting] = useState(false)
  const [patInput, setPatInput] = useState('')
  const [savingPat, setSavingPat] = useState(false)
  const [disconnecting, setDisconnecting] = useState(false)
  const [confirmDisconnect, setConfirmDisconnect] = useState(false)
  const [loadingInstallations, setLoadingInstallations] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const autoFetchedInstallationsRef = useRef(false)

  const device = useGithubDeviceFlow({
    configured: Boolean(status.githubDeviceFlowConfigured),
    disabled: savingPat || disconnecting,
    onStart: () => {
      setError('')
      setNotice('')
    },
    onAuthorized: async result => {
      setReconnecting(false)
      setError('')
      setStatus(result.accountStatus)
      const who = result.login ? ` · @${result.login}` : ''
      setNotice(`Connected to GitHub${who}. Found ${result.repoCount} accessible ${result.repoCount === 1 ? 'repository' : 'repositories'}.`)
      await router.invalidate()
    },
  })
  const {
    flow: deviceFlow,
    starting: startingFlow,
    error: deviceFlowError,
    clientId: clientIdInput,
    setClientId: setClientIdInput,
    codeCopied,
  } = device
  const displayError = error || deviceFlowError

  const isGithubAppSession = status.configured && (status.authKind === 'github_app_device' || status.tokenKind === 'github_app')

  useEffect(() => {
    setStatus(initialStatus)
  }, [initialStatus])

  useEffect(() => {
    if (!confirmDisconnect) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !disconnecting) setConfirmDisconnect(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [confirmDisconnect, disconnecting])

  useEffect(() => {
    if (!isGithubAppSession) {
      autoFetchedInstallationsRef.current = false
      return
    }
    if (status.installations !== undefined || autoFetchedInstallationsRef.current) return
    autoFetchedInstallationsRef.current = true
    let cancelled = false
    setLoadingInstallations(true)
    void listGithubRepositories()
      .then(res => {
        if (!cancelled) setStatus(res.status)
      })
      .catch(() => {
        // Best-effort background refresh; user can still click Refresh
      })
      .finally(() => {
        if (!cancelled) setLoadingInstallations(false)
      })
    return () => { cancelled = true }
  }, [isGithubAppSession, status.installations])

  async function refreshGithubInstallations() {
    if (loadingInstallations || disconnecting || startingFlow || savingPat) return
    setLoadingInstallations(true)
    setError('')
    try {
      const res = await listGithubRepositories()
      setStatus(res.status)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not refresh GitHub installations.')
    } finally {
      setLoadingInstallations(false)
    }
  }

  async function handleSavePat() {
    const trimmed = patInput.trim()
    if (trimmed.length < 10 || savingPat || disconnecting) return
    setSavingPat(true)
    setError('')
    setNotice('')
    try {
      const res = await saveGithubToken({ data: { token: trimmed } })
      setPatInput('')
      setReconnecting(false)
      setStatus(res.status)
      setNotice(`Read-only GitHub token saved privately on your machine. Found ${res.repos.length} accessible ${res.repos.length === 1 ? 'repository' : 'repositories'}.`)
      await router.invalidate()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save GitHub token.')
    } finally {
      setSavingPat(false)
    }
  }

  async function handleDisconnect() {
    if (disconnecting) return
    setDisconnecting(true)
    setError('')
    setNotice('')
    try {
      const res = await clearGithubToken()
      setStatus(res.status)
      setReconnecting(false)
      setNotice(res.status.configured
        ? 'Removed your saved GitHub credential (a local fallback token is still active).'
        : 'Disconnected GitHub and removed the saved credential from this machine.')
      await router.invalidate()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove GitHub credential.')
    } finally {
      setDisconnecting(false)
    }
  }

  const badge = githubConnectionSummary(status)
  const showConnectPanel = !status.configured || reconnecting

  return (
    <section className="sw-band" aria-labelledby="github-integration-heading">
      <div className="sw-sec-head">
        <div>
          <p className="sw-eyebrow">Source code &amp; dependency sync</p>
          <h2 id="github-integration-heading" className="sw-sec-title">GitHub integration</h2>
        </div>
        <span className={`sw-tag ${badge.tone}`}>
          <i className={`sw-dot ${badge.tone === 'ok' ? 'ok' : 'off'}`} aria-hidden="true" />
          {badge.label}
        </span>
      </div>

      <div className="sw-sheet">
        <div className="sw-sheet-row">
          <div className="sw-sheet-row-main">
            <span className="sw-sheet-row-title">
              {status.configured ? 'Read-only GitHub connection' : 'Sign in with GitHub'}
            </span>
            <p
              className="sw-sheet-row-desc"
              title="Credentials are stored privately on this machine"
            >
              {status.configured && status.authKind === 'github_app_device'
                ? 'Authorized with read-only GitHub App access (code and metadata only). Tokens refresh automatically and stay stored privately on your machine.'
                : status.configured
                  ? 'Connected using a read-only GitHub access token stored privately on your machine.'
                  : 'Connect a read-only GitHub App with one-time code sign-in and automatic token refresh, stored privately on your machine.'}
            </p>
          </div>
          <div className="sw-sheet-row-act">
            {status.configured ? (
              <>
                <button
                  type="button"
                  className="sw-btn"
                  disabled={disconnecting || startingFlow || savingPat}
                  onClick={() => {
                    setReconnecting(v => !v)
                    setError('')
                    setNotice('')
                  }}
                >
                  {reconnecting ? 'Cancel' : 'Change connection'}
                </button>
                {status.source === 'vault' && (
                  <button
                    type="button"
                    className="sw-btn danger"
                    disabled={disconnecting || startingFlow || savingPat}
                    onClick={() => setConfirmDisconnect(true)}
                  >
                    {disconnecting ? 'Disconnecting…' : 'Disconnect'}
                  </button>
                )}
              </>
            ) : !deviceFlow && status.githubDeviceFlowConfigured ? (
              <button
                type="button"
                className="sw-btn primary"
                disabled={startingFlow || savingPat}
                onClick={() => void device.start()}
              >
                {startingFlow ? 'Starting…' : 'Sign in with GitHub'}
              </button>
            ) : null}
          </div>
        </div>

        {isGithubAppSession && !reconnecting && !deviceFlow && (
          <div className="sw-gh-install-row">
            <GithubInstallBanner
              authKind={status.authKind}
              tokenKind={status.tokenKind}
              login={status.login}
              installUrl={status.installUrl}
              installations={status.installations}
              privateRepoCount={status.privateRepoCount}
              needsAppInstall={status.needsAppInstall}
              loading={loadingInstallations}
              onRefresh={() => void refreshGithubInstallations()}
            />
          </div>
        )}

        {showConnectPanel && !deviceFlow && (!status.githubDeviceFlowConfigured || reconnecting) && (
          <div className="sw-pair-drawer">
            {!status.githubDeviceFlowConfigured ? (
              <>
                <div className="sw-pair-top">
                  <strong>GitHub App Client ID</strong>
                  <span
                    className="sw-muted"
                    title="Stored privately on this machine for one-click sign-in"
                  >
                    Needed once for one-click GitHub sign-in
                  </span>
                </div>
                <div className="sw-pair-row">
                  <input
                    className="sw-input"
                    type="text"
                    value={clientIdInput}
                    onChange={e => setClientIdInput(e.target.value)}
                    placeholder="Iv23li…"
                    autoComplete="off"
                    disabled={startingFlow || savingPat}
                    aria-label="GitHub App Client ID"
                  />
                  <button
                    type="button"
                    className="sw-btn primary"
                    disabled={startingFlow || savingPat || clientIdInput.trim().length < 6}
                    onClick={() => void device.start()}
                  >
                    {startingFlow ? 'Starting…' : 'Sign in with GitHub'}
                  </button>
                </div>
              </>
            ) : (
              <div className="sw-pair-top">
                <span className="sw-muted">Switch to a read-only GitHub App Device Flow session.</span>
                <button
                  type="button"
                  className="sw-btn primary"
                  disabled={startingFlow || savingPat}
                  onClick={() => void device.start()}
                >
                  {startingFlow ? 'Starting…' : 'Sign in with GitHub'}
                </button>
              </div>
            )}
          </div>
        )}

        {deviceFlow && (
          <div className="sw-pair-drawer" role="region" aria-label="GitHub device authorization">
            <div className="sw-pair-top">
              <strong>Enter this verification code on GitHub</strong>
              <span className="sw-tag accent sw-num">Polling every {deviceFlow.intervalSec}s</span>
            </div>
            <div className="sw-pair-row" style={{ flexWrap: 'wrap' }}>
              <span
                className="sw-mono"
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  letterSpacing: '0.14em',
                  padding: '5px 12px',
                  borderRadius: 6,
                  background: 'var(--sw-panel)',
                  border: '1px solid var(--sw-line-2)',
                  userSelect: 'all',
                }}
              >
                {deviceFlow.userCode}
              </span>
              <button
                type="button"
                className="sw-btn"
                onClick={() => void device.copyCode()}
              >
                {codeCopied ? 'Copied code' : 'Copy code'}
              </button>
              <a
                className="sw-btn primary"
                href={deviceFlow.verificationUri}
                target="_blank"
                rel="noopener noreferrer"
              >
                Open GitHub verification ↗
              </a>
              <button
                type="button"
                className="sw-btn ghost"
                onClick={() => void device.cancel()}
              >
                Cancel
              </button>
            </div>
            <span className="sw-muted" style={{ fontSize: '11.5px' }}>
              Waiting for GitHub approval… This view updates automatically once authorized.
            </span>
          </div>
        )}

        {showConnectPanel && (
          <div className="sw-sheet-row" style={{ flexDirection: 'column', gap: 8 }}>
            <details style={{ width: '100%' }}>
              <summary style={{ cursor: 'pointer', fontSize: '12.5px', color: 'var(--sw-fg-2)', fontWeight: 500 }}>
                Or connect with a read-only GitHub token
              </summary>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                  <span
                    className="sw-sheet-row-desc"
                    title="Stored privately on this machine"
                  >
                    Scope a read-only token to <strong>Contents: Read-only</strong> and paste it below (stored privately on your machine).
                  </span>
                  <a
                    className="sw-btn sm"
                    href="https://github.com/settings/personal-access-tokens/new"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Create read-only token ↗
                  </a>
                </div>
                <div className="sw-pair-row">
                  <input
                    className="sw-input"
                    type="password"
                    value={patInput}
                    onChange={e => setPatInput(e.target.value)}
                    placeholder="github_pat_…"
                    autoComplete="off"
                    disabled={savingPat || disconnecting}
                    aria-label="Read-only GitHub access token"
                  />
                  <button
                    type="button"
                    className="sw-btn primary"
                    disabled={savingPat || disconnecting || patInput.trim().length < 10}
                    onClick={() => void handleSavePat()}
                  >
                    {savingPat ? 'Saving…' : 'Save token'}
                  </button>
                </div>
              </div>
            </details>
          </div>
        )}

        {displayError && (
          <div role="alert" className="sw-band-foot err">{displayError}</div>
        )}
        {notice && !error && (
          <div role="status" className="sw-band-foot ok">{notice}</div>
        )}
      </div>

      {confirmDisconnect && (
        <div
          className="sw-overlay"
          role="presentation"
          onMouseDown={event => {
            if (event.target === event.currentTarget && !disconnecting) setConfirmDisconnect(false)
          }}
        >
          <div
            className="sw-modal"
            style={{ width: 440 }}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="sw-disconnect-title"
          >
            <div className="sw-modal-h">
              <h2 id="sw-disconnect-title">Disconnect GitHub?</h2>
              <button
                type="button"
                className="sw-btn ghost sm"
                disabled={disconnecting}
                onClick={() => setConfirmDisconnect(false)}
                aria-label="Close"
              >
                <Icon name="close" size={14} />
              </button>
            </div>
            <div className="sw-modal-b">
              <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--sw-fg-2)' }}>
                This removes the saved GitHub credential from this machine. Source sync and repository discovery stop until you connect again.
              </p>
            </div>
            <div className="sw-modal-f">
              <div className="sw-modal-f-acts">
                <button
                  type="button"
                  className="sw-btn ghost"
                  disabled={disconnecting}
                  onClick={() => setConfirmDisconnect(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="sw-btn danger"
                  disabled={disconnecting}
                  onClick={() => {
                    setConfirmDisconnect(false)
                    void handleDisconnect()
                  }}
                >
                  {disconnecting ? 'Disconnecting…' : 'Disconnect'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

function healthLabel(profile: PublicModelProfile): { text: string; tone: 'ok' | 'warn' | 'bad' | 'off' } {
  if (!profile.enabled) return { text: 'Disabled', tone: 'off' }
  if (profile.healthState === 'open') {
    if (profile.cooldownUntil && profile.cooldownUntil > Date.now()) {
      const secs = Math.max(1, Math.ceil((profile.cooldownUntil - Date.now()) / 1000))
      return { text: `Temporarily unavailable (${secs}s)`, tone: 'bad' }
    }
    return { text: 'Temporarily unavailable', tone: 'bad' }
  }
  if (profile.healthState === 'half_open') return { text: 'Recovering', tone: 'warn' }
  return { text: 'Healthy', tone: 'ok' }
}

function poolSummary(profiles: PublicModelProfile[]): { label: string; tone: 'ok' | 'warn' | 'bad' | 'solid' } {
  const enabled = profiles.filter(p => p.enabled)
  if (enabled.length === 0) return { label: 'No model enabled', tone: 'warn' }
  const openCount = enabled.filter(p => p.healthState === 'open').length
  const halfCount = enabled.filter(p => p.healthState === 'half_open').length
  if (openCount === enabled.length) return { label: `All models unavailable · ${enabled.length} of ${profiles.length}`, tone: 'bad' }
  if (openCount > 0 || halfCount > 0) return { label: `Some models unavailable · ${enabled.length} of ${profiles.length} enabled`, tone: 'warn' }
  return { label: `Ready · ${enabled.length} of ${profiles.length} enabled`, tone: 'ok' }
}

function formatK(value: number) {
  if (value >= 1_000_000) {
    const m = value / 1_048_576
    return Number.isInteger(m) ? `${m}M` : `${(value / 1_000_000).toFixed(2).replace(/\.?0+$/, '')}M`
  }
  return value >= 1000 ? `${Math.round(value / 1000)}k` : String(value)
}

function formatRate(value: number) {
  if (value === 0) return '$0'
  if (value < 0.01) return `$${Number(value.toFixed(4))}`
  if (value < 0.1) return `$${Number(value.toFixed(3))}`
  return `$${value.toFixed(2)}`
}

function shortEndpointHost(endpoint: string): string {
  try {
    const url = new URL(endpoint)
    return url.host + (url.pathname && url.pathname !== '/' ? url.pathname : '')
  } catch {
    return endpoint
  }
}

function SettingsWorkbenchPage() {
  const { profiles, githubStatus } = Route.useLoaderData()
  const { runId } = Route.useSearch()
  const navigate = useNavigate()
  const poolAction = useAction()

  const [sheetOpen, setSheetOpen] = useState(false)
  const [editing, setEditing] = useState<PublicModelProfile>()
  const [testingId, setTestingId] = useState<string | null>(null)
  const [pageStatus, setPageStatus] = useState('')
  const [confirmDelete, setConfirmDelete] = useState<PublicModelProfile | null>(null)

  const pool = poolSummary(profiles)
  const enabledCount = profiles.filter(p => p.enabled).length

  function openCreate() {
    setEditing(undefined)
    setPageStatus('')
    setSheetOpen(true)
  }

  function openEdit(profile: PublicModelProfile) {
    setEditing(profile)
    setPageStatus('')
    setSheetOpen(true)
  }

  function handleRowTest(profile: PublicModelProfile) {
    setPageStatus('')
    setTestingId(profile.id)
    void poolAction.submit(
      () => testModel({
        data: {
          id: profile.id,
          name: profile.name,
          endpoint: profile.endpoint,
          model: profile.model,
          protocol: profile.protocol,
          key: '',
          priority: profile.priority,
          enabled: profile.enabled,
          contextWindow: profile.contextWindow,
          maxTokens: profile.maxTokens,
          thinkingLevel: profile.thinkingLevel,
          roleAffinity: profile.roleAffinity,
          inputCostPerMtok: profile.inputCostPerMtok,
          cachedInputCostPerMtok: profile.cachedInputCostPerMtok,
          outputCostPerMtok: profile.outputCostPerMtok,
        },
      }),
      () => {
        setTestingId(null)
        setPageStatus(`${profile.name}: connection verified. The model streamed a valid tool call.`)
      },
    ).finally(() => setTestingId(null))
  }

  return (
    <main className="sw">
      <header className="sw-hdr">
        <div className="sw-hdr-top">
          {runId ? (
            <>
              <Link to="/runs/$runId" params={{ runId }} className="sw-crumb">← Back to run</Link>
              <span className="sw-crumb-sep" aria-hidden="true">/</span>
            </>
          ) : (
            <>
              <Link to="/" className="sw-crumb">Projects</Link>
              <span className="sw-crumb-sep" aria-hidden="true">/</span>
            </>
          )}
          <h1 className="sw-hdr-title">Settings</h1>
          <span className={`sw-tag sw-num ${pool.tone}`}>
            <i className={`sw-dot ${pool.tone === 'solid' ? 'off' : pool.tone}`} aria-hidden="true" />
            {pool.label}
          </span>
          <span className="sw-hdr-sp" />
          {profiles.length > 0 && (
            <div className="sw-hdr-actions">
              <button type="button" className="sw-btn primary" onClick={openCreate}>
                <span aria-hidden="true">+</span>
                Add model profile
              </button>
            </div>
          )}
        </div>
      </header>

      {poolAction.error && (
        <div role="alert" className="sw-banner bad">
          <span className="sw-banner-text">{poolAction.error}</span>
        </div>
      )}
      {pageStatus && !poolAction.error && (
        <div role="status" className="sw-banner ok">
          <span className="sw-banner-text">{pageStatus}</span>
          <button type="button" className="sw-btn ghost sm" onClick={() => setPageStatus('')}>Dismiss</button>
        </div>
      )}

      <div className="sw-body">
        <section className="sw-sec" aria-labelledby="model-pool-heading">
          <div className="sw-sec-head">
            <div>
              <p className="sw-eyebrow">Automatic failover pool</p>
              <h2 id="model-pool-heading" className="sw-sec-title">Model profiles</h2>
            </div>
            <span
              className="sw-sec-meta sw-num"
              title="Keys are stored privately on this machine"
            >
              {profiles.length > 0
                ? `${enabledCount} of ${profiles.length} enabled · highest priority tried first`
                : '0 profiles configured · keys stored privately on your machine'}
            </span>
          </div>

          {profiles.length === 0 ? (
            <div
              className="sw-empty-sheet"
              style={{
                flexDirection: 'column',
                justifyContent: 'center',
                textAlign: 'center',
                padding: '40px 24px',
                gap: 14,
              }}
            >
              <ModelProfilesEmptyIllustration />
              <div>
                <h3>No model profiles configured</h3>
                <p>
                  Connect OpenRouter or any OpenAI / Anthropic compatible provider so Kovo Hunter can map attack surfaces,
                  investigate security issues, and verify findings.
                </p>
              </div>
              <button type="button" className="sw-btn primary" onClick={openCreate}>
                Add model profile
              </button>
            </div>
          ) : (
            <div className="sw-table-wrap">
              <table className="sw-table" aria-label="Configured model profiles">
                <thead>
                  <tr>
                    <th>Profile &amp; model</th>
                    <th>Status</th>
                    <th>Priority &amp; limits</th>
                    <th>Pricing (per 1M)</th>
                    <th className="right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {profiles.map(profile => {
                    const status = healthLabel(profile)
                    const isRowTesting = testingId === profile.id && poolAction.pending
                    const updated = formatHumanTime(profile.updatedAt)
                    return (
                      <tr key={profile.id} data-enabled={profile.enabled}>
                        <td>
                          <div className="sw-prof-main">
                            <div className="sw-prof-top">
                              <span className="sw-prof-name">{profile.name}</span>
                              <span className="sw-prof-model sw-mono" title={profile.model}>{profile.model}</span>
                            </div>
                            <div className="sw-prof-sub">
                              <span>{profile.protocol === 'messages' ? 'Anthropic Messages' : 'OpenAI Responses'}</span>
                              <span aria-hidden="true">·</span>
                              <span className="sw-mono" title={profile.endpoint}>{shortEndpointHost(profile.endpoint)}</span>
                              <span aria-hidden="true">·</span>
                              <span>Role: {profile.roleAffinity ?? 'any'}</span>
                              {updated.label && (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span className="sw-num" title={updated.full}>Updated {updated.label}</span>
                                </>
                              )}
                            </div>
                            {profile.lastError && (
                              <span className="sw-prof-err" title={profile.lastError}>
                                Last error: {profile.lastError}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span
                            className={`sw-status-cell ${status.tone}`}
                            title={profile.healthState === 'closed' ? 'Healthy' : status.text}
                          >
                            <i className={`sw-dot ${status.tone}`} aria-hidden="true" />
                            {status.text}
                          </span>
                        </td>
                        <td>
                          <div className="sw-meta-stack sw-num">
                            <span>Priority {profile.priority}</span>
                            <small>
                              {formatK(profile.contextWindow)} ctx · {formatK(profile.maxTokens)} out · {profile.thinkingLevel}
                            </small>
                          </div>
                        </td>
                        <td>
                          <div className="sw-meta-stack sw-num">
                            <span>
                              {formatRate(profile.inputCostPerMtok)} in · {formatRate(profile.outputCostPerMtok)} out
                            </span>
                            <small>{formatRate(profile.cachedInputCostPerMtok)} cached</small>
                          </div>
                        </td>
                        <td className="right">
                          <div className="sw-row-acts">
                            <button
                              type="button"
                              className="sw-btn sm"
                              disabled={poolAction.pending}
                              onClick={() => handleRowTest(profile)}
                            >
                              {isRowTesting ? 'Testing…' : 'Test'}
                            </button>
                            <button
                              type="button"
                              className="sw-btn ghost sm"
                              disabled={poolAction.pending}
                              onClick={() => openEdit(profile)}
                            >
                              Edit
                            </button>
                            <button
                              type="button"
                              className="sw-btn ghost sm"
                              disabled={poolAction.pending}
                              onClick={() => {
                                setPageStatus('')
                                void poolAction.submit(
                                  () => toggleModelProfile({ data: { profileId: profile.id, enabled: !profile.enabled } }),
                                  () => setPageStatus(`${profile.name} ${profile.enabled ? 'disabled' : 'enabled'}.`),
                                )
                              }}
                            >
                              {profile.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button
                              type="button"
                              className="sw-btn danger-ghost sm"
                              disabled={poolAction.pending}
                              onClick={() => {
                                setPageStatus('')
                                setConfirmDelete(profile)
                              }}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <GithubConnectionBand initialStatus={githubStatus} />
      </div>

      <ModelProfileSheet
        open={sheetOpen}
        editing={editing}
        profiles={profiles}
        onClose={() => {
          setSheetOpen(false)
          setEditing(undefined)
        }}
        onSaved={async message => {
          setSheetOpen(false)
          setEditing(undefined)
          setPageStatus(message)
          if (runId) await navigate({ to: '/runs/$runId', params: { runId } })
        }}
      />

      {confirmDelete && (
        <div
          className="sw-overlay"
          role="presentation"
          onMouseDown={event => {
            if (event.target === event.currentTarget && !poolAction.pending) setConfirmDelete(null)
          }}
        >
          <div
            className="sw-modal"
            style={{ width: 440 }}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="sw-delete-profile-title"
          >
            <div className="sw-modal-h">
              <h2 id="sw-delete-profile-title">Delete model profile?</h2>
              <button
                type="button"
                className="sw-btn ghost sm"
                disabled={poolAction.pending}
                onClick={() => setConfirmDelete(null)}
                aria-label="Close"
              >
                <Icon name="close" size={14} />
              </button>
            </div>
            <div className="sw-modal-b">
              <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--sw-fg-2)' }}>
                Remove <strong style={{ color: 'var(--sw-fg)' }}>{confirmDelete.name}</strong> from the failover pool. Its saved API key is deleted from this machine and cannot be recovered.
              </p>
            </div>
            <div className="sw-modal-f">
              <div className="sw-modal-f-acts">
                <button
                  type="button"
                  className="sw-btn ghost"
                  disabled={poolAction.pending}
                  onClick={() => setConfirmDelete(null)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="sw-btn danger"
                  disabled={poolAction.pending}
                  onClick={() => {
                    const profile = confirmDelete
                    void poolAction.submit(
                      () => removeModelProfile({ data: { profileId: profile.id } }),
                      () => {
                        if (editing?.id === profile.id) {
                          setEditing(undefined)
                          setSheetOpen(false)
                        }
                        setConfirmDelete(null)
                        setPageStatus(`${profile.name} deleted.`)
                      },
                    )
                  }}
                >
                  {poolAction.pending ? 'Deleting…' : 'Delete profile'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}
