import { createFileRoute, Link, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import {
  cancelGithubDeviceFlowAction,
  clearGithubToken,
  getGithubStatus,
  listModels,
  pollGithubDeviceFlowAction,
  removeModelProfile,
  saveGithubToken,
  startGithubDeviceFlowAction,
  testModel,
  toggleModelProfile,
} from '../actions.ts'
import { timeText, useAction } from '../components/common.tsx'
import { ModelProfileSheet } from '../components/settings/ModelProfileSheet.tsx'
import '../components/settings/settings.css'
import { id } from '../domain.ts'
import type { PublicModelProfile } from '../domain.ts'

export const Route = createFileRoute('/settings')({
  validateSearch: (search): { runId?: string } => ({ runId: id.safeParse(search.runId).data }),
  loader: async () => {
    const [profiles, githubStatus] = await Promise.all([listModels(), getGithubStatus()])
    return { profiles, githubStatus }
  },
  component: SettingsWorkbenchPage,
})

type GithubStatusData = Awaited<ReturnType<typeof getGithubStatus>>

interface ActiveDeviceFlow {
  flowId: string
  userCode: string
  verificationUri: string
  expiresIn: number
  intervalSec: number
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

function githubConnectionSummary(status: GithubStatusData): { label: string; tone: 'ok' | 'solid' } {
  if (!status.configured) return { label: 'Not connected', tone: 'solid' }
  if (status.authKind === 'github_app_device') {
    return {
      label: status.login ? `Connected via GitHub App · @${status.login}` : 'Connected via GitHub App',
      tone: 'ok',
    }
  }
  const kind = status.tokenKind === 'fine_grained'
    ? 'Fine-grained PAT'
    : status.tokenKind === 'classic'
      ? 'Classic PAT'
      : 'GitHub PAT'
  return {
    label: status.source === 'fixture' ? `${kind} · fixture` : `${kind} saved`,
    tone: 'ok',
  }
}

function GithubConnectionBand({ initialStatus }: { initialStatus: GithubStatusData }) {
  const router = useRouter()
  const [status, setStatus] = useState<GithubStatusData>(initialStatus)
  const [reconnecting, setReconnecting] = useState(false)
  const [clientIdInput, setClientIdInput] = useState('')
  const [deviceFlow, setDeviceFlow] = useState<ActiveDeviceFlow | null>(null)
  const [startingFlow, setStartingFlow] = useState(false)
  const [codeCopied, setCodeCopied] = useState(false)
  const [patInput, setPatInput] = useState('')
  const [savingPat, setSavingPat] = useState(false)
  const [disconnecting, setDisconnecting] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const activeFlowIdRef = useRef<string | null>(null)

  useEffect(() => {
    setStatus(initialStatus)
  }, [initialStatus])

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
          setReconnecting(false)
          setCodeCopied(false)
          setClientIdInput('')
          setError('')
          setStatus(res.accountStatus)
          const who = res.login ? ` · @${res.login}` : ''
          setNotice(`Connected via GitHub App${who}. Found ${res.repoCount} accessible ${res.repoCount === 1 ? 'repository' : 'repositories'}.`)
          await router.invalidate()
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
  }, [deviceFlow?.flowId, router])

  async function handleStartDeviceFlow() {
    if (startingFlow || savingPat || disconnecting) return
    const trimmedClientId = clientIdInput.trim()
    if (!status.githubDeviceFlowConfigured && trimmedClientId.length < 6) {
      setError('Enter your GitHub App Client ID (or set GUARDIAN_GITHUB_CLIENT_ID) to start sign-in.')
      return
    }
    setStartingFlow(true)
    setError('')
    setNotice('')
    setCodeCopied(false)
    try {
      const started = await startGithubDeviceFlowAction({
        data: trimmedClientId ? { clientId: trimmedClientId } : undefined,
      })
      setDeviceFlow(started)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start GitHub Device Flow.')
    } finally {
      setStartingFlow(false)
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
      setNotice(`Fine-Grained PAT saved to local 0600 vault. Found ${res.repos.length} accessible ${res.repos.length === 1 ? 'repository' : 'repositories'}.`)
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
        ? 'Removed saved vault credential (fallback fixture PAT is still present).'
        : 'Disconnected GitHub from local 0600 vault.')
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
          <p className="sw-eyebrow">Grey-box source &amp; CVE sync</p>
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
              {status.configured ? 'Read-only GitHub connection' : 'Sign in with GitHub (Device Flow)'}
            </span>
            <p className="sw-sheet-row-desc">
              {status.configured && status.authKind === 'github_app_device'
                ? 'Authorized via read-only GitHub App (Contents: Read-only, Metadata: Read-only). Expiring tokens refresh automatically in your local 0600 vault.'
                : status.configured
                  ? 'Connected using a local 0600 GitHub personal access token for read-only repository syncing.'
                  : 'Connect a read-only GitHub App using OAuth Device Flow with automatic silent token refresh in your local 0600 vault.'}
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
                    onClick={() => void handleDisconnect()}
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
                onClick={() => void handleStartDeviceFlow()}
              >
                {startingFlow ? 'Starting…' : 'Sign in with GitHub'}
              </button>
            ) : null}
          </div>
        </div>

        {showConnectPanel && !deviceFlow && (!status.githubDeviceFlowConfigured || reconnecting) && (
          <div className="sw-pair-drawer">
            {!status.githubDeviceFlowConfigured ? (
              <>
                <div className="sw-pair-top">
                  <strong>GitHub App Client ID</strong>
                  <span className="sw-muted">Or set <code>GUARDIAN_GITHUB_CLIENT_ID</code> for 1-click sign-in</span>
                </div>
                <div className="sw-pair-row">
                  <input
                    className="sw-input"
                    type="text"
                    value={clientIdInput}
                    onChange={e => { setClientIdInput(e.target.value); setError('') }}
                    placeholder="Iv23li…"
                    autoComplete="off"
                    disabled={startingFlow || savingPat}
                    aria-label="GitHub App Client ID"
                  />
                  <button
                    type="button"
                    className="sw-btn primary"
                    disabled={startingFlow || savingPat || clientIdInput.trim().length < 6}
                    onClick={() => void handleStartDeviceFlow()}
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
                  onClick={() => void handleStartDeviceFlow()}
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
                onClick={() => void copyText(deviceFlow.userCode).then(ok => setCodeCopied(ok))}
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
                onClick={() => void handleCancelDeviceFlow()}
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
                Or connect with a Fine-Grained PAT
              </summary>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                  <span className="sw-sheet-row-desc">
                    Scope a Fine-Grained PAT to <strong>Contents: Read-only</strong> and paste it below (stored in local <code>0600</code> vault).
                  </span>
                  <a
                    className="sw-btn sm"
                    href="https://github.com/settings/personal-access-tokens/new"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Create Fine-Grained PAT ↗
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
                    aria-label="GitHub Personal Access Token"
                  />
                  <button
                    type="button"
                    className="sw-btn primary"
                    disabled={savingPat || disconnecting || patInput.trim().length < 10}
                    onClick={() => void handleSavePat()}
                  >
                    {savingPat ? 'Saving…' : 'Save PAT'}
                  </button>
                </div>
              </div>
            </details>
          </div>
        )}

        {error && (
          <div role="alert" className="sw-band-foot err">{error}</div>
        )}
        {notice && !error && (
          <div role="status" className="sw-band-foot ok">{notice}</div>
        )}
      </div>
    </section>
  )
}

function healthLabel(profile: PublicModelProfile): { text: string; tone: 'ok' | 'warn' | 'bad' | 'off' } {
  if (!profile.enabled) return { text: 'Disabled', tone: 'off' }
  if (profile.healthState === 'open') {
    if (profile.cooldownUntil && profile.cooldownUntil > Date.now()) {
      const secs = Math.max(1, Math.ceil((profile.cooldownUntil - Date.now()) / 1000))
      return { text: `Circuit open (${secs}s)`, tone: 'bad' }
    }
    return { text: 'Circuit open', tone: 'bad' }
  }
  if (profile.healthState === 'half_open') return { text: 'Half-open', tone: 'warn' }
  return { text: 'Healthy', tone: 'ok' }
}

function poolSummary(profiles: PublicModelProfile[]): { label: string; tone: 'ok' | 'warn' | 'bad' | 'solid' } {
  const enabled = profiles.filter(p => p.enabled)
  if (enabled.length === 0) return { label: 'No active model', tone: 'warn' }
  const openCount = enabled.filter(p => p.healthState === 'open').length
  const halfCount = enabled.filter(p => p.healthState === 'half_open').length
  if (openCount === enabled.length) return { label: `Pool open · ${enabled.length} of ${profiles.length}`, tone: 'bad' }
  if (openCount > 0 || halfCount > 0) return { label: `Degraded · ${enabled.length} of ${profiles.length} enabled`, tone: 'warn' }
  return { label: `Healthy · ${enabled.length} of ${profiles.length} enabled`, tone: 'ok' }
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
          <div className="sw-hdr-actions">
            <button type="button" className="sw-btn primary" onClick={openCreate}>
              <span aria-hidden="true">+</span>
              Add model profile
            </button>
          </div>
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
              <p className="sw-eyebrow">Multi-profile failover pool</p>
              <h2 id="model-pool-heading" className="sw-sec-title">Model profiles</h2>
            </div>
            <span className="sw-sec-meta sw-num">
              {profiles.length > 0
                ? `${enabledCount} of ${profiles.length} enabled · highest priority tried first`
                : '0 profiles configured · 0600 local credentials'}
            </span>
          </div>

          {profiles.length === 0 ? (
            <div className="sw-empty-sheet">
              <div>
                <h3>No model profiles configured</h3>
                <p>
                  Connect OpenRouter or any OpenAI Responses / Anthropic Messages provider to run autonomous
                  investigations, threat modeling, and proof verification.
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
                    return (
                      <tr key={profile.id} data-enabled={profile.enabled}>
                        <td>
                          <div className="sw-prof-main">
                            <div className="sw-prof-top">
                              <span className="sw-prof-name">{profile.name}</span>
                              <span className="sw-tag solid sw-mono">{profile.model}</span>
                              <span className="sw-tag">
                                {profile.protocol === 'messages' ? 'Anthropic' : 'Responses'}
                              </span>
                              {profile.roleAffinity && profile.roleAffinity !== 'any' && (
                                <span className="sw-tag accent">{profile.roleAffinity}</span>
                              )}
                            </div>
                            <div className="sw-prof-sub">
                              <span className="sw-mono" title={profile.endpoint}>{shortEndpointHost(profile.endpoint)}</span>
                              <span aria-hidden="true">·</span>
                              <span>Role: {profile.roleAffinity ?? 'any'}</span>
                              <span aria-hidden="true">·</span>
                              <span className="sw-num">Updated {timeText(profile.updatedAt)}</span>
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
                            title={profile.healthState === 'closed' ? 'Circuit breaker closed' : status.text}
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
                                void poolAction.submit(
                                  () => removeModelProfile({ data: { profileId: profile.id } }),
                                  () => {
                                    if (editing?.id === profile.id) {
                                      setEditing(undefined)
                                      setSheetOpen(false)
                                    }
                                    setPageStatus(`${profile.name} deleted.`)
                                  },
                                )
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
    </main>
  )
}
