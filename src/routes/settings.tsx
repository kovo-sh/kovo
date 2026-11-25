import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { listModels, removeModelProfile, testModel, toggleModelProfile } from '../actions.ts'
import { timeText, useAction } from '../components/common.tsx'
import { DevicesSessionBand } from '../components/settings/DevicesSessionBand.tsx'
import { ModelProfileSheet } from '../components/settings/ModelProfileSheet.tsx'
import '../components/settings/settings.css'
import { id } from '../domain.ts'
import type { PublicModelProfile } from '../domain.ts'

export const Route = createFileRoute('/settings')({
  validateSearch: (search): { runId?: string } => ({ runId: id.safeParse(search.runId).data }),
  loader: () => listModels(),
  component: SettingsWorkbenchPage,
})

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
  const profiles = Route.useLoaderData()
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
          <h1 className="sw-hdr-title">Model &amp; Device Settings</h1>
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

        <DevicesSessionBand />
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
