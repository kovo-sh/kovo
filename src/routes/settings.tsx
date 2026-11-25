import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useRef, useState } from 'react'
import { listModels, removeModelProfile, saveModel, testModel, toggleModelProfile } from '../actions.ts'
import { FormError, Status, timeText, useAction } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible.tsx'
import { Input, NativeSelect } from '../components/ui/input.tsx'
import { DEFAULT_PROVIDER, id, roleAffinities, thinkingLevels } from '../domain.ts'
import type { PublicModelProfile, RoleAffinity, ThinkingLevel } from '../domain.ts'

export const Route = createFileRoute('/settings')({
  validateSearch: (search): { runId?: string } => ({ runId: id.safeParse(search.runId).data }),
  loader: () => listModels(),
  component: ModelPage,
})

function healthLabel(profile: PublicModelProfile) {
  if (profile.healthState === 'open') {
    if (profile.cooldownUntil && profile.cooldownUntil > Date.now()) {
      const secs = Math.max(1, Math.ceil((profile.cooldownUntil - Date.now()) / 1000))
      return `Circuit open (${secs}s cooldown)`
    }
    return 'Circuit open'
  }
  if (profile.healthState === 'half_open') return 'Half-open (probing)'
  return 'Healthy'
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

function ModelPage() {
  const profiles = Route.useLoaderData()
  const { runId } = Route.useSearch()
  const navigate = useNavigate()
  const action = useAction()
  const poolAction = useAction()
  const [feedback, setFeedback] = useState('')
  const [editing, setEditing] = useState<PublicModelProfile>()
  const [formKey, setFormKey] = useState(0)

  const activeCount = profiles.filter(p => p.enabled).length
  const defaults = editing ?? {
    name: profiles.length === 0 ? DEFAULT_PROVIDER.name : `Fallback profile ${profiles.length + 1}`,
    endpoint: DEFAULT_PROVIDER.endpoint,
    model: DEFAULT_PROVIDER.model,
    protocol: DEFAULT_PROVIDER.protocol,
    priority: profiles.length === 0 ? 100 : Math.max(10, Math.min(...profiles.map(p => p.priority)) - 10),
    enabled: true,
    contextWindow: DEFAULT_PROVIDER.contextWindow,
    maxTokens: DEFAULT_PROVIDER.maxTokens,
    thinkingLevel: DEFAULT_PROVIDER.thinkingLevel,
    roleAffinity: DEFAULT_PROVIDER.roleAffinity,
    inputCostPerMtok: DEFAULT_PROVIDER.inputCostPerMtok,
    cachedInputCostPerMtok: DEFAULT_PROVIDER.cachedInputCostPerMtok,
    outputCostPerMtok: DEFAULT_PROVIDER.outputCostPerMtok,
  }

  function startEdit(profile: PublicModelProfile) {
    setEditing(profile)
    setFeedback('')
    setFormKey(k => k + 1)
  }

  function cancelEdit() {
    setEditing(undefined)
    setFeedback('')
    setFormKey(k => k + 1)
  }

  return <main className="workspace-page">
    {runId ? <Link to="/runs/$runId" params={{ runId }} className="back-link">← Back to run</Link>
      : <Link to="/" className="back-link">← Projects</Link>}
    <div className="page-title">
      <div>
        <p className="eyebrow">Multi-profile failover pool</p>
        <h1>Model settings</h1>
      </div>
      {profiles.length > 0 && <span className="badge badge-accent">{activeCount} of {profiles.length} enabled</span>}
    </div>

    {profiles.length > 0 && <section className="profile-list" aria-label="Configured model profiles">
      {profiles.map(profile => <article key={profile.id} className="profile-card" data-enabled={profile.enabled}>
        <div className="section-heading">
          <div className="inline-badges">
            <strong>{profile.name}</strong>
            <span className="badge badge-accent">Priority {profile.priority}</span>
            {!profile.enabled && <span className="badge">Disabled</span>}
            <span
              className="state"
              data-status={profile.healthState}
              title={profile.healthState === 'closed' ? 'Circuit breaker closed' : healthLabel(profile)}
            >
              <i aria-hidden="true" />
              {healthLabel(profile)}
            </span>
          </div>
          <div className="toolbar">
            <Button variant="ghost" disabled={poolAction.pending} onClick={() => {
              void poolAction.submit(() => toggleModelProfile({ data: { profileId: profile.id, enabled: !profile.enabled } }))
            }}>{profile.enabled ? 'Disable' : 'Enable'}</Button>
            <Button variant="ghost" disabled={poolAction.pending} onClick={() => startEdit(profile)}>Edit</Button>
            <Button variant="ghost" className="btn-danger" disabled={poolAction.pending} onClick={() => {
              void poolAction.submit(() => removeModelProfile({ data: { profileId: profile.id } }), () => {
                if (editing?.id === profile.id) cancelEdit()
              })
            }}>Delete</Button>
          </div>
        </div>
        <div className="profile-meta">
          <span>Model <code>{profile.model}</code></span>
          <span>Endpoint <code>{profile.endpoint}</code></span>
          <span>Protocol <strong>{profile.protocol === 'messages' ? 'Anthropic Messages' : 'OpenAI Responses'}</strong></span>
          <span>Window <strong>{formatK(profile.contextWindow)}</strong></span>
          <span>Max out <strong>{formatK(profile.maxTokens)}</strong></span>
          <span>Thinking <strong>{profile.thinkingLevel}</strong>{' '}</span>
          <span>Role <strong>{profile.roleAffinity ?? 'any'}</strong>{' '}</span>
          <span>Cost <strong>{formatRate(profile.inputCostPerMtok)} in · {formatRate(profile.cachedInputCostPerMtok)} cached · {formatRate(profile.outputCostPerMtok)} out</strong> / Mtok</span>
          <span>Updated {timeText(profile.updatedAt)}</span>
        </div>
        {profile.lastError && <p className="profile-error">Last error: {profile.lastError}</p>}
      </article>)}
      <FormError error={poolAction.error} />
    </section>}

    <form key={formKey} className="form-card" onInput={() => setFeedback('')} onSubmit={event => {
      event.preventDefault()
      setFeedback('')
      const form = new FormData(event.currentTarget)
      const command = (event.nativeEvent as SubmitEvent).submitter?.getAttribute('value')
      const thinkingRaw = String(form.get('thinkingLevel') ?? DEFAULT_PROVIDER.thinkingLevel)
      const thinkingLevel = (thinkingLevels as readonly string[]).includes(thinkingRaw)
        ? thinkingRaw as ThinkingLevel : DEFAULT_PROVIDER.thinkingLevel
      const roleRaw = String(form.get('roleAffinity') ?? DEFAULT_PROVIDER.roleAffinity)
      const roleAffinity = (roleAffinities as readonly string[]).includes(roleRaw)
        ? roleRaw as RoleAffinity : DEFAULT_PROVIDER.roleAffinity
      const data = {
        ...(editing ? { id: editing.id } : {}),
        name: String(form.get('name') ?? '').trim() || DEFAULT_PROVIDER.name,
        endpoint: String(form.get('endpoint')),
        model: String(form.get('model')),
        protocol: form.get('protocol') === 'messages' ? 'messages' as const : 'responses' as const,
        key: String(form.get('key')),
        priority: Number(form.get('priority') ?? 100),
        enabled: form.has('enabled'),
        contextWindow: Number(form.get('contextWindow') ?? DEFAULT_PROVIDER.contextWindow),
        maxTokens: Number(form.get('maxTokens') ?? DEFAULT_PROVIDER.maxTokens),
        thinkingLevel,
        roleAffinity,
        inputCostPerMtok: Number(form.get('inputCostPerMtok') ?? DEFAULT_PROVIDER.inputCostPerMtok),
        cachedInputCostPerMtok: Number(form.get('cachedInputCostPerMtok') ?? DEFAULT_PROVIDER.cachedInputCostPerMtok),
        outputCostPerMtok: Number(form.get('outputCostPerMtok') ?? DEFAULT_PROVIDER.outputCostPerMtok),
      }
      const element = event.currentTarget
      void action.submit(() => command === 'test' ? testModel({ data }) : saveModel({ data }), async () => {
        setFeedback(command === 'test'
          ? 'Connection verified. The model streamed a valid tool call.'
          : editing ? 'Model profile updated.' : 'Model profile added to failover pool.')
        if (command !== 'test') {
          const input = element.elements.namedItem('key') as HTMLInputElement | null
          if (input) input.value = ''
          setEditing(undefined)
          setFormKey(k => k + 1)
          if (runId) await navigate({ to: '/runs/$runId', params: { runId } })
        }
      })
    }}>
      <div className="section-heading">
        <h2>{editing ? `Edit profile · ${editing.name}` : profiles.length ? 'Add failover profile' : 'Connect OpenRouter'}</h2>
        {editing && <Button variant="ghost" onClick={cancelEdit}>Cancel edit</Button>}
      </div>
      <div className="field-grid-3">
        <label>Profile name<Input name="name" required maxLength={160} defaultValue={defaults.name} /></label>
        <label>Priority (higher tried first)
          <Input name="priority" type="number" min={0} max={1000} step={1} required defaultValue={defaults.priority} />
        </label>
        <label>Role affinity
          <NativeSelect name="roleAffinity" defaultValue={defaults.roleAffinity}>
            <option value="any">Any (all roles)</option>
            <option value="reasoning">Reasoning (audit, repair, patch)</option>
            <option value="tactical">Tactical (specialists, planner)</option>
            <option value="fast">Fast (triage, dedupe)</option>
          </NativeSelect>
        </label>
      </div>
      <label>API key {editing && <span className="muted">(optional — leave blank to keep stored key)</span>}
        <Input name="key" type="password" required={!editing} minLength={editing ? undefined : 8} maxLength={512} autoComplete="off"
          placeholder={editing ? 'Leave blank to keep existing API key' : 'Enter your provider key'} />
        <span className="muted">Stored locally in 0600 credential files; never returned to the browser or target containers.</span>
      </label>
      <label className="checkbox">
        <Checkbox name="enabled" defaultChecked={defaults.enabled} aria-label="Enable this profile in the failover pool" />
        Enable this profile in the failover pool
      </label>
      <Collapsible className="provider-advanced" defaultOpen={Boolean(editing)}>
        <CollapsibleTrigger render={<Button variant="ghost" className="collapsible-trigger" />}>Advanced provider settings</CollapsibleTrigger>
        <CollapsibleContent keepMounted>
          <div className="field-grid">
            <div className="field-grid-2">
              <label>Model ID<Input name="model" required defaultValue={defaults.model} /></label>
              <label>Protocol<NativeSelect name="protocol" defaultValue={defaults.protocol}>
                <option value="responses">OpenAI Responses</option>
                <option value="messages">Anthropic Messages</option>
              </NativeSelect></label>
            </div>
            <label>Base URL<Input name="endpoint" type="url" required defaultValue={defaults.endpoint} /></label>
            <div className="field-grid-3">
              <label>Context window
                <Input name="contextWindow" type="number" min={32000} max={2000000} step={1} required defaultValue={defaults.contextWindow} />
              </label>
              <label>Max output tokens
                <Input name="maxTokens" type="number" min={512} max={393216} step={1} required defaultValue={defaults.maxTokens} />
              </label>
              <label>Thinking level
                <NativeSelect name="thinkingLevel" defaultValue={defaults.thinkingLevel}>
                  <option value="off">Off</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </NativeSelect>
              </label>
            </div>
            <div className="field-grid-3">
              <label>Input cost ($ / 1M tokens)
                <Input name="inputCostPerMtok" type="number" min={0} max={500} step="any" required defaultValue={defaults.inputCostPerMtok} />
              </label>
              <label>Cached input ($ / 1M tokens)
                <Input name="cachedInputCostPerMtok" type="number" min={0} max={500} step="any" required defaultValue={defaults.cachedInputCostPerMtok} />
              </label>
              <label>Output cost ($ / 1M tokens)
                <Input name="outputCostPerMtok" type="number" min={0} max={500} step="any" required defaultValue={defaults.outputCostPerMtok} />
              </label>
            </div>
          </div>
        </CollapsibleContent>
      </Collapsible>
      <p className="muted">Providers receive redacted context and evidence excerpts. Failover triggers only before a turn emits output.</p>
      <FormError error={action.error} />
      {feedback && <p role="status">{feedback}</p>}
      <div className="form-actions">
        <Button type="submit" value="test" disabled={action.pending}>Test connection</Button>
        <Button type="submit" value="save" variant="default" disabled={action.pending}>
          {editing ? 'Update profile' : 'Save model'}
        </Button>
      </div>
    </form>

    <DevicesSessionSection />
  </main>
}

interface PairingLinkResponse {
  url: string
  expiresAt: string
  ttlSeconds: number
}

async function copyTextToClipboard(text: string): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) return false
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

async function readAuthError(response: Response, fallback: string): Promise<string> {
  if (response.status === 401) return 'Local session expired. Open Guardian using the startup login URL.'
  if (response.status === 404) return 'Local session controls are only available when running the Guardian local server.'
  try {
    const contentType = response.headers.get('content-type') ?? ''
    if (contentType.includes('application/json')) {
      const body = await response.json() as { error?: string }
      if (body.error) return body.error
    } else {
      const text = (await response.text()).trim()
      if (text) return text
    }
  } catch {
    // Fall back to default message
  }
  return fallback
}

function DevicesSessionSection() {
  const [pairingPending, setPairingPending] = useState(false)
  const [pairingLink, setPairingLink] = useState<PairingLinkResponse | null>(null)
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'fallback'>('idle')
  const [rotatePending, setRotatePending] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const urlInputRef = useRef<HTMLInputElement | null>(null)

  async function handleMintPairingLink() {
    if (pairingPending) return
    setPairingPending(true)
    setErrorMessage('')
    setStatusMessage('')
    try {
      const response = await fetch('/_guardian/auth/pairing-link', {
        method: 'POST',
        credentials: 'same-origin',
      })
      if (!response.ok) {
        throw new Error(await readAuthError(response, 'Could not generate a one-time login link.'))
      }
      const data = await response.json() as PairingLinkResponse
      setPairingLink(data)
      const copied = await copyTextToClipboard(data.url)
      if (copied) {
        setCopyState('copied')
        setStatusMessage('One-time login link copied to clipboard.')
      } else {
        setCopyState('fallback')
        setStatusMessage('Clipboard access was denied. Use the Copy button or copy the link below manually.')
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not generate a one-time login link.')
    } finally {
      setPairingPending(false)
    }
  }

  async function handleCopyExisting() {
    if (!pairingLink) return
    setErrorMessage('')
    const copied = await copyTextToClipboard(pairingLink.url)
    if (copied) {
      setCopyState('copied')
      setStatusMessage('One-time login link copied to clipboard.')
      return
    }
    urlInputRef.current?.focus()
    urlInputRef.current?.select()
    let execCopied = false
    try {
      execCopied = typeof document !== 'undefined' && document.execCommand('copy')
    } catch {
      execCopied = false
    }
    if (execCopied) {
      setCopyState('copied')
      setStatusMessage('One-time login link copied to clipboard.')
    } else {
      setCopyState('fallback')
      setStatusMessage('Select the link above and press Ctrl+C / Cmd+C to copy.')
    }
  }

  async function handleRotateSession() {
    if (rotatePending) return
    setRotatePending(true)
    setErrorMessage('')
    setStatusMessage('')
    try {
      const response = await fetch('/_guardian/auth/rotate-session', {
        method: 'POST',
        credentials: 'same-origin',
      })
      if (!response.ok) {
        throw new Error(await readAuthError(response, 'Could not sign out other devices.'))
      }
      setConfirmRotate(false)
      setPairingLink(null)
      setCopyState('idle')
      setStatusMessage('All other devices have been signed out and pending login links cleared. This browser stays signed in.')
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not sign out other devices.')
    } finally {
      setRotatePending(false)
    }
  }

  return <section className="form-card stacked-section" aria-labelledby="devices-session-heading">
    <div className="section-heading">
      <div>
        <p className="eyebrow">Multi-device local access</p>
        <h2 id="devices-session-heading">Devices &amp; local session</h2>
      </div>
      <span className="badge">Owner session active</span>
    </div>

    <p className="muted">
      Sign in another browser on this machine or via your configured HTTPS proxy without exposing your long-lived session file.
      Single-use link expires in 5 minutes — never shares your permanent session cookie.
    </p>

    <div className="toolbar" style={{ flexWrap: 'wrap', gap: '10px' }}>
      <Button type="button" variant="default" disabled={pairingPending || rotatePending} onClick={() => void handleMintPairingLink()}>
        {pairingPending ? 'Generating link…' : 'Copy login link for another device'}
      </Button>
      {!confirmRotate && (
        <Button
          type="button"
          variant="outline"
          className="btn-danger"
          disabled={rotatePending || pairingPending}
          onClick={() => {
            setErrorMessage('')
            setStatusMessage('')
            setConfirmRotate(true)
          }}
        >
          Sign out other devices
        </Button>
      )}
    </div>

    {pairingLink && (
      <div className="inline-personas-box">
        <div className="section-heading">
          <strong>One-time device login link</strong>
          <span className="badge badge-attention">
            Expires {timeText(Date.parse(pairingLink.expiresAt))}
          </span>
        </div>
        <div className="curl-parse-row">
          <Input
            ref={urlInputRef}
            readOnly
            aria-label="One-time device login URL"
            value={pairingLink.url}
            onFocus={event => event.currentTarget.select()}
          />
          <Button type="button" variant="outline" onClick={() => void handleCopyExisting()}>
            {copyState === 'copied' ? 'Copied' : 'Copy'}
          </Button>
        </div>
        <p className="muted small-note">
          Single-use link expires in 5 minutes — never shares your permanent session cookie.
        </p>
      </div>
    )}

    {confirmRotate && (
      <div className="inline-personas-box" role="region" aria-label="Confirm sign out other devices">
        <p>
          <strong>Sign out all other devices?</strong> This rotates the local session token, immediately revokes every other browser,
          and invalidates any unused login links. This browser remains signed in.
        </p>
        <div className="toolbar">
          <Button
            type="button"
            variant="outline"
            className="btn-danger"
            disabled={rotatePending}
            onClick={() => void handleRotateSession()}
          >
            {rotatePending ? 'Signing out…' : 'Confirm sign out'}
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={rotatePending}
            onClick={() => setConfirmRotate(false)}
          >
            Cancel
          </Button>
        </div>
      </div>
    )}

    <FormError error={errorMessage} />
    {statusMessage && <p role="status">{statusMessage}</p>}
  </section>
}
