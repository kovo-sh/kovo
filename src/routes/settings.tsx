import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { listModels, removeModelProfile, saveModel, testModel, toggleModelProfile } from '../actions.ts'
import { FormError, Status, timeText, useAction } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible.tsx'
import { Input, NativeSelect } from '../components/ui/input.tsx'
import { DEFAULT_PROVIDER, id, thinkingLevels } from '../domain.ts'
import type { PublicModelProfile, ThinkingLevel } from '../domain.ts'

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
          <span>Thinking <strong>{profile.thinkingLevel}</strong></span>
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
      <div className="field-grid-2">
        <label>Profile name<Input name="name" required maxLength={160} defaultValue={defaults.name} /></label>
        <label>Priority (higher tried first)
          <Input name="priority" type="number" min={0} max={1000} step={1} required defaultValue={defaults.priority} />
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
  </main>
}
