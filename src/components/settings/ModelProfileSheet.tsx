import { useEffect, useState } from 'react'
import { saveModel, testModel } from '../../actions.ts'
import { useAction } from '../common.tsx'
import { DEFAULT_PROVIDER, roleAffinities, thinkingLevels } from '../../domain.ts'
import type { PublicModelProfile, RoleAffinity, ThinkingLevel } from '../../domain.ts'

export interface ModelProfileSheetProps {
  open: boolean
  editing: PublicModelProfile | undefined
  profiles: PublicModelProfile[]
  onClose: () => void
  onSaved: (message: string) => void | Promise<void>
}

export function ModelProfileSheet({
  open,
  editing,
  profiles,
  onClose,
  onSaved,
}: ModelProfileSheetProps) {
  const action = useAction()
  const [feedback, setFeedback] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(Boolean(editing))
  const [formKey, setFormKey] = useState(0)

  useEffect(() => {
    if (!open) return
    setFeedback('')
    setAdvancedOpen(Boolean(editing))
    setFormKey(k => k + 1)
  }, [open, editing])

  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape' && !action.pending) onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, action.pending, onClose])

  if (!open) return null

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

  return (
    <div
      className="sw-overlay"
      role="presentation"
      onMouseDown={event => {
        if (event.target === event.currentTarget && !action.pending) onClose()
      }}
    >
      <div className="sw-modal" role="dialog" aria-modal="true" aria-labelledby="model-profile-sheet-title">
        <div className="sw-modal-h">
          <div>
            <h2 id="model-profile-sheet-title">
              {editing ? `Edit profile · ${editing.name}` : profiles.length ? 'Add model profile' : 'Connect model provider'}
            </h2>
          </div>
          <button
            type="button"
            className="sw-btn ghost sm"
            disabled={action.pending}
            onClick={onClose}
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        <form
          key={formKey}
          onInput={() => setFeedback('')}
          onSubmit={event => {
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
            void action.submit(
              () => command === 'test' ? testModel({ data }) : saveModel({ data }),
              async () => {
                if (command === 'test') {
                  setFeedback('Connection verified. The model streamed a valid tool call.')
                  return
                }
                const input = element.elements.namedItem('key') as HTMLInputElement | null
                if (input) input.value = ''
                await onSaved(editing ? 'Model profile updated.' : 'Model profile added to failover pool.')
              },
            )
          }}
        >
          <div className="sw-modal-b">
            <div className="sw-grid-3">
              <label className="sw-fld">
                Profile name
                <input className="sw-input" name="name" required maxLength={160} defaultValue={defaults.name} />
              </label>
              <label className="sw-fld">
                Priority (higher tried first)
                <input
                  className="sw-input sw-num"
                  name="priority"
                  type="number"
                  min={0}
                  max={1000}
                  step={1}
                  required
                  defaultValue={defaults.priority}
                />
              </label>
              <label className="sw-fld">
                Role affinity
                <select className="sw-select" name="roleAffinity" defaultValue={defaults.roleAffinity}>
                  <option value="any">Any (all roles)</option>
                  <option value="reasoning">Reasoning (audit, repair, patch)</option>
                  <option value="tactical">Tactical (specialists, planner)</option>
                  <option value="fast">Fast (triage, dedupe)</option>
                </select>
              </label>
            </div>

            <label className="sw-fld">
              <span>
                API key {editing && <small>(optional — leave blank to keep stored key)</small>}
              </span>
              <input
                className="sw-input"
                name="key"
                type="password"
                required={!editing}
                minLength={editing ? undefined : 8}
                maxLength={512}
                autoComplete="off"
                placeholder={editing ? 'Leave blank to keep existing API key' : 'Enter your provider key'}
              />
              <small>Stored locally in 0600 credential files; never returned to the browser or target containers.</small>
            </label>

            <label className="sw-chk">
              <input
                type="checkbox"
                name="enabled"
                defaultChecked={defaults.enabled}
                aria-label="Enable this profile in the failover pool"
              />
              Enable this profile in the failover pool
            </label>

            <button
              type="button"
              className="sw-adv-btn"
              aria-expanded={advancedOpen}
              onClick={() => setAdvancedOpen(v => !v)}
            >
              <span aria-hidden="true">{advancedOpen ? '▾' : '▸'}</span>
              Advanced provider settings
            </button>

            <div className="sw-adv-panel" hidden={!advancedOpen}>
              <div className="sw-grid-2">
                <label className="sw-fld">
                  Model ID
                  <input className="sw-input sw-mono" name="model" required defaultValue={defaults.model} />
                </label>
                <label className="sw-fld">
                  Protocol
                  <select className="sw-select" name="protocol" defaultValue={defaults.protocol}>
                    <option value="responses">OpenAI Responses</option>
                    <option value="messages">Anthropic Messages</option>
                  </select>
                </label>
              </div>

              <label className="sw-fld">
                Base URL
                <input className="sw-input sw-mono" name="endpoint" type="url" required defaultValue={defaults.endpoint} />
              </label>

              <div className="sw-grid-3">
                <label className="sw-fld">
                  Context window
                  <input
                    className="sw-input sw-num"
                    name="contextWindow"
                    type="number"
                    min={32000}
                    max={2000000}
                    step={1}
                    required
                    defaultValue={defaults.contextWindow}
                  />
                </label>
                <label className="sw-fld">
                  Max output tokens
                  <input
                    className="sw-input sw-num"
                    name="maxTokens"
                    type="number"
                    min={512}
                    max={393216}
                    step={1}
                    required
                    defaultValue={defaults.maxTokens}
                  />
                </label>
                <label className="sw-fld">
                  Thinking level
                  <select className="sw-select" name="thinkingLevel" defaultValue={defaults.thinkingLevel}>
                    <option value="off">Off</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </label>
              </div>

              <div className="sw-grid-3">
                <label className="sw-fld">
                  Input cost ($ / 1M tokens)
                  <input
                    className="sw-input sw-num"
                    name="inputCostPerMtok"
                    type="number"
                    min={0}
                    max={500}
                    step="any"
                    required
                    defaultValue={defaults.inputCostPerMtok}
                  />
                </label>
                <label className="sw-fld">
                  Cached input ($ / 1M tokens)
                  <input
                    className="sw-input sw-num"
                    name="cachedInputCostPerMtok"
                    type="number"
                    min={0}
                    max={500}
                    step="any"
                    required
                    defaultValue={defaults.cachedInputCostPerMtok}
                  />
                </label>
                <label className="sw-fld">
                  Output cost ($ / 1M tokens)
                  <input
                    className="sw-input sw-num"
                    name="outputCostPerMtok"
                    type="number"
                    min={0}
                    max={500}
                    step="any"
                    required
                    defaultValue={defaults.outputCostPerMtok}
                  />
                </label>
              </div>
            </div>

            {action.error && <p role="alert" className="sw-msg-err">{action.error}</p>}
            {feedback && <p role="status" className="sw-msg-ok">{feedback}</p>}
          </div>

          <div className="sw-modal-f">
            <span className="sw-muted" style={{ fontSize: '11.5px' }}>
              Failover triggers only before a turn emits output.
            </span>
            <div className="sw-modal-f-acts">
              <button type="button" className="sw-btn ghost" disabled={action.pending} onClick={onClose}>
                Cancel
              </button>
              <button type="submit" value="test" className="sw-btn" disabled={action.pending}>
                Test connection
              </button>
              <button type="submit" value="save" className="sw-btn primary" disabled={action.pending}>
                {editing ? 'Update profile' : 'Save model'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}
