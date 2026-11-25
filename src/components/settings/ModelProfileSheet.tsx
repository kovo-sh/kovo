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

type SetupMode = 'default' | 'custom'

function OpenRouterIllustration() {
  return (
    <svg
      className="sw-mode-art"
      viewBox="0 0 64 40"
      fill="none"
      aria-hidden="true"
    >
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sw-sunk)" stroke="var(--sw-line-2)" strokeWidth="1.2" />
      <path d="M14 20h10.5c3.5 0 4.5-7 9-7H47" stroke="var(--sw-accent)" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M14 20h10.5c3.5 0 4.5 7 9 7H47" stroke="var(--sw-fg-4)" strokeWidth="1.3" strokeLinecap="round" strokeDasharray="2.5 2.5" />
      <circle cx="14" cy="20" r="3" fill="var(--sw-panel)" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="49" cy="13" r="3.25" fill="var(--sw-accent)" />
      <circle cx="49" cy="27" r="2.75" fill="var(--sw-panel)" stroke="var(--sw-fg-3)" strokeWidth="1.3" />
      <path d="M31.5 11.2 34 13l-2.5 1.8" stroke="var(--sw-accent)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function CustomProviderIllustration() {
  return (
    <svg
      className="sw-mode-art"
      viewBox="0 0 64 40"
      fill="none"
      aria-hidden="true"
    >
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sw-sunk)" stroke="var(--sw-line-2)" strokeWidth="1.2" />
      <path d="M12 13h40M12 20h40M12 27h40" stroke="var(--sw-line-strong)" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="24" cy="13" r="3.2" fill="var(--sw-panel)" stroke="var(--sw-accent)" strokeWidth="1.6" />
      <circle cx="40" cy="20" r="3.2" fill="var(--sw-panel)" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="29" cy="27" r="3.2" fill="var(--sw-panel)" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  )
}

export function ModelProfileSheet({
  open,
  editing,
  profiles,
  onClose,
  onSaved,
}: ModelProfileSheetProps) {
  const action = useAction()
  const [mode, setMode] = useState<SetupMode>('default')
  const [feedback, setFeedback] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(Boolean(editing))
  const [formKey, setFormKey] = useState(0)

  useEffect(() => {
    if (!open) return
    setMode(editing ? 'custom' : 'default')
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

  const isEditing = Boolean(editing)
  const isDefaultMode = !isEditing && mode === 'default'

  const nextPriority = profiles.length === 0 ? 100 : Math.max(10, Math.min(...profiles.map(p => p.priority)) - 10)
  const defaults = editing ?? {
    name: isDefaultMode || profiles.length === 0 ? DEFAULT_PROVIDER.name : `Custom profile ${profiles.length + 1}`,
    endpoint: DEFAULT_PROVIDER.endpoint,
    model: DEFAULT_PROVIDER.model,
    protocol: DEFAULT_PROVIDER.protocol,
    priority: nextPriority,
    enabled: true,
    contextWindow: DEFAULT_PROVIDER.contextWindow,
    maxTokens: DEFAULT_PROVIDER.maxTokens,
    thinkingLevel: DEFAULT_PROVIDER.thinkingLevel,
    roleAffinity: DEFAULT_PROVIDER.roleAffinity,
    inputCostPerMtok: DEFAULT_PROVIDER.inputCostPerMtok,
    cachedInputCostPerMtok: DEFAULT_PROVIDER.cachedInputCostPerMtok,
    outputCostPerMtok: DEFAULT_PROVIDER.outputCostPerMtok,
  }

  function selectMode(next: SetupMode) {
    if (next === mode) return
    setMode(next)
    setFeedback('')
    setFormKey(k => k + 1)
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
              {isEditing ? `Edit profile · ${editing!.name}` : 'Add model profile'}
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
              endpoint: String(form.get('endpoint') ?? DEFAULT_PROVIDER.endpoint),
              model: String(form.get('model') ?? DEFAULT_PROVIDER.model),
              protocol: form.get('protocol') === 'messages' ? 'messages' as const : 'responses' as const,
              key: String(form.get('key') ?? ''),
              priority: Number(form.get('priority') ?? nextPriority),
              enabled: isDefaultMode ? form.has('enabled') : form.has('enabled'),
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
                await onSaved(editing ? 'Model profile updated.' : 'Model profile added.')
              },
            )
          }}
        >
          <div className="sw-modal-b">
            {!isEditing && (
              <div className="sw-mode-grid" role="radiogroup" aria-label="Provider setup mode">
                <button
                  type="button"
                  role="radio"
                  aria-checked={mode === 'default'}
                  className={'sw-mode-card' + (mode === 'default' ? ' active' : '')}
                  onClick={() => selectMode('default')}
                >
                  <div className="sw-mode-card-top">
                    <OpenRouterIllustration />
                    <span className="sw-tag accent">Recommended</span>
                  </div>
                  <div className="sw-mode-card-copy">
                    <strong>Default · OpenRouter</strong>
                    <span>DeepSeek V4.1 Flash via OpenRouter — fast, high-recall default</span>
                  </div>
                </button>

                <button
                  type="button"
                  role="radio"
                  aria-checked={mode === 'custom'}
                  className={'sw-mode-card' + (mode === 'custom' ? ' active' : '')}
                  onClick={() => selectMode('custom')}
                >
                  <div className="sw-mode-card-top">
                    <CustomProviderIllustration />
                    <span className="sw-tag">Flexible</span>
                  </div>
                  <div className="sw-mode-card-copy">
                    <strong>Custom provider</strong>
                    <span>OpenAI, Anthropic, local Ollama/vLLM, or any compatible endpoint</span>
                  </div>
                </button>
              </div>
            )}

            {isDefaultMode ? (
              <>
                <input type="hidden" name="endpoint" value={DEFAULT_PROVIDER.endpoint} />
                <input type="hidden" name="model" value={DEFAULT_PROVIDER.model} />
                <input type="hidden" name="protocol" value={DEFAULT_PROVIDER.protocol} />

                <div className="sw-preset-bar" aria-label="Pre-filled OpenRouter defaults">
                  <span className="sw-tag solid sw-mono">openrouter.ai/api/v1</span>
                  <span className="sw-tag solid sw-mono">{DEFAULT_PROVIDER.model}</span>
                  <span className="sw-tag">Responses</span>
                </div>

                <label className="sw-fld">
                  <span className="sw-fld-row">
                    <span>OpenRouter API key</span>
                    <a
                      className="sw-ext-link"
                      href="https://openrouter.ai/keys"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Get an API key ↗
                    </a>
                  </span>
                  <input
                    className="sw-input sw-mono"
                    name="key"
                    type="password"
                    required
                    minLength={8}
                    maxLength={512}
                    autoComplete="off"
                    autoFocus
                    placeholder="sk-or-v1-..."
                  />
                  <small title="Saved locally in owner-only (0600) credential files">
                    Stored privately on your machine; never returned to the browser or target environments.
                  </small>
                </label>

                <details className="sw-details">
                  <summary className="sw-details-sum">Customize profile name &amp; limits</summary>
                  <div className="sw-details-body">
                    <div className="sw-grid-3">
                      <label className="sw-fld">
                        Profile name
                        <input className="sw-input" name="name" required maxLength={160} defaultValue={DEFAULT_PROVIDER.name} />
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
                        <select className="sw-select" name="roleAffinity" defaultValue={DEFAULT_PROVIDER.roleAffinity}>
                          <option value="any">Any (all roles)</option>
                          <option value="reasoning">Reasoning (audit, repair, patch)</option>
                          <option value="tactical">Tactical (specialists, planner)</option>
                          <option value="fast">Fast (triage, dedupe)</option>
                        </select>
                      </label>
                    </div>

                    <label className="sw-chk">
                      <input
                        type="checkbox"
                        name="enabled"
                        defaultChecked
                        aria-label="Enable this profile for automatic failover"
                      />
                      Enable this profile for automatic failover
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
                          defaultValue={DEFAULT_PROVIDER.contextWindow}
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
                          defaultValue={DEFAULT_PROVIDER.maxTokens}
                        />
                      </label>
                      <label className="sw-fld">
                        Thinking level
                        <select className="sw-select" name="thinkingLevel" defaultValue={DEFAULT_PROVIDER.thinkingLevel}>
                          <option value="off">Off</option>
                          <option value="low">Low</option>
                          <option value="medium">Medium</option>
                          <option value="high">High</option>
                        </select>
                      </label>
                    </div>

                    <div className="sw-grid-3">
                      <label className="sw-fld">
                        Input cost ($ / 1M)
                        <input
                          className="sw-input sw-num"
                          name="inputCostPerMtok"
                          type="number"
                          min={0}
                          max={500}
                          step="any"
                          required
                          defaultValue={DEFAULT_PROVIDER.inputCostPerMtok}
                        />
                      </label>
                      <label className="sw-fld">
                        Cached input ($ / 1M)
                        <input
                          className="sw-input sw-num"
                          name="cachedInputCostPerMtok"
                          type="number"
                          min={0}
                          max={500}
                          step="any"
                          required
                          defaultValue={DEFAULT_PROVIDER.cachedInputCostPerMtok}
                        />
                      </label>
                      <label className="sw-fld">
                        Output cost ($ / 1M)
                        <input
                          className="sw-input sw-num"
                          name="outputCostPerMtok"
                          type="number"
                          min={0}
                          max={500}
                          step="any"
                          required
                          defaultValue={DEFAULT_PROVIDER.outputCostPerMtok}
                        />
                      </label>
                    </div>
                  </div>
                </details>
              </>
            ) : (
              <>
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
                  Base URL
                  <input className="sw-input sw-mono" name="endpoint" type="url" required defaultValue={defaults.endpoint} />
                </label>

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
                  <span>
                    API key {isEditing && <small>(optional — leave blank to keep stored key)</small>}
                  </span>
                  <input
                    className="sw-input"
                    name="key"
                    type="password"
                    required={!isEditing}
                    minLength={isEditing ? undefined : 8}
                    maxLength={512}
                    autoComplete="off"
                    placeholder={isEditing ? 'Leave blank to keep existing API key' : 'Enter your provider key'}
                  />
                  <small title="Saved locally in owner-only (0600) credential files">
                    Stored privately on your machine; never returned to the browser or target environments.
                  </small>
                </label>

                <label className="sw-chk">
                  <input
                    type="checkbox"
                    name="enabled"
                    defaultChecked={defaults.enabled}
                    aria-label="Enable this profile for automatic failover"
                  />
                  Enable this profile for automatic failover
                </label>

                <button
                  type="button"
                  className="sw-adv-btn"
                  aria-expanded={advancedOpen}
                  onClick={() => setAdvancedOpen(v => !v)}
                >
                  <span aria-hidden="true">{advancedOpen ? '▾' : '▸'}</span>
                  Limits &amp; pricing
                </button>

                <div className="sw-adv-panel" hidden={!advancedOpen}>
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
              </>
            )}

            {action.error && <p role="alert" className="sw-msg-err">{action.error}</p>}
            {feedback && <p role="status" className="sw-msg-ok">{feedback}</p>}
          </div>

          <div className="sw-modal-f">
            <span className="sw-muted" style={{ fontSize: '11.5px' }}>
              Automatic failover only switches providers before a response begins streaming.
            </span>
            <div className="sw-modal-f-acts">
              <button type="button" className="sw-btn ghost" disabled={action.pending} onClick={onClose}>
                Cancel
              </button>
              <button type="submit" value="test" className="sw-btn" disabled={action.pending}>
                Test connection
              </button>
              <button type="submit" value="save" className="sw-btn primary" disabled={action.pending}>
                {isEditing ? 'Update profile' : 'Save model'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}
