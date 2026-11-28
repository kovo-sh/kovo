import { useEffect, useState } from 'react'
import { saveModel, testModel } from '../../actions.ts'
import { DEFAULT_PROVIDER, roleAffinities, thinkingLevels } from '../../domain.ts'
import type { PublicModelProfile, RoleAffinity, ThinkingLevel } from '../../domain.ts'
import { cn } from '../../lib/cn.ts'
import { MODEL_POOL_PRESETS, presetProfileFields } from '../../model-pool-presets.ts'
import type { ModelPoolPreset, ModelPoolPresetId } from '../../model-pool-presets.ts'
import { useAction } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import { Dialog, DialogContent, DialogTitle } from '../ui/dialog.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { Input, NativeSelect } from '../ui/input.tsx'
import { useServerDraft } from './useServerDraft.ts'

export interface ModelProfileSheetProps {
  open: boolean
  editing: PublicModelProfile | undefined
  profiles: PublicModelProfile[]
  onClose: () => void
  onSaved: (message: string) => void | Promise<void>
}

type SetupMode = 'default' | 'custom'

const FIELD_CLASS = 'flex flex-col gap-1 text-[12px] font-medium text-fg-muted'
const SELECT_CLASS = 'w-full bg-panel font-normal text-fg'
const CLOSE_ICON_CLASS =
  'block size-3.5 shrink-0 fill-none stroke-current [stroke-width:1.5] [stroke-linecap:round] [stroke-linejoin:round]'

function OpenRouterIllustration() {
  return (
    <svg
      className="block h-10 w-16 flex-none text-fg"
      viewBox="0 0 64 40"
      fill="none"
      aria-hidden="true"
    >
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <path d="M14 20h10.5c3.5 0 4.5-7 9-7H47" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M14 20h10.5c3.5 0 4.5 7 9 7H47" stroke="var(--fg-4)" strokeWidth="1.3" strokeLinecap="round" strokeDasharray="2.5 2.5" />
      <circle cx="14" cy="20" r="3" fill="var(--panel)" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="49" cy="13" r="3.25" fill="var(--accent)" />
      <circle cx="49" cy="27" r="2.75" fill="var(--panel)" stroke="var(--fg-3)" strokeWidth="1.3" />
      <path d="M31.5 11.2 34 13l-2.5 1.8" stroke="var(--accent)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function CustomProviderIllustration() {
  return (
    <svg
      className="block h-10 w-16 flex-none text-fg"
      viewBox="0 0 64 40"
      fill="none"
      aria-hidden="true"
    >
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <path d="M12 13h40M12 20h40M12 27h40" stroke="var(--line-strong)" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="24" cy="13" r="3.2" fill="var(--panel)" stroke="var(--accent)" strokeWidth="1.6" />
      <circle cx="40" cy="20" r="3.2" fill="var(--panel)" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="29" cy="27" r="3.2" fill="var(--panel)" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  )
}

const PROTOCOL_PILL: Record<typeof DEFAULT_PROVIDER.protocol | 'chat-completions' | 'messages', string> = {
  responses: 'Responses',
  'chat-completions': 'Chat Completions',
  messages: 'Messages',
}

/** Preset card summary derived from DEFAULT_PROVIDER.name ("OpenRouter <model>" -> "OpenRouter · <model>"). */
const DEFAULT_PROVIDER_SUMMARY = DEFAULT_PROVIDER.name.replace(/^OpenRouter\s+/, 'OpenRouter · ')

/** Editable configuration of a profile (no health fields), used to detect edits made elsewhere. */
function profileConfigKey(profile: PublicModelProfile): string {
  const { name, endpoint, model, protocol, priority, enabled, contextWindow, maxTokens, thinkingLevel, roleAffinity, inputCostPerMtok, cachedInputCostPerMtok, outputCostPerMtok } = profile
  return JSON.stringify([name, endpoint, model, protocol, priority, enabled, contextWindow, maxTokens, thinkingLevel, roleAffinity, inputCostPerMtok, cachedInputCostPerMtok, outputCostPerMtok])
}

/**
 * Shared failover presets (`src/model-pool-presets.ts`, also used by the CLI) as compact
 * cards: one click pre-fills name, endpoint, model, protocol, priority and limits, so only
 * the API key is left to enter.
 */
function PresetStrip({ activeId, onSelect }: { activeId: ModelPoolPresetId | null; onSelect: (preset: ModelPoolPreset) => void }) {
  return (
    <div className="flex flex-col gap-1.5" role="group" aria-labelledby="model-preset-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
        <span id="model-preset-heading" className="text-[12px] font-medium text-fg-muted">Failover presets</span>
        <span className="text-[11.5px] text-fg-subtle">Pre-fills everything except the API key</span>
      </div>
      <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-3">
        {MODEL_POOL_PRESETS.map(preset => {
          const active = preset.id === activeId
          return (
            <button
              key={preset.id}
              type="button"
              aria-pressed={active}
              data-preset={preset.id}
              className={cn(
                'flex h-auto w-full min-w-0 cursor-pointer flex-col items-start gap-0.5 whitespace-normal rounded-lg border px-2.5 py-2 text-left font-normal shadow-none transition-colors',
                active
                  ? 'border-accent-line bg-accent-soft hover:bg-accent-soft'
                  : 'border-line-2 bg-panel hover:border-line-strong hover:bg-hover',
              )}
              onClick={() => onSelect(preset)}
            >
              <span className="flex w-full min-w-0 items-center justify-between gap-1.5">
                <strong className="min-w-0 truncate text-[12.5px] font-semibold leading-[18px] text-fg">{preset.label}</strong>
                <span className="flex-none text-[11px] font-medium tabular-nums text-fg-subtle">{preset.tier}</span>
              </span>
              <span className="w-full min-w-0 truncate font-mono text-[11px] leading-4 text-fg-muted" title={preset.model}>{preset.model}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function suggestUniqueProfileName(baseName: string, profiles: readonly PublicModelProfile[]): string {
  const base = baseName.trim()
  const existing = new Set(profiles.map(profile => profile.name.trim().toLowerCase()))
  if (!existing.has(base.toLowerCase())) return base
  for (let n = 2; n < 10_000; n += 1) {
    const suffix = ` (${n})`
    const candidate = `${base.slice(0, 160 - suffix.length)}${suffix}`
    if (!existing.has(candidate.toLowerCase())) return candidate
  }
  return `${base.slice(0, 150)} (new)`
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
  const [presetId, setPresetId] = useState<ModelPoolPresetId | null>(null)
  // Edit mode is draft-safe: background polls never re-key the form. If the profile's
  // configuration changes elsewhere while the sheet is open, offer a reload instead.
  const [openedFor, setOpenedFor] = useState<string | null>(null)
  const [formSource, setFormSource] = useState<PublicModelProfile>()
  const liveEditing = editing ? profiles.find(profile => profile.id === editing.id) ?? editing : undefined
  const [, , serverDraft] = useServerDraft(liveEditing ? profileConfigKey(liveEditing) : '', {
    hold: Boolean(open && editing && openedFor === editing.id),
  })

  useEffect(() => {
    if (!open) {
      setOpenedFor(null)
      return
    }
    setMode(editing ? 'custom' : 'default')
    setFeedback('')
    setAdvancedOpen(Boolean(editing))
    setPresetId(null)
    setFormSource(undefined)
    setOpenedFor(editing?.id ?? null)
    setFormKey(k => k + 1)
  }, [open, editing])

  const isEditing = Boolean(editing)
  const isDefaultMode = !isEditing && mode === 'default'
  const preset = !isEditing && presetId ? MODEL_POOL_PRESETS.find(p => p.id === presetId) : undefined

  const nextPriority = profiles.length === 0 ? 100 : Math.max(10, Math.min(...profiles.map(p => p.priority)) - 10)
  const suggestedName = isDefaultMode || profiles.length === 0
    ? suggestUniqueProfileName(DEFAULT_PROVIDER.name, profiles)
    : suggestUniqueProfileName(`Custom profile ${profiles.length + 1}`, profiles)
  const defaults = (editing ? formSource ?? editing : undefined)
    ?? (preset ? { ...presetProfileFields(preset), name: suggestUniqueProfileName(preset.name, profiles) } : undefined)
    ?? {
    name: suggestedName,
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
    if (next === mode && !presetId) return
    setMode(next)
    setPresetId(null)
    setFeedback('')
    setFormKey(k => k + 1)
  }

  function applyPreset(next: ModelPoolPreset) {
    setMode('custom')
    setPresetId(next.id)
    setFeedback('')
    setAdvancedOpen(false)
    setFormKey(k => k + 1)
  }

  function reloadFromServer() {
    setFormSource(liveEditing)
    serverDraft.acceptServer()
    setFeedback('')
    setFormKey(k => k + 1)
  }

  return (
    <Dialog
      open={open}
      closeOnEscape={!action.pending}
      onOpenChange={(nextOpen, details) => {
        if (!nextOpen) {
          if (action.pending) {
            details.cancel()
            return
          }
          onClose()
        }
      }}
    >
      <DialogContent className="flex max-h-[calc(100vh-48px)] max-w-[620px] flex-col overflow-hidden rounded-2xl border-line-2 bg-raise p-0">
        <div className="flex flex-none items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div className="min-w-0 flex-1">
            <DialogTitle
              className="truncate text-[14px] font-semibold tracking-[-0.01em] text-fg"
              title={editing ? editing.name : undefined}
            >
              {editing ? `Edit profile · ${editing.name}` : 'Add model profile'}
            </DialogTitle>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-6 flex-none rounded-[5px] p-0 text-fg-subtle"
            disabled={action.pending}
            onClick={onClose}
            aria-label="Close modal"
          >
            <Icon name="close" size={14} className={CLOSE_ICON_CLASS} />
          </Button>
        </div>

        {isEditing && serverDraft.serverChanged && (
          <div role="status" data-testid="updated-elsewhere" className="flex flex-none flex-wrap items-center gap-x-2 gap-y-1 border-b border-line bg-warn-soft px-4 py-2 text-[12px] text-warn-text">
            <span className="min-w-0 flex-1">Updated elsewhere · this profile changed since you opened it.</span>
            <Button type="button" variant="outline" className="h-6 rounded-[5px] px-[7px] text-[12px]" disabled={action.pending} onClick={reloadFromServer}>
              Reload
            </Button>
          </div>
        )}

        <form
          key={formKey}
          className="flex min-h-0 min-w-0 flex-1 flex-col"
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
              name: String(form.get('name') ?? '').trim() || defaults.name,
              endpoint: String(form.get('endpoint') ?? DEFAULT_PROVIDER.endpoint),
              model: String(form.get('model') ?? DEFAULT_PROVIDER.model),
              protocol: form.get('protocol') === 'messages'
                ? 'messages' as const
                : form.get('protocol') === 'chat-completions'
                  ? 'chat-completions' as const
                  : 'responses' as const,
              key: String(form.get('key') ?? ''),
              priority: Number(form.get('priority') ?? nextPriority),
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
                await onSaved(editing ? 'Model profile updated.' : 'Model profile added.')
              },
            )
          }}
        >
          <div className="flex max-h-[calc(82vh-108px)] flex-col gap-[13px] overflow-y-auto p-4">
            {!isEditing && (
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2" role="radiogroup" aria-label="Provider setup mode">
                <button
                  type="button"
                  role="radio"
                  aria-checked={mode === 'default' && !presetId}
                  className={cn(
                    'flex h-auto w-full cursor-pointer flex-col gap-2.5 whitespace-normal rounded-[9px] border px-[13px] py-3 text-left font-normal shadow-none transition-colors',
                    mode === 'default' && !presetId
                      ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                      : 'border-line-2 bg-panel text-fg hover:border-line-strong hover:bg-hover',
                  )}
                  onClick={() => selectMode('default')}
                >
                  <div className="flex w-full items-start justify-between gap-2">
                    <OpenRouterIllustration />
                    <Badge variant="accent" className="font-medium">Recommended</Badge>
                  </div>
                  <div className="flex flex-col gap-[3px]">
                    <strong className="text-[13px] font-semibold leading-[18px] text-fg">
                      Default provider
                    </strong>
                    <span className="text-[11.5px] leading-4 text-fg-muted">
                      {DEFAULT_PROVIDER_SUMMARY}. Paste one key; Kovo pre-fills endpoint, model, and limits.
                    </span>
                  </div>
                </button>

                <button
                  type="button"
                  role="radio"
                  aria-checked={mode === 'custom' && !presetId}
                  className={cn(
                    'flex h-auto w-full cursor-pointer flex-col gap-2.5 whitespace-normal rounded-[9px] border px-[13px] py-3 text-left font-normal shadow-none transition-colors',
                    mode === 'custom' && !presetId
                      ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                      : 'border-line-2 bg-panel text-fg hover:border-line-strong hover:bg-hover',
                  )}
                  onClick={() => selectMode('custom')}
                >
                  <div className="flex w-full items-start justify-between gap-2">
                    <CustomProviderIllustration />
                    <Badge variant="neutral" className="font-medium">Flexible</Badge>
                  </div>
                  <div className="flex flex-col gap-[3px]">
                    <strong className="text-[13px] font-semibold leading-[18px] text-fg">
                      Custom provider
                    </strong>
                    <span className="text-[11.5px] leading-4 text-fg-muted">
                      OpenAI, Anthropic, local Ollama/vLLM, or any compatible endpoint
                    </span>
                  </div>
                </button>
              </div>
            )}

            {!isEditing && <PresetStrip activeId={presetId} onSelect={applyPreset} />}

            {isDefaultMode ? (
              <>
                <input type="hidden" name="endpoint" value={DEFAULT_PROVIDER.endpoint} />
                <input type="hidden" name="model" value={DEFAULT_PROVIDER.model} />
                <input type="hidden" name="protocol" value={DEFAULT_PROVIDER.protocol} />

                <div
                  className="flex flex-wrap items-center gap-1.5 rounded-lg border border-line bg-sunk px-[11px] py-[9px]"
                  aria-label="Pre-filled OpenRouter defaults"
                >
                  <Badge variant="neutral" className="bg-panel font-mono font-medium text-fg-muted">
                    openrouter.ai/api/v1
                  </Badge>
                  <Badge variant="neutral" className="bg-panel font-mono font-medium text-fg-muted">
                    {DEFAULT_PROVIDER.model}
                  </Badge>
                  <Badge variant="neutral" className="font-medium">{PROTOCOL_PILL[DEFAULT_PROVIDER.protocol]}</Badge>
                </div>

                <label className={FIELD_CLASS}>
                  <span className="flex items-center justify-between gap-2">
                    <span>OpenRouter API key</span>
                    <a
                      className="text-[11.5px] font-medium text-accent no-underline hover:underline"
                      href="https://openrouter.ai/keys"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Get an API key ↗
                    </a>
                  </span>
                  <Input
                    className="w-full font-mono"
                    name="key"
                    type="password"
                    required
                    minLength={8}
                    maxLength={512}
                    autoComplete="off"
                    autoFocus
                    placeholder="sk-or-v1-..."
                  />
                  <small className="text-[11.5px] font-normal text-fg-subtle" title="Stored privately on this machine">
                    Stored privately on your machine; never returned to the browser or target environments.
                  </small>
                </label>

                <div className="overflow-hidden rounded-lg border border-line bg-sunk">
                  <Disclosure>
                    <DisclosureTrigger className="rounded-none bg-transparent px-3 py-2 text-[12px] font-medium text-fg-muted shadow-none hover:bg-hover hover:text-fg">
                      Customize profile name &amp; limits
                    </DisclosureTrigger>
                    <DisclosureContent keepMounted className="flex flex-col gap-2.5 border-t border-line p-3">
                      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                        <label className={FIELD_CLASS}>
                          Profile name
                          <Input className="w-full" name="name" required maxLength={160} defaultValue={defaults.name} />
                        </label>
                        <label className={FIELD_CLASS}>
                          Priority (higher tried first)
                          <Input
                            className="w-full tabular-nums"
                            name="priority"
                            type="number"
                            min={0}
                            max={1000}
                            step={1}
                            required
                            defaultValue={defaults.priority}
                          />
                        </label>
                        <label className={FIELD_CLASS}>
                          Role affinity
                          <NativeSelect className={SELECT_CLASS} name="roleAffinity" defaultValue={DEFAULT_PROVIDER.roleAffinity}>
                            <option value="any">Any (all roles)</option>
                            <option value="reasoning">Reasoning (audit, repair, patch)</option>
                            <option value="tactical">Tactical (specialists, planner)</option>
                            <option value="fast">Fast (triage, dedupe)</option>
                          </NativeSelect>
                        </label>
                      </div>

                      <label className="inline-flex cursor-pointer select-none items-center gap-2 text-[12.5px] font-[450] text-fg-muted">
                        <Checkbox
                          name="enabled"
                          defaultChecked
                          aria-label="Enable this profile for automatic failover"
                        />
                        Enable this profile for automatic failover
                      </label>

                      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                        <label className={FIELD_CLASS}>
                          Context window
                          <Input
                            className="w-full tabular-nums"
                            name="contextWindow"
                            type="number"
                            min={32000}
                            max={2000000}
                            step={1}
                            required
                            defaultValue={DEFAULT_PROVIDER.contextWindow}
                          />
                        </label>
                        <label className={FIELD_CLASS}>
                          Max output tokens
                          <Input
                            className="w-full tabular-nums"
                            name="maxTokens"
                            type="number"
                            min={512}
                            max={393216}
                            step={1}
                            required
                            defaultValue={DEFAULT_PROVIDER.maxTokens}
                          />
                        </label>
                        <label className={FIELD_CLASS}>
                          Thinking level
                          <NativeSelect className={SELECT_CLASS} name="thinkingLevel" defaultValue={DEFAULT_PROVIDER.thinkingLevel}>
                            <option value="off">Off</option>
                            <option value="low">Low</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                          </NativeSelect>
                        </label>
                      </div>

                      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                        <label className={FIELD_CLASS}>
                          Input cost ($ / 1M)
                          <Input
                            className="w-full tabular-nums"
                            name="inputCostPerMtok"
                            type="number"
                            min={0}
                            max={500}
                            step="any"
                            required
                            defaultValue={DEFAULT_PROVIDER.inputCostPerMtok}
                          />
                        </label>
                        <label className={FIELD_CLASS}>
                          Cached input ($ / 1M)
                          <Input
                            className="w-full tabular-nums"
                            name="cachedInputCostPerMtok"
                            type="number"
                            min={0}
                            max={500}
                            step="any"
                            required
                            defaultValue={DEFAULT_PROVIDER.cachedInputCostPerMtok}
                          />
                        </label>
                        <label className={FIELD_CLASS}>
                          Output cost ($ / 1M)
                          <Input
                            className="w-full tabular-nums"
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
                    </DisclosureContent>
                  </Disclosure>
                </div>
              </>
            ) : (
              <>
                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                  <label className={FIELD_CLASS}>
                    Profile name
                    <Input className="w-full" name="name" required maxLength={160} defaultValue={defaults.name} />
                  </label>
                  <label className={FIELD_CLASS}>
                    Priority (higher tried first)
                    <Input
                      className="w-full tabular-nums"
                      name="priority"
                      type="number"
                      min={0}
                      max={1000}
                      step={1}
                      required
                      defaultValue={defaults.priority}
                    />
                  </label>
                  <label className={FIELD_CLASS}>
                    Role affinity
                    <NativeSelect className={SELECT_CLASS} name="roleAffinity" defaultValue={defaults.roleAffinity}>
                      <option value="any">Any (all roles)</option>
                      <option value="reasoning">Reasoning (audit, repair, patch)</option>
                      <option value="tactical">Tactical (specialists, planner)</option>
                      <option value="fast">Fast (triage, dedupe)</option>
                    </NativeSelect>
                  </label>
                </div>

                <label className={FIELD_CLASS}>
                  Base URL
                  <Input className="w-full font-mono" name="endpoint" type="url" required defaultValue={defaults.endpoint} />
                </label>

                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  <label className={FIELD_CLASS}>
                    Model ID
                    <Input className="w-full font-mono" name="model" required defaultValue={defaults.model} />
                  </label>
                  <label className={FIELD_CLASS}>
                    Protocol
                    <NativeSelect className={SELECT_CLASS} name="protocol" defaultValue={defaults.protocol}>
                      <option value="responses">OpenAI Responses</option>
                      <option value="chat-completions">OpenAI Chat Completions</option>
                      <option value="messages">Anthropic Messages</option>
                    </NativeSelect>
                  </label>
                </div>

                <label className={FIELD_CLASS}>
                  <span>
                    {preset ? `${preset.provider} API key` : 'API key'}{' '}
                    {isEditing && (
                      <small className="text-[11.5px] font-normal text-fg-subtle">
                        (optional — leave blank to keep stored key)
                      </small>
                    )}
                  </span>
                  <Input
                    className="w-full"
                    name="key"
                    type="password"
                    required={!isEditing}
                    minLength={isEditing ? undefined : 8}
                    maxLength={512}
                    autoComplete="off"
                    autoFocus={Boolean(preset)}
                    placeholder={isEditing ? 'Leave blank to keep existing API key' : 'Enter your provider key'}
                  />
                  <small className="text-[11.5px] font-normal text-fg-subtle" title="Stored privately on this machine">
                    Stored privately on your machine; never returned to the browser or target environments.
                  </small>
                </label>

                <label className="inline-flex cursor-pointer select-none items-center gap-2 text-[12.5px] font-[450] text-fg-muted">
                  <Checkbox
                    name="enabled"
                    defaultChecked={defaults.enabled}
                    aria-label="Enable this profile for automatic failover"
                  />
                  Enable this profile for automatic failover
                </label>

                <Disclosure open={advancedOpen} onOpenChange={setAdvancedOpen}>
                  <DisclosureTrigger className="-ml-1.5 h-6 w-auto gap-1.5 rounded-[5px] bg-transparent px-1.5 py-0 text-[12px] font-medium text-fg-muted shadow-none hover:bg-hover hover:text-fg">
                    Limits &amp; pricing
                  </DisclosureTrigger>

                  <DisclosureContent
                    keepMounted
                    className="mt-2 flex flex-col gap-2.5 rounded-lg border border-line bg-sunk p-3"
                  >
                    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                      <label className={FIELD_CLASS}>
                        Context window
                        <Input
                          className="w-full tabular-nums"
                          name="contextWindow"
                          type="number"
                          min={32000}
                          max={2000000}
                          step={1}
                          required
                          defaultValue={defaults.contextWindow}
                        />
                      </label>
                      <label className={FIELD_CLASS}>
                        Max output tokens
                        <Input
                          className="w-full tabular-nums"
                          name="maxTokens"
                          type="number"
                          min={512}
                          max={393216}
                          step={1}
                          required
                          defaultValue={defaults.maxTokens}
                        />
                      </label>
                      <label className={FIELD_CLASS}>
                        Thinking level
                        <NativeSelect className={SELECT_CLASS} name="thinkingLevel" defaultValue={defaults.thinkingLevel}>
                          <option value="off">Off</option>
                          <option value="low">Low</option>
                          <option value="medium">Medium</option>
                          <option value="high">High</option>
                        </NativeSelect>
                      </label>
                    </div>

                    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                      <label className={FIELD_CLASS}>
                        Input cost ($ / 1M tokens)
                        <Input
                          className="w-full tabular-nums"
                          name="inputCostPerMtok"
                          type="number"
                          min={0}
                          max={500}
                          step="any"
                          required
                          defaultValue={defaults.inputCostPerMtok}
                        />
                      </label>
                      <label className={FIELD_CLASS}>
                        Cached input ($ / 1M tokens)
                        <Input
                          className="w-full tabular-nums"
                          name="cachedInputCostPerMtok"
                          type="number"
                          min={0}
                          max={500}
                          step="any"
                          required
                          defaultValue={defaults.cachedInputCostPerMtok}
                        />
                      </label>
                      <label className={FIELD_CLASS}>
                        Output cost ($ / 1M tokens)
                        <Input
                          className="w-full tabular-nums"
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
                  </DisclosureContent>
                </Disclosure>
              </>
            )}

          </div>

          <div className="flex flex-wrap items-center justify-between gap-2.5 border-t border-line bg-sunk px-4 py-2.5">
            <SheetFeedback error={action.error} feedback={feedback} />
            <span className="text-[11.5px] text-fg-subtle">
              Automatic failover only switches providers before a response begins streaming.
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              <Button type="button" variant="ghost" disabled={action.pending} onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" value="test" variant="outline" disabled={action.pending}>
                Test connection
              </Button>
              <Button type="submit" value="save" variant="default" disabled={action.pending}>
                {isEditing ? 'Update profile' : 'Save model'}
              </Button>
            </div>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Save/Test outcome rendered in the sticky footer, right above the buttons that caused it. */
function SheetFeedback({ error, feedback }: { error: string; feedback: string }) {
  if (!error && !feedback) return null
  return (
    <div className="max-h-24 w-full min-w-0 overflow-y-auto">
      {error
        ? <p role="alert" className="m-0 min-w-0 whitespace-pre-wrap text-[12px] text-danger [overflow-wrap:anywhere]">{error}</p>
        : <p role="status" className="m-0 min-w-0 text-[12px] text-ok-text [overflow-wrap:anywhere]">{feedback}</p>}
    </div>
  )
}
