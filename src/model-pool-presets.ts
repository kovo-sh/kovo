/**
 * Model pool failover presets — the single source of truth shared by the CLI
 * (`scripts/configure-model-pool.ts`) and the Settings "Add model profile"
 * sheet (`src/components/settings/ModelProfileSheet.tsx`).
 *
 * Presets carry no secrets: the operator (or a key file, for the CLI) always
 * supplies the API key. Priorities follow the server's sort direction — higher
 * is tried first — so the default tiers read Primary (300) → Fallback 1 (200)
 * → Fallback 2 (100).
 */
import { DEFAULT_PROVIDER } from './domain.ts'
import type { ProviderProtocol, RoleAffinity, ThinkingLevel } from './domain.ts'

export type ModelPoolPresetId = 'morph' | 'opencode' | 'openrouter'

export interface ModelPoolPreset {
  readonly id: ModelPoolPresetId
  /** Short chip label. */
  readonly label: string
  /** Full profile name written to the pool. */
  readonly name: string
  readonly description: string
  /** Failover tier hint shown on the preset chip. */
  readonly tier: 'Primary' | 'Fallback 1' | 'Fallback 2'
  readonly roleAffinity: RoleAffinity
  readonly provider: string
  readonly endpoint: string
  readonly model: string
  readonly protocol: ProviderProtocol
  readonly priority: number
  readonly contextWindow: number
  readonly maxTokens: number
  readonly thinkingLevel: ThinkingLevel
  readonly inputCostPerMtok: number
  readonly cachedInputCostPerMtok: number
  readonly outputCostPerMtok: number
  /** Where the operator creates a key for this provider, when known. */
  readonly keyUrl?: string
}

export const MODEL_POOL_PRESETS: readonly ModelPoolPreset[] = [
  {
    id: 'morph',
    label: 'Morph Ultra',
    name: 'Morph Ultra DeepSeek V4.1 Flash',
    description: 'DeepSeek V4.1 Flash on Morph Ultra · $0 marginal',
    tier: 'Primary',
    roleAffinity: 'any',
    provider: 'Morph',
    endpoint: 'https://api.morphllm.com/v1',
    model: 'morph-dsv41flash-1017',
    protocol: 'chat-completions',
    priority: 300,
    contextWindow: 1_048_576,
    maxTokens: DEFAULT_PROVIDER.maxTokens,
    thinkingLevel: 'medium',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  },
  {
    id: 'opencode',
    label: 'OpenCode Go',
    name: 'OpenCode Go DeepSeek V4.1 Flash',
    description: 'DeepSeek V4.1 Flash on OpenCode Go · $0 marginal',
    tier: 'Fallback 1',
    roleAffinity: 'any',
    provider: 'OpenCode',
    endpoint: 'https://opencode.ai/inference/go/openai/v1',
    model: 'deepseek-v4.1-flash',
    protocol: 'chat-completions',
    priority: 200,
    contextWindow: 1_048_576,
    maxTokens: DEFAULT_PROVIDER.maxTokens,
    thinkingLevel: 'medium',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  },
  {
    id: 'openrouter',
    label: 'OpenRouter',
    name: DEFAULT_PROVIDER.name,
    description: 'DeepSeek V4.1 Flash via OpenRouter · metered',
    tier: 'Fallback 2',
    roleAffinity: DEFAULT_PROVIDER.roleAffinity,
    provider: 'OpenRouter',
    endpoint: DEFAULT_PROVIDER.endpoint,
    model: DEFAULT_PROVIDER.model,
    protocol: DEFAULT_PROVIDER.protocol,
    priority: 100,
    contextWindow: DEFAULT_PROVIDER.contextWindow,
    maxTokens: DEFAULT_PROVIDER.maxTokens,
    thinkingLevel: DEFAULT_PROVIDER.thinkingLevel,
    inputCostPerMtok: DEFAULT_PROVIDER.inputCostPerMtok,
    cachedInputCostPerMtok: DEFAULT_PROVIDER.cachedInputCostPerMtok,
    outputCostPerMtok: DEFAULT_PROVIDER.outputCostPerMtok,
    keyUrl: 'https://openrouter.ai/keys',
  },
]

export function modelPoolPreset(id: ModelPoolPresetId): ModelPoolPreset {
  const preset = MODEL_POOL_PRESETS.find(p => p.id === id)
  if (!preset) throw new Error(`Unknown model pool preset: ${id}`)
  return preset
}

/** Profile fields a preset pre-fills (everything except the API key). */
export function presetProfileFields(preset: ModelPoolPreset) {
  return {
    name: preset.name,
    endpoint: preset.endpoint,
    model: preset.model,
    protocol: preset.protocol,
    priority: preset.priority,
    enabled: true,
    contextWindow: preset.contextWindow,
    maxTokens: preset.maxTokens,
    thinkingLevel: preset.thinkingLevel,
    roleAffinity: preset.roleAffinity,
    inputCostPerMtok: preset.inputCostPerMtok,
    cachedInputCostPerMtok: preset.cachedInputCostPerMtok,
    outputCostPerMtok: preset.outputCostPerMtok,
  }
}

/** Failover role for a 1-based rank: 1 → Primary, 2 → Fallback 1, … */
export function failoverRoleLabel(rank: number): string {
  return rank <= 1 ? 'Primary' : `Fallback ${rank - 1}`
}

/** Priority step between adjacent failover ranks when the pool is reordered. */
export const FAILOVER_PRIORITY_STEP = 10

/**
 * Explicit priorities for a ranked list (index 0 = Primary), in steps of 10 and
 * descending because the server tries the highest priority first: 3 profiles →
 * [30, 20, 10].
 */
export function failoverPriorities(count: number): number[] {
  return Array.from({ length: count }, (_, index) => (count - index) * FAILOVER_PRIORITY_STEP)
}
