#!/usr/bin/env node
/**
 * Key-safe 3-tier DeepSeek V4.1 Flash model pool configurator (Track E1).
 * Tier definitions come from the shared `src/model-pool-presets.ts`.
 *
 * Reads owner-only (mode 0600) API key files from disk and idempotently upserts:
 *   - Priority 300: Morph Ultra DeepSeek V4.1 Flash (chat-completions, $0 marginal)
 *   - Priority 200: OpenCode Go DeepSeek V4.1 Flash (chat-completions, $0 marginal)
 * alongside any existing OpenRouter profile (priority 100) inside `$KOVO_DATA_DIR`.
 *
 * Security invariant: NEVER prints, logs, or interpolates any API key value.
 */
import { existsSync, lstatSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import {
  listModelProfiles,
  normalizeModelEndpoint,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import { Store } from '../src/server/store.ts'
import type { PublicModelProfile } from '../src/domain.ts'
import { modelPoolPreset } from '../src/model-pool-presets.ts'

export interface PoolTierPreset {
  readonly idKey: 'morph' | 'opencode'
  readonly name: string
  readonly endpoint: string
  readonly model: string
  readonly protocol: 'chat-completions'
  readonly priority: number
  readonly contextWindow: number
  readonly thinkingLevel: 'medium'
  readonly inputCostPerMtok: number
  readonly cachedInputCostPerMtok: number
  readonly outputCostPerMtok: number
}

/** CLI tier view of the shared presets (`src/model-pool-presets.ts`, also used by the Settings sheet). */
function poolTier(idKey: PoolTierPreset['idKey']): PoolTierPreset {
  const preset = modelPoolPreset(idKey)
  if (preset.protocol !== 'chat-completions' || preset.thinkingLevel !== 'medium') {
    throw new Error(`Model pool preset ${idKey} must use chat-completions with medium thinking.`)
  }
  return {
    idKey,
    name: preset.name,
    endpoint: preset.endpoint,
    model: preset.model,
    protocol: preset.protocol,
    priority: preset.priority,
    contextWindow: preset.contextWindow,
    thinkingLevel: preset.thinkingLevel,
    inputCostPerMtok: preset.inputCostPerMtok,
    cachedInputCostPerMtok: preset.cachedInputCostPerMtok,
    outputCostPerMtok: preset.outputCostPerMtok,
  }
}

export const POOL_TIER_PRESETS: readonly PoolTierPreset[] = [poolTier('morph'), poolTier('opencode')]

export interface ConfigureModelPoolOptions {
  dataDir: string
  morphKeyFile?: string
  opencodeKeyFile?: string
  /** When true, require missing explicit key files to throw instead of skipping. */
  strictMorphKeyFile?: boolean
  strictOpencodeKeyFile?: boolean
  /** When true, run live `testProvider` connection check before saving (default false). */
  verifyConnection?: boolean
}

export interface ConfigureModelPoolResult {
  dataDir: string
  upserted: Array<{ idKey: 'morph' | 'opencode'; id: string; name: string; priority: number; action: 'created' | 'updated' }>
  skipped: Array<{ idKey: 'morph' | 'opencode'; name: string; reason: string }>
  profiles: PublicModelProfile[]
}

function expandHome(rawPath: string): string {
  const trimmed = rawPath.trim()
  if (trimmed === '~') return homedir()
  if (trimmed.startsWith('~/')) return join(homedir(), trimmed.slice(2))
  return resolve(trimmed)
}

function readOwnerOnlyKeyFile(filePath: string, label: string): string {
  const resolved = expandHome(filePath)
  const st = lstatSync(resolved)
  if (st.isSymbolicLink()) {
    throw new Error(`${label} key file must not be a symbolic link.`)
  }
  if (!st.isFile()) {
    throw new Error(`${label} key path must be a regular file.`)
  }
  if ((st.mode & 0o077) !== 0) {
    throw new Error(`${label} key file must have owner-only permissions (mode 0600).`)
  }
  const key = readFileSync(resolved, 'utf8').trim()
  if (key.length < 8 || !/^[\x21-\x7e]+$/.test(key)) {
    throw new Error(`${label} key file does not contain a valid API key.`)
  }
  return key
}

function findMatchingProfile(
  profiles: readonly PublicModelProfile[],
  preset: PoolTierPreset,
): PublicModelProfile | undefined {
  const normalizedTarget = normalizeModelEndpoint(preset.endpoint)
  return profiles.find(
    p =>
      p.name.trim().toLowerCase() === preset.name.toLowerCase() ||
      (normalizeModelEndpoint(p.endpoint) === normalizedTarget &&
        p.model.trim().toLowerCase() === preset.model.toLowerCase()),
  )
}

export async function configureModelPool(
  options: ConfigureModelPoolOptions,
): Promise<ConfigureModelPoolResult> {
  const dataDir = expandHome(options.dataDir)
  const storage = new Store(dataDir, { autoRecover: false })
  try {
    const upserted: ConfigureModelPoolResult['upserted'] = []
    const skipped: ConfigureModelPoolResult['skipped'] = []

    const keySpecs: Array<{
      preset: PoolTierPreset
      keyFile: string | undefined
      strict: boolean
      label: string
    }> = [
      {
        preset: POOL_TIER_PRESETS[0],
        keyFile: options.morphKeyFile,
        strict: Boolean(options.strictMorphKeyFile),
        label: 'Morph Ultra',
      },
      {
        preset: POOL_TIER_PRESETS[1],
        keyFile: options.opencodeKeyFile,
        strict: Boolean(options.strictOpencodeKeyFile),
        label: 'OpenCode Go',
      },
    ]

    for (const spec of keySpecs) {
      if (!spec.keyFile) {
        skipped.push({ idKey: spec.preset.idKey, name: spec.preset.name, reason: 'no key file configured' })
        continue
      }
      const resolvedKeyPath = expandHome(spec.keyFile)
      if (!existsSync(resolvedKeyPath)) {
        if (spec.strict) {
          throw new Error(`${spec.label} key file does not exist: ${resolvedKeyPath}`)
        }
        skipped.push({ idKey: spec.preset.idKey, name: spec.preset.name, reason: 'key file absent' })
        continue
      }

      const key = readOwnerOnlyKeyFile(resolvedKeyPath, spec.label)
      const existing = findMatchingProfile(listModelProfiles(storage), spec.preset)
      const saved = await saveModelProfile(
        {
          ...(existing ? { id: existing.id } : {}),
          name: spec.preset.name,
          endpoint: spec.preset.endpoint,
          model: spec.preset.model,
          protocol: spec.preset.protocol,
          key,
          priority: spec.preset.priority,
          enabled: true,
          contextWindow: spec.preset.contextWindow,
          thinkingLevel: spec.preset.thinkingLevel,
          inputCostPerMtok: spec.preset.inputCostPerMtok,
          cachedInputCostPerMtok: spec.preset.cachedInputCostPerMtok,
          outputCostPerMtok: spec.preset.outputCostPerMtok,
        },
        storage,
        { skipConnectionCheck: !options.verifyConnection },
      )
      upserted.push({
        idKey: spec.preset.idKey,
        id: saved.id,
        name: spec.preset.name,
        priority: spec.preset.priority,
        action: existing ? 'updated' : 'created',
      })
    }

    const profiles = listModelProfiles(storage)
    return { dataDir, upserted, skipped, profiles }
  } finally {
    storage.close()
  }
}

export function formatPoolSummaryTable(result: ConfigureModelPoolResult): string {
  const lines: string[] = [
    `Data dir: ${result.dataDir}`,
    `Upserted: ${result.upserted.length} | Skipped: ${result.skipped.length} | Total profiles: ${result.profiles.length}`,
  ]
  if (result.skipped.length > 0) {
    for (const s of result.skipped) {
      lines.push(`  [skipped] ${s.name} (${s.reason})`)
    }
  }
  lines.push('')
  lines.push('PRIORITY  ENABLED  HEALTH     PROTOCOL          MODEL                          NAME                           ENDPOINT')
  lines.push('--------  -------  ---------  ----------------  -----------------------------  -----------------------------  ------------------------------------------')
  for (const p of result.profiles) {
    const prio = String(p.priority).padEnd(8)
    const enabled = (p.enabled ? 'yes' : 'no').padEnd(7)
    const health = p.healthState.padEnd(9)
    const proto = p.protocol.padEnd(16)
    const model = p.model.slice(0, 29).padEnd(29)
    const name = p.name.slice(0, 29).padEnd(29)
    lines.push(`${prio}  ${enabled}  ${health}  ${proto}  ${model}  ${name}  ${p.endpoint}`)
  }
  return lines.join('\n')
}

async function main() {
  const { values } = parseArgs({
    options: {
      'data-dir': { type: 'string' },
      'morph-key-file': { type: 'string' },
      'opencode-key-file': { type: 'string' },
      verify: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  })

  if (values.help) {
    console.log([
      'Usage: npx tsx scripts/configure-model-pool.ts [options]',
      '',
      'Options:',
      '  --data-dir <path>          Kovo data directory (default: $KOVO_DATA_DIR or ~/guardian-data)',
      '  --morph-key-file <path>    Owner-only Morph Ultra key file (default: ~/.config/guardian-fixtures/morph.key)',
      '  --opencode-key-file <path> Owner-only OpenCode Go key file (default: ~/.config/guardian-fixtures/opencode-go.key)',
      '  --verify                   Run live connection test before saving each profile',
      '  -h, --help                 Show this help message',
    ].join('\n'))
    return
  }

  const dataDir = values['data-dir'] ?? process.env.KOVO_DATA_DIR ?? join(homedir(), 'guardian-data')
  const morphKeyFile = values['morph-key-file'] ?? join(homedir(), '.config', 'guardian-fixtures', 'morph.key')
  const opencodeKeyFile = values['opencode-key-file'] ?? join(homedir(), '.config', 'guardian-fixtures', 'opencode-go.key')

  const result = await configureModelPool({
    dataDir,
    morphKeyFile,
    opencodeKeyFile,
    strictMorphKeyFile: Boolean(values['morph-key-file']),
    strictOpencodeKeyFile: Boolean(values['opencode-key-file']),
    verifyConnection: Boolean(values.verify),
  })
  console.log(formatPoolSummaryTable(result))
}

const isMain = process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])
if (isMain) {
  main().catch(err => {
    const message = err instanceof Error ? err.message : String(err)
    console.error(`configure-model-pool failed: ${message}`)
    process.exitCode = 1
  })
}
