// Dev vs held-out seed resolution. Dev seeds are freely reproducible; held-out seeds require an
// unguessable salt (never committed) so a scanner cannot derive them from the repository.
import { createHmac } from 'node:crypto'
import { createPrng } from '../lib/prng.ts'
import type { Prng } from '../lib/prng.ts'
import type { SeedSet } from '../lib/types.ts'

export const DEV_MIN = 1
export const DEV_MAX = 9999
export const HELDOUT_MIN = 1_000_000
const MIN_SALT_LEN = 16
const HELDOUT_SPAN = 2_000_000_000 // keep derived seeds well inside the safe-integer range

export function seedSetFor(seed: number): SeedSet {
  if (Number.isInteger(seed) && seed >= DEV_MIN && seed <= DEV_MAX) return 'dev'
  if (Number.isInteger(seed) && seed >= HELDOUT_MIN) return 'held-out'
  throw new Error(
    `invalid seed ${seed}: dev seeds are integers ${DEV_MIN}..${DEV_MAX}, held-out seeds are integers >= ${HELDOUT_MIN}`,
  )
}

function requireHeldOutSalt(salt?: string): string {
  const s = salt ?? process.env.KOVO_RB_HELDOUT_SALT
  if (!s || s.length < MIN_SALT_LEN) {
    throw new Error(
      `held-out seeds require a salt of >= ${MIN_SALT_LEN} chars via the salt argument or ` +
        'KOVO_RB_HELDOUT_SALT; refusing to derive a held-out variant without it',
    )
  }
  return s
}

export interface ResolvedSeed {
  seed: number
  seedSet: SeedSet
  prng: Prng
}

/** Resolve a seed into its set + a keyed PRNG. Held-out seeds demand a salt. */
export function resolveSeed(seed: number, salt?: string): ResolvedSeed {
  const seedSet = seedSetFor(seed)
  if (seedSet === 'held-out') {
    const s = requireHeldOutSalt(salt)
    return { seed, seedSet, prng: createPrng(seed, s) }
  }
  return { seed, seedSet, prng: createPrng(seed) }
}

export type SeedDomain = 'certify' | 'smoke'

export interface ListSeedsOptions {
  /** Starting HMAC derivation index (default 0; certifying draws advance past highest exposed index). */
  startIndex?: number
  /** HMAC domain separation: `'certify'` for certification runs, `'smoke'` for non-certifying smoke runs. */
  domain?: SeedDomain
}

export interface DerivedHeldoutSeed {
  index: number
  seed: number
  domain: SeedDomain
}

function heldoutDomainPrefix(domain: SeedDomain): string {
  return domain === 'smoke'
    ? 'realistic-bench:held-out-smoke-seed:'
    : 'realistic-bench:held-out-seed:'
}

/** Derive one opaque salted held-out seed at a specific HMAC index and domain. */
export function deriveHeldoutSeedAt(
  index: number,
  salt?: string,
  domain: SeedDomain = 'certify',
): DerivedHeldoutSeed {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`deriveHeldoutSeedAt: index must be a non-negative integer (got ${index})`)
  }
  const s = requireHeldOutSalt(salt)
  const mac = createHmac('sha256', s).update(`${heldoutDomainPrefix(domain)}${index}`).digest()
  const seed = HELDOUT_MIN + (mac.readUInt32BE(0) % HELDOUT_SPAN)
  return { index, seed, domain }
}

/** Enumerate salted held-out seeds together with their HMAC indices, starting at `startIndex`. */
export function listHeldoutSeedsWithIndices(
  n = 5,
  salt?: string,
  options: ListSeedsOptions = {},
): DerivedHeldoutSeed[] {
  const startIndex = options.startIndex ?? 0
  if (!Number.isInteger(startIndex) || startIndex < 0) {
    throw new Error(`listHeldoutSeedsWithIndices: startIndex must be a non-negative integer (got ${startIndex})`)
  }
  const domain: SeedDomain = options.domain ?? 'certify'
  const s = requireHeldOutSalt(salt)
  const out: DerivedHeldoutSeed[] = []
  const seen = new Set<number>()
  for (let i = startIndex; out.length < n; i++) {
    const derived = deriveHeldoutSeedAt(i, s, domain)
    if (!seen.has(derived.seed)) {
      seen.add(derived.seed)
      out.push(derived)
    }
  }
  return out
}

/** Enumerate reproducible seeds. Dev => [1..n]. Held-out => opaque HMAC-derived seeds (needs salt). */
export function listSeeds(
  set: SeedSet,
  n = 5,
  salt?: string,
  options: ListSeedsOptions = {},
): number[] {
  if (set === 'dev') return Array.from({ length: n }, (_, i) => DEV_MIN + i)
  return listHeldoutSeedsWithIndices(n, salt, options).map(entry => entry.seed)
}
