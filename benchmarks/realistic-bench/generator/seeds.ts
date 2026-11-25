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

/** Enumerate reproducible seeds. Dev => [1..n]. Held-out => opaque HMAC-derived seeds (needs salt). */
export function listSeeds(set: SeedSet, n = 5, salt?: string): number[] {
  if (set === 'dev') return Array.from({ length: n }, (_, i) => DEV_MIN + i)
  const s = requireHeldOutSalt(salt)
  const out: number[] = []
  for (let i = 0; out.length < n; i++) {
    const mac = createHmac('sha256', s).update(`realistic-bench:held-out-seed:${i}`).digest()
    const value = HELDOUT_MIN + (mac.readUInt32BE(0) % HELDOUT_SPAN)
    if (!out.includes(value)) out.push(value)
  }
  return out
}
