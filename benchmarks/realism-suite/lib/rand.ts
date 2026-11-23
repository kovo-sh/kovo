// Deterministic PRNG helpers. Fixtures must be reproducible run to run for a given seed.
export type Rng = () => number

/** mulberry32 — small, fast, deterministic. */
export function makeRng(seed: number): Rng {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export function intBetween(rng: Rng, min: number, max: number): number {
  if (max <= min) return min
  return min + Math.floor(rng() * (max - min + 1))
}

export function pick<T>(rng: Rng, items: readonly T[]): T {
  return items[Math.floor(rng() * items.length) % items.length]
}

export function hexToken(rng: Rng, bytes: number): string {
  let out = ''
  for (let i = 0; i < bytes; i++) {
    out += Math.floor(rng() * 256)
      .toString(16)
      .padStart(2, '0')
  }
  return out
}
