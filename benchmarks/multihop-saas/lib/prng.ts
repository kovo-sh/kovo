// Deterministic, dependency-free PRNG for per-seed domain variation. Held-out seeds key the
// generator with a host-only salt so the written-out repository cannot reproduce their variants.
import { createHmac } from 'node:crypto'

export interface Prng {
  readonly seed: number
  readonly label: string
  int(minInclusive: number, maxInclusive: number): number
  float(): number
  bool(probability?: number): boolean
  pick<T>(items: readonly T[]): T
  hex(bytes: number): string
  token(prefix: string, bytes?: number): string
  fork(label: string): Prng
}

function sfc32(a: number, b: number, c: number, d: number): () => number {
  return () => {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0
    let t = (a + b) | 0
    a = b ^ (b >>> 9)
    b = (c + (c << 3)) | 0
    c = (c << 21) | (c >>> 11)
    d = (d + 1) | 0
    t = (t + d) | 0
    c = (c + t) | 0
    return (t >>> 0) / 4294967296
  }
}

export function createPrng(seed: number, salt?: string, label = 'root'): Prng {
  if (!Number.isSafeInteger(seed)) throw new Error(`prng: seed must be a safe integer, got ${seed}`)
  const key = createHmac('sha256', salt ?? 'multihop-dev-salt').update(`${seed}:${label}`).digest()
  const next = sfc32(key.readUInt32BE(0), key.readUInt32BE(4), key.readUInt32BE(8), key.readUInt32BE(12))
  for (let i = 0; i < 12; i++) next()

  const prng: Prng = {
    seed,
    label,
    float: () => next(),
    int(minInclusive, maxInclusive) {
      if (maxInclusive < minInclusive) throw new Error('prng.int: empty range')
      return minInclusive + Math.floor(next() * (maxInclusive - minInclusive + 1))
    },
    bool(probability = 0.5) {
      return next() < probability
    },
    pick(items) {
      if (items.length === 0) throw new Error('prng.pick: empty list')
      return items[Math.floor(next() * items.length)]!
    },
    hex(bytes) {
      let out = ''
      for (let i = 0; i < bytes; i++) out += Math.floor(next() * 256).toString(16).padStart(2, '0')
      return out
    },
    token(prefix, bytes = 8) {
      return `${prefix}${this.hex(bytes)}`
    },
    fork(child) {
      return createPrng(seed, salt, `${label}:${child}`)
    },
  }
  return prng
}

export function hashLabel(value: string): number {
  let h = 2166136261
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}
