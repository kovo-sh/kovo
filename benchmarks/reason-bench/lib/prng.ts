// Deterministic seeded PRNG (sfc32 seeded from SHA-256) shared by generator/ and lib/ for
// reason-bench. Held-out streams are keyed by HMAC-SHA256 over the unguessable salt.
import { createHash, createHmac } from 'node:crypto'

export interface Prng {
  next(): number // [0, 1)
  int(minInclusive: number, maxInclusive: number): number
  pick<T>(items: readonly T[]): T
  shuffle<T>(items: readonly T[]): T[]
  hex(bytes: number): string
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

function fromDigest(digest: Buffer): Prng {
  const rand = sfc32(digest.readUInt32LE(0), digest.readUInt32LE(4), digest.readUInt32LE(8), digest.readUInt32LE(12))
  for (let i = 0; i < 12; i++) rand()
  const self: Prng = {
    next: rand,
    int(min, max) {
      if (max < min) throw new Error(`prng.int: empty range ${min}..${max}`)
      return min + Math.floor(rand() * (max - min + 1))
    },
    pick(items) {
      if (items.length === 0) throw new Error('prng.pick: empty list')
      return items[Math.floor(rand() * items.length)]!
    },
    shuffle(items) {
      const out = items.slice()
      for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1))
        ;[out[i], out[j]] = [out[j]!, out[i]!]
      }
      return out
    },
    hex(bytes) {
      let s = ''
      for (let i = 0; i < bytes; i++) s += Math.floor(rand() * 256).toString(16).padStart(2, '0')
      return s
    },
    fork(label) {
      return fromDigest(createHash('sha256').update(digest).update('\0').update(label).digest())
    },
  }
  return self
}

/** Seeded PRNG. When `salt` is given (held-out seeds) the stream is keyed by HMAC-SHA256(salt). */
export function createPrng(seed: number | string, salt?: string): Prng {
  const material = `reason-bench:${seed}`
  const digest = salt
    ? createHmac('sha256', salt).update(material).digest()
    : createHash('sha256').update(material).digest()
  return fromDigest(digest)
}
