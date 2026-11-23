// Per-seed identifier formatting. Different seeds present object ids in different shapes so a scanner
// cannot assume numeric enumeration.
import type { IdFormat } from './types.ts'
import { createPrng } from './prng.ts'

const ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789' // no look-alikes

export interface IdCodec {
  readonly format: IdFormat
  encode(kind: string, n: number): string
  decode(kind: string, s: string): number | null
}

function hashidChars(seedStr: string, n: number): string {
  const p = createPrng(`${seedStr}:${n}`)
  return p.hex(6)
}

export function createIdCodec(format: IdFormat, salt: string): IdCodec {
  // prefix per kind, derived from salt so it's stable within a seed
  const prefixes = new Map<string, string>()
  const prefixFor = (kind: string): string => {
    let p = prefixes.get(kind)
    if (!p) {
      p = kind.replace(/[^a-z]/gi, '').slice(0, 3).toLowerCase() || 'obj'
      prefixes.set(kind, p)
    }
    return p
  }

  return {
    format,
    encode(kind, n) {
      switch (format) {
        case 'int':
          return String(n)
        case 'uuid': {
          const h = createPrng(`${salt}:${kind}:${n}`).hex(16)
          return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${((parseInt(h[16]!, 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`
        }
        case 'prefixed': {
          const body = hashidChars(`${salt}:${kind}`, n)
          return `${prefixFor(kind)}_${body}`
        }
        case 'hashid': {
          // reversible-ish: encode n with a per-(salt,kind) keyed offset; decode by scan is avoided,
          // we store a map at encode time
          const key = `${salt}:${kind}`
          const map = getHashMap(key)
          let s = map.fwd.get(n)
          if (!s) {
            const p = createPrng(`${key}:${n}`)
            do {
              s = Array.from({ length: 6 }, () => ALPHABET[Math.floor(p.next() * ALPHABET.length)]).join('')
            } while (map.rev.has(s))
            map.fwd.set(n, s)
            map.rev.set(s, n)
          }
          return s
        }
      }
    },
    decode(kind, s) {
      switch (format) {
        case 'int': {
          const n = Number(s)
          return Number.isInteger(n) && n >= 0 ? n : null
        }
        case 'uuid':
        case 'prefixed': {
          // not reversible; apps look up by stored external id. Return null.
          return null
        }
        case 'hashid': {
          const map = getHashMap(`${salt}:${kind}`)
          return map.rev.has(s) ? map.rev.get(s)! : null
        }
      }
    },
  }
}

const hashMaps = new Map<string, { fwd: Map<number, string>; rev: Map<string, number> }>()
function getHashMap(key: string) {
  let m = hashMaps.get(key)
  if (!m) {
    m = { fwd: new Map(), rev: new Map() }
    hashMaps.set(key, m)
  }
  return m
}
