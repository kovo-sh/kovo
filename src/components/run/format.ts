// Formatting helpers shared by every run view. Pure functions, no React.

export const host = (origin: string | null | undefined) =>
  String(origin ?? '').replace(/^https?:\/\//, '').replace(/\/$/, '')

export const fmtN = (n: number | null | undefined) => (n == null ? '—' : Number(n).toLocaleString('en-US'))
export const fmtUsd = (n: number | null | undefined) => '$' + Number(n || 0).toFixed(2)
export const fmtTok = (n: number) => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? Math.round(n / 1e3) + 'k' : String(n || 0)
export const short = (id: string | null | undefined) => String(id ?? '').slice(0, 8)

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
export const pad = (n: number) => String(n).padStart(2, '0')
export const fmtTime = (ms: number) => { const d = new Date(ms); return pad(d.getHours()) + ':' + pad(d.getMinutes()) }
export const fmtTimeS = (ms: number) => { const d = new Date(ms); return fmtTime(ms) + ':' + pad(d.getSeconds()) }
export const fmtDay = (ms: number) => { const d = new Date(ms); return MON[d.getMonth()] + ' ' + d.getDate() }
export const fmtDate = (ms: number) => fmtDay(ms) + ', ' + fmtTime(ms)
/** "+mm:ss" / "h:mm:ss" offset from the run start, used in time columns. */
export const fmtRel = (ms: number, base: number) => {
  let s = Math.max(0, Math.round((ms - base) / 1000))
  const h = Math.floor(s / 3600); s -= h * 3600
  const m = Math.floor(s / 60); s -= m * 60
  return (h ? h + ':' + pad(m) : '+' + pad(m)) + ':' + pad(s)
}
export const fmtDur = (ms: number) => {
  const s = Math.round(ms / 1000)
  if (s < 60) return s + 's'
  const m = Math.floor(s / 60)
  if (m < 60) return m + 'm ' + pad(s % 60) + 's'
  return Math.floor(m / 60) + 'h ' + pad(m % 60) + 'm'
}
export const cap = (s: string | null | undefined) => String(s ?? '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
export const capF = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)
export const plural = (n: number, w: string, p?: string) => fmtN(n) + ' ' + (n === 1 ? w : (p ?? w + 's'))
const WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty']
/** Small numbers as words ("two medium-severity weaknesses"), larger as digits. */
export const words = (n: number) => n < WORDS.length ? WORDS[n] : fmtN(n)
export const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v))

export const firstSentence = (input: string | null | undefined) => {
  const s = String(input ?? '').trim()
  const m = s.match(/^(.{20,150}?[.;:])(\s|$)/)
  let r = m ? m[1] : s.slice(0, 140)
  if (r.length >= 140 && !m) r = r.replace(/\s+\S*$/, '') + '…'
  return r.replace(/[.;:]$/, '')
}

/** Short label for a run in the rail / palette ("Tier 1 Deep Read-Only + Safe…"). */
export function runLabel(goal: string) {
  let g = String(goal || '').replace(/^(perform|conduct|run)\s+an?\s+/i, '').replace(/^strictly defensive,\s*non-destructive\s+/i, '')
  g = g.split(/[.:]/)[0]
  return g.charAt(0).toUpperCase() + g.slice(1)
}

/** Most common apex domain, if at least half the hosts share it (used to dim it in host labels). */
export function sharedApex(hosts: readonly string[]) {
  const cnt = new Map<string, number>()
  for (const h of hosts) {
    const k = h.split('.').slice(-2).join('.')
    cnt.set(k, (cnt.get(k) ?? 0) + 1)
  }
  const best = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0]
  return best && best[1] >= hosts.length / 2 && hosts.length > 1 ? best[0] : null
}

export const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
export const modKey = () => (isMac() ? '⌘' : 'Ctrl')

/** Body text for display: JSON is pretty-printed, anything else is returned as is; empty → ''. */
export function prettyBody(body: unknown, mediaType = ''): string {
  if (body == null) return ''
  if (typeof body !== 'string') return JSON.stringify(body, null, 2)
  const t = body.trim()
  if (!t) return ''
  if (mediaType.includes('json') || t.startsWith('{') || t.startsWith('[')) {
    try { return JSON.stringify(JSON.parse(t), null, 2) } catch { return body }
  }
  return body
}
