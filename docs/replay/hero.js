// Replay hero: one scripted timeline drives every pixel.
//
// render(t) is a pure function of the playhead t (0..51 s): it sets classes,
// text and inline transforms from t alone, so scrubbing, looping, pausing and
// frame-accurate recording all fall out of the same code path. `ut` is the
// "UI time", a piecewise-linear map of t: the cold open replays the proof
// moment (ut 17.5..19), the rewind runs ut backwards to the start of the story,
// and flat stretches of the map are holds while a caption reads.
(() => {
  'use strict'
  const W = 1440, H = 810
  // ?embed=1: landing-page iframe mode (see embed.css and the bridge at the end)
  const EMBED = new URLSearchParams(location.search).has('embed')
  const $ = s => document.querySelector(s)
  const $$ = s => [...document.querySelectorAll(s)]

  // ------------------------------------------------------------ math
  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v))
  const seg = (t, a, b) => clamp((t - a) / (b - a))
  const lerp = (a, b, p) => a + (b - a) * p
  const eio = p => p < .5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2
  const eo = p => 1 - Math.pow(1 - p, 3)
  const ei = p => p * p * p
  const pw = (t, pts) => { // piecewise linear
    if (t <= pts[0][0]) return pts[0][1]
    for (let i = 1; i < pts.length; i++) if (t <= pts[i][0]) return lerp(pts[i - 1][1], pts[i][1], seg(t, pts[i - 1][0], pts[i][0]))
    return pts[pts.length - 1][1]
  }

  // ------------------------------------------------------------ icons (src/components/run/icons.tsx)
  const P = {
    search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 14 14"/>',
    overview: '<path d="M2.75 3.25h10.5M2.75 6.25h10.5M2.75 9.25h6.5M2.75 12.25h4.5"/>',
    queue: '<path d="M2.25 9.25 3.5 3.75A1 1 0 0 1 4.47 3h7.06a1 1 0 0 1 .97.75l1.25 5.5V12a1 1 0 0 1-1 1H3.25a1 1 0 0 1-1-1Z"/><path d="M2.25 9.25H5.5l.75 1.5h3.5l.75-1.5h3.25"/>',
    findings: '<path d="M8 1.75 13.25 4v4c0 3-2.25 5.25-5.25 6.25C5 13.25 2.75 11 2.75 8V4Z"/><path d="M8 5.5v3"/><path d="M8 10.75v.01"/>',
    workflow: '<rect x="1.75" y="2.5" width="4" height="3.5" rx="1"/><rect x="10.25" y="2.5" width="4" height="3.5" rx="1"/><rect x="10.25" y="10" width="4" height="3.5" rx="1"/><path d="M5.75 4.25h4.5M5.75 4.25c2.5 0 2 7.5 4.5 7.5"/>',
    surface: '<rect x="2.25" y="2.25" width="4.5" height="4.5" rx="1"/><rect x="9.25" y="2.25" width="4.5" height="4.5" rx="1"/><rect x="2.25" y="9.25" width="4.5" height="4.5" rx="1"/><rect x="9.25" y="9.25" width="4.5" height="4.5" rx="1"/>',
    exchanges: '<path d="M2.5 5.5h10M10 3l2.5 2.5L10 8"/><path d="M13.5 10.5h-10M6 8l-2.5 2.5L6 13"/>',
    activity: '<path d="M1.75 8h2.5l2-4.5 3.5 9 2-4.5h2.5"/>',
    report: '<path d="M4 1.75h5.25L12.25 4.75v9.5H4Z"/><path d="M9 1.75V5h3.25"/><path d="M6.25 8.25h3.5M6.25 10.75h3.5"/>',
    chat: '<path d="M2.75 3.25h10.5v7.5H7L4.25 13v-2.25h-1.5Z"/>',
    moon: '<path d="M13.25 9.5A5.5 5.5 0 0 1 6.5 2.75a5.5 5.5 0 1 0 6.75 6.75Z"/>',
    keyboard: '<rect x="1.75" y="4" width="12.5" height="8" rx="1.5"/><path d="M4.5 6.75h.01M7 6.75h.01M9.5 6.75h.01M12 6.75h.01M5 9.5h6"/>',
    close: '<path d="M4 4l8 8M12 4l-8 8"/>',
    chev: '<path d="M4 6l4 4 4-4"/>',
    chevR: '<path d="M6 4l4 4-4 4"/>',
    copy: '<rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25"/><path d="M3.25 10.75h-.5a1.25 1.25 0 0 1-1.25-1.25v-6.75A1.25 1.25 0 0 1 2.75 1.5h6.75a1.25 1.25 0 0 1 1.25 1.25v.5"/>',
    dots: '<path d="M3.5 8h.01M8 8h.01M12.5 8h.01" stroke-width="2.2"/>',
    panelR: '<rect x="2.25" y="2.75" width="11.5" height="10.5" rx="1.5"/><path d="M9.75 2.75v10.5"/>',
    pause: '<path d="M5.5 3.5v9M10.5 3.5v9"/>',
    play: '<path d="M5 3.25v9.5L12.5 8Z"/>',
    plus: '<path d="M8 3.5v9M3.5 8h9"/>',
    grid: '<path d="M2.5 2.5h11v11h-11ZM2.5 6.17h11M2.5 9.83h11M6.17 2.5v11M9.83 2.5v11"/>',
    sliders: '<path d="M2.5 5h6M11.5 5h2M2.5 11h2M7.5 11h6"/><circle cx="10" cy="5" r="1.5"/><circle cx="6" cy="11" r="1.5"/>',
    globe: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c1.75 1.75 2.5 3.75 2.5 6S9.75 12.25 8 14C6.25 12.25 5.5 10.25 5.5 8S6.25 3.75 8 2Z"/>',
    lock: '<rect x="3.25" y="7" width="9.5" height="6.75" rx="1.25"/><path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2"/>',
    shield: '<path d="M8 1.75 13.25 4v4c0 3-2.25 5.25-5.25 6.25C5 13.25 2.75 11 2.75 8V4Z"/>',
    replay: '<path d="M2.75 8a5.25 5.25 0 1 0 1.6-3.78"/><path d="M2.5 2.5v3h3"/><path d="M7 6v4l3-2Z" fill="currentColor" stroke="none"/>',
    ext: '<path d="M6 3.5H3.5v9h9V10M9 3.5h3.5V7M12.5 3.5 7 9"/>',
    check: '<path d="M3.5 8.5 6.5 11.5 12.5 4.5"/>',
    undo: '<path d="M5.5 3.5 2.5 6.5l3 3"/><path d="M2.5 6.5h7a4 4 0 0 1 0 8H7"/>',
    sparkle: '<path d="M8 2.5v3M8 10.5v3M2.5 8h3M10.5 8h3"/>',
    alert: '<path d="M8 2.25 14.25 13H1.75Z"/><path d="M8 6.5v3M8 11.25v.01"/>',
    node: '<circle cx="8" cy="8" r="2.25"/><path d="M8 1.75v4M8 10.25v4M1.75 8h4M10.25 8h4"/>',
  }
  const icon = (name, cls = 'ico', style = '') => `<svg class="${cls}" viewBox="0 0 16 16" aria-hidden="true"${style ? ` style="${style}"` : ''}>${P[name] || ''}</svg>`

  // ------------------------------------------------------------ glyphs (src/components/run/glyphs.tsx)
  const ring = (stroke, inner, dash) => `<svg class="g14" viewBox="0 0 14 14" width="14" height="14" style="display:block;flex:none"><circle cx="7" cy="7" r="5.75" fill="none" stroke="${stroke}" stroke-width="1.4"${dash ? ' stroke-dasharray="2.1 1.9"' : ''}/>${inner}</svg>`
  const glyph = s => {
    switch (s) {
      case 'confirmed': case 'approved': return ring('var(--fg-3)', '<path d="M4.6 7.1 6.3 8.8 9.5 5.4" fill="none" stroke="var(--fg-2)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>')
      case 'reported': return ring('var(--fg-3)', '<path d="M7 4.25 9.75 7 7 9.75 4.25 7Z" fill="var(--fg-2)"/>')
      case 'complete': return '<svg viewBox="0 0 14 14" width="14" height="14" style="display:block;flex:none"><circle cx="7" cy="7" r="6.5" fill="var(--fg-4)"/><path d="M4.4 7.2 6.2 9 9.7 5.3" fill="none" stroke="var(--panel)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      case 'fixed': return '<svg viewBox="0 0 14 14" width="14" height="14" style="display:block;flex:none"><circle cx="7" cy="7" r="6.5" fill="var(--ok)"/><path d="M4.4 7.2 6.2 9 9.7 5.3" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      case 'pending': return ring('var(--fg-2)', '<path d="M7 3.5A3.5 3.5 0 0 1 7 10.5Z" fill="var(--fg-2)"/>')
      case 'running': return ring('var(--accent)', '<path d="M7 3.5A3.5 3.5 0 0 1 10.5 7H7Z" fill="var(--accent)"/>')
      case 'waiting': return ring('var(--warn)', '<path d="M7 4.5V7l1.6 1.2" fill="none" stroke="var(--warn)" stroke-width="1.4" stroke-linecap="round"/>')
      case 'inconclusive': return ring('var(--fg-3)', '<path d="M7 7h.01" stroke="var(--fg-3)" stroke-width="2" stroke-linecap="round"/>', true)
      case 'blocked': return ring('var(--bad)', '<path d="M4.9 9.1l4.2-4.2" stroke="var(--bad)" stroke-width="1.4" stroke-linecap="round"/>')
      default: return ring('var(--fg-4)', '')
    }
  }
  const sevGlyph = s => {
    const n = { high: 3, medium: 2, low: 1 }[s] ?? 0
    const col = { high: 'var(--high)', medium: 'var(--med)', low: 'var(--fg-2)' }[s] ?? 'var(--fg-3)'
    const bars = [[1.5, 8, 4], [5.75, 5.5, 6.5], [10, 3, 9]]
    return `<svg viewBox="0 0 14 14" width="14" height="14" style="display:block;flex:none">${bars.map((b, i) => n === 0
      ? `<rect x="${b[0]}" y="6" width="2.5" height="2" rx="1" fill="var(--fg-3)"/>`
      : `<rect x="${b[0]}" y="${b[1]}" width="2.5" height="${b[2]}" rx="1" fill="${i < n ? col : 'var(--fg-4)'}"/>`).join('')}</svg>`
  }
  const SEV_L = { high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' }
  const pinGlyph = (sev, solid) => {
    const col = { high: 'var(--high)', medium: 'var(--med)', low: 'var(--fg-2)', informational: 'var(--fg-3)' }[sev]
    const s = 10, h = 5
    const shape = sev === 'high' ? `<path d="M${h} .8 ${s - .6} ${s - .9} .6 ${s - .9}Z"/>` : sev === 'medium' ? `<rect x="1" y="1" width="8" height="8" rx="1"/>` : sev === 'low' ? `<circle cx="5" cy="5" r="4"/>` : `<circle cx="5" cy="5" r="2.8"/>`
    return `<svg width="10" height="10" viewBox="0 0 10 10" style="overflow:visible;display:block"><g fill="${solid ? col : 'none'}" stroke="${col}" stroke-width="${solid ? 0 : 1.3}">${shape}</g></svg>`
  }
  const mark = (size, color = 'currentColor') => `<svg viewBox="0 0 64 64" width="${size}" height="${size}" fill="none" style="display:block;flex:none">
    <path d="M 11.25 24.79 A 19.80 19.80 0 0 1 33.80 22.02" stroke="${color}" stroke-width="4.6"/>
    <path d="M 41.98 30.20 A 19.80 19.80 0 0 1 39.21 52.75" stroke="${color}" stroke-width="4.6"/>
    <path d="M 16.20 47.80 L 48.00 16.00" stroke="${color}" stroke-width="4.6"/>
    <path d="M 38.00 15.20 H 48.80 V 26.00" stroke="${color}" stroke-width="4.6" stroke-linecap="square"/>
    <path d="M 10.20 47.80 L 14.20 43.80 H 19.60 L 20.20 44.40 V 49.80 L 16.20 53.80 V 47.80 Z" fill="${color}"/></svg>`
  const CHECK_SVG = '<svg viewBox="0 0 16 16" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 8.5 6.5 11.5 12.5 4.5"/></svg>'

  // ------------------------------------------------------------ story data (simulated)
  const HOSTS = [
    { h: 'staging.acme.dev', src: 'seed', at: 5.9, ck: 0 },
    { h: 'api.staging.acme.dev', src: 'DNS', at: 6.12, ck: 6.75 },
    { h: 'auth.staging.acme.dev', src: 'crawl', at: 6.32, ck: 7.1 },
    { h: 'cdn.thirdparty.com', src: 'link', at: 6.5, tp: true },
  ]
  const CATS = [['A', 'Auth'], ['B', 'Access'], ['C', 'Injection'], ['D', 'CORS'], ['E', 'Config'], ['F', 'TLS'], ['G', 'DNS'], ['H', 'SSRF'], ['I', 'Upload'], ['J', 'Logic'], ['K', 'LLM']]
  const R = 'reported', NF = 'needs_follow_up', NI = 'no_issue_found', RO = 'ruled_out', NA = 'not_applicable', UT = 'untested'
  const ROWS = [
    { grp: 'High-risk surface', tier: 3, host: 'api', apex: '.staging.acme.dev', cells: [NI, [NF, R], RO, NI, NI, NA, NA, NF, NA, NF, NA] },
    { tier: 3, host: 'auth', apex: '.staging.acme.dev', cells: [NF, NI, RO, NI, NI, NI, NA, RO, NA, NI, NA] },
    { grp: 'Medium-risk surface', tier: 2, host: 'staging', apex: '.acme.dev', cells: [NI, NI, RO, NI, R, NI, NI, NA, NI, UT, NA] },
  ]
  // deterministic fill order for the matrix
  const CELL_T = (() => {
    let seed = 7
    const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647
    const out = {}
    const ids = []
    ROWS.forEach((r, ri) => r.cells.forEach((_, ci) => ids.push([ri, ci])))
    ids.forEach(([ri, ci]) => { out[ri + ':' + ci] = 8.55 + rnd() * 4.6 + ci * 0.02 })
    out['0:1'] = 9.7 // access-control cell lights up as @bola's lead lands
    return out
  })()
  const cellState = (ri, ci, ut) => {
    const c = ROWS[ri].cells[ci]
    if (Array.isArray(c)) return ut < CELL_T[ri + ':' + ci] ? UT : ut < 13.3 ? c[0] : c[1]
    if (c === UT) return UT
    return ut < CELL_T[ri + ':' + ci] ? UT : c
  }
  const PINS = [[0, 'high', true, 13.3], [0, 'informational', false, 15.05], [1, 'medium', false, 14.4], [2, 'low', true, 14.75]]

  const FINDINGS = [
    { sev: 'high', st: 'confirmed', title: 'Cross-tenant invoice read via object ID', cat: 'Access control', o: 'api.staging.acme.dev', at: 13.3 },
    { sev: 'medium', st: 'pending', title: 'Session cookie missing SameSite on auth callback', cat: 'Auth & identity', o: 'auth.staging.acme.dev', at: 14.4 },
    { sev: 'low', st: 'confirmed', title: 'Server version disclosed in response headers', cat: 'Misconfig & exposure', o: 'staging.acme.dev', at: 14.75 },
    { sev: 'informational', st: 'inconclusive', title: 'No rate limit observed on invoice export', cat: 'Logic & race', o: 'api.staging.acme.dev', at: 15.05 },
  ]

  const KIND_L = { brief: 'Brief', claim: 'Claim', lead: 'Lead', blocker: 'Blocker', verdict: 'Verdict', status: 'Status', note: 'Note' }
  const MSGS = [
    { at: 5.95, who: 'Coordinator', role: 'co', kind: 'status', body: 'Discovery found 3 hosts from <code>staging.acme.dev</code>. Holding until you approve the scope; nothing is sent before that.' },
    { at: 8.35, who: '@coordinator', role: 'co', kind: 'brief', body: 'Scope approved: 3 hosts, Authenticated, personas <code>user_a</code> and <code>user_b</code>. <span class="mention">@bola</span> invoices + orgs, <span class="mention">@auth</span> session, <span class="mention">@injection</span> search, <span class="mention">@edge</span> caching.' },
    { at: 8.95, who: '@auth', kind: 'claim', body: 'Taking session and token lifecycle on <code>auth.staging.acme.dev</code>.' },
    { at: 9.55, who: '@bola', kind: 'lead', body: '<code>GET /api/v1/invoices/:id</code> looks keyed by ID only. Planning a <code>bola_idor</code> control vs. variant with user_a / user_b.', refs: [['exchanges', 'GET /api/v1/invoices/inv_8842']] },
    { at: 10.2, who: '@injection', kind: 'status', body: 'Search parameter: <code>sqli_boolean</code> and <code>ssti_math</code> probes show no anomaly. Ruled out.' },
    { at: 10.85, who: '@edge', kind: 'lead', body: 'Invoice PDFs link to <code>cdn.thirdparty.com</code>. Checking cache headers there.' },
    { at: 11.3, who: '@broker', role: 'br', kind: 'blocker', body: 'Refused a request from <span class="mention">@edge</span>: host is not in the approved scope.', receipt: true },
    { at: 12.55, who: '@edge', kind: 'note', body: 'Understood. Logged as out of scope; nothing was sent.' },
    { at: 13.25, who: '@verifier', kind: 'verdict', body: '<code>bola_idor</code> on <code>inv_8842</code> reproduced by replay, 2 of 2 attempts. Confirmed.', refs: [['findings', 'Cross-tenant invoice read via object ID']] },
    { at: 14.5, who: '@auth', kind: 'lead', body: 'Callback cookie lacks SameSite. Handing to <span class="mention">@verifier</span>.' },
  ]

  // ------------------------------------------------------------ the fix (outside Guardian: the user's own terminal)
  const P_ = '<span class="tp1">~/acme-saas</span> <span class="tp2">main</span> <span class="tp3">$</span> '
  const TERM = [
    { at: 20.5, cmd: 'git diff', dur: .28 },
    { at: 20.9, html: '<span class="tb">diff --git a/src/routes/invoices.ts b/src/routes/invoices.ts</span>' },
    { at: 20.9, html: '<span class="tc">@@ -42,3 +42,4 @@</span> <span class="td">invoices.get(\'/api/v1/invoices/:id\', …</span>' },
    { at: 21.0, html: '   <span class="td">if (!invoice) return res.sendStatus(404)</span>' },
    { at: 21.0, html: ' ' },
    { at: 21.12, html: '<span class="tadd">+  if (invoice.tenantId !== req.user.tenantId) return res.sendStatus(404)</span><span class="tl">L44</span>', add: true },
    { at: 21.12, html: '   <span class="td">return res.json(invoice)</span>' },
    { at: 21.75, cmd: 'git commit -qam "Scope invoice reads to the caller\'s tenant"', dur: .5 },
    { at: 22.5, cmd: 'git push', dur: .2 },
    { at: 22.8, html: '<span class="td">To github.com:acme/acme-saas.git</span>' },
    { at: 22.8, html: '<span class="td">   a41c9e2..7d03f1b  main -&gt; main</span>' },
    { at: 23.05, deploy: true },
  ]
  const DOCKER = 'docker run -p 8000:8000 -v kovo-data:/data ghcr.io/kovo-sh/kovo-hunter'

  // ------------------------------------------------------------ playhead → UI time
  // Piecewise-linear [playhead s, UI s]. Flat-ish segments are holds (the UI
  // barely advances while a caption reads); steep ones are brisk fill-in.
  const DUR = 51
  const RW_A = 5.1, RW_B = 5.7, END_A = 44.4
  const OPEN = [[0, 17.45], [1.3, 18.2], [RW_A, 18.95]]
  const STORY = [
    [RW_B, 4.4], [7.02, 5.72], [8.0, 6.5], [8.9, 7.1], [9.6, 7.32], [11.5, 7.44], [11.9, 7.72], [12.4, 8.3], // scope
    [15.9, 11.3], [16.4, 11.8], [20.9, 12.9], [21.4, 13.4], // surface, broker hold
    [23.4, 15.6], [24.6, 16.95], [25.9, 18.2], [30.2, 20.2], // findings, proof hold
    [30.4, 20.3], [35.9, 24.3], // the fix, outside Guardian
    [36.1, 24.4], [37.0, 25.1], [39.5, 27.4], [40.0, 27.8], [41.6, 29.1], [END_A, 29.6], // verify fix, retest hold
  ]
  const uiTime = t => {
    if (t < RW_A) return pw(t, OPEN)
    if (t < RW_B) return 18.95 - (18.95 - 4.4) * eio(seg(t, RW_A, RW_B))
    if (t < END_A) return pw(t, STORY)
    return 30
  }
  const STAMP_AT = [1.3, 25.9] // playhead seconds the CONFIRMED stamp lands (cold open, story)

  // ------------------------------------------------------------ captions: word-by-word, 2–4 words per chunk
  const WR = .36, TAIL = .55 // seconds per word, hold after the last word
  const CAP_SRC = [
    [0.2, ['Your AI pentester', 'found a leak.']],
    [3.4, ['Proven by replay.']],
    [5.85, ['Paste your site.']],
    [7.5, ['You approve the scope.']],
    [9.6, ['Third-party host?', 'Stays unchecked.']],
    [12.45, ['Agents map the surface.']],
    [14.5, ['One reaches for', 'an unapproved host.']],
    [17.75, ['The broker blocks it.']],
    [19.8, ['Zero bytes sent.']],
    [21.45, ['Confirmed findings', 'carry a replay.']],
    [24.25, ['Same request,', 'another tenant’s session.']],
    [27.1, ['The AI never sees', 'your cookies.']],
    [30.4, ['You ship the fix', 'in your own repo.']],
    [34.3, ['Push to staging.']],
    [36.05, ['One click re-verifies.'], 'top'],
    [37.7, ['Same stored replay.', 'Zero LLM tokens.'], 'top'],
    [41.65, ['Verified fixed.'], 'top'],
    [44.9, ['Don’t just trust', 'the AI, verify.'], 'dup'],
    [48.15, ['One command.', 'Your machine.'], 'top'],
  ]
  const CAPS = []
  CAP_SRC.forEach(([at, chunks, pos], pi) => {
    let a = Math.max(at, CAPS.length ? CAPS[CAPS.length - 1].b : 0) // never clip the previous phrase
    chunks.forEach(c => {
      const words = c.split(' ')
      const b = a + words.length * WR + TAIL
      CAPS.push({ a, b, words, pos: pos || 'low', pi, html: words.map((w, i) => `<span class="w" data-k="${i}">${w}</span>`).join(' ') })
      a = b
    })
  })
  const END_PHRASE = CAPS.filter(c => c.pos === 'dup')
  const CHAPTERS = [[0, 'Proof'], [RW_B, 'Scope'], [12.4, 'Surface'], [15.9, 'Broker'], [21.4, 'Findings'], [24.6, 'Replay'], [30.3, 'Fix'], [36.0, 'Verify'], [END_A, 'End']]

  // ------------------------------------------------------------ build DOM
  $$('[data-i]').forEach(el => {
    const cls = el.getAttribute('class') || 'ico'
    el.outerHTML = icon(el.dataset.i, cls, el.getAttribute('style') || '')
  })
  $$('[data-mark]').forEach(el => { el.outerHTML = mark(+el.dataset.mark, el.dataset.markColor) })
  $$('[data-glyph]').forEach(el => { el.innerHTML = glyph(el.dataset.glyph); el.style.display = 'inline-flex' })
  $$('[data-sev]').forEach(el => { el.innerHTML = sevGlyph(el.dataset.sev) + SEV_L[el.dataset.sev] })

  // consent host grid
  $('#hostgrid').innerHTML = HOSTS.map((h, i) => `<div class="host" id="host-${i}"><span class="cb">${CHECK_SVG}</span><span>${h.h}</span>${h.tp ? '<span class="tp" title="Third-party host — unchecked by default">3P · unchecked</span>' : ''}<span class="src">${h.src}</span></div>`).join('')

  // surface legend + matrix
  const LEG = [[R, 'Reported'], [NF, 'Follow-up'], [NI, 'No issue'], [RO, 'Ruled out'], [NA, 'N/A'], [UT, 'Uncharted']]
  $('#s-legend').innerHTML = LEG.map(([k, l]) => `<span class="lg"><span class="sw tile st-${k}" style="position:static;inset:auto"><span class="gl" style="transform:scale(.75)"></span></span>${l}<span class="n" id="lg-${k}">0</span></span>`).join('')
  const tierBars = n => `<span class="tier">${[0, 1, 2, 3].map(i => `<i class="${i < n ? 'on' : ''}" style="height:${4 + i * 1.5}px"></i>`).join('')}</span>`
  let mx = `<thead><tr><th class="hc"><div>Origin</div></th>${CATS.map(c => `<th class="cc2"><small>${c[0]}</small><span>${c[1]}</span></th>`).join('')}<th class="fc">Findings</th></tr></thead><tbody>`
  ROWS.forEach((r, ri) => {
    if (r.grp) mx += `<tr class="grp"><th colspan="13"><span>${tierBars(r.tier)}${r.grp}<em>${r.grp.startsWith('High') ? 2 : 1}</em></span></th></tr>`
    mx += `<tr><th class="oh"><div><span>${r.host}<span class="apex">${r.apex}</span></span>${tierBars(r.tier)}</div></th>`
    r.cells.forEach((_, ci) => { mx += `<td class="cell"><span class="tile st-untested bt" id="cell-${ri}-${ci}"><span class="gl"></span></span></td>` })
    mx += `<td><div class="fpins">${PINS.map((p, pi) => p[0] === ri ? `<span class="pin" id="pin-${pi}">${pinGlyph(p[1], p[2])}</span>` : '').join('')}<span class="dash" id="dash-${ri}"></span></div></td></tr>`
  })
  mx += `<tr class="chart"><th>Charted</th>${CATS.map((_, ci) => `<td><div class="cbar" id="cbar-${ci}"></div><div class="ccount" id="ccnt-${ci}">0/3</div></td>`).join('')}<td></td></tr></tbody>`
  $('#matrix').innerHTML = mx

  // findings list (severity groups)
  const GROUPS = ['high', 'medium', 'low', 'informational']
  $('#flist').innerHTML = GROUPS.map(g => {
    const rows = FINDINGS.map((f, i) => [f, i]).filter(([f]) => f.sev === g)
    return `<div class="fitem" id="fg-${g}"><div class="ghead">${icon('chev', 'ico sm')}${sevGlyph(g)}<span>${SEV_L[g]}</span><span class="n">${rows.length}</span></div></div>` +
      rows.map(([f, i]) => `<div class="fitem" id="fi-${i}"><div class="frow" id="frow-${i}"><span style="display:inline-flex">${glyph(f.st)}</span><span class="t">${f.title}</span><span class="c">${f.cat}</span><span class="o">${f.o}</span></div></div>`).join('')
  }).join('')

  // board timeline
  $('#btl').innerHTML = '<p class="bempty" id="b-empty">Nothing on the board yet. Briefs, handoffs and verdicts land here as the run progresses.</p>' + MSGS.map((m, i) => {
    const av = m.role === 'co' ? `<span class="av co"><svg viewBox="0 0 14 14" width="12" height="12"><circle cx="7" cy="7" r="2.5" fill="currentColor"/></svg></span>`
      : m.role === 'br' ? `<span class="av br">${icon('shield', 'ico sm')}</span>`
      : `<span class="av">${m.who.charAt(1).toUpperCase()}</span>`
    const refs = m.refs ? `<div class="refs">${m.refs.map(([ic, l]) => `<span class="ref">${icon(ic, 'ico sm')}${l}</span>`).join('')}</div>` : ''
    const rc = m.receipt ? `<div class="receipt"><div class="rh">${icon('shield', 'ico sm')}BLOCKED · Host Request Broker</div><dl><dt>Host</dt><dd>cdn.thirdparty.com</dd><dt>Rule</dt><dd>scope.host_not_approved</dd><dt>Sent</dt><dd>0 bytes</dd></dl></div>` : ''
    return `<div class="bm" id="bm-${i}">${av}<div style="min-width:0"><div class="bmh"><span>${m.who}</span><span class="k ${m.kind}">${KIND_L[m.kind]}</span><span class="tm" id="bmt-${i}"></span></div><div class="bmb">${m.body}</div>${refs}${rc}</div></div>`
  }).join('')

  // terminal lines
  $('#tw-body').innerHTML = TERM.map((l, i) => `<div class="tln${l.add ? ' add' : ''}" id="tl-${i}">${l.cmd != null ? P_ + `<span id="tlc-${i}"></span>` : l.deploy ? '<span id="tl-dep"></span>' : l.html}</div>`).join('')

  // end-card headline, revealed word by word in step with its caption
  const END_WORDS = END_PHRASE.flatMap(c => c.words.map((w, k) => ({ w, at: c.a + k * WR })))
  $('#end-h2').innerHTML = END_WORDS.map((x, i) => `<span class="ew${i === END_WORDS.length - 1 ? ' em' : ''}" id="ew-${i}">${x.w}</span>`).join(' ')

  // control-bar chapter ticks
  $('#ticks').innerHTML = CHAPTERS.map(([t, l]) => `<span style="left:${t / DUR * 100}%">${l}</span>`).join('')

  // ------------------------------------------------------------ DOM write helpers (skip no-op writes)
  const cache = new WeakMap()
  const memo = (el, k, v) => { let m = cache.get(el); if (!m) cache.set(el, m = {}); if (m[k] === v) return false; m[k] = v; return true }
  const cls = (el, c, on) => { if (el && memo(el, 'c:' + c, !!on)) el.classList.toggle(c, !!on) }
  const txt = (el, s) => { if (el && memo(el, 't', s)) el.textContent = s }
  const html = (el, s) => { if (el && memo(el, 'h', s)) el.innerHTML = s }
  const css = (el, p, v) => { if (el && memo(el, 's:' + p, v)) el.style[p] = v }
  const show = (el, on, disp = '') => css(el, 'display', on ? disp : 'none')
  const gl = (el, s) => { if (el && memo(el, 'g', s)) el.innerHTML = glyph(s) }

  const E = id => document.getElementById(id)
  const el = {
    hero: E('hero'), win: E('win'), app: E('app'), chrome: E('chrome'), url: E('url-path'), stage: E('stage'), frame: E('frame'),
    cap: E('cap'), capShade: E('capshade'),
    hdrP: E('hdr-projects'), hdrR: E('hdr-run'), hGlyph: E('h-glyph'), hStatus: E('h-status'), hPhase: E('h-phase'), hRound: E('h-round'),
    hUsd: E('h-usd'), hMeter: E('h-meter'), hReq: E('h-req'), hRMeter: E('h-rmeter'), hHosts: E('h-hosts'), hDur: E('h-dur'), hAction: E('h-action'),
    track: [...E('h-track').children],
    newproj: E('ov-newproj'), npName: E('np-name'), npNameV: E('np-name-v'), npNamePh: E('np-name-ph'), npSites: E('np-sites'), npSitesV: E('np-sites-v'), npSitesPh: E('np-sites-ph'), npPaste: E('np-paste'),
    cEyebrow: E('c-eyebrow'), cEyeGlyph: E('c-eyeglyph'), cCount: E('c-count'),
    blocked: E('ov-blocked'), replay: E('ov-replay'), rsheet: E('rsheet'), term: E('ov-term'), toast: E('toast'), rewind: E('ov-rewind'), end: E('ov-end'),
    skip: E('ov-skip'), llm: E('ov-llm'),
    cursor: E('cursor'), ripple: E('ripple'), stampR: E('stamp-red'), ring: E('rs-ring'),
    bCount: E('b-count'), bGlyph: E('b-glyph'), bStatus: E('b-status'), bAgents: E('b-agents'), bDot: E('b-dot'), bEmpty: E('b-empty'),
    pBoard: E('p-board'), pFinding: E('p-finding'),
  }
  const views = { projects: E('v-projects'), overview: E('v-overview'), surface: E('v-surface'), findings: E('v-findings') }
  const railItems = $$('.ri[data-view]')

  // ------------------------------------------------------------ derived clocks
  const ELAPSED = [[8.0, 0], [13.25, 232], [16.8, 252]]
  const elapsed = ut => pw(ut, ELAPSED)
  const fmtDur = s => `${Math.floor(s / 60)}m ${String(Math.floor(s % 60)).padStart(2, '0')}s`
  const START = 10 * 3600 + 38 * 60 + 4
  const clock = ut => { const s = Math.floor(START + elapsed(ut)); return `${String(Math.floor(s / 3600)).padStart(2, '0')}:${String(Math.floor(s / 60) % 60).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}` }
  const shortClock = ut => clock(ut).slice(0, 5)
  txt($('.ticket .ts'), clock(11.3) + '.318')
  MSGS.forEach((m, i) => txt(E('bmt-' + i), shortClock(Math.max(m.at, 8))))
  const requests = ut => Math.round(pw(ut, [[8.0, 0], [9, 22], [11, 141], [13.25, 287], [16.8, 318], [28.7, 318], [28.8, 320]]))
  const usd = ut => pw(ut, [[8.0, 0], [10, .31], [13.25, .71], [16.8, .84]])

  // ------------------------------------------------------------ cursor script (UI time)
  const WAY = [
    { t: 4.45, xy: [760, 560] },
    { t: 4.62, sel: '#np-name', ax: .3, click: true },
    { t: 4.99, sel: '#np-sites', ax: .42, ay: .35, click: true },
    { t: 5.47, sel: '#btn-create', click: true },
    { t: 6.1, xy: [900, 600] },
    { t: 6.75, sel: '#host-1 .cb', click: true },
    { t: 7.1, sel: '#host-2 .cb', click: true },
    { t: 7.32, sel: '#host-3 .src', ax: .6, ay: .9, dur: .22 },
    { t: 7.7, sel: '#btn-approve', ax: .4, click: true, dur: .26 },
    { t: 8.24, sel: '#ri-surface', ax: .35, click: true },
    { t: 9.7, xy: [1180, 640], dur: .9 },
    { t: 11.1, xy: [1250, 560], dur: .7 },
    { t: 11.8, sel: '.ticket .big b', ax: .92, ay: .8, dur: .45 },
    { t: 13.2, sel: '.ticket .big b', ax: .92, ay: .8 },
    { t: 13.95, sel: '#ri-findings', ax: .35, click: true, dur: .6 },
    { t: 15.55, sel: '#frow-0', ax: .38, click: true, dur: .55 },
    { t: 16.6, sel: '#fi-tech', ax: .3, click: true, dur: .5 },
    { t: 18.4, xy: [1250, 520], dur: .6 },
    { t: 20.1, xy: [1220, 560], dur: .6 },
    { t: 24.45, xy: [1200, 610] },
    { t: 25.1, sel: '#btn-verify', ax: .45, click: true, dur: .55 },
    { t: 25.75, xy: [1330, 300], dur: .5 },
  ]
  const CURSOR_ON = [[4.42, 20.15], [24.42, 29.55]]

  // ------------------------------------------------------------ geometry
  let scale = 1
  const toStage = (sel, ax = .5, ay = .5) => {
    const node = typeof sel === 'string' ? document.querySelector(sel) : sel
    if (!node) return [W / 2, H / 2]
    const r = node.getBoundingClientRect(), s = el.stage.getBoundingClientRect()
    return [(r.left + r.width * ax - s.left) / scale, (r.top + r.height * ay - s.top) / scale]
  }
  const wpPos = w => w.xy ? w.xy : toStage(w.sel, w.ax ?? .5, w.ay ?? .5)

  function layout() {
    const w = el.frame.clientWidth
    scale = w / W
    el.frame.style.height = Math.round(H * scale) + 'px'
    el.stage.style.transform = `scale(${scale})`
  }

  // ------------------------------------------------------------ render(t)
  function render(t) {
    const ut = uiTime(t)
    const story = t >= RW_B && t < END_A

    // ----- page frame: rewind + end card
    const rewinding = t >= RW_A && t < RW_B
    cls(el.rewind, 'on', rewinding)
    cls(el.app, 'rewinding', rewinding)
    cls(el.chrome, 'rewinding', rewinding)
    if (rewinding) {
      const p = seg(t, RW_A, RW_B)
      const secs = Math.round(252 * (1 - eio(p)))
      txt(E('rw-tc'), `${String(Math.floor(secs / 60)).padStart(2, '0')}:${String(secs % 60).padStart(2, '0')}`)
      css(E('rw-band'), 'top', ((p * 2600) % 900 - 60).toFixed(0) + 'px')
      css(el.app, 'transform', `translateX(${(Math.sin(t * 90) * 3).toFixed(1)}px)`)
    } else css(el.app, 'transform', '')

    const endOn = t >= END_A
    cls(el.end, 'on', endOn)
    for (const [k, a] of [['s1', END_A + .2], ['s2', END_A + .4], ['s3', 47.4], ['s4', 47.85], ['s5', 49.4]]) cls(el.end, k, endOn && t >= a)
    END_WORDS.forEach((x, i) => {
      const n = E('ew-' + i)
      cls(n, 'in', t >= x.at)
      cls(n, 'cur', t >= x.at && (i === END_WORDS.length - 1 || t < END_WORDS[i + 1].at))
    })
    const n = Math.round(DOCKER.length * seg(t, 47.95, 48.95))
    txt(E('end-cmd'), DOCKER.slice(0, n))

    // ----- which screen
    const pre = ut < 5.8
    const view = pre ? 'projects' : ut < 8.3 ? 'overview' : ut < 14.05 ? 'surface' : 'findings'
    for (const k in views) cls(views[k], 'on', k === view)
    railItems.forEach(r => cls(r, 'on', r.dataset.view === view))
    show(el.hdrP, pre); show(el.hdrR, !pre)
    show(E('rp-acme'), !pre); show(E('rr-acme'), !pre, 'flex')
    txt(E('c-runs'), pre ? '1' : '2')
    const selFinding = ut >= 15.6
    txt(el.url, pre ? '/' : `/runs/r_7f3a2c?view=${view}${selFinding ? '&sel=finding:f_8842' : ''}`)

    // ----- new-project modal
    cls(el.newproj, 'on', ut >= 4.4 && ut < 5.72)
    const name = 'Acme staging'
    const nn = Math.round(name.length * seg(ut, 4.66, 4.95))
    const nameFocus = ut >= 4.62 && ut < 4.99, sitesFocus = ut >= 4.99 && ut < 5.6
    html(el.npNameV, name.slice(0, nn) + (nameFocus ? '<span class="caret"></span>' : ''))
    show(el.npNamePh, nn === 0 && !nameFocus)
    cls(el.npName, 'focus', nameFocus)
    const pasted = ut >= 5.06
    html(el.npSitesV, (pasted ? '<span class="val paste">https://staging.acme.dev</span>' : '') + (sitesFocus ? '<span class="caret"></span>' : ''))
    show(el.npSitesPh, !pasted && !sitesFocus)
    cls(el.npSites, 'focus', sitesFocus)
    cls(el.npPaste, 'on', ut >= 4.98 && ut < 5.4)

    // ----- consent
    let checked = 0
    HOSTS.forEach((h, i) => {
      const node = E('host-' + i)
      const on = h.ck === 0 || (h.ck && ut >= h.ck)
      if (on) checked++
      cls(node, 'in', ut >= h.at)
      cls(node, 'ck', on)
      const cb = node.firstChild
      cls(cb, 'on', on)
      cls(cb, 'pop', !!h.ck && ut >= h.ck && ut < h.ck + .3)
      cls(node, 'hov', (h.ck && ut >= h.ck - .12 && ut < h.ck + .2) || (h.tp && ut >= 7.2 && ut < 7.6))
      cls(node, 'spot', !!h.tp && ut >= 7.25 && ut < 7.72)
    })
    const found = HOSTS.filter(h => ut >= h.at).length
    txt(el.cCount, `${checked} of ${Math.max(1, found)} discovered host${found === 1 ? '' : 's'}`)
    const approved = ut >= 7.72
    txt(el.cEyebrow, approved ? 'Approved · the coordinator is starting' : 'Waiting on your scope approval')
    gl(el.cEyeGlyph, approved ? 'complete' : 'waiting')

    // ----- run header
    const status = ut < 8.0 ? 'waiting' : ut < 16.8 ? 'running' : 'complete'
    const stLabel = { waiting: 'Waiting', running: 'Running', complete: 'Complete' }[status]
    gl(el.hGlyph, status); txt(el.hStatus, stLabel)
    gl(el.bGlyph, status); txt(el.bStatus, stLabel)
    gl(E('rr-glyph'), status); txt(E('rr-st'), stLabel)
    const pi = ut < 8.0 ? 0 : ut < 9.0 ? 1 : ut < 13.25 ? 2 : ut < 16.8 ? 3 : 4
    el.track.forEach((i, k) => { cls(i, 'done', k < pi); cls(i, 'cur', k === pi) })
    txt(el.hPhase, ['Scope review', 'Threat model', 'Investigation', 'Verification', ''][pi])
    txt(el.hRound, (pi === 4 ? '' : '· ') + 'Round ' + (ut < 11 ? 1 : 2))
    const u = usd(ut), rq = requests(ut)
    txt(el.hUsd, '$' + u.toFixed(2)); css(el.hMeter, 'width', (u / 5 * 100).toFixed(1) + '%')
    txt(el.hReq, rq.toLocaleString('en-US')); css(el.hRMeter, 'width', (rq / 2000 * 100).toFixed(1) + '%')
    txt(el.hHosts, approved ? '· 3 hosts' : '· 1 host')
    txt(el.hDur, status === 'waiting' ? 'Created 10:38' : fmtDur(elapsed(ut)))
    html(el.hAction, status === 'waiting' ? icon('globe') + 'Review scope' : status === 'running' ? icon('pause') + 'Pause' : icon('report') + 'Report')
    cls(el.hAction, 'primary', status === 'waiting')

    // ----- rail counts
    const nFind = FINDINGS.filter(f => ut >= f.at).length
    txt(E('c-findings'), nFind ? String(nFind) : '')
    txt(E('rr-n'), nFind ? String(nFind) : '')
    txt(E('c-surface'), ut >= 8.0 ? '3' : '')
    txt(E('c-workflow'), ut >= 8.35 ? String(Math.round(pw(ut, [[8.35, 1], [9.0, 4], [11, 7], [13.3, 9], [27.35, 9], [27.4, 10]]))) : '')
    txt(E('c-exchanges'), rq ? rq.toLocaleString('en-US') : '')
    txt(E('c-activity'), ut >= 5.8 ? Math.round(3 + rq * 1.4 + MSGS.filter(m => ut >= m.at).length).toLocaleString('en-US') : '')
    txt(E('c-report'), ut >= 16.8 ? 'v1' : '')
    show(E('q-badge'), ut >= 14.4, 'inline-block')

    // ----- surface
    const tally = { [R]: 0, [NF]: 0, [NI]: 0, [RO]: 0, [NA]: 0, [UT]: 0 }
    const colTally = CATS.map(() => ({}))
    ROWS.forEach((r, ri) => r.cells.forEach((_, ci) => {
      const st = cellState(ri, ci, ut)
      tally[st]++
      colTally[ci][st] = (colTally[ci][st] || 0) + 1
      const tile = E(`cell-${ri}-${ci}`)
      if (memo(tile, 'st', st)) {
        tile.className = `tile st-${st} bt`
        if (st !== UT) { void tile.offsetWidth; tile.classList.add('flash') }
      }
      cls(tile, 'selc', ri === 0 && ci === 1 && st === R && ut < 14.05)
    }))
    LEG.forEach(([k]) => txt(E('lg-' + k), String(tally[k])))
    CATS.forEach((_, ci) => {
      const ct = colTally[ci]
      const charted = 3 - (ct[UT] || 0)
      html(E('cbar-' + ci), [R, NF, NI, RO, NA].map(s => ct[s] ? `<i style="width:${ct[s] / 3 * 100}%;background:${{ [R]: '#c2410c', [NF]: '#a86400', [NI]: '#2e6aa6', [RO]: '#6b7078', [NA]: '#dddcd6' }[s]}"></i>` : '').join(''))
      txt(E('ccnt-' + ci), `${charted}/3`)
    })
    PINS.forEach((p, pi2) => cls(E('pin-' + pi2), 'in', ut >= p[3]))
    ROWS.forEach((_, ri) => show(E('dash-' + ri), !PINS.some(p => p[0] === ri && ut >= p[3]), 'block'))

    // ----- findings
    FINDINGS.forEach((f, i) => {
      const it = E('fi-' + i)
      cls(it, 'in', ut >= f.at)
      cls(it, 'new', ut >= f.at && ut < f.at + 1.2 && ut >= 14.05)
      cls(E('frow-' + i), 'cur', i === 0 && selFinding)
      cls(E('frow-' + i), 'hov', i === 0 && ut >= 15.4 && ut < 15.6)
    })
    GROUPS.forEach(g => cls(E('fg-' + g), 'in', FINDINGS.some(f => f.sev === g && ut >= f.at)))
    const confirmed = FINDINGS.filter(f => ut >= f.at && f.st === 'confirmed').length
    txt(E('ft-all'), String(nFind)); txt(E('ft-conf'), String(confirmed)); txt(E('ft-pend'), String(FINDINGS.filter(f => ut >= f.at && f.st === 'pending').length))
    txt(E('f-hed'), nFind ? '1 confirmed high-severity issue' : 'Mapping the surface…')
    txt(E('f-conf'), nFind ? 'High confidence' : 'Not yet assessed')

    // ----- board
    let shown = 0
    MSGS.forEach((m, i) => { const on = ut >= m.at; if (on) shown++; cls(E('bm-' + i), 'in', on) })
    show(el.bEmpty, shown === 0, 'block')
    txt(el.bCount, `${shown} message${shown === 1 ? '' : 's'}`)
    const working = status === 'running' && ut >= 8.35
    show(el.bDot, working, 'inline-block')
    txt(el.bAgents, working ? `Agents · ${ut < 9 ? 2 : 5} working` : 'Agents')

    // ----- inspector pane (findings-inspector.tsx)
    cls(el.pBoard, 'on', !selFinding)
    cls(el.pFinding, 'on', selFinding)
    const techOpen = ut >= 16.62
    cls(E('fi-tech'), 'open', techOpen)
    cls(E('fi-tech'), 'hov', ut >= 16.4 && ut < 16.62)
    show(E('fi-techb'), techOpen, 'block')
    // Verify fix: toast.undoable (6 s window, compressed) → "Queued" → retest worker active → "Verifying fix…" → retest row
    const queued = ut >= 25.15 && ut < 27.4
    const verifying = ut >= 27.4 && ut < 29.1
    txt(E('verify-lbl'), verifying ? 'Verifying fix…' : queued ? 'Queued' : 'Verify fix')
    cls(E('btn-verify'), 'dis', queued || verifying)
    cls(E('btn-verify'), 'hov', ut >= 24.95 && ut < 25.15)
    const retested = ut >= 29.1
    cls(E('fi-retest'), 'in', retested)
    cls(E('fi-retest'), 'lit', retested && ut < 29.6 && t < END_A)

    // ----- broker receipt callout
    cls(el.blocked, 'on', ut >= 11.42 && ut < 13.35)

    // ----- toast (toast.tsx; undoable)
    const toastA = ut >= 7.74 && ut < 9.4, toastB = queued
    cls(el.toast, 'on', toastA || toastB)
    if (toastA || toastB) {
      txt(E('tst-msg'), toastA ? 'Scope approved for 3 hosts (Authenticated)' : 'Verify fix queued')
      txt(E('tst-sub'), toastA ? 'Sends when this closes' : 'Replays the check against the live origin when this closes')
      html(E('tst-ico'), icon(toastA ? 'globe' : 'replay'))
      css(E('tst-bar'), 'transform', `scaleX(${(1 - (toastA ? seg(ut, 7.74, 9.4) : seg(ut, 25.15, 27.4))).toFixed(3)})`)
    }

    // ----- time-skip marker + zero-LLM annotation (film overlays, not product UI)
    cls(el.skip, 'on', ut >= 27.8 && ut < 29.1 && t < END_A)
    const llmOn = ut >= 29.25 && t < END_A
    cls(el.llm, 'on', llmOn)
    if (llmOn) {
      const [x, y] = toStage('#fi-retest', 0, .5)
      css(el.llm, 'left', (x - 14).toFixed(0) + 'px'); css(el.llm, 'top', y.toFixed(0) + 'px')
    }

    // ----- automated replay, magnified (16.95..20.2; also the cold open)
    const proof = ut >= 16.95 && ut < 20.2
    cls(el.replay, 'on', proof)
    cls(E('fi-replaysec'), 'lit', proof)
    cls(el.rsheet, 'vault', proof && ut >= 18.75 && t >= RW_B)
    const stamp = (node, land, on) => {
      const p = seg(t, land - .22, land)
      const vis = on && t >= land - .22
      const sc = vis ? 2.6 - 1.6 * ei(p) : 2.6
      css(node, 'opacity', vis ? Math.min(1, p * 2.2).toFixed(3) : '0')
      css(node, 'transform', `rotate(-9deg) scale(${sc.toFixed(3)})`)
      return vis && t >= land && t < land + .7 ? seg(t, land, land + .7) : -1
    }
    const land = t < RW_B ? STAMP_AT[0] : STAMP_AT[1]
    const rp = stamp(el.stampR, land, proof)
    cls(el.rsheet, 'shake', proof && t >= land && t < land + .42)
    if (rp >= 0) {
      const s = el.stampR
      css(el.ring, 'left', s.offsetLeft + 'px'); css(el.ring, 'top', s.offsetTop + 'px')
      css(el.ring, 'width', s.offsetWidth + 'px'); css(el.ring, 'height', s.offsetHeight + 'px')
      css(el.ring, 'opacity', (.6 * (1 - rp)).toFixed(3))
      css(el.ring, 'transform', `rotate(-9deg) scale(${(1 + .55 * eo(rp)).toFixed(3)})`)
    } else css(el.ring, 'opacity', '0')

    // ----- the fix: the user's terminal, outside Guardian
    const termOn = ut >= 20.3 && ut < 24.3 && story
    cls(el.term, 'on', termOn)
    cls(el.win, 'away', termOn)
    TERM.forEach((l, i) => {
      const row = E('tl-' + i)
      cls(row, 'in', ut >= l.at)
      if (l.cmd != null) {
        const k = Math.round(l.cmd.length * seg(ut, l.at + .05, l.at + .05 + l.dur))
        const nextAt = TERM[i + 1] ? TERM[i + 1].at : 99
        html(E('tlc-' + i), l.cmd.slice(0, k).replace(/</g, '&lt;') + (ut >= l.at && ut < nextAt ? '<span class="tcar"></span>' : ''))
      }
    })
    const live = ut >= 23.75
    html(E('tl-dep'), live
      ? '<span class="tok2">✓</span> <span class="td">deploy</span> staging.acme.dev <span class="tok2">live</span> <span class="td">· 7d03f1b · 41 s</span>'
      : '<span class="spin2"></span> <span class="td">deploy</span> staging.acme.dev <span class="td">building 7d03f1b…</span>')
    html(E('tw-final'), live && ut >= 23.85 ? P_ + '<span class="tcar"></span>' : '')

    // ----- captions
    renderCaption(t)

    // ----- cursor (needs layout, so last)
    const curOn = story && CURSOR_ON.some(([a, b]) => ut >= a && ut < b)
    css(el.cursor, 'opacity', curOn ? '1' : '0')
    let rip = -1, pos = null
    if (curOn) {
      const i = WAY.findIndex(w => w.t > ut)
      if (i === -1) pos = wpPos(WAY[WAY.length - 1])
      else if (i === 0) pos = wpPos(WAY[0])
      else {
        const a = WAY[i - 1], b = WAY[i]
        const d = b.dur ?? .42
        const start = Math.max(a.t + (a.click ? .12 : 0), b.t - d)
        const p = eio(seg(ut, start, b.t))
        const pa = wpPos(a), pb = wpPos(b)
        const dx = pb[0] - pa[0], dy = pb[1] - pa[1]
        const arc = Math.sin(Math.PI * p) * Math.min(40, Math.hypot(dx, dy) * .08)
        const len = Math.hypot(dx, dy) || 1
        pos = [lerp(pa[0], pb[0], p) + (-dy / len) * arc, lerp(pa[1], pb[1], p) + (dx / len) * arc]
      }
      const press = WAY.find(w => w.click && ut >= w.t && ut < w.t + .14)
      css(el.cursor, 'transform', `translate(${(pos[0] - 2).toFixed(1)}px, ${(pos[1] - 1).toFixed(1)}px) scale(${press ? .86 : 1})`)
      const lastClick = [...WAY].reverse().find(w => w.click && ut >= w.t && ut < w.t + .45)
      if (lastClick) { const rp2 = wpPos(lastClick); rip = seg(ut, lastClick.t, lastClick.t + .45); css(el.ripple, 'left', rp2[0].toFixed(1) + 'px'); css(el.ripple, 'top', rp2[1].toFixed(1) + 'px') }
    }
    css(el.ripple, 'opacity', rip >= 0 ? (.7 * (1 - rip)).toFixed(3) : '0')
    css(el.ripple, 'transform', `scale(${rip >= 0 ? (.4 + rip * 1.1).toFixed(3) : .4})`)
    const pressed = curOn ? WAY.filter(w => w.click && w.sel && ut >= w.t - .02 && ut < w.t + .16).map(w => w.sel) : []
    for (const s of ['#btn-create', '#btn-approve', '#btn-verify', '#fi-tech']) cls($(s), 'press', pressed.includes(s))
    cls($('#btn-approve'), 'hov', ut >= 7.5 && ut < 7.72)
    cls($('#btn-create'), 'hov', ut >= 5.3 && ut < 5.48)
    cls(E('ri-surface'), 'hov', ut >= 8.05 && ut < 8.3)
    cls(E('ri-findings'), 'hov', ut >= 13.75 && ut < 14.05)
  }

  // ------------------------------------------------------------ captions
  let capIdx = -2
  function renderCaption(t) {
    const i = CAPS.findIndex(c => t >= c.a && t < c.b)
    const c = CAPS[i]
    cls(el.cap, 'on', !!c)
    cls(el.capShade, 'on', !!c && c.pos !== 'dup')
    if (i !== capIdx) {
      capIdx = i
      if (c) {
        el.cap.innerHTML = c.html
        el.cap.classList.toggle('top', c.pos === 'top')
        el.cap.classList.toggle('dup', c.pos === 'dup')
        el.capShade.classList.toggle('top', c.pos === 'top')
      }
    }
    if (!c) return
    const k = Math.min(c.words.length - 1, Math.floor((t - c.a) / WR))
    el.cap.querySelectorAll('.w').forEach((w, j) => {
      w.classList.toggle('cur', j === k)
      w.classList.toggle('next', j > k)
    })
    el.cap.style.setProperty('--pop', eo(seg(t, c.a, c.a + .16)).toFixed(3))
  }

  // ------------------------------------------------------------ player
  const q = new URLSearchParams(location.search)
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
  const REC = q.has('rec')
  if (REC) document.body.classList.add('rec')
  if (EMBED) {
    document.body.classList.add('embed')
    document.body.classList.toggle('dark', q.get('theme') === 'dark')
  }
  const KEYFRAME = 3.0 // cold-open frame: stamp landed, caption up
  let t = q.has('t') ? clamp(+q.get('t'), 0, DUR - .001) : 0
  let playing = !(q.has('paused') || reduce)
  let speed = q.has('speed') ? +q.get('speed') || 1 : 1
  let last = performance.now()
  let wasPlaying = false
  if (reduce && !q.has('t')) t = KEYFRAME

  const scrub = E('scrub'), timeEl = E('time'), bPlay = E('b-play'), bSpeed = E('b-speed'), gate = E('gate')
  scrub.max = String(DUR)
  const PLAY_SVG = '<path d="M4.5 2.75v10.5L13 8Z" fill="currentColor"/>'
  const PAUSE_SVG = '<path d="M5 3v10M11 3v10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>'
  const syncUi = () => {
    E('i-play').innerHTML = playing ? PAUSE_SVG : PLAY_SVG
    bPlay.setAttribute('aria-label', playing ? 'Pause' : 'Play')
    bSpeed.textContent = speed + '×'
  }
  const syncScrub = () => {
    scrub.value = t.toFixed(2)
    scrub.style.setProperty('--p', (t / DUR * 100).toFixed(2) + '%')
    timeEl.textContent = `${t.toFixed(1).padStart(4, '0')} / ${DUR.toFixed(1)}`
  }
  // A discontinuous seek (scrub, arrow keys, loop wrap) renders the target frame
  // with CSS transitions off, so overlays don't fade/ghost toward it.
  let shownT = -1, jumpRaf = 0
  const draw = () => {
    if (shownT >= 0 && Math.abs(t - shownT) > .25) {
      el.hero.classList.add('jump')
      cancelAnimationFrame(jumpRaf)
      jumpRaf = requestAnimationFrame(() => requestAnimationFrame(() => el.hero.classList.remove('jump')))
    }
    shownT = t
    render(t)
    syncScrub()
  }
  const frame = now => {
    const dt = Math.min(.1, (now - last) / 1000)
    last = now
    if (playing) { t += dt * speed; if (t >= DUR) t -= DUR }
    draw()
    requestAnimationFrame(frame)
  }
  const setPlaying = p => { playing = p; if (p) cls(gate, 'on', false); syncUi() }
  bPlay.addEventListener('click', () => setPlaying(!playing))
  E('b-restart').addEventListener('click', () => { t = 0; draw(); setPlaying(true) })
  bSpeed.addEventListener('click', () => { speed = speed === 1 ? 2 : speed === 2 ? .5 : 1; syncUi() })
  scrub.addEventListener('pointerdown', () => { wasPlaying = playing; playing = false; syncUi() })
  scrub.addEventListener('input', () => { t = +scrub.value; draw() })
  scrub.addEventListener('pointerup', () => { if (wasPlaying) setPlaying(true) })
  E('gate-play').addEventListener('click', () => { t = 0; draw(); setPlaying(true) })
  document.addEventListener('keydown', e => {
    if (e.target instanceof HTMLInputElement && e.key !== ' ') return
    if (e.key === ' ') { e.preventDefault(); setPlaying(!playing) }
    else if (e.key === 'ArrowRight') { t = Math.min(DUR - .001, t + 1); draw() }
    else if (e.key === 'ArrowLeft') { t = Math.max(0, t - 1); draw() }
  })
  if (reduce && !REC) cls(gate, 'on', true)

  new ResizeObserver(() => { layout(); render(t) }).observe(el.frame)
  layout()
  syncUi()
  draw()
  requestAnimationFrame(frame)

  // embed bridge: the host page says when the hero is on screen (play/pause),
  // which theme to use, and gets the document height back to size the iframe.
  if (EMBED) {
    let userPaused = false, optedIn = !reduce
    const note = () => { userPaused = !playing; if (playing) optedIn = true }
    bPlay.addEventListener('click', note)
    E('b-restart').addEventListener('click', note)
    E('gate-play').addEventListener('click', note)
    document.addEventListener('keydown', e => { if (e.key === ' ') note() })
    const post = msg => { try { parent.postMessage(Object.assign({ kh: 'replay' }, msg), location.origin) } catch (err) { /* detached */ } }
    window.addEventListener('message', e => {
      if (e.origin !== location.origin || !e.data || e.data.kh !== 'replay') return
      const d = e.data
      if (d.type === 'visible') {
        if (!d.on) { if (playing) setPlaying(false) }
        else if (!userPaused && optedIn && !playing) setPlaying(true)
      } else if (d.type === 'theme') document.body.classList.toggle('dark', d.theme === 'dark')
      else if (d.type === 'toggle') { if (!playing) cls(gate, 'on', false); setPlaying(!playing); note() }
    })
    const page = document.querySelector('.page')
    const size = () => post({ type: 'height', h: Math.ceil(page.getBoundingClientRect().height) })
    new ResizeObserver(size).observe(page)
    size()
  }

  // hooks for record.mjs / screenshots
  window.hero = {
    get t() { return t },
    seek(v) { t = clamp(v, 0, DUR - .001); draw() },
    play() { setPlaying(true) },
    pause() { setPlaying(false) },
    duration: DUR,
    captions: CAPS.map(c => ({ a: +c.a.toFixed(2), b: +c.b.toFixed(2), text: c.words.join(' '), pos: c.pos })),
    ready: document.fonts ? document.fonts.ready : Promise.resolve(),
  }
})()
