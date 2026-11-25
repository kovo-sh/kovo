// Kovo Hunter landing (lab). Plain JS, no deps.
// Icons, glyphs and behaviours mirror src/components/run/{icons,glyphs,palette,toast,theme,keyboard}.tsx.
(() => {
  'use strict'
  const $ = (s, r = document) => r.querySelector(s)
  const $$ = (s, r = document) => [...r.querySelectorAll(s)]
  const root = document.documentElement
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)

  // ------------------------------------------------------------ icons (icons.tsx, 16px grid, 1.5 stroke)
  const P = {
    search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 14 14"/>',
    overview: '<path d="M2.75 3.25h10.5M2.75 6.25h10.5M2.75 9.25h6.5M2.75 12.25h4.5"/>',
    workflow: '<rect x="1.75" y="2.5" width="4" height="3.5" rx="1"/><rect x="10.25" y="2.5" width="4" height="3.5" rx="1"/><rect x="10.25" y="10" width="4" height="3.5" rx="1"/><path d="M5.75 4.25h4.5M5.75 4.25c2.5 0 2 7.5 4.5 7.5"/>',
    report: '<path d="M4 1.75h5.25L12.25 4.75v9.5H4Z"/><path d="M9 1.75V5h3.25"/><path d="M6.25 8.25h3.5M6.25 10.75h3.5"/>',
    chat: '<path d="M2.75 3.25h10.5v7.5H7L4.25 13v-2.25h-1.5Z"/>',
    sun: '<circle cx="8" cy="8" r="2.75"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1.06 1.06M11.54 11.54l1.06 1.06M3.4 12.6l1.06-1.06M11.54 4.46l1.06-1.06"/>',
    moon: '<path d="M13.25 9.5A5.5 5.5 0 0 1 6.5 2.75a5.5 5.5 0 1 0 6.75 6.75Z"/>',
    keyboard: '<rect x="1.75" y="4" width="12.5" height="8" rx="1.5"/><path d="M4.5 6.75h.01M7 6.75h.01M9.5 6.75h.01M12 6.75h.01M5 9.5h6"/>',
    close: '<path d="M4 4l8 8M12 4l-8 8"/>',
    chev: '<path d="M4 6l4 4 4-4"/>',
    chevR: '<path d="M6 4l4 4-4 4"/>',
    arrowR: '<path d="M3 8h10M9 4l4 4-4 4"/>',
    ext: '<path d="M6 3.5H3.5v9h9V10M9 3.5h3.5V7M12.5 3.5 7 9"/>',
    lock: '<rect x="3.25" y="7" width="9.5" height="6.75" rx="1.25"/><path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2"/>',
    globe: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c1.75 1.75 2.5 3.75 2.5 6S9.75 12.25 8 14C6.25 12.25 5.5 10.25 5.5 8S6.25 3.75 8 2Z"/>',
    sliders: '<path d="M2.5 5h6M11.5 5h2M2.5 11h2M7.5 11h6"/><circle cx="10" cy="5" r="1.5"/><circle cx="6" cy="11" r="1.5"/>',
    check: '<path d="M3.5 8.5 6.5 11.5 12.5 4.5"/>',
    shield: '<path d="M8 1.75 13.25 4v4c0 3-2.25 5.25-5.25 6.25C5 13.25 2.75 11 2.75 8V4Z"/>',
    flag: '<path d="M3.5 14V2.5M3.5 3h8l-1.5 3 1.5 3h-8"/>',
    undo: '<path d="M5.5 3.5 2.5 6.5l3 3"/><path d="M2.5 6.5h7a4 4 0 0 1 0 8H7"/>',
    node: '<circle cx="8" cy="8" r="2.25"/><path d="M8 1.75v4M8 10.25v4M1.75 8h4M10.25 8h4"/>',
    alert: '<path d="M8 2.25 14.25 13H1.75Z"/><path d="M8 6.5v3M8 11.25v.01"/>',
    replay: '<path d="M2.75 8a5.25 5.25 0 1 0 1.6-3.78"/><path d="M2.5 2.5v3h3"/><path d="M7 6v4l3-2Z" fill="currentColor" stroke="none"/>',
    list: '<path d="M5.5 4h8M5.5 8h8M5.5 12h8M2.5 4h.01M2.5 8h.01M2.5 12h.01"/>',
    download: '<path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.5h10"/>',
    copy: '<rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25"/><path d="M3.25 10.75h-.5a1.25 1.25 0 0 1-1.25-1.25v-6.75A1.25 1.25 0 0 1 2.75 1.5h6.75a1.25 1.25 0 0 1 1.25 1.25v.5"/>',
    play: '<path d="M5 3.25v9.5L12.5 8Z"/>',
    pause: '<path d="M5.5 3.5v9M10.5 3.5v9"/>',
  }
  const icon = (name, cls = 'ico') => `<svg class="${cls}" viewBox="0 0 16 16" aria-hidden="true">${P[name] || ''}</svg>`
  const hydrateIcons = (scope = document) => $$('i[data-i]', scope).forEach(el => {
    const cls = el.className || 'ico'
    el.outerHTML = `<svg class="${cls}" data-i="${el.dataset.i}" viewBox="0 0 16 16" aria-hidden="true">${P[el.dataset.i] || ''}</svg>`
  })
  const setIcon = (svg, name) => { if (svg) { svg.innerHTML = P[name]; svg.dataset.i = name } }

  // ------------------------------------------------------------ glyphs (glyphs.tsx: shape doubles colour)
  const S = (body) => `<svg viewBox="0 0 14 14" width="14" height="14" aria-hidden="true" style="display:block;flex:none">${body}</svg>`
  const ring = (stroke, inner = '', dash = false) => S(`<circle cx="7" cy="7" r="5.75" fill="none" stroke="${stroke}" stroke-width="1.4"${dash ? ' stroke-dasharray="2.1 1.9"' : ''}/>${inner}`)
  function glyph(st) {
    switch (st) {
      case 'confirmed': return ring('var(--fg-3)', '<path d="M4.6 7.1 6.3 8.8 9.5 5.4" fill="none" stroke="var(--fg-2)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>')
      case 'complete': return S('<circle cx="7" cy="7" r="6.5" fill="var(--fg-4)"/><path d="M4.4 7.2 6.2 9 9.7 5.3" fill="none" stroke="var(--panel)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>')
      case 'fixed': return S('<circle cx="7" cy="7" r="6.5" fill="var(--ok)"/><path d="M4.4 7.2 6.2 9 9.7 5.3" fill="none" stroke="var(--panel)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>')
      case 'pending': return ring('var(--fg-2)', '<path d="M7 3.5A3.5 3.5 0 0 1 7 10.5Z" fill="var(--fg-2)"/>')
      case 'running': return ring('var(--accent)', '<path d="M7 3.5A3.5 3.5 0 0 1 10.5 7H7Z" fill="var(--accent)"/>')
      case 'failed': return S('<circle cx="7" cy="7" r="6.5" fill="var(--bad)"/><path d="M5 5l4 4M9 5 5 9" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>')
      case 'inconclusive': return ring('var(--fg-3)', '<path d="M7 7h.01" stroke="var(--fg-3)" stroke-width="2" stroke-linecap="round"/>', true)
      default: return ring('var(--fg-3)')
    }
  }
  function sev(s) {
    const n = { high: 3, medium: 2, low: 1 }[s] || 0
    const col = { high: 'var(--high)', medium: 'var(--med)', low: 'var(--fg-2)' }[s] || 'var(--fg-3)'
    const bars = [[1.5, 8, 4], [5.75, 5.5, 6.5], [10, 3, 9]]
    return S(bars.map((b, i) => `<rect x="${b[0]}" y="${b[1]}" width="2.5" height="${b[2]}" rx="1" fill="${i < n ? col : 'var(--fg-4)'}"/>`).join(''))
  }
  const hydrateGlyphs = (scope = document) => {
    $$('[data-glyph]', scope).forEach(el => { el.innerHTML = glyph(el.dataset.glyph) })
    $$('[data-sev]', scope).forEach(el => { el.innerHTML = sev(el.dataset.sev) })
  }
  // KovoHunterMark (brand/KovoHunterMark.tsx), monochrome
  const MARK = '<svg viewBox="0 0 64 64" fill="none" aria-hidden="true"><path d="M 11.25 24.79 A 19.80 19.80 0 0 1 33.80 22.02" stroke="currentColor" stroke-width="4.6"/><path d="M 41.98 30.20 A 19.80 19.80 0 0 1 39.21 52.75" stroke="currentColor" stroke-width="4.6"/><path d="M 16.20 47.80 L 48.00 16.00" stroke="currentColor" stroke-width="4.6"/><path d="M 38.00 15.20 H 48.80 V 26.00" stroke="currentColor" stroke-width="4.6" stroke-linecap="square"/><path d="M 10.20 47.80 L 14.20 43.80 H 19.60 L 20.20 44.40 V 49.80 L 16.20 53.80 V 47.80 Z" fill="currentColor"/></svg>'

  hydrateIcons()
  hydrateGlyphs()
  $$('.mk').forEach(el => { el.innerHTML = MARK })
  if (isMac) $$('[data-mod]').forEach(el => { el.textContent = '⌘' })

  // ------------------------------------------------------------ toasts (toast.tsx)
  const toastsEl = $('#toasts')
  let toastTimer = 0, pending = null
  function closeToasts() { $$('.toast', toastsEl).forEach(t => { t.classList.add('out'); setTimeout(() => t.remove(), reduce ? 0 : 200) }) }
  function toast(message, opts = {}) {
    clearTimeout(toastTimer)
    if (pending && !opts.keepPending) flushPending()
    closeToasts()
    const t = document.createElement('div')
    t.className = 'toast enter'
    const ms = opts.ms || (opts.undo ? 6000 : 2200)
    t.innerHTML = `${opts.icon ? `<span class="ti">${icon(opts.icon)}</span>` : ''}<div class="tb"></div>${opts.undo ? `<button type="button" class="undo">Undo <span class="kbd">Z</span></button><i class="bar"></i>` : ''}`
    const tb = $('.tb', t)
    tb.textContent = message
    if (opts.sub) { const s = document.createElement('small'); s.textContent = opts.sub; tb.appendChild(s) }
    toastsEl.appendChild(t)
    if (opts.undo) {
      $('.undo', t).addEventListener('click', undoPending)
      const bar = $('.bar', t)
      if (!reduce) bar.animate([{ transform: 'scaleX(1)' }, { transform: 'scaleX(0)' }], { duration: ms, easing: 'linear', fill: 'forwards' })
    }
    toastTimer = setTimeout(() => { if (opts.undo) flushPending(); closeToasts() }, ms)
  }
  function undoable(message, opts) {
    flushPending()
    pending = { commit: opts.commit, undo: opts.undo }
    toast(message, Object.assign({}, opts, { undo: true, keepPending: true }))
  }
  function flushPending() { const p = pending; pending = null; if (p && p.commit) p.commit() }
  function undoPending() { const p = pending; pending = null; clearTimeout(toastTimer); closeToasts(); if (p && p.undo) p.undo(); return !!p }

  // ------------------------------------------------------------ copy
  const CMDS = {
    docker: 'docker run -p 8000:8000 -v kovo-data:/data ghcr.io/kovo-sh/kovo-hunter',
    source: 'git clone https://github.com/kovo-sh/kovo-hunter.git\ncd kovo-hunter && npm ci && npm run worker:build && npm run build && npm start',
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true } catch (e) {
      const ta = document.createElement('textarea')
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0'
      document.body.appendChild(ta); ta.select()
      let ok = false
      try { ok = document.execCommand('copy') } catch (err) { ok = false }
      ta.remove()
      return ok
    }
  }
  async function copyCmd(key) {
    const ok = await copyText(CMDS[key])
    if (ok) toast(key === 'docker' ? 'Copied the Docker command' : 'Copied the build-from-source commands', { icon: 'check', sub: key === 'docker' ? 'Then open http://localhost:8000' : 'Needs Node.js 24+ and Docker' })
    else toast('Could not copy. Select the command and copy it by hand.', { icon: 'alert' })
  }
  $$('[data-copy]').forEach(b => b.addEventListener('click', () => copyCmd(b.dataset.copy)))

  // ------------------------------------------------------------ theme (theme.ts contract)
  const KEY = 'guardian-appearance'
  const mq = matchMedia('(prefers-color-scheme: dark)')
  const resolved = () => {
    const a = root.dataset.appearance
    return a === 'dark' || a === 'light' ? a : (mq.matches ? 'dark' : 'light')
  }
  function applyTheme() {
    const th = resolved()
    root.dataset.theme = th
    $$('.theme-lbl').forEach(el => { el.textContent = th === 'dark' ? 'Light' : 'Dark' })
    $$('[data-act=theme] svg').forEach(svg => setIcon(svg, th === 'dark' ? 'sun' : 'moon'))
    postReplay({ type: 'theme', theme: th })
  }
  function toggleTheme() {
    const next = resolved() === 'dark' ? 'light' : 'dark'
    root.dataset.appearance = next
    try { localStorage.setItem(KEY, next) } catch (e) { /* private mode */ }
    applyTheme()
  }
  mq.addEventListener('change', () => { if (root.dataset.appearance === 'system' || !root.dataset.appearance) applyTheme() })

  // ------------------------------------------------------------ replay hero iframe
  const frame = $('#replay')
  let frameReady = false
  function postReplay(msg) {
    if (!frameReady || !frame.contentWindow) return
    frame.contentWindow.postMessage(Object.assign({ kh: 'replay' }, msg), location.origin)
  }
  const estimate = () => {
    const w = frame.clientWidth || frame.parentElement.clientWidth
    return Math.round(w * 810 / 1440) + 40 + (w <= 720 ? 82 : 0)
  }
  let gotHeight = false
  const sizeFrame = () => { if (!gotHeight) frame.style.height = estimate() + 'px' }
  sizeFrame()
  new ResizeObserver(sizeFrame).observe(frame.parentElement)
  window.addEventListener('message', e => {
    if (e.origin !== location.origin || !e.data || e.data.kh !== 'replay') return
    if (e.data.type === 'height' && e.data.h > 50) { gotHeight = true; frame.style.height = e.data.h + 'px' }
  })
  let heroVisible = false
  frame.addEventListener('load', () => {
    frameReady = true
    postReplay({ type: 'theme', theme: resolved() })
    postReplay({ type: 'visible', on: heroVisible && !document.hidden })
  })
  frame.src = frame.dataset.src + '&theme=' + resolved()
  new IntersectionObserver(entries => {
    entries.forEach(en => { heroVisible = en.intersectionRatio >= 0.35 })
    postReplay({ type: 'visible', on: heroVisible && !document.hidden })
  }, { threshold: [0, 0.35, 0.6] }).observe(frame)
  document.addEventListener('visibilitychange', () => postReplay({ type: 'visible', on: heroVisible && !document.hidden }))

  // ------------------------------------------------------------ header: scrolled state + run-line fit (header.tsx useFitRunline)
  const hdr = $('#hdr')
  const onScroll = () => hdr.classList.toggle('scrolled', window.scrollY > 40)
  window.addEventListener('scroll', onScroll, { passive: true })
  onScroll()
  const rl = $('#runline')
  function fitRunline() {
    const items = $$('.rl', rl).sort((a, b) => +a.dataset.p - +b.dataset.p)
    items.forEach(i => { i.style.display = '' })
    for (const it of items) { if (rl.scrollWidth <= rl.clientWidth + 1) break; it.style.display = 'none' }
    const vis = $$('.rl', rl).filter(x => x.style.display !== 'none')
    $$('.rl', rl).forEach(x => x.classList.toggle('last', x === vis[vis.length - 1]))
  }
  new ResizeObserver(fitRunline).observe(rl)
  const setHdrH = () => root.style.setProperty('--hdr-h', Math.round($('.hdr-row').getBoundingClientRect().height + ($('.tabs').offsetHeight || 0)) + 'px')
  window.addEventListener('resize', setHdrH)
  setHdrH()

  // ------------------------------------------------------------ scroll spy: rail + tabs + breadcrumb
  const SECTIONS = [
    ['overview', 'Overview', 'O', 'overview'], ['proof', 'Proof', 'P', 'replay'], ['architecture', 'Architecture', 'A', 'workflow'],
    ['install', 'Install', 'I', 'download'], ['compare', 'Compare', 'C', 'list'], ['faq', 'FAQ', 'F', 'chat'],
  ]
  const crumb = $('#crumb-view')
  const tabs = $('.tabs')
  let active = ''
  function setActive(id) {
    if (id === active) return
    active = id
    $$('[data-nav]').forEach(a => {
      const on = a.dataset.nav === id
      a.classList.toggle('on', on)
      if (on) a.setAttribute('aria-current', 'location'); else a.removeAttribute('aria-current')
    })
    const s = SECTIONS.find(x => x[0] === id)
    if (s) crumb.textContent = s[1]
    const tab = $(`.tabs [data-nav="${id}"]`)
    if (tab && tabs.offsetParent !== null) {
      const left = tab.offsetLeft - (tabs.clientWidth - tab.offsetWidth) / 2
      tabs.scrollTo({ left: Math.max(0, left), behavior: reduce ? 'auto' : 'smooth' })
    }
  }
  const secEls = SECTIONS.map(s => document.getElementById(s[0]))
  function spy() {
    const y = (parseFloat(getComputedStyle(root).getPropertyValue('--hdr-h')) || 50) + window.innerHeight * 0.3
    let cur = secEls[0]
    for (const el of secEls) if (el.getBoundingClientRect().top <= y) cur = el
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) cur = secEls[secEls.length - 1]
    setActive(cur.id)
  }
  let spyRaf = 0
  window.addEventListener('scroll', () => { cancelAnimationFrame(spyRaf); spyRaf = requestAnimationFrame(spy) }, { passive: true })
  window.addEventListener('resize', spy)
  spy()
  function go(id) {
    const el = document.getElementById(id)
    if (!el) return
    el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' })
    history.replaceState(null, '', '#' + id)
    setActive(id)
  }

  // ------------------------------------------------------------ install tabs (Seg)
  const segBtns = $$('.seg [role=tab]')
  function selectInstall(btn, focus) {
    segBtns.forEach(b => {
      const on = b === btn
      b.setAttribute('aria-selected', String(on))
      b.tabIndex = on ? 0 : -1
      document.getElementById(b.getAttribute('aria-controls')).hidden = !on
    })
    if (focus) btn.focus()
  }
  segBtns.forEach((b, i) => {
    b.addEventListener('click', () => selectInstall(b))
    b.addEventListener('keydown', e => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault()
        selectInstall(segBtns[(i + (e.key === 'ArrowRight' ? 1 : segBtns.length - 1)) % segBtns.length], true)
      }
    })
  })

  // ------------------------------------------------------------ dialogs
  const pal = $('#palette'), help = $('#help'), report = $('#report')
  let lastFocus = null
  function openDlg(d) {
    if (d.open) return
    $$('dialog[open]').forEach(x => x.close())
    lastFocus = document.activeElement
    d.showModal()
  }
  $$('dialog').forEach(d => {
    d.addEventListener('click', e => { if (e.target === d) d.close() })
    d.addEventListener('close', () => { if (lastFocus && lastFocus.focus) lastFocus.focus({ preventScroll: true }) })
    $$('[data-close]', d).forEach(b => b.addEventListener('click', () => d.close()))
  })

  // ------------------------------------------------------------ command palette (palette.tsx)
  const q = $('#pal-q'), list = $('#pal-list')
  const COMMANDS = [
    ...SECTIONS.map(([id, label, k, ic]) => ({ id: 'v-' + id, section: 'Sections', label, icon: ic, keys: ['G', k], run: () => go(id) })),
    { id: 'copy-docker', section: 'Actions', label: 'Copy the Docker command', icon: 'copy', right: 'docker run …', run: () => copyCmd('docker') },
    { id: 'copy-source', section: 'Actions', label: 'Copy the build-from-source commands', icon: 'copy', right: 'git clone …', run: () => copyCmd('source') },
    { id: 'replay', section: 'Actions', label: 'Play or pause the replay', icon: 'play', run: () => { go('overview'); setTimeout(() => postReplay({ type: 'toggle' }), reduce ? 0 : 450) } },
    { id: 'report', section: 'Actions', label: 'Open the sample report', icon: 'report', keys: ['R'], run: () => openDlg(report) },
    { id: 'verify', section: 'Actions', label: 'Try Verify fix on the sample finding', icon: 'replay', run: () => { go('proof'); setTimeout(() => $('#verify').focus({ preventScroll: true }), reduce ? 0 : 600) } },
    { id: 'theme', section: 'Actions', label: 'Toggle light / dark theme', icon: 'moon', keys: ['⇧', 'T'], run: toggleTheme },
    { id: 'help', section: 'Actions', label: 'Keyboard shortcuts', icon: 'keyboard', keys: ['?'], run: () => openDlg(help) },
    { id: 'gh', section: 'Links', label: 'GitHub · kovo-sh/kovo-hunter', icon: 'globe', right: 'github.com', run: () => window.open('https://github.com/kovo-sh/kovo-hunter', '_blank', 'noopener') },
    { id: 'license', section: 'Links', label: 'Apache 2.0 license', icon: 'report', run: () => window.open('https://github.com/kovo-sh/kovo-hunter/blob/main/LICENSE', '_blank', 'noopener') },
    { id: 'ent', section: 'Links', label: 'Contact us about Enterprise Edition', icon: 'shield', right: 'email', run: () => { location.href = 'mailto:will@kovo.sh?subject=Kovo%20Hunter%20Enterprise' } },
  ]
  let items = [], cur = 0
  const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
  const hi = (label, query) => {
    if (!query) return esc(label)
    const i = label.toLowerCase().indexOf(query.split(/\s+/)[0])
    return i < 0 ? esc(label) : esc(label.slice(0, i)) + '<mark>' + esc(label.slice(i, i + query.split(/\s+/)[0].length)) + '</mark>' + esc(label.slice(i + query.split(/\s+/)[0].length))
  }
  function renderPal() {
    const query = q.value.trim().toLowerCase()
    const toks = query.split(/\s+/).filter(Boolean)
    items = COMMANDS.filter(c => toks.every(t => (c.label + ' ' + c.section + ' ' + (c.right || '')).toLowerCase().includes(t)))
    if (query) items.sort((a, b) => (a.label.toLowerCase().startsWith(toks[0]) ? 0 : 1) - (b.label.toLowerCase().startsWith(toks[0]) ? 0 : 1))
    cur = Math.min(cur, Math.max(0, items.length - 1))
    if (!items.length) { list.innerHTML = `<div class="pal-empty">No matches for “${esc(q.value)}”</div>`; q.removeAttribute('aria-activedescendant'); return }
    let last = ''
    const order = ['Sections', 'Actions', 'Links']
    if (!query) items.sort((a, b) => order.indexOf(a.section) - order.indexOf(b.section))
    list.innerHTML = items.map((c, i) => {
      const head = c.section !== last && !query ? `<div class="pal-sec" role="presentation">${c.section}</div>` : ''
      last = c.section
      const right = c.keys ? `<span class="kgrp">${c.keys.map(k => `<kbd class="kbd">${k}</kbd>`).join('')}</span>` : c.right ? `<span class="rt">${esc(c.right)}</span>` : ''
      return `${head}<div class="pal-it" id="pal-${c.id}" role="option" aria-selected="${i === cur}" data-i="${i}">${icon(c.icon)}<span class="lbl">${hi(c.label, query)}</span>${right}</div>`
    }).join('')
    q.setAttribute('aria-activedescendant', 'pal-' + items[cur].id)
  }
  function moveSel(d) {
    if (!items.length) return
    cur = (cur + d + items.length) % items.length
    $$('.pal-it', list).forEach((el, i) => el.setAttribute('aria-selected', String(i === cur)))
    const el = $$('.pal-it', list)[cur]
    q.setAttribute('aria-activedescendant', el.id)
    el.scrollIntoView({ block: 'nearest' })
  }
  function runSel(i) { const c = items[i]; if (!c) return; pal.close(); c.run() }
  function openPalette() { q.value = ''; cur = 0; renderPal(); openDlg(pal); q.focus() }
  q.addEventListener('input', () => { cur = 0; renderPal() })
  q.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) { e.preventDefault(); moveSel(1) }
    else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key === 'p')) { e.preventDefault(); moveSel(-1) }
    else if (e.key === 'Enter') { e.preventDefault(); runSel(cur) }
  })
  list.addEventListener('mousemove', e => {
    const it = e.target.closest('.pal-it'); if (!it) return
    const i = +it.dataset.i; if (i !== cur) { cur = i; $$('.pal-it', list).forEach((el, j) => el.setAttribute('aria-selected', String(j === cur))) }
  })
  list.addEventListener('click', e => { const it = e.target.closest('.pal-it'); if (it) runSel(+it.dataset.i) })

  // ------------------------------------------------------------ action buttons
  $$('[data-act]').forEach(b => b.addEventListener('click', () => {
    const a = b.dataset.act
    if (a === 'palette') openPalette()
    else if (a === 'help') openDlg(help)
    else if (a === 'report') openDlg(report)
    else if (a === 'theme') toggleTheme()
  }))
  $$('a[href^="#"]').forEach(a => a.addEventListener('click', e => {
    const id = a.getAttribute('href').slice(1)
    if (!id || !document.getElementById(id)) return
    e.preventDefault()
    go(id)
    if (id === 'main') document.getElementById('main').focus({ preventScroll: true })
  }))

  // ------------------------------------------------------------ keyboard (keyboard.tsx layering, simplified)
  let gAt = 0
  document.addEventListener('keydown', e => {
    const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target.isContentEditable
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal.open ? pal.close() : openPalette(); return }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return
    if ($('dialog[open]')) return
    if (e.key === '/') { e.preventDefault(); openPalette() }
    else if (e.key === '?') { e.preventDefault(); openDlg(help) }
    else if (e.key === 'T' && e.shiftKey) { e.preventDefault(); toggleTheme() }
    else if (e.key === 'z' || e.key === 'Z') { if (undoPending()) e.preventDefault() }
    else if (e.key === 'g' || e.key === 'G') { gAt = Date.now() }
    else if (Date.now() - gAt < 1200) {
      const s = SECTIONS.find(x => x[2] === e.key.toUpperCase())
      gAt = 0
      if (s) { e.preventDefault(); go(s[0]) }
    } else if (e.key === 'r' || e.key === 'R') { openDlg(report) }
  })

  // ------------------------------------------------------------ Verify fix demo (findings-inspector.tsx FixVerifyActions)
  const vBtn = $('#verify'), vLbl = $('#verify-l'), vReset = $('#verify-reset'), vNote = $('#verify-note'), retests = $('#retests')
  const fiTag = $('#fi-tag'), fiSt = $('#fi-st'), fiGlyph = $('#fi-glyph'), cmpVar = $('#cmp-var'), varRes = $('#var-res')
  const VAR_BEFORE = varRes.innerHTML
  let vTimers = []
  const later = (fn, ms) => vTimers.push(setTimeout(fn, reduce ? Math.min(ms, 300) : ms))
  const vSvg = () => vBtn.querySelector('svg')
  function resetVerify() {
    vTimers.forEach(clearTimeout); vTimers = []
    vBtn.disabled = false; vLbl.textContent = 'Verify fix'; setIcon(vSvg(), 'replay'); vSvg().classList.remove('spin')
    vReset.hidden = true; vNote.textContent = 'Sample finding · simulated'
    retests.innerHTML = ''
    fiTag.className = 'tag accent'; fiSt.textContent = 'Confirmed by replay'; fiGlyph.dataset.glyph = 'confirmed'; hydrateGlyphs(fiTag)
    cmpVar.classList.remove('fixed', 'diff'); varRes.innerHTML = VAR_BEFORE
  }
  function retestRow(glyphName, html) {
    const d = document.createElement('div')
    d.className = 'retest'
    d.innerHTML = `<span data-glyph="${glyphName}"></span><div>${html}</div>`
    hydrateGlyphs(d)
    retests.prepend(d)
    return d
  }
  vBtn.addEventListener('click', () => {
    vBtn.disabled = true; vLbl.textContent = 'Queued'
    vNote.textContent = 'Undo is available while the toast is open'
    undoable('Verify fix queued', {
      icon: 'replay', sub: 'Replays the check against the live origin when this closes', ms: 4500,
      undo: () => { resetVerify(); toast('Retest canceled', { icon: 'undo', sub: 'Nothing was sent' }) },
      commit: () => {
        vLbl.textContent = 'Verifying fix…'; setIcon(vSvg(), 'replay'); if (!reduce) vSvg().classList.add('spin')
        vNote.textContent = 'Retest worker re-running the stored replay spec'
        cmpVar.classList.add('diff')
        const row = retestRow('running', '<b>Retest running</b> <span class="s">· stored replay spec · 2 steps</span>')
        later(() => {
          row.remove()
          vSvg().classList.remove('spin'); setIcon(vSvg(), 'check'); vLbl.textContent = 'Verified fixed'
          retestRow('fixed', '<b>Verified fixed</b> <span class="s">· just now</span><span class="tag ok">0 LLM tokens</span><div class="s">fixed: variant now 404 Not Found; control still 200 OK.</div>')
          fiTag.className = 'tag ok'; fiSt.textContent = 'Verified fixed'; fiGlyph.dataset.glyph = 'fixed'; hydrateGlyphs(fiTag)
          cmpVar.classList.remove('diff'); cmpVar.classList.add('fixed')
          varRes.innerHTML = '<span class="code2 ok">404</span> denied <span class="s">· as expected</span>'
          vNote.textContent = ''
          vReset.hidden = false
          toast('Verified fixed', { icon: 'check', sub: 'Variant now denied; control still 200 OK' })
        }, 2400)
      },
    })
  })
  vReset.addEventListener('click', () => { resetVerify(); vBtn.focus() })

  // ------------------------------------------------------------ architecture strip (lab/schematic-c behaviour)
  ;(() => {
    const panels = $$('.panel')
    if (reduce) { const n = $('#strip-note'); if (n) n.hidden = true; return }
    const STEP = 2000, RUN = 2600, LOOP = 9000
    panels.forEach(p => p.classList.add('armed'))
    const timers = new Map(), visible = new Set()
    function play(p) {
      clearTimeout(timers.get(p))
      p.classList.remove('play', 'idle')
      void p.getBoundingClientRect()
      p.classList.add('play')
      p.dataset.played = '1'
      timers.set(p, setTimeout(() => {
        p.classList.add('idle')
        timers.set(p, setTimeout(() => { if (visible.has(p)) play(p) }, LOOP + panels.indexOf(p) * 700))
      }, RUN))
    }
    const wide = matchMedia('(min-width: 820px)')
    const pio = new IntersectionObserver(entries => entries.forEach(e => {
      if (e.isIntersecting) { visible.add(e.target); if (!wide.matches && !e.target.dataset.played) play(e.target) }
      else visible.delete(e.target)
    }), { threshold: 0.55 })
    panels.forEach(p => pio.observe(p))
    const sio = new IntersectionObserver(entries => {
      if (!wide.matches || !entries.some(e => e.isIntersecting)) return
      sio.disconnect()
      panels.forEach((p, i) => { if (!p.dataset.played) setTimeout(() => play(p), i * STEP) })
    }, { threshold: 0.45 })
    sio.observe($('#strip'))
    panels.forEach(p => {
      p.addEventListener('mouseenter', () => { if (p.classList.contains('idle')) play(p) })
      p.addEventListener('click', () => play(p))
      p.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); play(p) } })
    })
  })()

  applyTheme()
  fitRunline()
})()
