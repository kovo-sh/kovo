// Kovo Hunter landing (lab). Plain JS, no deps.
// Icons, glyphs and behaviours mirror src/components/run/{icons,glyphs,toast,theme}.tsx.
(() => {
  'use strict'
  const $ = (s, r = document) => r.querySelector(s)
  const $$ = (s, r = document) => [...r.querySelectorAll(s)]
  const root = document.documentElement
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches

  // ------------------------------------------------------------ icons (icons.tsx, 16px grid, 1.5 stroke)
  const P = {
    menu: '<path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11"/>',
    star: '<path d="M8 1.9l1.85 3.75 4.15.6-3 2.92.71 4.12L8 11.35 4.29 13.3 5 9.17 2 6.25l4.15-.6Z"/>',
    chat: '<path d="M2.75 3.25h10.5v7.5H7L4.25 13v-2.25h-1.5Z"/>',
    report: '<path d="M4 1.75h5.25L12.25 4.75v9.5H4Z"/><path d="M9 1.75V5h3.25"/><path d="M6.25 8.25h3.5M6.25 10.75h3.5"/>',
    sun: '<circle cx="8" cy="8" r="2.75"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1.06 1.06M11.54 11.54l1.06 1.06M3.4 12.6l1.06-1.06M11.54 4.46l1.06-1.06"/>',
    moon: '<path d="M13.25 9.5A5.5 5.5 0 0 1 6.5 2.75a5.5 5.5 0 1 0 6.75 6.75Z"/>',
    close: '<path d="M4 4l8 8M12 4l-8 8"/>',
    chev: '<path d="M4 6l4 4 4-4"/>',
    arrowR: '<path d="M3 8h10M9 4l4 4-4 4"/>',
    ext: '<path d="M6 3.5H3.5v9h9V10M9 3.5h3.5V7M12.5 3.5 7 9"/>',
    lock: '<rect x="3.25" y="7" width="9.5" height="6.75" rx="1.25"/><path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2"/>',
    sliders: '<path d="M2.5 5h6M11.5 5h2M2.5 11h2M7.5 11h6"/><circle cx="10" cy="5" r="1.5"/><circle cx="6" cy="11" r="1.5"/>',
    check: '<path d="M3.5 8.5 6.5 11.5 12.5 4.5"/>',
    shield: '<path d="M8 1.75 13.25 4v4c0 3-2.25 5.25-5.25 6.25C5 13.25 2.75 11 2.75 8V4Z"/>',
    flag: '<path d="M3.5 14V2.5M3.5 3h8l-1.5 3 1.5 3h-8"/>',
    undo: '<path d="M5.5 3.5 2.5 6.5l3 3"/><path d="M2.5 6.5h7a4 4 0 0 1 0 8H7"/>',
    node: '<circle cx="8" cy="8" r="2.25"/><path d="M8 1.75v4M8 10.25v4M1.75 8h4M10.25 8h4"/>',
    alert: '<path d="M8 2.25 14.25 13H1.75Z"/><path d="M8 6.5v3M8 11.25v.01"/>',
    replay: '<path d="M2.75 8a5.25 5.25 0 1 0 1.6-3.78"/><path d="M2.5 2.5v3h3"/><path d="M7 6v4l3-2Z" fill="currentColor" stroke="none"/>',
    copy: '<rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25"/><path d="M3.25 10.75h-.5a1.25 1.25 0 0 1-1.25-1.25v-6.75A1.25 1.25 0 0 1 2.75 1.5h6.75a1.25 1.25 0 0 1 1.25 1.25v.5"/>',
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
    t.innerHTML = `${opts.icon ? `<span class="ti">${icon(opts.icon)}</span>` : ''}<div class="tb"></div>${opts.undo ? `<button type="button" class="undo">Undo</button><i class="bar"></i>` : ''}`
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
    const next = th === 'dark' ? 'light' : 'dark'
    $$('.theme-lbl').forEach(el => { el.textContent = th === 'dark' ? 'Light theme' : 'Dark theme' })
    $$('[data-act=theme]').forEach(b => {
      setIcon(b.querySelector('svg'), th === 'dark' ? 'sun' : 'moon')
      if (!b.querySelector('.theme-lbl')) b.setAttribute('aria-label', 'Switch to ' + next + ' theme')
    })
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
    // ≤ 720 px the replay switches to its 4:5 focus crop (see replay/hero.js)
    return w <= 720 ? Math.min(Math.round(w * 1.25), 640) + 48 + 88 : Math.round(w * 810 / 1440) + 40
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

  // ------------------------------------------------------------ top bar: solid once scrolled, scroll spy, mobile menu
  const nav = $('#nav'), menuBtn = $('#nav-menu'), sheet = $('#nav-sheet')
  const onScroll = () => nav.classList.toggle('scrolled', window.scrollY > 8)
  window.addEventListener('scroll', onScroll, { passive: true })
  onScroll()

  const SECTIONS = ['overview', 'proof', 'architecture', 'install', 'compare', 'faq']
  let active = null
  function setActive(id) {
    if (id === active) return
    active = id
    $$('[data-nav]').forEach(a => {
      const on = a.dataset.nav === id
      a.classList.toggle('on', on)
      if (on) a.setAttribute('aria-current', 'location'); else a.removeAttribute('aria-current')
    })
  }
  const secEls = SECTIONS.map(id => document.getElementById(id))
  function spy() {
    const y = nav.offsetHeight + window.innerHeight * 0.3
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

  const menuOpen = () => !sheet.hidden
  function setMenu(open, restoreFocus) {
    if (open === menuOpen()) return
    sheet.hidden = !open
    nav.classList.toggle('menu-open', open)
    menuBtn.setAttribute('aria-expanded', String(open))
    menuBtn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu')
    setIcon(menuBtn.querySelector('svg'), open ? 'close' : 'menu')
    if (open) { const first = $('a, button', sheet); if (first) first.focus() }
    else if (restoreFocus) menuBtn.focus()
  }
  menuBtn.addEventListener('click', () => setMenu(!menuOpen()))
  nav.addEventListener('keydown', e => {
    if (!menuOpen()) return
    if (e.key === 'Escape') { e.preventDefault(); setMenu(false, true); return }
    if (e.key !== 'Tab') return
    // keep focus inside the menu button + sheet while it is open
    const f = [menuBtn, ...$$('a, button', sheet)]
    const i = f.indexOf(document.activeElement)
    if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus() }
    else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus() }
  })
  // composedPath, not contains(): the menu icon is swapped mid-click, detaching the original target
  document.addEventListener('click', e => { if (menuOpen() && !e.composedPath().includes(nav)) setMenu(false) })
  $$('a', sheet).forEach(a => a.addEventListener('click', () => setMenu(false)))
  matchMedia('(min-width: 901px)').addEventListener('change', e => { if (e.matches) setMenu(false) })

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
  const report = $('#report')
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

  // ------------------------------------------------------------ action buttons
  $$('[data-act]').forEach(b => b.addEventListener('click', () => {
    const a = b.dataset.act
    if (a === 'report') openDlg(report)
    else if (a === 'theme') toggleTheme()
  }))
  $$('a[href^="#"]').forEach(a => a.addEventListener('click', e => {
    const id = a.getAttribute('href').slice(1)
    if (!id || !document.getElementById(id)) return
    e.preventDefault()
    go(id)
    if (id === 'main') document.getElementById('main').focus({ preventScroll: true })
  }))

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
})()
