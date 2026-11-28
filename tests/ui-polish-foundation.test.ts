// Phase 4 Bucket A — PR 1 (foundation, overlays, shell, settings) behavioural UI QA.
//
// Boots an isolated Kovo server (ephemeral port, temp KOVO_DATA_DIR, built
// client bundle) and drives real headless Chromium. Every assertion is a DOM
// geometry, computed-style, WCAG contrast, focus or interaction check against
// the running app — never a source-text match.
//
// Set KOVO_UI_SHOTS_DIR=<dir> to also write the visual-QA screenshots.
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Locator, Page } from '@playwright/test'
import { HARDENED_NODE_FLAGS } from './app.ts'

type Theme = 'light' | 'dark'
type Motion = 'reduce' | 'no-preference'
interface Viewport { width: number; height: number }

const DESKTOP: Viewport = { width: 1280, height: 720 }
const WIDE: Viewport = { width: 1440, height: 900 }
const PHONE: Viewport = { width: 390, height: 844 }
const THEMES: Theme[] = ['light', 'dark']
const SHOTS_DIR = process.env.KOVO_UI_SHOTS_DIR ?? ''

// Extreme-but-valid fixtures: unbroken tokens at every schema limit.
const LONG_PROFILE_NAME = 'Primary-' + 'ExtremelyLongUnbrokenProfileName'.repeat(5).slice(0, 152)
const LONG_MODEL_ID = 'vendor/' + 'unbroken-model-identifier-'.repeat(5).slice(0, 120)
const LONG_ENDPOINT = 'https://' + 'very-long-gateway-subdomain-'.repeat(4) + 'example.test/' + 'nested-path-segment/'.repeat(6) + 'v1'
const LONG_ERROR = 'upstream-rejected:' + 'x'.repeat(380)
const LONG_WORKSPACE = 'Workspace-' + 'NamedWithoutAnySpacesAtAll'.repeat(6).slice(0, 150)

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const pw = (await import(modName)) as Partial<PlaywrightModule>
      if (!pw.chromium?.launch) continue
      const candidates = [
        (() => { try { return pw.chromium!.executablePath() } catch { return '' } })(),
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
      ]
      const executablePath = candidates.find(p => p && existsSync(p))
      if (executablePath) return { pw: pw as PlaywrightModule, executablePath }
    } catch {
      // Try the next package name.
    }
  }
  return null
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate an ephemeral port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

function ensureBuilt(): void {
  if (existsSync(resolve('build/server/server.js')) && existsSync(resolve('build/client'))) return
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'pipe' })
}

interface KovoServer {
  origin: string
  dataDir: string
  bootstrapSecret: string
  output(): string
  stop(): Promise<void>
}

async function startKovoServer(): Promise<KovoServer> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-ui-polish-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''
  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      KOVO_DATA_DIR: dataDir,
      KOVO_ALLOW_LOCAL_LAB: '1',
      KOVO_ALLOW_LOCAL_MODEL: '1',
      KOVO_OFFLINE: '',
      KOVO_PUBLIC_ORIGIN: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', chunk => { output += String(chunk) })
  child.stderr?.on('data', chunk => { output += String(chunk) })
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      if (await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
    await rm(dataDir, { recursive: true, force: true })
  }
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) break
    try {
      if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })).ok) {
        let bootstrapSecret = ''
        for (let read = 0; read < 40 && !bootstrapSecret; read += 1) {
          try { bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
        }
        if (!bootstrapSecret) break
        return { origin, dataDir, bootstrapSecret, output: () => output, stop }
      }
    } catch {
      // Not bound yet.
    }
    await delay(70)
  }
  await stop()
  throw new Error(`scripts/serve.ts failed to start on ${origin}.\n${output}`)
}

/** Minimal local target so a local-lab project can be created through the real form. */
async function startTargetServer(): Promise<{ origin: string; server: Server }> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<!doctype html><title>QA target</title><p>ok</p>')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')
  return { origin: `http://127.0.0.1:${addr.port}`, server }
}

function withSqlite<T>(dataDir: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
  try {
    db.exec('PRAGMA busy_timeout = 5000;')
    return fn(db)
  } finally {
    db.close()
  }
}

/** Seed an extreme-stress model pool straight into the isolated data dir. */
function seedModelProfiles(dataDir: string): void {
  withSqlite(dataDir, db => {
    const workspace = db.prepare('SELECT id FROM workspaces LIMIT 1').get() as { id: string } | undefined
    assert.ok(workspace, 'workspace row must exist after bootstrap')
    const insert = db.prepare(`INSERT INTO model_profiles
      (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, enabled, context_window, max_tokens,
       thinking_level, role_affinity, input_cost_per_mtok, cached_input_cost_per_mtok, output_cost_per_mtok,
       health_state, cooldown_until, last_error, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'medium', ?, ?, ?, ?, ?, NULL, ?, ?)`)
    const now = Date.now()
    insert.run(randomUUID(), workspace.id, LONG_PROFILE_NAME, LONG_ENDPOINT, LONG_MODEL_ID, 'chat-completions',
      'model-' + randomUUID(), 300, 1_048_576, 16_384, 'reasoning', 1234.56, 0.0035, 0.6, 'half_open', LONG_ERROR, now)
    insert.run(randomUUID(), workspace.id, 'OpenRouter DeepSeek V4.1 Flash', 'https://openrouter.ai/api/v1',
      'deepseek/deepseek-v4.1-flash-1017', 'responses', 'model-' + randomUUID(), 200, 999_999, 16_384, 'any', 0.15, 0.003, 0.6,
      'closed', null, now - 3_600_000)
    insert.run(randomUUID(), workspace.id, 'Local vLLM fallback', 'http://127.0.0.1:9/v1', 'qwen/qwen3-coder', 'messages',
      'model-' + randomUUID(), 100, 131_072, 8_192, 'fast', 0, 0, 0, 'closed', null, now - 86_400_000)
  })
}

// ---------------------------------------------------------------------------
// In-page QA helpers (installed before any document script runs).
// ---------------------------------------------------------------------------

// Plain JS (not a TS function) so the transpiler never injects helpers such as
// `__name` that do not exist inside the page.
const QA_HELPERS_SCRIPT = String.raw`(() => {
  const canvas = document.createElement('canvas')
  canvas.width = 1
  canvas.height = 1
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  const lin = v => { const c = v / 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4 }
  const luminance = rgb => 0.2126 * lin(rgb[0]) + 0.7152 * lin(rgb[1]) + 0.0722 * lin(rgb[2])
  // Composite the background chain of el (root first), then extra colours, on an opaque white base.
  const paint = (el, colors) => {
    ctx.globalCompositeOperation = 'source-over'
    ctx.fillStyle = '#ffffff'
    ctx.fillRect(0, 0, 1, 1)
    const chain = []
    for (let node = el; node; node = node.parentElement) {
      const bg = getComputedStyle(node).backgroundColor
      if (bg && bg !== 'transparent' && bg !== 'rgba(0, 0, 0, 0)') chain.unshift(bg)
    }
    for (const color of chain.concat(colors)) {
      ctx.fillStyle = color
      ctx.fillRect(0, 0, 1, 1)
    }
    const d = ctx.getImageData(0, 0, 1, 1).data
    return [d[0], d[1], d[2]]
  }
  const ratio = (a, b) => {
    const la = luminance(a)
    const lb = luminance(b)
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
  }
  const qa = {
    contrastOn: (el, color) => ratio(paint(el, [color]), paint(el, [])),
    textContrast: el => qa.contrastOn(el, getComputedStyle(el).color),
    hasOwnText: el => [...el.childNodes].some(n => n.nodeType === Node.TEXT_NODE && (n.textContent || '').trim().length > 0),
    isRendered: el => {
      const r = el.getBoundingClientRect()
      if (r.width < 1 || r.height < 1) return false
      if (el.closest('[disabled],[data-disabled],[aria-disabled=true],[data-enabled=false]')) return false
      for (let node = el; node; node = node.parentElement) {
        const cs = getComputedStyle(node)
        if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) < 1) return false
      }
      return true
    },
  }
  window.__qa = qa
})()`

declare global {
  interface Window {
    __qa: {
      contrastOn(el: Element, color: string): number
      textContrast(el: Element): number
      hasOwnText(el: Element): boolean
      isRendered(el: Element): boolean
    }
  }
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

let skipReason: string | null = null
let browser: Browser | undefined
let kovo: KovoServer | undefined
let target: { origin: string; server: Server } | undefined
let authCookies: Awaited<ReturnType<BrowserContext['cookies']>> = []
let projectPath = ''
const openContexts = new Set<BrowserContext>()
const pageErrors: string[] = []

interface PageOptions {
  viewport?: Viewport
  theme?: Theme
  motion?: Motion
  touch?: boolean
  authenticated?: boolean
}

async function openPage(opts: PageOptions = {}): Promise<{ page: Page; context: BrowserContext }> {
  assert.ok(browser && kovo)
  const viewport = opts.viewport ?? DESKTOP
  const context = await browser.newContext({
    viewport,
    reducedMotion: opts.motion ?? 'no-preference',
    colorScheme: opts.theme ?? 'light',
    hasTouch: Boolean(opts.touch),
    isMobile: Boolean(opts.touch),
    deviceScaleFactor: 1,
  })
  openContexts.add(context)
  if (opts.authenticated !== false) await context.addCookies(authCookies)
  await context.addInitScript({ content: QA_HELPERS_SCRIPT })
  const theme = opts.theme ?? 'light'
  await context.addInitScript(mode => {
    try { localStorage.setItem('kovo-appearance', mode) } catch { /* storage unavailable */ }
  }, theme)
  const page = await context.newPage()
  page.on('pageerror', err => { pageErrors.push(`${new URL(page.url()).pathname}: ${err instanceof Error ? err.message : String(err)}`) })
  return { page, context }
}

async function closePage(context: BrowserContext) {
  openContexts.delete(context)
  await context.close().catch(() => {})
}

async function shot(page: Page, name: string, target?: Locator) {
  if (!SHOTS_DIR) return
  mkdirSync(SHOTS_DIR, { recursive: true })
  const path = join(SHOTS_DIR, `${name}.png`)
  if (target) await target.screenshot({ path, animations: 'disabled' })
  else await page.screenshot({ path, animations: 'disabled' })
}

function tag(viewport: Viewport, theme: Theme, extra = '') {
  return `${viewport.width}x${viewport.height}-${theme}${extra ? '-' + extra : ''}`
}

async function gotoApp(page: Page, path: string, ready: () => Promise<unknown>) {
  assert.ok(kovo)
  await page.goto(`${kovo.origin}${path}`, { waitUntil: 'domcontentloaded' })
  await ready()
  // Let hydration and the first effects settle (theme boot, ResizeObservers).
  await page.waitForFunction(() => Boolean(window.__TSR_ROUTER__))
  await page.evaluate(() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))))
}

async function settleTransitions(page: Page) {
  await page.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity), undefined, { timeout: 5_000 })
}

/** Horizontal-overflow + clipped-control invariants for any container. */
async function assertNoOverflow(page: Page, selector: string, label: string) {
  const report = await page.evaluate(sel => {
    const out: string[] = []
    for (const el of document.querySelectorAll<HTMLElement>(sel)) {
      if (!window.__qa.isRendered(el)) continue
      if (el.scrollWidth > el.clientWidth + 1) out.push(`${sel} scrollWidth ${el.scrollWidth} > clientWidth ${el.clientWidth}`)
    }
    return out
  }, selector)
  assert.deepEqual(report, [], `${label}: horizontal overflow`)
}

async function assertButtonsUnclipped(page: Page, scope: string, label: string) {
  const clipped = await page.evaluate(sel => {
    const out: string[] = []
    for (const root of document.querySelectorAll(sel)) {
      for (const el of root.querySelectorAll<HTMLElement>('button, a[data-slot=button], [role=radio]')) {
        if (!window.__qa.isRendered(el)) continue
        if (el.scrollHeight > el.clientHeight + 2) out.push(`${(el.textContent ?? '').trim().slice(0, 40)} (${el.scrollHeight}>${el.clientHeight})`)
      }
    }
    return out
  }, scope)
  assert.deepEqual(clipped, [], `${label}: vertically clipped buttons`)
}

async function assertNoOverlappingSiblings(page: Page, selector: string, label: string) {
  const overlaps = await page.evaluate(sel => {
    const out: string[] = []
    for (const root of document.querySelectorAll(sel)) {
      const controls = [...root.querySelectorAll<HTMLElement>('button, input:not([type=hidden]), select, textarea, a[href]')]
        .filter(el => window.__qa.isRendered(el))
      for (let i = 0; i < controls.length; i += 1) {
        for (let j = i + 1; j < controls.length; j += 1) {
          const a = controls[i]!
          const b = controls[j]!
          if (a.contains(b) || b.contains(a) || a.parentElement !== b.parentElement) continue
          const ra = a.getBoundingClientRect()
          const rb = b.getBoundingClientRect()
          const w = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left)
          const h = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top)
          if (w > 1 && h > 1) out.push(`${a.tagName}:${(a.textContent ?? '').trim().slice(0, 20)} × ${b.tagName}:${(b.textContent ?? '').trim().slice(0, 20)}`)
        }
      }
    }
    return out
  }, selector)
  assert.deepEqual(overlaps, [], `${label}: overlapping sibling controls`)
}

async function assertInViewport(locator: Locator, viewport: Viewport, label: string) {
  const box = await locator.boundingBox()
  assert.ok(box, `${label}: not rendered`)
  assert.ok(box.x >= 0 && box.y >= 0 && box.x + box.width <= viewport.width + 0.5 && box.y + box.height <= viewport.height + 0.5,
    `${label}: outside the ${viewport.width}x${viewport.height} viewport (${JSON.stringify(box)})`)
}

/** Record when the open dialog popup enters its ending style and when it unmounts. */
async function watchExit(page: Page) {
  await page.evaluate(() => {
    const el = document.querySelector<HTMLElement>('[data-slot=dialog-content]')!
    const state = { sawEnding: false, duration: '', start: 0, removedAfter: -1 }
    ;(window as unknown as { __exit: typeof state }).__exit = state
    const mo = new MutationObserver(() => {
      if (!state.sawEnding && el.hasAttribute('data-ending-style')) {
        state.sawEnding = true
        state.start = performance.now()
        state.duration = getComputedStyle(el).transitionDuration
      }
      if (!el.isConnected) {
        state.removedAfter = performance.now() - state.start
        mo.disconnect()
      }
    })
    mo.observe(document.body, { attributes: true, subtree: true, childList: true })
  })
}

async function readExit(page: Page): Promise<{ sawEnding: boolean; duration: string; removedAfter: number }> {
  await page.waitForFunction(() => (window as unknown as { __exit: { removedAfter: number } }).__exit.removedAfter >= 0)
  return page.evaluate(() => (window as unknown as { __exit: { sawEnding: boolean; duration: string; removedAfter: number } }).__exit)
}

async function waitForSettingsTable(page: Page) {
  await page.getByRole('table', { name: 'Configured model profiles' }).waitFor({ state: 'visible', timeout: 15_000 })
}

function requireEnv(t: { skip(msg?: string): void }): boolean {
  if (skipReason || !browser || !kovo) {
    t.skip(skipReason ?? 'Browser setup unavailable')
    return false
  }
  return true
}

describe('UI polish foundation — tokens, overlays, shell, sign-in & settings (behavioural)', { timeout: 240_000 }, () => {
  before(async () => {
    const pwEnv = await loadPlaywright()
    if (!pwEnv) {
      skipReason = 'Playwright or Chromium binary unavailable in this environment'
      return
    }
    ensureBuilt()
    target = await startTargetServer()
    kovo = await startKovoServer()
    browser = await pwEnv.pw.chromium.launch({ headless: true, executablePath: pwEnv.executablePath, args: ['--no-sandbox'] })

    // One real bootstrap sign-in; every later context reuses the session cookie.
    const context = await browser.newContext({ viewport: DESKTOP })
    const page = await context.newPage()
    await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, { waitUntil: 'domcontentloaded' })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 20_000 })
    authCookies = await context.cookies()

    // A real local-lab project (through the real form) for the dropdown + New run sheet.
    await page.getByLabel('Project name').fill('QA polish target')
    await page.getByLabel('Sites').fill(target.origin)
    await page.getByRole('button', { name: /Advanced configuration/ }).click()
    await page.getByLabel('Target environment').selectOption('local-lab')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 20_000 })
    projectPath = new URL(page.url()).pathname

    // Extreme workspace name, renamed through the real Settings form.
    await page.goto(`${kovo.origin}/settings`, { waitUntil: 'domcontentloaded' })
    const nameInput = page.locator('input[name="workspaceName"]')
    await nameInput.waitFor({ state: 'visible', timeout: 15_000 })
    await page.waitForFunction(() => Boolean(window.__TSR_ROUTER__))
    await nameInput.fill(LONG_WORKSPACE)
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await page.getByText('Workspace name updated.').waitFor({ state: 'visible', timeout: 10_000 })
    await context.close()

    seedModelProfiles(kovo.dataDir)
  })

  after(async () => {
    for (const context of openContexts) await context.close().catch(() => {})
    await browser?.close().catch(() => {})
    await kovo?.stop().catch(() => {})
    if (target) {
      target.server.closeAllConnections()
      await new Promise<void>(done => target!.server.close(() => done()))
    }
  })

  it('sign-in page: cascade-proof dark polarity, AA contrast, phone fit, 16px input and app focus halo', async t => {
    if (!requireEnv(t)) return
    for (const viewport of [DESKTOP, WIDE, PHONE]) {
      for (const theme of THEMES) {
        const { page, context } = await openPage({ viewport, theme, authenticated: false })
        const res = await page.goto(kovo!.origin + '/', { waitUntil: 'domcontentloaded' })
        assert.equal(res?.status(), 401)
        const metrics = await page.evaluate(() => {
          const card = document.querySelector('.card')!
          const h1 = document.querySelector('h1')!
          const pre = document.querySelector('pre')!
          const button = document.querySelector('button')!
          const input = document.querySelector('input')!
          return {
            cardBg: getComputedStyle(card).backgroundColor,
            h1: window.__qa.textContrast(h1),
            pre: window.__qa.textContrast(pre),
            button: window.__qa.textContrast(button),
            buttonVsCard: window.__qa.contrastOn(card, getComputedStyle(button).backgroundColor),
            inputFont: getComputedStyle(input).fontSize,
            docOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          }
        })
        const label = tag(viewport, theme, 'signin')
        if (theme === 'dark') assert.notEqual(metrics.cardBg, 'rgb(255, 255, 255)', `${label}: dark card must not stay white`)
        else assert.equal(metrics.cardBg, 'rgb(255, 255, 255)', `${label}: light card unchanged`)
        assert.ok(metrics.h1 >= 4.5, `${label}: heading contrast ${metrics.h1.toFixed(2)}`)
        assert.ok(metrics.pre >= 4.5, `${label}: recovery command contrast ${metrics.pre.toFixed(2)}`)
        assert.ok(metrics.button >= 4.5, `${label}: CTA label contrast ${metrics.button.toFixed(2)}`)
        assert.ok(metrics.buttonVsCard >= 3, `${label}: CTA fill reads as enabled (${metrics.buttonVsCard.toFixed(2)})`)
        assert.equal(metrics.inputFont, '16px', `${label}: token input is 16px (no iOS zoom)`)
        assert.ok(metrics.docOverflow <= 0, `${label}: horizontal overflow ${metrics.docOverflow}px`)
        await assertInViewport(page.getByRole('button', { name: 'Sign in' }), viewport, `${label}: Sign in CTA`)
        await page.locator('input').focus()
        await page.keyboard.press('Shift+Tab')
        await page.keyboard.press('Tab')
        const ring = await page.locator('input').evaluate(el => getComputedStyle(el).boxShadow)
        assert.match(ring, /rgba\((47, 95, 223|108, 147, 255)/, `${label}: accent focus halo`)
        await shot(page, label)
        await closePage(context)
      }
    }
  })

  it('tokens: fg-subtle AA, checkbox border 3:1, status text on soft fills, accent focus ring, one easing curve', async t => {
    if (!requireEnv(t)) return
    for (const theme of THEMES) {
      const { page, context } = await openPage({ viewport: DESKTOP, theme })
      await gotoApp(page, '/settings', () => waitForSettingsTable(page))
      const probe = await page.evaluate(() => {
        const host = document.createElement('div')
        host.setAttribute('data-qa-probe', '')
        document.body.append(host)
        const out: Record<string, number | string> = {}
        for (const surface of ['bg-panel', 'bg-rail', 'bg-sunk', 'bg-raise', 'bg-bg']) {
          const box = document.createElement('div')
          box.className = surface
          box.innerHTML = '<span class="text-fg-subtle">subtle</span><span data-slot="checkbox"></span>'
          host.append(box)
          out[`subtle:${surface}`] = window.__qa.textContrast(box.firstElementChild!)
          const checkbox = box.lastElementChild!
          out[`checkbox:${surface}`] = window.__qa.contrastOn(box, getComputedStyle(checkbox).borderTopColor)
        }
        for (const tone of ['ok', 'warn', 'accent']) {
          const badge = document.createElement('span')
          badge.className = { ok: 'bg-ok-soft text-ok-text', warn: 'bg-warn-soft text-warn-text', accent: 'bg-accent-soft text-accent-text' }[tone]!
          badge.textContent = tone
          host.firstElementChild!.append(badge)
          out[`badge:${tone}`] = window.__qa.textContrast(badge)
        }
        const bare = document.createElement('span')
        bare.className = 'transition-colors'
        host.append(bare)
        out.easing = getComputedStyle(bare).transitionTimingFunction
        host.remove()
        return out
      })
      for (const [key, value] of Object.entries(probe)) {
        if (key.startsWith('subtle:')) assert.ok(Number(value) >= 4.5, `${theme} ${key} = ${Number(value).toFixed(2)}`)
        if (key.startsWith('checkbox:')) assert.ok(Number(value) >= 3, `${theme} ${key} = ${Number(value).toFixed(2)}`)
        if (key.startsWith('badge:')) assert.ok(Number(value) >= 4.5, `${theme} ${key} = ${Number(value).toFixed(2)}`)
      }
      assert.equal(probe.easing, 'cubic-bezier(0.2, 0.8, 0.2, 1)', 'bare transition utilities use the Kovo curve')

      // Every rendered .text-fg-subtle text node on the real settings page is AA.
      const failures = await page.evaluate(() => [...document.querySelectorAll('.text-fg-subtle')]
        .filter(el => window.__qa.hasOwnText(el) && window.__qa.isRendered(el))
        .map(el => ({ text: (el.textContent ?? '').trim().slice(0, 32), ratio: window.__qa.textContrast(el) }))
        .filter(row => row.ratio < 4.5))
      assert.deepEqual(failures, [], `${theme}: .text-fg-subtle below AA on /settings`)

      // Keyboard focus ring: accent outline at >= 3:1, following the control radius.
      await page.locator('body').click({ position: { x: 600, y: 700 } })
      await page.keyboard.press('Tab')
      const ring = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement
        const cs = getComputedStyle(el)
        const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
        return { style: cs.outlineStyle, width: cs.outlineWidth, color: cs.outlineColor, offset: cs.outlineOffset, ratio: window.__qa.contrastOn(el.parentElement ?? el, cs.outlineColor), accent }
      })
      assert.equal(ring.style, 'solid')
      assert.equal(ring.width, '2px')
      assert.equal(ring.offset, '2px')
      assert.ok(ring.ratio >= 3, `${theme}: focus ring contrast ${ring.ratio.toFixed(2)}`)
      await closePage(context)
    }
  })

  it('reduced motion: overlays fade without travel, spinners breathe, loops stop; full motion keeps the scale', async t => {
    if (!requireEnv(t)) return
    for (const motion of ['reduce', 'no-preference'] as Motion[]) {
      const { page, context } = await openPage({ viewport: DESKTOP, motion })
      await gotoApp(page, projectPath, () => page.getByRole('button', { name: 'New run' }).waitFor({ state: 'visible', timeout: 15_000 }))
      await page.getByRole('button', { name: 'New run' }).click()
      const popup = page.locator('[data-slot=dialog-content]')
      await popup.waitFor({ state: 'visible' })
      const enter = await popup.evaluate(el => {
        const cs = getComputedStyle(el)
        return { property: cs.transitionProperty, duration: cs.transitionDuration }
      })
      assert.match(enter.property, /opacity/, `${motion}: dialog still fades`)
      if (motion === 'reduce') assert.doesNotMatch(enter.property, /scale|transform|translate/, 'reduce: no travel in dialog transition')
      else assert.match(enter.property, /scale/, 'full motion: dialog scales in')
      assert.match(enter.duration, /0\.15s/, `${motion}: 150ms enter preserved`)

      const disclosure = page.getByRole('button', { name: /Advanced configuration/ })
      await disclosure.click()
      const panel = page.locator('[data-slot=disclosure-content][data-open]').first()
      await panel.waitFor({ state: 'attached' })
      const panelProps = await panel.evaluate(el => getComputedStyle(el).transitionProperty)
      if (motion === 'reduce') {
        assert.doesNotMatch(panelProps, /height/, 'reduce: disclosure height snaps')
        assert.match(panelProps, /opacity/, 'reduce: disclosure still fades')
      } else {
        assert.match(panelProps, /height/, 'full motion: disclosure height animates')
      }
      await settleTransitions(page)
      if (motion === 'reduce') await shot(page, tag(DESKTOP, 'light', 'reduced-motion-new-run-sheet'))

      const loops = await page.evaluate(() => {
        const host = document.createElement('div')
        host.innerHTML = '<span class="animate-spin"></span><span class="animate-ping"></span><span class="animate-pulse"></span>'
        document.body.append(host)
        const [spin, ping, pulse] = [...host.children].map(el => getComputedStyle(el).animationName)
        host.remove()
        return { spin, ping, pulse }
      })
      if (motion === 'reduce') {
        assert.equal(loops.spin, 'kovo-breathe', 'reduce: spinner breathes instead of turning')
        assert.equal(loops.ping, 'none')
        assert.equal(loops.pulse, 'none')
      } else {
        assert.equal(loops.spin, 'spin')
      }
      await page.keyboard.press('Escape')
      await popup.waitFor({ state: 'detached', timeout: 5_000 })
      await closePage(context)
    }
  })

  it('dialog timing: pointer modals fade 150ms in and exit faster; the New run sheet animates its Advanced panel', async t => {
    if (!requireEnv(t)) return
    const { page, context } = await openPage({ viewport: WIDE })
    await gotoApp(page, projectPath, () => page.getByRole('button', { name: 'New run' }).waitFor({ state: 'visible', timeout: 15_000 }))
    await page.getByRole('button', { name: 'New run' }).click()
    const popup = page.locator('[data-slot=dialog-content]')
    await popup.waitFor({ state: 'visible' })
    await settleTransitions(page)

    // Disclosure height interpolates (sampled mid-transition) instead of snapping in one frame.
    const samples = await page.evaluate(async () => {
      const trigger = [...document.querySelectorAll<HTMLElement>('[data-slot=disclosure-trigger]')]
        .find(el => /Advanced configuration/.test(el.textContent ?? ''))!
      trigger.click()
      const heights: number[] = []
      const start = performance.now()
      while (performance.now() - start < 400) {
        await new Promise(r => requestAnimationFrame(r))
        const panel = trigger.parentElement!.querySelector<HTMLElement>('[data-slot=disclosure-content]')
        if (panel) heights.push(panel.getBoundingClientRect().height)
      }
      return heights
    })
    const final = samples.at(-1) ?? 0
    assert.ok(final > 40, 'panel opened')
    assert.ok(samples.some(h => h > 1 && h < final - 1), `panel height interpolates (samples: ${samples.map(h => h.toFixed(0)).join(',')})`)

    // Exit is shorter than entry.
    await watchExit(page)
    await page.keyboard.press('Escape')
    await popup.waitFor({ state: 'detached', timeout: 5_000 })
    const exit = await readExit(page)
    assert.ok(exit.sawEnding, 'exit transition ran while mounted')
    assert.match(exit.duration, /0\.1s/, `exit runs at 100ms (got ${exit.duration})`)
    assert.ok(exit.removedAfter > 60 && exit.removedAfter < 400, `dialog removed ~100ms after exit starts (${exit.removedAfter.toFixed(0)}ms)`)
    await closePage(context)
  })

  it('⌘K palette and ? help sheet: instant, bounded workspace chip, stable height, focus on the sheet, dark edge', async t => {
    if (!requireEnv(t)) return
    for (const theme of THEMES) {
      const { page, context } = await openPage({ viewport: DESKTOP, theme })
      await gotoApp(page, '/settings', () => waitForSettingsTable(page))
      await page.keyboard.press('Control+k')
      const popup = page.locator('[data-slot=dialog-content][aria-label="Command palette"]')
      await popup.waitFor({ state: 'visible' })
      const firstFrame = await popup.evaluate(el => ({
        opacity: getComputedStyle(el).opacity,
        animations: document.getAnimations().filter(a => {
          const target = (a.effect as KeyframeEffect | null)?.target
          return target instanceof Element && (target.closest('[data-slot=dialog-content]') === el || target.matches('[data-slot=dialog-backdrop]'))
        }).length,
        borderWidth: getComputedStyle(el).borderTopWidth,
        transition: getComputedStyle(el).transitionDuration,
      }))
      assert.equal(firstFrame.opacity, '1', `${theme}: palette fully opaque on its first frame`)
      assert.equal(firstFrame.animations, 0, `${theme}: palette open runs no transitions`)
      assert.equal(firstFrame.borderWidth, '1px', `${theme}: palette has a hairline edge`)
      assert.equal(firstFrame.transition, '0s')

      const input = page.getByRole('textbox', { name: 'Search workspace' })
      await assert.doesNotReject(input.waitFor({ state: 'visible' }))
      const geometry = await page.evaluate(() => {
        const field = document.querySelector<HTMLInputElement>('input[aria-label="Search workspace"]')!
        const chip = field.parentElement!.querySelector<HTMLElement>('span[title]')!
        const dialog = field.closest<HTMLElement>('[data-slot=dialog-content]')!
        return {
          inputWidth: field.getBoundingClientRect().width,
          chipEllipsis: chip.scrollWidth > chip.clientWidth && getComputedStyle(chip).textOverflow === 'ellipsis',
          chipTitle: chip.title,
          chipInside: chip.getBoundingClientRect().right <= dialog.getBoundingClientRect().right,
          dialogOverflow: dialog.scrollWidth - dialog.clientWidth,
        }
      })
      assert.ok(geometry.inputWidth >= 300, `${theme}: search input keeps ${geometry.inputWidth}px`)
      assert.ok(geometry.chipEllipsis, `${theme}: long workspace chip ends with an ellipsis`)
      assert.equal(geometry.chipTitle, LONG_WORKSPACE)
      assert.ok(geometry.chipInside)
      assert.ok(geometry.dialogOverflow <= 0)
      await assertInViewport(popup, DESKTOP, `${theme}: palette`)

      const settingsRow = popup.getByRole('option', { name: /Model settings/ })
      const hint = await settingsRow.locator('span').last().evaluate(el => getComputedStyle(el).fontFamily)
      assert.doesNotMatch(hint, /mono/i, 'status hint renders proportional')
      assert.equal(await settingsRow.getAttribute('title'), 'Model settings')

      const before = (await popup.boundingBox())!.height
      await input.fill('zz-no-such-command-zz')
      await popup.getByText(/No matches for/).waitFor({ state: 'visible' })
      const afterHeight = (await popup.boundingBox())!.height
      assert.equal(Math.round(afterHeight - before), 0, `${theme}: palette height stable at zero matches`)
      await input.fill('')
      await shot(page, tag(DESKTOP, theme, 'palette'))

      // Escape closes instantly; the help sheet opens with focus on the sheet itself.
      await page.keyboard.press('Escape')
      await popup.waitFor({ state: 'detached', timeout: 2_000 })
      await page.locator('body').click({ position: { x: 700, y: 650 } })
      await page.keyboard.press('?')
      const sheet = page.locator('[data-slot=dialog-content][aria-label="Keyboard shortcuts"]')
      await sheet.waitFor({ state: 'visible' })
      await page.waitForFunction(() => document.activeElement?.getAttribute('aria-label') === 'Keyboard shortcuts', undefined, { timeout: 2_000 }).catch(() => {})
      const sheetFocus = await sheet.evaluate(el => ({
        focused: document.activeElement === el,
        opacity: getComputedStyle(el).opacity,
        borderWidth: getComputedStyle(el).borderTopWidth,
      }))
      assert.ok(sheetFocus.focused, `${theme}: help sheet container takes initial focus`)
      assert.equal(sheetFocus.opacity, '1')
      assert.equal(sheetFocus.borderWidth, '1px')
      await page.keyboard.press('Tab')
      assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-label')), 'Close shortcuts')
      await shot(page, tag(DESKTOP, theme, 'help-sheet'))
      await page.keyboard.press('Escape')
      await sheet.waitFor({ state: 'detached', timeout: 2_000 })
      await closePage(context)
    }

    // Phone: the chip yields to the search field.
    const { page, context } = await openPage({ viewport: PHONE })
    await gotoApp(page, '/settings', () => waitForSettingsTable(page))
    await page.keyboard.press('Control+k')
    const phoneInput = page.getByRole('textbox', { name: 'Search workspace' })
    await phoneInput.waitFor({ state: 'visible' })
    const phone = await phoneInput.evaluate(el => {
      const chip = el.parentElement!.querySelector<HTMLElement>('span[title]')!
      const field = el as HTMLInputElement
      return { chipDisplay: getComputedStyle(chip).display, placeholderFits: field.scrollWidth <= field.clientWidth + 1 }
    })
    assert.equal(phone.chipDisplay, 'none', '390px: workspace chip hidden')
    await shot(page, tag(PHONE, 'light', 'palette'))
    await closePage(context)
  })

  it('dropdown menu grows from its trigger with an interpolated scale, closes on Escape and restores focus', async t => {
    if (!requireEnv(t)) return
    for (const theme of THEMES) {
      const { page, context } = await openPage({ viewport: DESKTOP, theme })
      await gotoApp(page, projectPath, () => page.getByRole('button', { name: 'Project actions' }).waitFor({ state: 'visible', timeout: 15_000 }))
      const trigger = page.getByRole('button', { name: 'Project actions' })
      await trigger.click()
      const menu = page.locator('[data-slot=dropdown-menu-content]')
      await menu.waitFor({ state: 'visible' })
      const motion = await menu.evaluate(el => {
        const cs = getComputedStyle(el)
        const origin = cs.getPropertyValue('--transform-origin').trim()
        // Resolve the variable against a box of the popup's own size (percentages are self-relative).
        const probe = document.createElement('div')
        probe.style.cssText = `position:absolute;visibility:hidden;width:${(el as HTMLElement).offsetWidth}px;height:${(el as HTMLElement).offsetHeight}px;transform-origin:${origin}`
        document.body.append(probe)
        const expected = getComputedStyle(probe).transformOrigin
        probe.remove()
        return { origin: cs.transformOrigin, expected, raw: origin, property: cs.transitionProperty, scaleAnimating: el.getAnimations().some(a => (a as CSSTransition).transitionProperty === 'scale') }
      })
      assert.ok(motion.raw.length > 0, 'Base UI exposes --transform-origin')
      assert.equal(motion.origin, motion.expected, `${theme}: menu transform-origin follows the trigger`)
      assert.match(motion.property, /scale/, 'scale is a transitioned property')
      assert.doesNotMatch(motion.property, /transform/, 'no transform-vs-scale mismatch')
      const [menuBox, triggerBox] = [await menu.boundingBox(), await trigger.boundingBox()]
      assert.ok(menuBox && triggerBox)
      assert.ok(Math.abs(menuBox.x + menuBox.width - (triggerBox.x + triggerBox.width)) < 2, 'end-aligned to the trigger')
      assert.ok(menuBox.y >= triggerBox.y + triggerBox.height, 'opens below the trigger')
      await assertInViewport(menu, DESKTOP, `${theme}: dropdown`)
      await settleTransitions(page)
      await shot(page, tag(DESKTOP, theme, 'dropdown'))
      await page.keyboard.press('Escape')
      await menu.waitFor({ state: 'detached', timeout: 2_000 })
      assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-label')), 'Project actions')
      await closePage(context)
    }
  })

  it('settings extreme-stress table: no page overflow, Actions on screen, wrapped header, formatted numbers, no orphan separators', async t => {
    if (!requireEnv(t)) return
    for (const viewport of [DESKTOP, WIDE, PHONE]) {
      for (const theme of THEMES) {
        const label = tag(viewport, theme, 'settings')
        const { page, context } = await openPage({ viewport, theme })
        await gotoApp(page, '/settings', () => waitForSettingsTable(page))
        await assertNoOverflow(page, 'html, main, main > header', label)
        await assertButtonsUnclipped(page, 'main', label)
        const pageOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
        assert.ok(pageOverflow <= 0, `${label}: document overflow ${pageOverflow}`)

        const table = page.getByRole('table', { name: 'Configured model profiles' })
        const tableText = await table.innerText()
        assert.match(tableText, /1\.05M ctx/, 'formatK(1_048_576) = 1.05M')
        assert.match(tableText, /1M ctx/, 'formatK(999_999) = 1M')
        assert.doesNotMatch(tableText, /1000k/)
        assert.match(tableText, /\$1,234\.56 in/, 'formatRate groups thousands')
        assert.match(tableText, /\$0\.0035 cached/, 'sub-dime rate keeps 2 significant digits')
        await page.getByText('1 recovering · 3 of 3 enabled').waitFor({ state: 'attached' })

        if (viewport.width >= 1280) {
          const fit = await table.evaluate(el => {
            const card = el.parentElement!
            const actions = [...el.querySelectorAll('tbody tr td:last-child')].map(td => td.getBoundingClientRect())
            const cardRect = card.getBoundingClientRect()
            return { tableWidth: el.scrollWidth, cardWidth: card.clientWidth, actionsInside: actions.every(r => r.right <= cardRect.right + 0.5) }
          })
          assert.ok(fit.tableWidth <= fit.cardWidth, `${label}: table ${fit.tableWidth}px fits card ${fit.cardWidth}px`)
          assert.ok(fit.actionsInside, `${label}: Actions column fully visible`)
          await assertInViewport(page.getByRole('button', { name: 'Add model profile' }), viewport, `${label}: header CTA`)
        }

        const nameCell = table.getByTitle(LONG_PROFILE_NAME)
        assert.equal(await nameCell.count(), 1, 'long profile name exposes its full text via title')
        const lines = await nameCell.evaluate(el => Math.round(el.getBoundingClientRect().height / parseFloat(getComputedStyle(el).lineHeight)))
        assert.ok(lines <= 2, `${label}: profile name clamps to 2 lines (${lines})`)

        // Meta-line separators never start a line (each dot travels with its item).
        const orphans = await page.evaluate(() => {
          const out: string[] = []
          for (const wrapper of document.querySelectorAll<HTMLElement>('[data-slot=profile-meta]')) {
            const row = wrapper.firstElementChild as HTMLElement
            const rowLeft = row.getBoundingClientRect().left
            const items = [...row.children].map(el => el.getBoundingClientRect())
            items.forEach((r, i) => {
              const startsLine = !items.some((o, j) => j !== i && Math.abs(o.top - r.top) < 2 && o.left < r.left)
              if (startsLine && Math.abs(r.left - rowLeft) > 1) out.push(`item ${i} starts a line at ${r.left - rowLeft}px`)
              if (startsLine && r.left >= wrapper.getBoundingClientRect().left) out.push(`item ${i} shows a leading dot`)
            })
          }
          return out
        })
        assert.deepEqual(orphans, [], `${label}: orphan meta-line separators`)

        // Header badge truncates instead of clipping the CTA.
        const badge = page.locator('main > header [data-slot=badge]')
        const badgeFit = await badge.evaluate(el => {
          const header = el.closest('header')!.getBoundingClientRect()
          const r = el.getBoundingClientRect()
          return { inside: r.right <= header.right + 0.5, title: el.getAttribute('title') }
        })
        assert.ok(badgeFit.inside, `${label}: pool badge stays inside the header`)
        assert.equal(badgeFit.title, '1 recovering · 3 of 3 enabled')
        if (viewport === PHONE) {
          await assertInViewport(page.getByRole('button', { name: 'Add model profile' }), viewport, `${label}: compact CTA`)
        }
        await shot(page, label)
        if (viewport === PHONE) await shot(page, label + '-full', page.locator('main'))
        await closePage(context)
      }
    }
  })

  it('settings: an unsaved workspace draft and its focus survive loader revalidation; pristine fields follow the server', async t => {
    if (!requireEnv(t)) return
    const { page, context } = await openPage({ viewport: WIDE })
    await gotoApp(page, '/settings', () => waitForSettingsTable(page))
    const field = page.locator('input[name="workspaceName"]')
    await field.click()
    await field.fill('Unsaved Workspace Draft 123')

    // A second device renames the workspace while the draft is in progress.
    const other = await openPage({ viewport: WIDE })
    await gotoApp(other.page, '/settings', () => waitForSettingsTable(other.page))
    const otherField = other.page.locator('input[name="workspaceName"]')
    await otherField.fill('Renamed From Paired Device')
    await other.page.getByRole('button', { name: 'Save', exact: true }).click()
    await other.page.getByText('Workspace name updated.').waitFor({ state: 'visible', timeout: 10_000 })

    await page.evaluate(() => window.__TSR_ROUTER__!.invalidate())
    await page.waitForFunction(() => document.querySelector('[data-slot=dialog-content]') === null)
    await delay(150)
    assert.equal(await field.inputValue(), 'Unsaved Workspace Draft 123', 'draft preserved across revalidation')
    assert.ok(await field.evaluate(el => document.activeElement === el), 'focus retained')

    // A pristine field on the other device follows the next server rename.
    await field.fill(LONG_WORKSPACE)
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await page.getByText('Workspace name updated.').waitFor({ state: 'visible', timeout: 10_000 })
    await other.page.evaluate(() => window.__TSR_ROUTER__!.invalidate())
    await other.page.waitForFunction(name => (document.querySelector('input[name="workspaceName"]') as HTMLInputElement | null)?.value === name, LONG_WORKSPACE, { timeout: 5_000 })
    await closePage(other.context)
    await closePage(context)
  })

  it('ModelProfileSheet: long edit title truncates, no horizontal scroll on focus, CTA above the fold, footer feedback, animated disclosures', async t => {
    if (!requireEnv(t)) return
    for (const viewport of [DESKTOP, PHONE]) {
      for (const theme of THEMES) {
        const label = tag(viewport, theme, 'model-profile-sheet')
        const { page, context } = await openPage({ viewport, theme })
        await gotoApp(page, '/settings', () => waitForSettingsTable(page))
        const row = page.getByRole('row').filter({ has: page.getByTitle(LONG_PROFILE_NAME) })
        await row.getByRole('button', { name: 'Edit', exact: true }).click()
        const sheet = page.locator('[data-slot=dialog-content]')
        await sheet.waitFor({ state: 'visible' })
        await settleTransitions(page)

        const title = sheet.locator('[data-slot=dialog-title]')
        const titleFit = await title.evaluate(el => ({ truncated: el.scrollWidth > el.clientWidth, title: el.getAttribute('title'), overflow: getComputedStyle(el).textOverflow }))
        assert.ok(titleFit.truncated && titleFit.overflow === 'ellipsis', `${label}: edit title ends with an ellipsis`)
        assert.equal(titleFit.title, LONG_PROFILE_NAME)
        await assertNoOverflow(page, '[data-slot=dialog-content], [data-slot=dialog-content] form', label)

        const fields = sheet.locator('input:not([type=hidden]):not([type=checkbox]), select')
        const count = await fields.count()
        for (let i = 0; i < count; i += 1) {
          const field = fields.nth(i)
          if (!(await field.isVisible())) continue
          await field.focus()
          const scrollLeft = await sheet.evaluate(el => Math.max(el.scrollLeft, ...[...el.querySelectorAll('*:not(input):not(textarea):not(select)')].map(c => c.scrollLeft)))
          assert.equal(scrollLeft, 0, `${label}: focusing field ${i} never scrolls the sheet sideways`)
        }
        const close = sheet.getByRole('button', { name: 'Close modal' })
        const [closeBox, sheetBox] = [await close.boundingBox(), await sheet.boundingBox()]
        assert.ok(closeBox && sheetBox && closeBox.x + closeBox.width <= sheetBox.x + sheetBox.width + 0.5, `${label}: Close fully visible`)
        await assertNoOverlappingSiblings(page, '[data-slot=dialog-content]', label)
        await assertButtonsUnclipped(page, '[data-slot=dialog-content]', label)
        if (viewport === DESKTOP) await assertInViewport(sheet.getByRole('button', { name: 'Update profile' }), viewport, `${label}: primary CTA`)

        // Contrast inside the sheet (light + dark): subtle text and the unchecked-capable checkbox border.
        const sheetContrast = await sheet.evaluate(el => {
          const subtle = [...el.querySelectorAll('.text-fg-subtle')].filter(n => window.__qa.hasOwnText(n) && window.__qa.isRendered(n))
          const checkbox = el.querySelector('[data-slot=checkbox]')!
          return {
            subtleMin: Math.min(...subtle.map(n => window.__qa.textContrast(n))),
            checkboxBorder: window.__qa.contrastOn(checkbox.parentElement!, getComputedStyle(checkbox).getPropertyValue('--fg-3').trim() || '#000'),
          }
        })
        assert.ok(sheetContrast.subtleMin >= 4.5, `${label}: subtle text ${sheetContrast.subtleMin.toFixed(2)}`)
        assert.ok(sheetContrast.checkboxBorder >= 3, `${label}: checkbox border ${sheetContrast.checkboxBorder.toFixed(2)}`)
        await shot(page, label)

        if (viewport === DESKTOP && theme === 'light') {
          // A failed Test renders its alert in the sticky footer, inside the viewport, wrapped.
          // The stress fixture's $1,234.56 price is above the form's max; use a valid one so the submit is not blocked natively.
          await sheet.locator('input[name="inputCostPerMtok"]').fill('1.5')
          await sheet.locator('input[name="endpoint"]').fill('http://127.0.0.1:9/' + 'unreachable-gateway-path-'.repeat(8))
          await sheet.getByRole('button', { name: 'Test connection' }).click()
          const alert = sheet.getByRole('alert')
          await alert.waitFor({ state: 'visible', timeout: 20_000 })
          await assertInViewport(alert, viewport, `${label}: Save/Test error`)
          assert.ok(await alert.evaluate(el => el.scrollWidth <= el.clientWidth + 1), 'alert wraps long tokens')
          await shot(page, label + '-footer-error')
        }
        await page.keyboard.press('Escape')
        await sheet.waitFor({ state: 'detached', timeout: 5_000 })

        if (viewport === DESKTOP) {
          // Add flow: the "Customize" disclosure is a real animated panel, not display-toggled.
          await page.getByRole('button', { name: 'Add model profile' }).click()
          await sheet.waitFor({ state: 'visible' })
          await settleTransitions(page)
          const recommended = sheet.locator('[data-slot=badge]', { hasText: 'Recommended' })
          const recommendedRatio = await recommended.evaluate(el => window.__qa.textContrast(el.querySelector('[data-slot=badge-label]') ?? el))
          assert.ok(recommendedRatio >= 4.5, `${label}: Recommended badge AA (${recommendedRatio.toFixed(2)})`)
          await sheet.getByText('Paste one key; Kovo pre-fills endpoint, model, and limits.', { exact: false }).waitFor({ state: 'visible' })
          await sheet.getByRole('button', { name: /Customize profile name/ }).click()
          const panel = sheet.locator('[data-slot=disclosure-content]').first()
          await panel.waitFor({ state: 'visible' })
          assert.match(await panel.evaluate(el => getComputedStyle(el).transitionProperty), /height/)
          await settleTransitions(page)
          await assertNoOverflow(page, '[data-slot=dialog-content]', label + ' add')
          await assertInViewport(sheet.getByRole('button', { name: 'Save model' }), viewport, `${label}: Save model CTA`)
          await shot(page, label + '-add-customize')
          await page.keyboard.press('Escape')
          await sheet.waitFor({ state: 'detached', timeout: 5_000 })
        }
        await closePage(context)
      }
    }
  })

  it('Devices modal: real enter/exit transition, stable geometry while loading, AA warning, shared primary CTA, wrapped errors', async t => {
    if (!requireEnv(t)) return
    for (const viewport of [DESKTOP, PHONE]) {
      for (const theme of THEMES) {
        const label = tag(viewport, theme, 'devices')
        const { page, context } = await openPage({ viewport, theme })
        await gotoApp(page, '/settings', () => waitForSettingsTable(page))
        // Hold the status response so the loading frame can be measured.
        let release: () => void = () => {}
        const gate = new Promise<void>(r => { release = r })
        await page.route('**/_kovo/auth/status', async route => { await gate; await route.continue() })

        await page.getByRole('button', { name: /Local session/ }).click()
        const popup = page.locator('[data-slot=dialog-content]')
        const firstFrame = await page.waitForFunction(() => {
          const el = document.querySelector<HTMLElement>('[data-slot=dialog-content]')
          return el ? { opacity: Number(getComputedStyle(el).opacity), top: el.offsetTop, height: el.offsetHeight } : null
        }, undefined, { polling: 'raf' }).then(h => h.jsonValue())
        assert.ok(firstFrame, 'dialog mounted')
        assert.ok(firstFrame.opacity < 1, `${label}: first frame fades in (opacity ${firstFrame.opacity})`)
        await settleTransitions(page)
        const loading = await popup.evaluate(el => ({ top: (el as HTMLElement).offsetTop, height: (el as HTMLElement).offsetHeight }))
        release()
        await popup.getByText('Active', { exact: true }).waitFor({ state: 'visible', timeout: 10_000 })
        await popup.getByText('Loopback-only pairing URL').waitFor({ state: 'visible' })
        await settleTransitions(page)
        const loaded = await popup.evaluate(el => ({ top: (el as HTMLElement).offsetTop, height: (el as HTMLElement).offsetHeight }))
        assert.ok(Math.abs(loaded.top - loading.top) <= 1, `${label}: dialog top stable while status loads (${loading.top} → ${loaded.top})`)
        assert.ok(Math.abs(loaded.height - loading.height) <= 1, `${label}: dialog height reserved (${loading.height} → ${loaded.height})`)

        await assertNoOverflow(page, '[data-slot=dialog-content], [data-slot=dialog-content] *', label)
        await assertButtonsUnclipped(page, '[data-slot=dialog-content]', label)
        await assertNoOverlappingSiblings(page, '[data-slot=dialog-content]', label)
        const tones = await popup.evaluate(el => {
          const warn = [...el.querySelectorAll('strong')].find(n => /Loopback-only/.test(n.textContent ?? ''))!
          const cta = [...el.querySelectorAll('button')].find(n => /Generate pairing link/.test(n.textContent ?? ''))!
          const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
          const probe = document.createElement('span')
          probe.style.color = accent
          el.append(probe)
          const accentRgb = getComputedStyle(probe).color
          probe.remove()
          const subtle = [...el.querySelectorAll('.text-fg-subtle')].filter(n => window.__qa.hasOwnText(n) && window.__qa.isRendered(n))
          return {
            warn: window.__qa.textContrast(warn),
            ctaBg: getComputedStyle(cta).backgroundColor,
            accentRgb,
            ctaLabel: window.__qa.textContrast(cta),
            subtleMin: Math.min(...subtle.map(n => window.__qa.textContrast(n))),
          }
        })
        assert.ok(tones.warn >= 4.5, `${label}: loopback warning title ${tones.warn.toFixed(2)}`)
        assert.equal(tones.ctaBg, tones.accentRgb, `${label}: pairing CTA uses the shared accent fill`)
        assert.ok(tones.ctaLabel >= 4.5, `${label}: CTA label contrast ${tones.ctaLabel.toFixed(2)}`)
        assert.ok(tones.subtleMin >= 4.5, `${label}: subtle text ${tones.subtleMin.toFixed(2)}`)
        if (viewport === DESKTOP) await assertInViewport(popup.getByRole('button', { name: 'Generate pairing link' }), viewport, `${label}: pairing CTA`)
        await shot(page, label)

        // Long server error tokens wrap inside the alert.
        await page.route('**/_kovo/auth/pairing-link', route => route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'pairing-link-mint-failed:' + 'z'.repeat(420) }),
        }))
        await popup.getByRole('button', { name: 'Generate pairing link' }).click()
        const alert = popup.getByRole('alert')
        await alert.waitFor({ state: 'visible' })
        assert.ok(await alert.evaluate(el => el.scrollWidth <= el.clientWidth + 1), `${label}: alert wraps long tokens`)
        await assertNoOverflow(page, '[data-slot=dialog-content], [data-slot=dialog-content] *', label + ' error')
        await shot(page, label + '-error')

        // Close keeps the popup mounted through its ending style, then unmounts and resets.
        await watchExit(page)
        await popup.getByRole('button', { name: 'Close', exact: true }).click()
        await popup.waitFor({ state: 'detached', timeout: 5_000 })
        const exit = await readExit(page)
        assert.ok(exit.sawEnding, `${label}: exit transition runs while still mounted`)
        assert.ok(exit.removedAfter > 60, `${label}: popup stays mounted through the exit (${exit.removedAfter.toFixed(0)}ms)`)
        await page.unroute('**/_kovo/auth/pairing-link')
        await page.getByRole('button', { name: /Local session/ }).click()
        await popup.getByText('Active', { exact: true }).waitFor({ state: 'visible', timeout: 10_000 })
        assert.equal(await popup.getByRole('alert').count(), 0, 'stale error cleared on reopen')
        await page.keyboard.press('Escape')
        await popup.waitFor({ state: 'detached', timeout: 5_000 })
        await closePage(context)
      }
    }
  })

  it('touch (coarse pointer, 390×844): 16px fields, 44px hit areas on buttons/closes/checkboxes, 40px rail items', async t => {
    if (!requireEnv(t)) return
    const { page, context } = await openPage({ viewport: PHONE, touch: true })
    await gotoApp(page, '/settings', () => waitForSettingsTable(page))
    assert.ok(await page.evaluate(() => matchMedia('(pointer: coarse)').matches), 'touch context reports a coarse pointer')
    const touchOverflow = await page.evaluate(() => {
      const width = document.documentElement.clientWidth
      const offenders = [...document.querySelectorAll<HTMLElement>('body *')]
        .filter(el => window.__qa.isRendered(el) && !el.closest('[class*=overflow-x-auto], [class*=overflow-auto], [class*=overflow-hidden]') && el.getBoundingClientRect().right > width + 1)
        .slice(0, 5)
        .map(el => `${el.tagName}.${String(el.className).slice(0, 60)}`)
      return { overflow: document.documentElement.scrollWidth - width, offenders }
    })
    assert.ok(touchOverflow.overflow <= 0, `touch 390px: no horizontal overflow (${touchOverflow.overflow}px; ${touchOverflow.offenders.join(' | ')})`)
    const railHeights = await page.evaluate(() => [...document.querySelectorAll('nav[aria-label=Workspace] a')].map(a => a.getBoundingClientRect().height))
    assert.ok(railHeights.every(h => h >= 40), `rail items ${railHeights.join(',')}`)

    const hitBoxes = await page.evaluate(() => {
      const results: string[] = []
      const targets = [...document.querySelectorAll<HTMLElement>('main [data-slot=button]')].filter(el => {
        if (!window.__qa.isRendered(el)) return false
        // Only measure buttons that are actually reachable (not scrolled away inside a card).
        const r = el.getBoundingClientRect()
        const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2)
        return Boolean(hit && el.contains(hit))
      })
      for (const el of targets) {
        const r = el.getBoundingClientRect()
        const cx = r.left + r.width / 2
        const cy = r.top + r.height / 2
        for (const [dx, dy] of [[-21.5, 0], [21.5, 0], [0, -21.5], [0, 21.5]] as const) {
          const x = cx + dx
          const y = cy + dy
          if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) continue
          const hit = document.elementFromPoint(x, y)
          // Neighbouring controls may own the shared edge; only a miss to non-control content fails.
          if (!hit || (!el.contains(hit) && !hit.closest('[data-slot=button], button, a, input'))) {
            results.push(`${(el.textContent ?? '').trim().slice(0, 16)} misses at (${dx},${dy})`)
          }
        }
      }
      return { count: targets.length, misses: results }
    })
    assert.ok(hitBoxes.count >= 1, `buttons measured (${hitBoxes.count})`)
    assert.deepEqual(hitBoxes.misses, [], 'every Button hit box reaches 44×44')

    const row = page.getByRole('row').filter({ has: page.getByTitle(LONG_PROFILE_NAME) })
    await row.getByRole('button', { name: 'Edit', exact: true }).click()
    const sheet = page.locator('[data-slot=dialog-content]')
    await sheet.waitFor({ state: 'visible' })
    await settleTransitions(page)
    const touch = await sheet.evaluate(el => {
      const close = el.querySelector<HTMLElement>('[aria-label="Close modal"]')!
      const r = close.getBoundingClientRect()
      const after = getComputedStyle(close, '::after')
      const checkbox = el.querySelector<HTMLElement>('[data-slot=checkbox]')!
      const cb = checkbox.getBoundingClientRect()
      const cbAfter = getComputedStyle(checkbox, '::after')
      const fonts = [...el.querySelectorAll<HTMLElement>('input:not([type=hidden]):not([type=checkbox]), select')].map(n => getComputedStyle(n).fontSize)
      return {
        closeHit: Math.min(r.width - 2 * parseFloat(after.left), r.height - 2 * parseFloat(after.top)),
        checkboxHit: Math.min(cb.width - 2 * parseFloat(cbAfter.left), cb.height - 2 * parseFloat(cbAfter.top)),
        fonts,
      }
    })
    assert.ok(touch.closeHit >= 44, `sheet Close hit box ${touch.closeHit}px`)
    assert.ok(touch.checkboxHit >= 44, `checkbox hit box ${touch.checkboxHit}px`)
    assert.ok(touch.fonts.length > 0 && touch.fonts.every(f => f === '16px'), `dialog fields are 16px (${touch.fonts.join(',')})`)
    await page.keyboard.press('Escape')
    await sheet.waitFor({ state: 'detached', timeout: 5_000 })

    await page.locator('body').click({ position: { x: 300, y: 800 } }).catch(() => {})
    await page.keyboard.press('?')
    const help = page.locator('[data-slot=dialog-content][aria-label="Keyboard shortcuts"]')
    await help.waitFor({ state: 'visible' })
    await settleTransitions(page)
    const helpClose = await help.getByRole('button', { name: 'Close shortcuts' }).evaluate(el => {
      const r = el.getBoundingClientRect()
      const after = getComputedStyle(el, '::after')
      return Math.min(r.width - 2 * parseFloat(after.left), r.height - 2 * parseFloat(after.top))
    })
    assert.ok(helpClose >= 44, `help sheet Close hit box ${helpClose}px`)
    await closePage(context)

    // Fine pointers keep desktop density.
    const desk = await openPage({ viewport: WIDE })
    await gotoApp(desk.page, '/settings', () => waitForSettingsTable(desk.page))
    const density = await desk.page.evaluate(() => ({
      field: getComputedStyle(document.querySelector('input[name="workspaceName"]')!).fontSize,
      rail: document.querySelector('nav[aria-label=Workspace] a')!.getBoundingClientRect().height,
      button: document.querySelector('main header [data-slot=button]')!.getBoundingClientRect().height,
    }))
    assert.equal(density.field, '12.5px')
    assert.equal(density.rail, 30)
    assert.equal(density.button, 26)
    await closePage(desk.context)
  })

  it('shell: styled in-shell 404 (HTTP 404) and friendly recoverable route errors with collapsed technical details', async t => {
    if (!requireEnv(t)) return
    for (const theme of THEMES) {
      const { page, context } = await openPage({ viewport: DESKTOP, theme })
      const res = await page.goto(`${kovo!.origin}/does-not-exist`, { waitUntil: 'domcontentloaded' })
      assert.equal(res?.status(), 404, 'unknown route answers HTTP 404')
      await page.getByRole('heading', { name: 'Page not found' }).waitFor({ state: 'visible', timeout: 15_000 })
      await page.getByRole('navigation', { name: 'Workspace' }).waitFor({ state: 'visible' })
      await assertInViewport(page.getByRole('link', { name: 'Go to Projects' }), DESKTOP, `${theme}: 404 CTA`)
      await page.waitForFunction(() => document.title === 'Not found · Kovo')
      const centred = await page.getByRole('heading', { name: 'Page not found' }).evaluate(el => {
        const main = el.closest('main')!.getBoundingClientRect()
        const r = el.getBoundingClientRect()
        return Math.abs((r.left + r.right) / 2 - (main.left + main.right) / 2)
      })
      assert.ok(centred < 2, 'empty state centred in the content column')
      await shot(page, tag(DESKTOP, theme, 'not-found'))

      await gotoApp(page, '/projects/not-a-valid-project-id', () => page.getByRole('heading', { name: 'Kovo couldn’t open this view' }).waitFor({ state: 'visible', timeout: 15_000 }))
      await page.getByRole('navigation', { name: 'Workspace' }).waitFor({ state: 'visible' })
      const errorView = page.getByRole('alert').filter({ hasText: 'Kovo couldn’t open this view' })
      const visibleCopy = await errorView.evaluate(el => {
        const clone = el.cloneNode(true) as HTMLElement
        clone.querySelector('details')?.remove()
        return { text: clone.textContent ?? '', detailsOpen: el.querySelector('details')?.open ?? false }
      })
      assert.equal(visibleCopy.detailsOpen, false, 'technical details start collapsed')
      assert.doesNotMatch(visibleCopy.text, /invalid_|"code"|Zod|Cannot read properties|\[\s*\{/, 'no raw error text outside details')
      assert.ok(await page.locator('details pre').evaluate(el => !(el as HTMLElement).checkVisibility()), 'raw message hidden until expanded')
      await assertInViewport(page.getByRole('button', { name: 'Try again' }), DESKTOP, `${theme}: Try again`)
      const reloads: string[] = []
      page.on('request', req => { if (req.url().includes('/_serverFn/')) reloads.push(req.url()) })
      await page.getByRole('button', { name: 'Try again' }).click()
      await page.getByRole('heading', { name: 'Kovo couldn’t open this view' }).waitFor({ state: 'visible' })
      await delay(300)
      assert.ok(reloads.length > 0, 'Try again re-runs the loaders')
      await page.locator('details summary').click()
      await shot(page, tag(DESKTOP, theme, 'route-error'))
      await closePage(context)
    }
  })

  it('shell: theme switch flips in one frame, rail meta line protects counts, Devices row nudge animates translate', async t => {
    if (!requireEnv(t)) return
    const { page, context } = await openPage({ viewport: WIDE })
    await gotoApp(page, '/settings', () => waitForSettingsTable(page))
    await page.locator('body').click({ position: { x: 900, y: 860 } })
    const flip = await page.evaluate(async () => {
      const root = document.documentElement
      const before = root.dataset.theme
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'T', shiftKey: true, bubbles: true }))
      const sameFrame = root.classList.contains('no-transitions')
      await new Promise(r => requestAnimationFrame(r))
      const running = document.getAnimations().filter(a => a instanceof CSSTransition).length
      await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))
      await new Promise(r => requestAnimationFrame(r))
      return { before, after: root.dataset.theme, sameFrame, running, cleaned: !root.classList.contains('no-transitions') }
    })
    assert.notEqual(flip.after, flip.before, 'Shift+T toggles the theme')
    assert.ok(flip.sameFrame, 'transitions suspended during the flip')
    assert.equal(flip.running, 0, 'no colour transitions ripple on the frame after the flip')
    assert.ok(flip.cleaned, 'transitions restored two frames later')

    const nudge = await page.evaluate(() => {
      const chevron = document.querySelector('aside button[aria-haspopup=dialog] > svg:last-child')
      return chevron ? getComputedStyle(chevron).transitionProperty : ''
    })
    assert.match(nudge, /translate/, 'Local session chevron transitions `translate`')
    const fade = await page.evaluate(() => getComputedStyle(document.querySelector('aside nav')!.parentElement!).maskImage)
    assert.match(fade, /linear-gradient/, 'recent-runs scroller fades at the bottom edge')
    await closePage(context)
    assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
  })
})
