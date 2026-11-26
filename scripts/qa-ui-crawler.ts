import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import { HARDENED_NODE_FLAGS } from '../tests/app.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { projectReposDir } from '../src/server/github-repo-sync.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

// ============================================================================
// Types & Constants (pure, exported for unit tests)
// ============================================================================

export type CrawlScope = 'all' | 'project' | 'run' | 'modals' | 'settings'
export type ThemeMode = 'light' | 'dark'
export type ViolationSeverity = 'error' | 'warn'

export interface ViewportSpec {
  width: number
  height: number
  label: string
}

export interface CrawlerCliOptions {
  only: CrawlScope[]
  viewports: ViewportSpec[]
  themes: ThemeMode[]
  outDir: string
  failOnWarn: boolean
  screenshots: boolean
  help: boolean
}

export interface RectBox {
  left: number
  top: number
  right: number
  bottom: number
  width: number
  height: number
}

export interface LandmarkSnapshot {
  kind: 'tablist' | 'header' | 'dialog' | 'button'
  label: string
  selector: string
  rect: RectBox
  visible: boolean
  disabled?: boolean
  isPrimaryCta?: boolean
  scrollWidth: number
  clientWidth: number
  scrollHeight: number
  clientHeight: number
  overflowX: string
  overflowY: string
  textOverflow?: string
  insideDialog?: boolean
}

export interface CardSnapshot {
  label: string
  selector: string
  rect: RectBox
  scrollWidth: number
  clientWidth: number
  scrollHeight: number
  clientHeight: number
  overflowX: string
  overflowY: string
  textOverflow?: string
}

export interface SiblingControlItem {
  label: string
  tag: string
  rect: RectBox
}

export interface SiblingControlGroup {
  containerLabel: string
  items: SiblingControlItem[]
}

export interface TextNodeSample {
  text: string
  tag: string
  isCodeElement?: boolean
}

export interface BrokenCopyHit {
  token: string
  context: string
  tag: string
}

export interface OverflowContainerSample {
  label: string
  selector: string
  scrollWidth: number
  clientWidth: number
  overflowX: string
}

export interface DomGeometrySnapshot {
  viewport: { width: number; height: number }
  scrollTop: number
  docScrollWidth: number
  docClientWidth: number
  overflowContainers: OverflowContainerSample[]
  landmarks: LandmarkSnapshot[]
  cards: CardSnapshot[]
  siblingGroups: SiblingControlGroup[]
  textNodes: TextNodeSample[]
}

export interface FailedRequestRecord {
  url: string
  method: string
  status?: number
  errorText?: string
  resourceType?: string
}

export interface RuntimeEventSample {
  consoleErrors: string[]
  pageErrors: string[]
  failedRequests: FailedRequestRecord[]
}

export interface CheckContext {
  stateId: string
  route: string
  viewport: string
  theme: ThemeMode
  scrollTop: number
}

export interface QaViolation {
  severity: ViolationSeverity
  rule:
    | 'collapsed-control'
    | 'horizontal-overflow'
    | 'clipped-text'
    | 'sibling-overlap'
    | 'cta-outside-viewport'
    | 'dialog-outside-viewport'
    | 'broken-copy'
    | 'console-error'
    | 'page-error'
    | 'http-5xx'
    | 'failed-fetch'
    | 'input-clobbered'
    | 'smoke-navigation'
  message: string
  stateId: string
  route: string
  viewport: string
  theme: ThemeMode
  scrollTop: number
  detail?: Record<string, unknown>
}

export interface StateAuditResult {
  stateId: string
  route: string
  viewport: string
  theme: ThemeMode
  scrollPositionsChecked: number[]
  violations: QaViolation[]
  screenshotPaths: string[]
  durationMs: number
}

export interface InputStabilityResult {
  stateId: string
  inputLabel: string
  viewport: string
  theme: ThemeMode
  typedValue: string
  observedAfterMs: number
  observedValue: string
  stable: boolean
}

export interface CrawlerReport {
  generatedAt: string
  options: {
    only: CrawlScope[]
    viewports: string[]
    themes: ThemeMode[]
    outDir: string
    failOnWarn: boolean
    screenshots: boolean
  }
  fixture: {
    projectId: string
    subdomainsTotal: number
    subdomainsApproved: number
    subdomainsUnapproved: number
    reposCount: number
    personasCount: number
    runs: Record<string, string>
  }
  summary: {
    statesVisited: number
    checksExecuted: number
    errorCount: number
    warnCount: number
    inputChecksPassed: number
    inputChecksFailed: number
    passed: boolean
    byRule: Record<string, number>
  }
  inputStability: InputStabilityResult[]
  violations: QaViolation[]
  states: StateAuditResult[]
}

const VALID_SCOPES = new Set<CrawlScope>(['all', 'project', 'run', 'modals', 'settings'])
const VALID_THEMES = new Set<ThemeMode>(['light', 'dark'])

export const MIN_CONTROL_HEIGHT_PX = 20
export const MIN_CONTROL_HEIGHT_TOLERANCE_PX = 0.5
export const HORIZONTAL_OVERFLOW_TOLERANCE_PX = 2
export const VERTICAL_CLIP_TOLERANCE_PX = 3
export const SIBLING_OVERLAP_TOLERANCE_PX = 2
export const VIEWPORT_BOUNDS_TOLERANCE_PX = 2

// ============================================================================
// Pure CLI Parser
// ============================================================================

export function parseViewportToken(token: string): ViewportSpec {
  const m = /^(\d{3,4})x(\d{3,4})$/i.exec(token.trim())
  if (!m) {
    throw new Error(`Invalid viewport "${token}". Expected WxH (e.g. 1280x720, 1440x900, 1024x640).`)
  }
  const width = Number(m[1])
  const height = Number(m[2])
  if (!Number.isFinite(width) || !Number.isFinite(height) || width < 320 || height < 320) {
    throw new Error(`Viewport "${token}" is too small (minimum 320x320).`)
  }
  return { width, height, label: `${width}x${height}` }
}

export function parseCliArgs(
  argv: readonly string[],
  env: Record<string, string | undefined> = process.env,
): CrawlerCliOptions {
  let onlyRaw = 'all'
  let viewportsRaw = '1280x720,1440x900'
  let themesRaw = 'light,dark'
  let outDir = join(env.TMPDIR || tmpdir(), 'kovo-qa-ui')
  let failOnWarn = false
  let screenshots = false
  let help = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      help = true
      continue
    }
    if (arg === '--fail-on-warn') {
      failOnWarn = true
      continue
    }
    if (arg === '--screenshots') {
      screenshots = true
      continue
    }
    if (arg.startsWith('--only=')) {
      onlyRaw = arg.slice('--only='.length)
      continue
    }
    if (arg === '--only') {
      const next = argv[i + 1]
      if (!next) throw new Error('--only requires a value (all|project|run|modals|settings).')
      onlyRaw = next
      i += 1
      continue
    }
    if (arg.startsWith('--viewports=')) {
      viewportsRaw = arg.slice('--viewports='.length)
      continue
    }
    if (arg === '--viewports') {
      const next = argv[i + 1]
      if (!next) throw new Error('--viewports requires a comma-separated list (e.g. 1280x720,1440x900).')
      viewportsRaw = next
      i += 1
      continue
    }
    if (arg.startsWith('--themes=')) {
      themesRaw = arg.slice('--themes='.length)
      continue
    }
    if (arg === '--themes') {
      const next = argv[i + 1]
      if (!next) throw new Error('--themes requires a comma-separated list (light,dark).')
      themesRaw = next
      i += 1
      continue
    }
    if (arg.startsWith('--out-dir=')) {
      outDir = arg.slice('--out-dir='.length)
      continue
    }
    if (arg === '--out-dir') {
      const next = argv[i + 1]
      if (!next) throw new Error('--out-dir requires a directory path.')
      outDir = next
      i += 1
      continue
    }
    throw new Error(`Unknown CLI argument: ${arg}`)
  }

  const onlyTokens = onlyRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
  if (onlyTokens.length === 0) {
    throw new Error('--only cannot be empty.')
  }
  const only: CrawlScope[] = []
  for (const tok of onlyTokens) {
    if (!VALID_SCOPES.has(tok as CrawlScope)) {
      throw new Error(`Invalid --only scope "${tok}". Valid values: all, project, run, modals, settings.`)
    }
    if (!only.includes(tok as CrawlScope)) only.push(tok as CrawlScope)
  }

  const viewportTokens = viewportsRaw.split(',').map(s => s.trim()).filter(Boolean)
  if (viewportTokens.length === 0) {
    throw new Error('--viewports cannot be empty.')
  }
  const viewports = viewportTokens.map(parseViewportToken)

  const themeTokens = themesRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
  if (themeTokens.length === 0) {
    throw new Error('--themes cannot be empty.')
  }
  const themes: ThemeMode[] = []
  for (const tok of themeTokens) {
    if (!VALID_THEMES.has(tok as ThemeMode)) {
      throw new Error(`Invalid --themes entry "${tok}". Valid values: light, dark.`)
    }
    if (!themes.includes(tok as ThemeMode)) themes.push(tok as ThemeMode)
  }

  if (!outDir.trim()) {
    throw new Error('--out-dir cannot be empty.')
  }

  return {
    only,
    viewports,
    themes,
    outDir: resolve(outDir),
    failOnWarn,
    screenshots,
    help,
  }
}

export function scopeSelected(only: readonly CrawlScope[], target: Exclude<CrawlScope, 'all'>): boolean {
  return only.includes('all') || only.includes(target)
}

// ============================================================================
// Pure Anomaly & Geometry Classifiers (unit-tested in tests/qa-ui-crawler-unit.test.ts)
// ============================================================================

const BROKEN_COPY_ALL_RE = /(\[object Object\]|\b(?:undefined|NaN)\b)/
const BROKEN_COPY_NON_CODE_RE = /(\[object Object\]|\b(?:null|undefined|NaN)\b)/

export function detectBrokenCopyTokens(textNodes: readonly TextNodeSample[]): BrokenCopyHit[] {
  const hits: BrokenCopyHit[] = []
  const seen = new Set<string>()
  for (const node of textNodes) {
    const trimmed = node.text.trim()
    if (!trimmed) continue
    const re = node.isCodeElement ? BROKEN_COPY_ALL_RE : BROKEN_COPY_NON_CODE_RE
    const match = re.exec(trimmed)
    if (!match) continue
    const token = match[1]!
    const context = trimmed.length > 96 ? `${trimmed.slice(0, 93)}...` : trimmed
    const dedupeKey = `${node.tag}:${token}:${context}`
    if (seen.has(dedupeKey)) continue
    seen.add(dedupeKey)
    hits.push({ token, context, tag: node.tag })
  }
  return hits
}

export function rectsOverlap(a: RectBox, b: RectBox, tolerancePx = SIBLING_OVERLAP_TOLERANCE_PX): {
  overlaps: boolean
  overlapX: number
  overlapY: number
} {
  const overlapX = Math.min(a.right, b.right) - Math.max(a.left, b.left)
  const overlapY = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top)
  return {
    overlaps: overlapX > tolerancePx && overlapY > tolerancePx,
    overlapX: Math.max(0, Math.round(overlapX * 10) / 10),
    overlapY: Math.max(0, Math.round(overlapY * 10) / 10),
  }
}

export function isScrollableOverflow(overflowVal: string | undefined): boolean {
  return overflowVal === 'auto' || overflowVal === 'scroll' || overflowVal === 'overlay'
}

export function classifyGeometrySnapshot(
  snapshot: DomGeometrySnapshot,
  ctx: CheckContext,
): QaViolation[] {
  const violations: QaViolation[] = []
  const push = (
    severity: ViolationSeverity,
    rule: QaViolation['rule'],
    message: string,
    detail?: Record<string, unknown>,
  ) => {
    violations.push({
      severity,
      rule,
      message,
      stateId: ctx.stateId,
      route: ctx.route,
      viewport: ctx.viewport,
      theme: ctx.theme,
      scrollTop: ctx.scrollTop,
      ...(detail ? { detail } : {}),
    })
  }

  // 1. Document-level horizontal overflow
  if (snapshot.docScrollWidth > snapshot.docClientWidth + HORIZONTAL_OVERFLOW_TOLERANCE_PX) {
    push(
      'error',
      'horizontal-overflow',
      `Document horizontal overflow: scrollWidth=${snapshot.docScrollWidth}px > clientWidth=${snapshot.docClientWidth}px`,
      { scrollWidth: snapshot.docScrollWidth, clientWidth: snapshot.docClientWidth },
    )
  }

  // 2. Non-scrollable container horizontal overflow (dialogs, dialog bodies, main regions)
  for (const container of snapshot.overflowContainers) {
    if (isScrollableOverflow(container.overflowX)) continue
    if (container.scrollWidth > container.clientWidth + HORIZONTAL_OVERFLOW_TOLERANCE_PX) {
      push(
        'error',
        'horizontal-overflow',
        `Container "${container.label}" overflows horizontally (${container.scrollWidth}px > ${container.clientWidth}px)`,
        {
          selector: container.selector,
          scrollWidth: container.scrollWidth,
          clientWidth: container.clientWidth,
        },
      )
    }
  }

  // 3. Landmark & button geometry: height >= 20px, zero text clipping, dialog/CTA viewport bounds
  const minHeightCutoff = MIN_CONTROL_HEIGHT_PX - MIN_CONTROL_HEIGHT_TOLERANCE_PX
  for (const lm of snapshot.landmarks) {
    if (!lm.visible) continue
    if (lm.rect.height < minHeightCutoff) {
      push(
        'error',
        'collapsed-control',
        `Visible ${lm.kind} "${lm.label}" collapsed to height=${Math.round(lm.rect.height * 10) / 10}px (< ${MIN_CONTROL_HEIGHT_PX}px)`,
        { kind: lm.kind, selector: lm.selector, height: lm.rect.height, width: lm.rect.width },
      )
    }

    if (lm.kind === 'dialog') {
      if (
        lm.rect.left < -VIEWPORT_BOUNDS_TOLERANCE_PX
        || lm.rect.top < -VIEWPORT_BOUNDS_TOLERANCE_PX
        || lm.rect.right > snapshot.viewport.width + VIEWPORT_BOUNDS_TOLERANCE_PX
        || lm.rect.bottom > snapshot.viewport.height + VIEWPORT_BOUNDS_TOLERANCE_PX
      ) {
        push(
          'error',
          'dialog-outside-viewport',
          `Dialog "${lm.label}" extends outside ${snapshot.viewport.width}x${snapshot.viewport.height} viewport`,
          { rect: lm.rect, viewport: snapshot.viewport },
        )
      }
      if (lm.scrollWidth > lm.clientWidth + HORIZONTAL_OVERFLOW_TOLERANCE_PX) {
        push(
          'error',
          'horizontal-overflow',
          `Dialog "${lm.label}" overflows horizontally (${lm.scrollWidth}px > ${lm.clientWidth}px)`,
          { scrollWidth: lm.scrollWidth, clientWidth: lm.clientWidth },
        )
      }
    }

    if (lm.kind === 'button') {
      if (
        !isScrollableOverflow(lm.overflowY)
        && lm.clientHeight > 0
        && lm.scrollHeight > lm.clientHeight + VERTICAL_CLIP_TOLERANCE_PX
      ) {
        push(
          'error',
          'clipped-text',
          `Button "${lm.label}" clips text vertically (scrollHeight=${lm.scrollHeight}px > clientHeight=${lm.clientHeight}px)`,
          { selector: lm.selector, scrollHeight: lm.scrollHeight, clientHeight: lm.clientHeight },
        )
      }

      const mustBeInViewport = Boolean(lm.isPrimaryCta) && (ctx.scrollTop === 0 || Boolean(lm.insideDialog))
      if (mustBeInViewport) {
        const outOfBounds =
          lm.rect.left < -VIEWPORT_BOUNDS_TOLERANCE_PX
          || lm.rect.top < -VIEWPORT_BOUNDS_TOLERANCE_PX
          || lm.rect.right > snapshot.viewport.width + VIEWPORT_BOUNDS_TOLERANCE_PX
          || lm.rect.bottom > snapshot.viewport.height + VIEWPORT_BOUNDS_TOLERANCE_PX
        if (outOfBounds) {
          push(
            'error',
            'cta-outside-viewport',
            `Primary CTA "${lm.label}" is outside viewport (${snapshot.viewport.width}x${snapshot.viewport.height})`,
            { rect: lm.rect, viewport: snapshot.viewport, insideDialog: Boolean(lm.insideDialog) },
          )
        }
      }
    }
  }

  // 4. Card text clipping & overflow
  for (const card of snapshot.cards) {
    if (
      !isScrollableOverflow(card.overflowY)
      && card.clientHeight > 0
      && card.scrollHeight > card.clientHeight + VERTICAL_CLIP_TOLERANCE_PX
    ) {
      push(
        'error',
        'clipped-text',
        `Card "${card.label}" clips content vertically (scrollHeight=${card.scrollHeight}px > clientHeight=${card.clientHeight}px)`,
        { selector: card.selector, scrollHeight: card.scrollHeight, clientHeight: card.clientHeight },
      )
    }
    if (
      !isScrollableOverflow(card.overflowX)
      && card.textOverflow !== 'ellipsis'
      && card.clientWidth > 0
      && card.scrollWidth > card.clientWidth + HORIZONTAL_OVERFLOW_TOLERANCE_PX
    ) {
      push(
        'error',
        'horizontal-overflow',
        `Card "${card.label}" overflows horizontally (scrollWidth=${card.scrollWidth}px > clientWidth=${card.clientWidth}px)`,
        { selector: card.selector, scrollWidth: card.scrollWidth, clientWidth: card.clientWidth },
      )
    }
  }

  // 5. Overlapping sibling interactive controls
  for (const group of snapshot.siblingGroups) {
    const items = group.items
    for (let i = 0; i < items.length; i += 1) {
      const a = items[i]!
      if (a.rect.width <= 0 || a.rect.height <= 0) continue
      for (let j = i + 1; j < items.length; j += 1) {
        const b = items[j]!
        if (b.rect.width <= 0 || b.rect.height <= 0) continue
        const ov = rectsOverlap(a.rect, b.rect)
        if (ov.overlaps) {
          push(
            'error',
            'sibling-overlap',
            `Sibling controls "${a.label}" (${a.tag}) and "${b.label}" (${b.tag}) overlap by ${ov.overlapX}x${ov.overlapY}px in ${group.containerLabel}`,
            {
              container: group.containerLabel,
              first: a.label,
              second: b.label,
              overlapX: ov.overlapX,
              overlapY: ov.overlapY,
            },
          )
        }
      }
    }
  }

  // 6. Broken copy / raw null/undefined/NaN/[object Object] text nodes
  for (const hit of detectBrokenCopyTokens(snapshot.textNodes)) {
    push(
      'error',
      'broken-copy',
      `Broken copy token "${hit.token}" rendered in <${hit.tag}>: "${hit.context}"`,
      { token: hit.token, tag: hit.tag, context: hit.context },
    )
  }

  return violations
}

export function isBenignAbortedStream(req: FailedRequestRecord): boolean {
  const err = (req.errorText ?? '').toLowerCase()
  if (!err.includes('err_aborted') && !err.includes('aborted') && !err.includes('cancelled')) {
    return false
  }
  return /\/api\/runs\/[^/]+\/events/.test(req.url) || req.resourceType === 'eventsource'
}

export function classifyRuntimeEvents(
  events: RuntimeEventSample,
  ctx: CheckContext,
): QaViolation[] {
  const violations: QaViolation[] = []
  for (const msg of events.consoleErrors) {
    violations.push({
      severity: 'error',
      rule: 'console-error',
      message: `Browser console.error: ${msg.slice(0, 240)}`,
      stateId: ctx.stateId,
      route: ctx.route,
      viewport: ctx.viewport,
      theme: ctx.theme,
      scrollTop: ctx.scrollTop,
    })
  }
  for (const err of events.pageErrors) {
    violations.push({
      severity: 'error',
      rule: 'page-error',
      message: `Uncaught pageerror: ${err.slice(0, 240)}`,
      stateId: ctx.stateId,
      route: ctx.route,
      viewport: ctx.viewport,
      theme: ctx.theme,
      scrollTop: ctx.scrollTop,
    })
  }
  for (const req of events.failedRequests) {
    if (isBenignAbortedStream(req)) continue
    if (typeof req.status === 'number' && req.status >= 500) {
      violations.push({
        severity: 'error',
        rule: 'http-5xx',
        message: `HTTP ${req.status} on ${req.method} ${req.url}`,
        stateId: ctx.stateId,
        route: ctx.route,
        viewport: ctx.viewport,
        theme: ctx.theme,
        scrollTop: ctx.scrollTop,
        detail: { status: req.status, method: req.method, url: req.url },
      })
    } else if (req.errorText) {
      violations.push({
        severity: 'error',
        rule: 'failed-fetch',
        message: `Failed ${req.resourceType ?? 'request'} (${req.errorText}) on ${req.method} ${req.url}`,
        stateId: ctx.stateId,
        route: ctx.route,
        viewport: ctx.viewport,
        theme: ctx.theme,
        scrollTop: ctx.scrollTop,
        detail: { errorText: req.errorText, method: req.method, url: req.url },
      })
    }
  }
  return violations
}

export function classifyInputStability(
  typedValue: string,
  observedValue: string,
  inputLabel: string,
  ctx: CheckContext,
): QaViolation[] {
  if (observedValue === typedValue) return []
  return [{
    severity: 'error',
    rule: 'input-clobbered',
    message: `Input "${inputLabel}" was clobbered during background ticks (expected "${typedValue}", got "${observedValue}")`,
    stateId: ctx.stateId,
    route: ctx.route,
    viewport: ctx.viewport,
    theme: ctx.theme,
    scrollTop: ctx.scrollTop,
    detail: { inputLabel, expected: typedValue, observed: observedValue },
  }]
}

export function shouldFailRun(violations: readonly QaViolation[], failOnWarn: boolean): boolean {
  return violations.some(v => v.severity === 'error' || (failOnWarn && v.severity === 'warn'))
}

// ============================================================================
// Stress-Seeded Realistic SQLite Fixture (using Store)
// ============================================================================

export interface SeededFixtureIds {
  projectId: string
  subdomainsTotal: number
  subdomainsApproved: number
  subdomainsUnapproved: number
  reposCount: number
  personasCount: number
  runs: {
    scopeReview: string
    threatModel: string
    investigation: string
    complete: string
    freshRunning: string
  }
}

export function seedStressFixture(dataDir: string): SeededFixtureIds {
  const storage = new Store(dataDir)
  try {
    const seedOrigin = 'https://app.acme-saas.example'
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(),
      name: 'Acme Enterprise SaaS',
      environment: 'public',
      seeds: [seedOrigin],
      includeSubdomains: true,
    })

    // 1. Seed 30 subdomains total: 24 approved (including seed) + 6 unapproved (4 third-party CNAMEs + 2 unapproved first-party)
    const approvedSubdomains = [
      'api', 'auth', 'admin', 'billing', 'portal', 'dashboard', 'graphql', 'gateway',
      'accounts', 'console', 'webhooks', 'uploads', 'reports', 'analytics', 'search',
      'notifications', 'payments', 'checkout', 'partners', 'developers', 'docs',
      'status', 'staging-api',
    ] // 23 + 1 seed = 24 approved

    const approvedAssetIds: string[] = []
    const projectInitial = storage.projectDetail(projectId)
    for (const a of projectInitial.assets) approvedAssetIds.push(a.id)

    for (const sub of approvedSubdomains) {
      const origin = `https://${sub}.acme-saas.example`
      const { id: assetId } = storage.addProjectAsset({
        requestId: randomUUID(),
        projectId,
        origin,
        source: 'DNS zone export',
        thirdParty: false,
        includeSubdomains: false,
      })
      storage.updateProjectAssetScope({
        requestId: randomUUID(),
        projectId,
        assetId,
        approveInDefaultScope: true,
      })
      approvedAssetIds.push(assetId)
    }

    const unapprovedAssets: Array<{
      origin: string
      source: string
      thirdParty: boolean
      cnameTarget?: string
    }> = [
      { origin: 'https://help.acme-saas.example', source: 'DNS CNAME record', thirdParty: true, cnameTarget: 'acme.zendesk.com' },
      { origin: 'https://mail.acme-saas.example', source: 'DNS CNAME record', thirdParty: true, cnameTarget: 'u12345.wl.sendgrid.net' },
      { origin: 'https://marketing.acme-saas.example', source: 'DNS CNAME record', thirdParty: true, cnameTarget: 'acme.sites.hubspot.net' },
      { origin: 'https://blog.acme-saas.example', source: 'DNS CNAME record', thirdParty: true, cnameTarget: 'acme-blog.ghost.io' },
      { origin: 'https://preview-42.acme-saas.example', source: 'Certificate transparency', thirdParty: false },
      { origin: 'https://sandbox-legacy.acme-saas.example', source: 'Certificate transparency', thirdParty: false },
    ]
    for (const item of unapprovedAssets) {
      storage.addProjectAsset({
        requestId: randomUUID(),
        projectId,
        origin: item.origin,
        source: item.source,
        thirdParty: item.thirdParty,
        includeSubdomains: false,
        ...(item.cnameTarget
          ? {
              dnsSource: {
                zone: 'acme-saas.example',
                recordTypes: ['CNAME'] as ('A' | 'AAAA' | 'CNAME')[],
                externalAliases: [item.cnameTarget],
              },
            }
          : {}),
      })
    }

    // 2. Seed 3 mounted repos on disk + 2 project specs
    const reposRoot = projectReposDir(dataDir, projectId)
    const repoNames = [
      ['acme-corp', 'web-app'],
      ['acme-corp', 'api-gateway'],
      ['acme-corp', 'auth-service'],
    ] as const
    for (const [owner, repo] of repoNames) {
      const repoDir = join(reposRoot, owner, repo)
      mkdirSync(join(repoDir, 'src'), { recursive: true })
      writeFileSync(
        join(repoDir, 'package.json'),
        JSON.stringify({ name: `@${owner}/${repo}`, version: '1.4.0', private: true }, null, 2),
        'utf8',
      )
      writeFileSync(
        join(repoDir, 'src', 'index.ts'),
        `export const service = '${repo}'\nexport const owner = '${owner}'\n`,
        'utf8',
      )
    }

    storage.upsertProjectSpecRaw(projectId, {
      name: 'acme-corp/api-gateway:openapi.yaml',
      kind: 'openapi',
      origin: 'https://api.acme-saas.example',
      content: 'openapi: 3.1.0\ninfo:\n  title: Acme Gateway API\n  version: 2.4.0\npaths:\n  /api/v2/orders/refund:\n    post:\n      summary: Issue order refund\n',
    })
    storage.upsertProjectSpecRaw(projectId, {
      name: 'Security architecture notes',
      kind: 'notes',
      origin: seedOrigin,
      content: '# Architecture\nTenant isolation is enforced on org_id claims across api and billing services.\n',
    })

    // 3. Seed 2 test accounts (personas)
    const persona1 = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'user-a',
      roleLabel: 'User A · Standard Member',
      originAllowlist: [seedOrigin, 'https://api.acme-saas.example'],
      authKind: 'bearer',
      secret: 'qa-synthetic-bearer-token-user-a-0001',
      canaryMarkers: ['user-a@acme-saas.example'],
    })
    const persona2 = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'admin-b',
      roleLabel: 'Admin B · Org Owner',
      originAllowlist: [seedOrigin, 'https://api.acme-saas.example', 'https://admin.acme-saas.example'],
      authKind: 'header',
      headerName: 'X-Admin-Token',
      secret: 'qa-synthetic-header-token-admin-b-0002',
      canaryMarkers: ['admin-b@acme-saas.example'],
    })

    // 4a. Waiting Scope Review run with 27 candidate hosts
    const { id: scopeReviewRunId } = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal: 'Scope review across 27 discovered first-party and third-party Acme hosts before active testing.',
      sourceMode: 'public',
      capabilityTier: 3,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [persona1.id, persona2.id],
      budgetUsd: 25,
      budgetRequests: 1500,
      maxRpsPerOrigin: 8,
      workerConcurrency: 3,
      workerMaxTurns: 25,
    })
    const scopeRun = storage.run(scopeReviewRunId)
    const scopeCandidates: Array<{ origin: string; source: string; thirdParty: boolean; cnameTarget?: string }> = [
      { origin: seedOrigin, source: 'Project seed', thirdParty: false },
      ...approvedSubdomains.slice(0, 20).map(sub => ({
        origin: `https://${sub}.acme-saas.example`,
        source: 'subdomain_discovery',
        thirdParty: false,
      })),
      ...unapprovedAssets,
    ] // 1 + 20 + 6 = 27 candidate hosts
    for (const c of scopeCandidates) {
      storage.suggestCandidateHost(
        scopeRun,
        c.origin,
        c.source,
        c.thirdParty,
        c.cnameTarget
          ? { zone: 'acme-saas.example', recordTypes: ['CNAME'], externalAliases: [c.cnameTarget] }
          : undefined,
      )
    }
    storage.updateRun(scopeReviewRunId, {
      phase: 'review',
      status: 'waiting',
    })

    // 4b. Running Round-0 Threat Model run
    const { id: threatModelRunId } = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal: 'Map attack surface and prioritize high-risk endpoints in Round-0 threat modeling.',
      sourceMode: 'public',
      capabilityTier: 2,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [persona1.id, persona2.id],
      budgetUsd: 20,
      budgetRequests: 1200,
      maxRpsPerOrigin: 6,
      workerConcurrency: 3,
      workerMaxTurns: 25,
    })
    let tmRun = storage.run(threatModelRunId)
    const tmOrigins = [
      seedOrigin,
      'https://api.acme-saas.example',
      'https://auth.acme-saas.example',
      'https://admin.acme-saas.example',
      'https://billing.acme-saas.example',
      'https://webhooks.acme-saas.example',
    ]
    for (const o of tmOrigins) {
      storage.suggestCandidateHost(tmRun, o, 'Project scope', false)
    }
    tmRun = storage.run(threatModelRunId)
    storage.updateRun(threatModelRunId, {
      phase: 'threat_model',
      status: 'running',
      roundNo: 0,
      scopeRevision: 1,
      goalRevision: 1,
      approved: tmRun.candidates.map(c => c.id),
      spentUsd: 0.42,
      spentRequests: 48,
      turnsUsed: 4,
    })
    tmRun = storage.run(threatModelRunId)
    storage.saveThreatModel(
      tmRun,
      [
        {
          origin: 'https://api.acme-saas.example',
          riskTier: 'critical',
          surfaceTags: ['multi-tenant-api', 'orders', 'refunds'],
          rationale: 'Primary multi-tenant REST API handling financial mutations and org-scoped objects.',
        },
        {
          origin: 'https://auth.acme-saas.example',
          riskTier: 'critical',
          surfaceTags: ['oauth', 'sso', 'session-mint'],
          rationale: 'Central identity broker issuing tenant-scoped JWTs and SSO callbacks.',
        },
        {
          origin: 'https://admin.acme-saas.example',
          riskTier: 'high',
          surfaceTags: ['privileged-console', 'rbac'],
          rationale: 'Administrative portal for role assignment and audit log exports.',
        },
        {
          origin: 'https://billing.acme-saas.example',
          riskTier: 'high',
          surfaceTags: ['payments', 'credits'],
          rationale: 'Subscription and invoice adjustment workflows sensitive to race conditions.',
        },
        {
          origin: 'https://webhooks.acme-saas.example',
          riskTier: 'medium',
          surfaceTags: ['outbound-fetch', 'hmac'],
          rationale: 'Customer-configured webhook destinations warranting egress boundary checks.',
        },
        {
          origin: seedOrigin,
          riskTier: 'medium',
          surfaceTags: ['spa', 'client-bundle'],
          rationale: 'Primary web frontend exposing client routing and API client contracts.',
        },
      ],
      'Round-0 threat model ranked 6 approved hosts; prioritizing api, auth, and billing surfaces.',
    )
    const tmWorker = storage.makeWorker(
      tmRun,
      'threat_model',
      tmRun.candidates[0],
      'Round-0 Surface Prioritization',
      'Synthesize endpoint inventory and rank high-value verification targets.',
    )
    storage.updateWorker(tmWorker.id, { status: 'running', turnsUsed: 3, requestsUsed: 18 })
    storage.event(threatModelRunId, 'threat_model.started', 'Round-0 threat modeling in progress across 6 hosts.', {
      hostCount: 6,
    })

    // 4c. Running Investigation run with 10 pending approvals (including duplicate route cards) + active leases
    const { id: investigationRunId } = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal: 'Investigate access-control boundaries and state-changing mutation routes under strict approval.',
      sourceMode: 'public',
      capabilityTier: 3,
      approvalPolicy: 'strict',
      approvedPersonaIds: [persona1.id, persona2.id],
      budgetUsd: 35,
      budgetRequests: 2000,
      maxRpsPerOrigin: 8,
      workerConcurrency: 3,
      workerMaxTurns: 30,
    })
    let invRun = storage.run(investigationRunId)
    for (const o of [seedOrigin, 'https://api.acme-saas.example', 'https://billing.acme-saas.example', 'https://admin.acme-saas.example']) {
      storage.suggestCandidateHost(invRun, o, 'Project scope', false)
    }
    invRun = storage.run(investigationRunId)
    storage.updateRun(investigationRunId, {
      phase: 'investigation',
      status: 'running',
      roundNo: 2,
      scopeRevision: 1,
      goalRevision: 1,
      approved: invRun.candidates.map(c => c.id),
      spentUsd: 2.85,
      spentRequests: 214,
      turnsUsed: 19,
    })
    invRun = storage.run(investigationRunId)

    const invWorkers = [
      storage.makeWorker(invRun, 'discovery', invRun.candidates[0], 'Surface Discovery', 'Enumerate routes and API contracts.'),
      storage.makeWorker(invRun, 'investigation', invRun.candidates[1], 'Orders & Refunds Probe', 'Verify cross-tenant refund authorization.'),
      storage.makeWorker(invRun, 'investigation', invRun.candidates[2], 'Billing Credits Probe', 'Verify credit balance idempotency and authorization.'),
      storage.makeWorker(invRun, 'investigation', invRun.candidates[3], 'Admin RBAC Probe', 'Verify role-update and SSO configuration boundaries.'),
    ]
    storage.updateWorker(invWorkers[0]!.id, { status: 'complete', turnsUsed: 8, requestsUsed: 64 })
    storage.updateWorker(invWorkers[1]!.id, { status: 'running', turnsUsed: 6, requestsUsed: 52 })
    storage.updateWorker(invWorkers[2]!.id, { status: 'running', turnsUsed: 3, requestsUsed: 41 })
    storage.updateWorker(invWorkers[3]!.id, { status: 'running', turnsUsed: 2, requestsUsed: 33 })

    // 10 pending approval requests including duplicate route cards
    const pendingApprovalSpecs: Array<{
      workerIdx: number
      origin: string
      method: string
      pathAndQuery: string
      personaHandle: string
      rationale: string
      riskLevel: 'low' | 'medium' | 'high'
    }> = [
      {
        workerIdx: 1,
        origin: 'https://api.acme-saas.example',
        method: 'POST',
        pathAndQuery: '/api/v2/orders/refund',
        personaHandle: 'user-a',
        rationale: 'Verify whether non-owner user-a can initiate a control refund mutation on order #1041.',
        riskLevel: 'high',
      },
      {
        workerIdx: 1,
        origin: 'https://api.acme-saas.example',
        method: 'POST',
        pathAndQuery: '/api/v2/orders/refund',
        personaHandle: 'user-a',
        rationale: 'Repeat differential check on /api/v2/orders/refund with alternate order ID #1042.',
        riskLevel: 'high',
      },
      {
        workerIdx: 1,
        origin: 'https://api.acme-saas.example',
        method: 'POST',
        pathAndQuery: '/api/v2/orders/refund',
        personaHandle: 'admin-b',
        rationale: 'Baseline control check on /api/v2/orders/refund as authorized owner admin-b.',
        riskLevel: 'medium',
      },
      {
        workerIdx: 3,
        origin: 'https://admin.acme-saas.example',
        method: 'PATCH',
        pathAndQuery: '/api/v2/users/42/role',
        personaHandle: 'user-a',
        rationale: 'Check privilege boundary when standard member attempts role modification on user 42.',
        riskLevel: 'high',
      },
      {
        workerIdx: 3,
        origin: 'https://admin.acme-saas.example',
        method: 'PATCH',
        pathAndQuery: '/api/v2/users/42/role',
        personaHandle: 'user-a',
        rationale: 'Check mass-assignment protection on secondary role field for user 42.',
        riskLevel: 'high',
      },
      {
        workerIdx: 2,
        origin: 'https://billing.acme-saas.example',
        method: 'POST',
        pathAndQuery: '/api/v2/billing/credits/apply',
        personaHandle: 'user-a',
        rationale: 'Verify idempotency key enforcement on credit voucher redemption endpoint.',
        riskLevel: 'medium',
      },
      {
        workerIdx: 1,
        origin: 'https://api.acme-saas.example',
        method: 'PUT',
        pathAndQuery: '/api/v2/webhooks/config',
        personaHandle: 'user-a',
        rationale: 'Check destination URL validation on webhook update route.',
        riskLevel: 'medium',
      },
      {
        workerIdx: 3,
        origin: 'https://admin.acme-saas.example',
        method: 'DELETE',
        pathAndQuery: '/api/v2/tokens/revoke',
        personaHandle: 'user-a',
        rationale: 'Verify whether member token can revoke another org member API key.',
        riskLevel: 'high',
      },
      {
        workerIdx: 2,
        origin: 'https://billing.acme-saas.example',
        method: 'POST',
        pathAndQuery: '/api/v2/exports/invoices',
        personaHandle: 'user-a',
        rationale: 'Verify tenant filter enforcement when triggering invoice export job.',
        riskLevel: 'low',
      },
      {
        workerIdx: 3,
        origin: 'https://admin.acme-saas.example',
        method: 'PATCH',
        pathAndQuery: '/api/v2/org/sso-settings',
        personaHandle: 'user-a',
        rationale: 'Verify admin-only guard on organization SSO domain update endpoint.',
        riskLevel: 'high',
      },
    ]

    for (const spec of pendingApprovalSpecs) {
      storage.createApprovalRequest(invRun, invWorkers[spec.workerIdx]!, {
        origin: spec.origin,
        method: spec.method,
        pathAndQuery: spec.pathAndQuery,
        personaHandle: spec.personaHandle,
        rationale: spec.rationale,
        requestPreview: `${spec.method} ${spec.origin}${spec.pathAndQuery}\nContent-Type: application/json\n\n{"dryRun":true}`,
        riskLevel: spec.riskLevel,
        policyNote: 'Strict approval policy requires explicit operator review before state-changing requests.',
      })
    }

    // Grant 2 active approval leases so Approval leases popover renders rich lease rows
    storage.grantApprovalLease(invRun, {
      origin: 'https://api.acme-saas.example',
      method: 'POST',
      pathAndQuery: '/api/v2/comments/preview',
      leaseScope: 'route',
      personaHandle: 'user-a',
      createdBy: 'operator',
    })
    storage.grantApprovalLease(invRun, {
      origin: 'https://billing.acme-saas.example',
      method: 'POST',
      pathAndQuery: '/api/v2/drafts/**',
      source: 'operator_explicit',
      leaseScope: 'prefix',
      personaHandle: 'user-a',
      createdBy: 'operator',
    })

    // 4d. Complete run with confirmed + static_verified findings + report
    const { id: completeRunId } = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal: 'Full verification pass with runtime-confirmed findings and source-backed static advisories.',
      sourceMode: 'public',
      capabilityTier: 3,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [persona1.id, persona2.id],
      budgetUsd: 30,
      budgetRequests: 2000,
      maxRpsPerOrigin: 8,
      workerConcurrency: 3,
      workerMaxTurns: 30,
    })
    let doneRun = storage.run(completeRunId)
    for (const o of [seedOrigin, 'https://api.acme-saas.example', 'https://admin.acme-saas.example']) {
      storage.suggestCandidateHost(doneRun, o, 'Project scope', false)
    }
    doneRun = storage.run(completeRunId)
    storage.updateRun(completeRunId, {
      phase: 'investigation',
      status: 'running',
      roundNo: 3,
      scopeRevision: 1,
      goalRevision: 1,
      approved: doneRun.candidates.map(c => c.id),
      spentUsd: 4.12,
      spentRequests: 390,
      turnsUsed: 28,
    })
    doneRun = storage.run(completeRunId)

    const apiCandidate = doneRun.candidates.find(c => c.origin === 'https://api.acme-saas.example') ?? doneRun.candidates[0]!
    const adminCandidate = doneRun.candidates.find(c => c.origin === 'https://admin.acme-saas.example') ?? doneRun.candidates[0]!
    const doneWorker = storage.makeWorker(
      doneRun,
      'investigation',
      apiCandidate,
      'Access Control & Source Audit',
      'Verify multi-tenant authorization boundaries and inspect linked repositories.',
    )
    storage.updateWorker(doneWorker.id, { status: 'complete', turnsUsed: 14, requestsUsed: 142 })

    const ex1 = storage.recordExchange({
      runId: doneRun.id,
      assignmentId: doneWorker.id,
      scopeRevision: doneRun.scopeRevision,
      origin: 'https://api.acme-saas.example',
      finalOrigin: 'https://api.acme-saas.example',
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/api/v2/orgs/org-beta/invoices/inv-9001',
      personaHandle: 'user-a',
      status: 200,
      mediaType: 'application/json',
      reqHeaders: { accept: 'application/json' },
      respHeaders: { 'content-type': 'application/json' },
      body: JSON.stringify({ invoiceId: 'inv-9001', orgId: 'org-beta', totalUsd: 1420 }),
      durationMs: 38,
    })

    // Confirmed finding #1 (runtime_confirmed, backed by replay spec with verdict='confirmed')
    const confirmedFindingId1 = randomUUID()
    const confirmedSpec1: DeclarativeReplaySpec = {
      version: 1,
      kind: 'http_chain',
      spaCatchallControl: false,
      origin: 'https://api.acme-saas.example',
      title: 'Cross-tenant invoice read via missing org scope check',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      severity: 'high',
      severityRationale: 'Direct cross-tenant read of billing records without org authorization.',
      impact: 'Any authenticated member can read invoices belonging to other organizations.',
      remediation: 'Scope invoice queries by the authenticated session organization ID.',
      recheckInstructions: 'Replay GET /api/v2/orgs/org-beta/invoices/inv-9001 as user-a and verify HTTP 403/404.',
      assertionsJq: '{confirmed: (.steps.probe.status == 200), controlPassed: (.steps.control.status == 200), observed: "200", expected: "403"}',
      steps: [
        {
          id: 'control',
          role: 'control',
          description: 'Read own invoice as user-a',
          expectedStatus: 200,
          request: {
            origin: 'https://api.acme-saas.example',
            method: 'GET',
            pathAndQuery: '/api/v2/orgs/org-alpha/invoices/inv-1001',
            persona: 'user-a',
            followRedirects: false,
          },
        },
        {
          id: 'probe',
          role: 'probe',
          description: 'Read sibling tenant invoice as user-a',
          expectedStatus: 200,
          request: {
            origin: 'https://api.acme-saas.example',
            method: 'GET',
            pathAndQuery: '/api/v2/orgs/org-beta/invoices/inv-9001',
            persona: 'user-a',
            followRedirects: false,
          },
        },
      ],
    }
    const specRow1 = storage.createReplaySpec(doneRun, doneWorker, confirmedFindingId1, confirmedSpec1, [apiCandidate.origin], {
      verifiedInline: true,
      lastVerificationDiff: {
        verdict: 'confirmed',
        controlPassed: true,
        assertionSummary: {
          observed: 'HTTP 200 returned sibling tenant invoice payload for org-beta.',
          expected: 'HTTP 403/404 for cross-tenant resource identifier.',
          reason: 'Differential access boundary check reproduced deterministically.',
        },
        stepStatuses: [
          { id: 'control', role: 'control', status: 200, mediaType: 'application/json', bodyLen: 72 },
          { id: 'probe', role: 'probe', status: 200, mediaType: 'application/json', bodyLen: 74 },
        ],
        retriesRemaining: 0,
      },
    })
    storage.upsertChainFinding(
      doneRun,
      apiCandidate.id,
      {
        id: confirmedFindingId1,
        origin: apiCandidate.origin,
        title: 'Cross-tenant invoice read via missing organization scope check',
        status: 'confirmed',
        severity: 'high',
        category: 'broken-access-control',
        cwe: 'CWE-639',
        confidence: 'high',
        verificationTier: 'runtime_confirmed',
        findingKind: 'multi_step_chain',
        replaySpecId: specRow1.id,
        reason: 'Standard member user-a retrieved invoice records belonging to org-beta via direct invoice ID.',
        impact: 'Any authenticated member can enumerate and read invoices from other organizations.',
        remediation: 'Enforce organization ownership checks on /api/v2/orgs/:orgId/invoices/:id using session claims.',
        evidenceIds: [],
        exchangeIds: [ex1.id],
        scopeRevision: doneRun.scopeRevision,
      },
      specRow1.id,
      [apiCandidate.origin],
      { provenance: 'agent_only', verificationClass: 'runtime_confirmed' },
    )

    // Confirmed finding #2 (medium severity)
    const confirmedFindingId2 = randomUUID()
    const confirmedSpec2: DeclarativeReplaySpec = {
      version: 1,
      kind: 'http_chain',
      spaCatchallControl: false,
      origin: 'https://admin.acme-saas.example',
      title: 'Audit export endpoint allows unprivileged role access',
      category: 'broken-access-control',
      cwe: 'CWE-862',
      severity: 'medium',
      severityRationale: 'Standard member role can read administrative audit telemetry.',
      impact: 'Non-admin organization members can view administrative audit telemetry.',
      remediation: 'Require the org_admin role middleware on /api/v2/admin/audit-summary.',
      recheckInstructions: 'Replay GET /api/v2/admin/audit-summary as user-a and verify HTTP 403.',
      assertionsJq: '{confirmed: (.steps.probe.status == 200), controlPassed: (.steps.control.status == 200), observed: "200", expected: "403"}',
      steps: [
        {
          id: 'control',
          role: 'control',
          description: 'Fetch audit summary as admin-b',
          expectedStatus: 200,
          request: {
            origin: 'https://admin.acme-saas.example',
            method: 'GET',
            pathAndQuery: '/api/v2/admin/audit-summary',
            persona: 'admin-b',
            followRedirects: false,
          },
        },
        {
          id: 'probe',
          role: 'probe',
          description: 'Fetch audit summary as user-a',
          expectedStatus: 200,
          request: {
            origin: 'https://admin.acme-saas.example',
            method: 'GET',
            pathAndQuery: '/api/v2/admin/audit-summary',
            persona: 'user-a',
            followRedirects: false,
          },
        },
      ],
    }
    const specRow2 = storage.createReplaySpec(doneRun, doneWorker, confirmedFindingId2, confirmedSpec2, [adminCandidate.origin], {
      verifiedInline: true,
      lastVerificationDiff: {
        verdict: 'confirmed',
        controlPassed: true,
        assertionSummary: {
          observed: 'HTTP 200 audit summary returned to non-admin persona user-a.',
          expected: 'HTTP 403 Forbidden for non-admin personas.',
          reason: 'Missing role guard confirmed across paired personas.',
        },
        stepStatuses: [
          { id: 'control', role: 'control', status: 200, mediaType: 'application/json', bodyLen: 120 },
          { id: 'probe', role: 'probe', status: 200, mediaType: 'application/json', bodyLen: 120 },
        ],
        retriesRemaining: 0,
      },
    })
    storage.upsertChainFinding(
      doneRun,
      adminCandidate.id,
      {
        id: confirmedFindingId2,
        origin: adminCandidate.origin,
        title: 'Admin audit summary accessible to standard member role',
        status: 'confirmed',
        severity: 'medium',
        category: 'broken-access-control',
        cwe: 'CWE-862',
        confidence: 'high',
        verificationTier: 'runtime_confirmed',
        findingKind: 'multi_step_chain',
        replaySpecId: specRow2.id,
        reason: 'The /api/v2/admin/audit-summary route validates authentication but omits role authorization.',
        impact: 'Non-admin organization members can view administrative audit telemetry.',
        remediation: 'Attach requireRole("org_admin") middleware to the audit summary route.',
        evidenceIds: [],
        exchangeIds: [],
        scopeRevision: doneRun.scopeRevision,
      },
      specRow2.id,
      [adminCandidate.origin],
      { provenance: 'agent_only', verificationClass: 'runtime_confirmed' },
    )

    // Static verified advisory #1
    const staticFindingId1 = randomUUID()
    const staticSpec1: DeclarativeReplaySpec = {
      version: 1,
      kind: 'static_ast_proof',
      origin: apiCandidate.origin,
      title: 'Unsafe dynamic redirect target in OAuth callback helper',
      category: 'ssrf-redirects',
      cwe: 'CWE-601',
      severity: 'medium',
      severityRationale: 'Source AST inspection identified an unvalidated returnTo query parameter forwarded to res.redirect.',
      impact: 'Attackers could redirect authenticated users after OAuth sign-in to an external origin.',
      remediation: 'Validate redirect targets against an explicit allowlist of relative application paths.',
      recheckInstructions: 'Verify handleOAuthCallback enforces relative-path validation in src/oauth-callback.ts.',
      assertionsJq: '{confirmed: true, controlPassed: true, observed: "static_ast", expected: "allowlist"}',
      repo: 'acme-corp/auth-service',
      file: 'src/oauth-callback.ts',
      startLine: 44,
      endLine: 58,
      engine: 'opengrep',
      ruleOrPattern: 'res.redirect(req.query.returnTo)',
      runtimeProofGap: 'OAuth provider callback state requires live IdP round-trip not enabled in this run.',
    }
    const staticSpecRow1 = storage.createReplaySpec(doneRun, doneWorker, staticFindingId1, staticSpec1, [apiCandidate.origin], {
      verifiedInline: false,
    })
    storage.upsertChainFinding(
      doneRun,
      apiCandidate.id,
      {
        id: staticFindingId1,
        origin: apiCandidate.origin,
        title: 'Unvalidated redirect target in OAuth callback helper (static advisory)',
        status: 'static_verified',
        severity: 'medium',
        category: 'ssrf-redirects',
        cwe: 'CWE-601',
        confidence: 'medium',
        verificationTier: 'static_verified',
        findingKind: 'multi_step_chain',
        replaySpecId: staticSpecRow1.id,
        reason: 'Static source audit verified direct flow from returnTo query parameter into redirect helper.',
        remediation: 'Enforce same-origin relative path validation before redirecting.',
        runtimeProofGap: 'OAuth provider callback state requires live IdP round-trip not enabled in this run.',
        codeLocations: [{ repo: 'acme-corp/auth-service', file: 'src/oauth-callback.ts', startLine: 44, endLine: 58, label: 'handleOAuthCallback' }],
        evidenceIds: [],
        exchangeIds: [],
        scopeRevision: doneRun.scopeRevision,
      },
      staticSpecRow1.id,
      [apiCandidate.origin],
      { provenance: 'agent_only', verificationClass: 'static_advisory' },
    )

    // Static verified advisory #2
    const staticFindingId2 = randomUUID()
    const staticSpec2: DeclarativeReplaySpec = {
      version: 1,
      kind: 'static_ast_proof',
      origin: apiCandidate.origin,
      title: 'Missing webhook signature timestamp window check',
      category: 'auth-identity',
      cwe: 'CWE-294',
      severity: 'low',
      severityRationale: 'Static analysis found HMAC signature check without replay timestamp tolerance.',
      impact: 'Captured signed webhook deliveries remain replayable indefinitely.',
      remediation: 'Reject signed webhook deliveries older than 5 minutes.',
      recheckInstructions: 'Verify verifyWebhookSignature enforces timestamp tolerance in src/webhooks/verify.ts.',
      assertionsJq: '{confirmed: true, controlPassed: true, observed: "static_ast", expected: "timestamp_window"}',
      repo: 'acme-corp/api-gateway',
      file: 'src/webhooks/verify.ts',
      startLine: 19,
      endLine: 34,
      engine: 'opengrep',
      ruleOrPattern: 'verifyWebhookSignature(payload, sig)',
      runtimeProofGap: 'Inbound webhook secret is not provisioned in test fixture.',
    }
    const staticSpecRow2 = storage.createReplaySpec(doneRun, doneWorker, staticFindingId2, staticSpec2, [apiCandidate.origin], {
      verifiedInline: false,
    })
    storage.upsertChainFinding(
      doneRun,
      apiCandidate.id,
      {
        id: staticFindingId2,
        origin: apiCandidate.origin,
        title: 'Webhook signature verifier omits timestamp freshness window (static advisory)',
        status: 'static_verified',
        severity: 'low',
        category: 'auth-identity',
        cwe: 'CWE-294',
        confidence: 'medium',
        verificationTier: 'static_verified',
        findingKind: 'multi_step_chain',
        replaySpecId: staticSpecRow2.id,
        reason: 'Static review confirmed signature verification ignores timestamp age.',
        remediation: 'Compare x-acme-timestamp against current time within ±300 seconds.',
        runtimeProofGap: 'Inbound webhook secret is not provisioned in test fixture.',
        codeLocations: [{ repo: 'acme-corp/api-gateway', file: 'src/webhooks/verify.ts', startLine: 19, endLine: 34, label: 'verifyWebhookSignature' }],
        evidenceIds: [],
        exchangeIds: [],
        scopeRevision: doneRun.scopeRevision,
      },
      staticSpecRow2.id,
      [apiCandidate.origin],
      { provenance: 'agent_only', verificationClass: 'static_advisory' },
    )

    doneRun = storage.run(completeRunId)
    storage.writeReport(doneRun, false)
    storage.updateRun(completeRunId, { phase: 'complete', status: 'complete' })

    // 4e. Fresh 0-finding running run
    const { id: freshRunningRunId } = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal: 'Continuous passive baseline verification across primary web origin.',
      sourceMode: 'public',
      capabilityTier: 1,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [],
      budgetUsd: 10,
      budgetRequests: 500,
      maxRpsPerOrigin: 5,
      workerConcurrency: 2,
      workerMaxTurns: 15,
    })
    let freshRun = storage.run(freshRunningRunId)
    storage.suggestCandidateHost(freshRun, seedOrigin, 'Project seed', false)
    freshRun = storage.run(freshRunningRunId)
    storage.updateRun(freshRunningRunId, {
      phase: 'discovery',
      status: 'running',
      roundNo: 0,
      scopeRevision: 1,
      goalRevision: 1,
      approved: freshRun.candidates.map(c => c.id),
      spentUsd: 0.05,
      spentRequests: 9,
      turnsUsed: 1,
    })
    freshRun = storage.run(freshRunningRunId)
    const freshWorker = storage.makeWorker(
      freshRun,
      'discovery',
      freshRun.candidates[0],
      'Initial Surface Discovery',
      'Collect baseline routes and response headers.',
    )
    storage.updateWorker(freshWorker.id, { status: 'running', turnsUsed: 1, requestsUsed: 9 })

    storage.flushNow()

    return {
      projectId,
      subdomainsTotal: 1 + approvedSubdomains.length + unapprovedAssets.length,
      subdomainsApproved: 1 + approvedSubdomains.length,
      subdomainsUnapproved: unapprovedAssets.length,
      reposCount: repoNames.length,
      personasCount: 2,
      runs: {
        scopeReview: scopeReviewRunId,
        threatModel: threatModelRunId,
        investigation: investigationRunId,
        complete: completeRunId,
        freshRunning: freshRunningRunId,
      },
    }
  } finally {
    storage.close()
  }
}

// ============================================================================
// Server Boot & Playwright Loader (dynamic import so unit tests stay zero-PW)
// ============================================================================

const SYSTEM_CHROMIUM_CANDIDATES = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
]

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string }> {
  let pw: PlaywrightModule | null = null
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') {
        pw = loaded as PlaywrightModule
        break
      }
    } catch {
      // Try next package
    }
  }
  if (!pw) {
    throw new Error('Playwright is not installed. Install @playwright/test to run scripts/qa-ui-crawler.ts.')
  }

  const bundled = (() => {
    try {
      return pw.chromium.executablePath()
    } catch {
      return ''
    }
  })()
  if (bundled && existsSync(bundled)) {
    return { pw, executablePath: bundled }
  }
  for (const candidate of SYSTEM_CHROMIUM_CANDIDATES) {
    if (existsSync(candidate)) {
      return { pw, executablePath: candidate }
    }
  }
  throw new Error('Chromium binary unavailable in Playwright cache or system paths.')
}

function ensureBuilt(): void {
  const serverEntry = resolve('build/server/server.js')
  const clientDir = resolve('build/client')
  if (existsSync(serverEntry) && existsSync(clientDir)) return
  console.log('[qa:ui] build/ missing — running npm run build...')
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'inherit' })
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate ephemeral port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

interface SpawnedServer {
  origin: string
  dataDir: string
  bootstrapSecret: string
  getOutput(): string
  stop(): Promise<void>
}

async function startSeededKovoServer(dataDir: string): Promise<SpawnedServer> {
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      KOVO_DATA_DIR: dataDir,
      KOVO_OFFLINE: '1',
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
      const timedOut = await Promise.race([
        exited.then(() => false),
        delay(3_000).then(() => true),
      ])
      if (timedOut && child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
  }

  let healthy = false
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) break
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })
      if (res.ok) {
        healthy = true
        break
      }
    } catch {
      // Server not bound yet
    }
    await delay(70)
  }
  if (!healthy) {
    await stop()
    throw new Error(`scripts/serve.ts failed to start on ${origin}.\n${output}`)
  }

  let bootstrapSecret = ''
  for (let read = 0; read < 30 && !bootstrapSecret; read += 1) {
    try {
      bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim()
    } catch {
      await delay(50)
    }
  }
  if (!bootstrapSecret) {
    await stop()
    throw new Error(`Bootstrap secret file was not written in ${dataDir}.\n${output}`)
  }

  return {
    origin,
    dataDir,
    bootstrapSecret,
    getOutput: () => output,
    stop,
  }
}

// ============================================================================
// In-Page DOM Inspection & Scroll Helpers
// ============================================================================

async function scrollViewTo(page: Page, targetScrollTop: number): Promise<number> {
  return page.evaluate((targetY: number) => {
    const isScrollable = (el: Element): boolean => {
      const style = window.getComputedStyle(el)
      const oy = style.overflowY
      return (oy === 'auto' || oy === 'scroll' || oy === 'overlay') && el.scrollHeight > el.clientHeight + 4
    }

    // If a modal dialog is open, scroll its body container
    const openDialog = Array.from(document.querySelectorAll('dialog[open], [role="dialog"]')).find(el => {
      const r = el.getBoundingClientRect()
      const st = window.getComputedStyle(el)
      return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none'
    })
    if (openDialog) {
      const dialogBody = openDialog.querySelector('[data-slot="dialog-body"]')
      const scrollTarget = (dialogBody && isScrollable(dialogBody))
        ? dialogBody
        : Array.from(openDialog.querySelectorAll('*')).find(isScrollable)
      if (scrollTarget) {
        scrollTarget.scrollTop = targetY
        return Math.round(scrollTarget.scrollTop)
      }
      return 0
    }

    // Otherwise find the primary scrollable container inside <main> (falling back to document)
    const main = document.querySelector('main')
    const candidates: Element[] = []
    if (main) {
      if (isScrollable(main)) candidates.push(main)
      for (const el of main.querySelectorAll('*')) {
        if (isScrollable(el)) candidates.push(el)
      }
    }
    candidates.sort((a, b) => (b.scrollHeight - b.clientHeight) - (a.scrollHeight - a.clientHeight))
    const primary = candidates[0]
    if (primary) {
      primary.scrollTop = targetY
      return Math.round(primary.scrollTop)
    }
    window.scrollTo(0, targetY)
    return Math.round(window.scrollY)
  }, targetScrollTop)
}

async function collectDomGeometrySnapshot(page: Page, scrollTop: number): Promise<DomGeometrySnapshot> {
  return page.evaluate((currentScrollTop: number) => {
    const vp = { width: window.innerWidth, height: window.innerHeight }

    const toRect = (r: DOMRect) => ({
      left: Math.round(r.left * 10) / 10,
      top: Math.round(r.top * 10) / 10,
      right: Math.round(r.right * 10) / 10,
      bottom: Math.round(r.bottom * 10) / 10,
      width: Math.round(r.width * 10) / 10,
      height: Math.round(r.height * 10) / 10,
    })

    const isElementVisible = (el: Element): boolean => {
      if (!(el instanceof HTMLElement)) return false
      if (el.hidden || el.getAttribute('aria-hidden') === 'true') return false
      const st = window.getComputedStyle(el)
      if (st.display === 'none' || st.visibility === 'hidden' || Number(st.opacity) === 0) return false
      // Check ancestor hidden/collapsed states
      let cur: HTMLElement | null = el.parentElement
      while (cur) {
        if (cur.hidden || cur.getAttribute('aria-hidden') === 'true') return false
        const pst = window.getComputedStyle(cur)
        if (pst.display === 'none' || pst.visibility === 'hidden') return false
        cur = cur.parentElement
      }
      return true
    }

    const labelFor = (el: Element): string => {
      const aria = el.getAttribute('aria-label')?.trim()
      if (aria) return aria.slice(0, 64)
      const title = el.getAttribute('title')?.trim()
      if (title) return title.slice(0, 64)
      const text = (el.textContent ?? '').replace(/\s+/g, ' ').trim()
      if (text) return text.slice(0, 64)
      const slot = el.getAttribute('data-slot') || el.getAttribute('data-testid') || el.id
      return slot ? `${el.tagName.toLowerCase()}#${slot}` : el.tagName.toLowerCase()
    }

    const selectorHint = (el: Element): string => {
      const tag = el.tagName.toLowerCase()
      const testid = el.getAttribute('data-testid')
      if (testid) return `${tag}[data-testid="${testid}"]`
      const role = el.getAttribute('role')
      const aria = el.getAttribute('aria-label')
      if (role && aria) return `${tag}[role="${role}"][aria-label="${aria.slice(0, 32)}"]`
      if (aria) return `${tag}[aria-label="${aria.slice(0, 32)}"]`
      const slot = el.getAttribute('data-slot')
      if (slot) return `${tag}[data-slot="${slot}"]`
      return tag
    }

    const openDialogs = Array.from(document.querySelectorAll('dialog[open], [role="dialog"]')).filter(el => {
      if (!isElementVisible(el)) return false
      const r = el.getBoundingClientRect()
      return r.width > 0 && r.height > 0
    })
    const activeDialog = openDialogs[openDialogs.length - 1] ?? null

    // Overflow containers
    const overflowContainers: Array<{
      label: string
      selector: string
      scrollWidth: number
      clientWidth: number
      overflowX: string
    }> = []
    const containerCandidates = Array.from(
      document.querySelectorAll('main, [role="dialog"], dialog[open], [data-slot="dialog-body"], [role="region"]'),
    )
    for (const el of containerCandidates) {
      if (!isElementVisible(el)) continue
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) continue
      const st = window.getComputedStyle(el)
      overflowContainers.push({
        label: labelFor(el),
        selector: selectorHint(el),
        scrollWidth: el.scrollWidth,
        clientWidth: el.clientWidth,
        overflowX: st.overflowX,
      })
    }

    // Landmarks & buttons
    const landmarks: Array<{
      kind: 'tablist' | 'header' | 'dialog' | 'button'
      label: string
      selector: string
      rect: ReturnType<typeof toRect>
      visible: boolean
      disabled?: boolean
      isPrimaryCta?: boolean
      scrollWidth: number
      clientWidth: number
      scrollHeight: number
      clientHeight: number
      overflowX: string
      overflowY: string
      textOverflow?: string
      insideDialog?: boolean
    }> = []

    const pushLandmark = (kind: 'tablist' | 'header' | 'dialog' | 'button', el: Element) => {
      if (!isElementVisible(el)) return
      const r = el.getBoundingClientRect()
      // Ignore genuinely detached zero-width elements unless it's a tablist/header/dialog (which should NEVER collapse to 0px!)
      if (kind === 'button' && r.width === 0 && r.height === 0) {
        // Still check if it has layout presence via offsetParent (catches 0px collapsed visible buttons)
        if (!(el as HTMLElement).offsetParent) return
      }
      const st = window.getComputedStyle(el)
      const insideDialog = Boolean(activeDialog && activeDialog.contains(el))
      const cls = typeof el.className === 'string' ? el.className : ''
      const text = (el.textContent ?? '').replace(/\s+/g, ' ').trim()
      const isSubmit = kind === 'button' && (el as HTMLButtonElement).type === 'submit'
      const inHeaderOrStickyBar = Boolean(el.closest('header, [data-slot="dialog-footer"]'))
      const isNamedPrimary = kind === 'button' && (
        (isSubmit && (insideDialog || inHeaderOrStickyBar))
        || /^(New run|Start run|Save test account|Approve scope|Save model|Create project|Add model profile)$/i.test(text)
        || (insideDialog && cls.includes('bg-accent') && !cls.includes('bg-accent-soft'))
      )
      landmarks.push({
        kind,
        label: labelFor(el),
        selector: selectorHint(el),
        rect: toRect(r),
        visible: true,
        disabled: kind === 'button' ? Boolean((el as HTMLButtonElement).disabled) : undefined,
        isPrimaryCta: isNamedPrimary,
        scrollWidth: el.scrollWidth,
        clientWidth: el.clientWidth,
        scrollHeight: el.scrollHeight,
        clientHeight: el.clientHeight,
        overflowX: st.overflowX,
        overflowY: st.overflowY,
        textOverflow: st.textOverflow,
        insideDialog,
      })
    }

    for (const el of document.querySelectorAll('nav[role="tablist"], [role="tablist"]')) {
      pushLandmark('tablist', el)
    }
    for (const el of document.querySelectorAll('header')) {
      pushLandmark('header', el)
    }
    for (const el of document.querySelectorAll('dialog[open], [role="dialog"]')) {
      pushLandmark('dialog', el)
    }
    // Check buttons (if a dialog is open, inspect dialog buttons + top-level buttons)
    const buttonRoot = activeDialog ?? document
    for (const el of buttonRoot.querySelectorAll('button')) {
      pushLandmark('button', el)
    }

    // Cards (radio cards, data-slot="card", rounded-card containers)
    const cards: Array<{
      label: string
      selector: string
      rect: ReturnType<typeof toRect>
      scrollWidth: number
      clientWidth: number
      scrollHeight: number
      clientHeight: number
      overflowX: string
      overflowY: string
      textOverflow?: string
    }> = []
    const cardRoot = activeDialog ?? document
    const cardEls = cardRoot.querySelectorAll('[role="radio"], [data-slot="card"]')
    for (const el of cardEls) {
      if (!isElementVisible(el)) continue
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) continue
      const st = window.getComputedStyle(el)
      cards.push({
        label: labelFor(el),
        selector: selectorHint(el),
        rect: toRect(r),
        scrollWidth: el.scrollWidth,
        clientWidth: el.clientWidth,
        scrollHeight: el.scrollHeight,
        clientHeight: el.clientHeight,
        overflowX: st.overflowX,
        overflowY: st.overflowY,
        textOverflow: st.textOverflow,
      })
    }

    // Sibling interactive control groups (direct interactive children sharing a parent)
    const interactiveSelector = 'button, a[href], input:not([type="hidden"]), select, textarea, [role="tab"], [role="radio"], [role="checkbox"], [role="menuitem"]'
    const siblingGroups: Array<{
      containerLabel: string
      items: Array<{ label: string; tag: string; rect: ReturnType<typeof toRect> }>
    }> = []
    const seenParents = new Set<Element>()
    const groupRoot = activeDialog ?? document
    for (const el of groupRoot.querySelectorAll(interactiveSelector)) {
      const parent = el.parentElement
      if (!parent || seenParents.has(parent)) continue
      seenParents.add(parent)
      const directChildren = Array.from(parent.children).filter(child => {
        if (!child.matches(interactiveSelector)) return false
        if (!isElementVisible(child)) return false
        const st = window.getComputedStyle(child)
        // Skip intentionally positioned overlays/floating badges
        if (st.position === 'absolute' || st.position === 'fixed') return false
        const r = child.getBoundingClientRect()
        return r.width > 1 && r.height > 1
      })
      if (directChildren.length < 2) continue
      siblingGroups.push({
        containerLabel: selectorHint(parent),
        items: directChildren.map(child => ({
          label: labelFor(child),
          tag: child.tagName.toLowerCase(),
          rect: toRect(child.getBoundingClientRect()),
        })),
      })
    }

    // Visible text nodes for broken copy detection
    const textNodes: Array<{ text: string; tag: string; isCodeElement: boolean }> = []
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    let curNode = walker.nextNode()
    while (curNode) {
      const raw = curNode.nodeValue ?? ''
      if (raw.trim().length > 0) {
        const parent = curNode.parentElement
        if (parent && isElementVisible(parent)) {
          const tag = parent.tagName.toLowerCase()
          if (tag !== 'script' && tag !== 'style' && tag !== 'noscript') {
            const isCodeElement = Boolean(parent.closest('pre, code'))
            textNodes.push({ text: raw, tag, isCodeElement })
          }
        }
      }
      curNode = walker.nextNode()
    }

    return {
      viewport: vp,
      scrollTop: currentScrollTop,
      docScrollWidth: document.documentElement.scrollWidth,
      docClientWidth: document.documentElement.clientWidth,
      overflowContainers,
      landmarks,
      cards,
      siblingGroups,
      textNodes,
    }
  }, scrollTop)
}

// ============================================================================
// Crawler Runner
// ============================================================================

function sanitizeFileSegment(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80) || 'state'
}

async function applyTheme(page: Page, theme: ThemeMode): Promise<void> {
  await page.evaluate((t: ThemeMode) => {
    try {
      window.localStorage.setItem('kovo-appearance', t)
    } catch {
      // Ignore storage errors
    }
    document.documentElement.dataset.appearance = t
    document.documentElement.dataset.theme = t
  }, theme)
  await delay(120)
}

interface ActiveEventRecorder {
  drain(): RuntimeEventSample
}

function attachRuntimeRecorder(page: Page): ActiveEventRecorder {
  let consoleErrors: string[] = []
  let pageErrors: string[] = []
  let failedRequests: FailedRequestRecord[] = []

  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text())
    }
  })
  page.on('pageerror', err => {
    pageErrors.push(err instanceof Error ? err.message : String(err))
  })
  page.on('response', res => {
    if (res.status() >= 500) {
      failedRequests.push({
        url: res.url(),
        method: res.request().method(),
        status: res.status(),
        resourceType: res.request().resourceType(),
      })
    }
  })
  page.on('requestfailed', req => {
    failedRequests.push({
      url: req.url(),
      method: req.method(),
      errorText: req.failure()?.errorText ?? 'request_failed',
      resourceType: req.resourceType(),
    })
  })

  return {
    drain(): RuntimeEventSample {
      const sample: RuntimeEventSample = {
        consoleErrors,
        pageErrors,
        failedRequests,
      }
      consoleErrors = []
      pageErrors = []
      failedRequests = []
      return sample
    },
  }
}

async function auditCurrentState(
  page: Page,
  recorder: ActiveEventRecorder,
  options: {
    stateId: string
    viewport: ViewportSpec
    theme: ThemeMode
    outDir: string
    captureAllScreenshots: boolean
  },
): Promise<StateAuditResult> {
  const startedAt = Date.now()
  await delay(220) // Allow layout transitions / initial hydration to settle
  const route = (() => {
    try {
      const u = new URL(page.url())
      return `${u.pathname}${u.search}`
    } catch {
      return page.url()
    }
  })()

  const violations: QaViolation[] = []
  const screenshotPaths: string[] = []
  const scrollPositionsChecked: number[] = []

  for (const desiredScroll of [0, 600]) {
    const actualScroll = await scrollViewTo(page, desiredScroll)
    await delay(100)
    scrollPositionsChecked.push(actualScroll)

    const ctx: CheckContext = {
      stateId: options.stateId,
      route,
      viewport: options.viewport.label,
      theme: options.theme,
      scrollTop: actualScroll,
    }
    const snapshot = await collectDomGeometrySnapshot(page, actualScroll)
    const geoViolations = classifyGeometrySnapshot(snapshot, ctx)
    const runtimeViolations = classifyRuntimeEvents(recorder.drain(), ctx)
    const stepViolations = [...geoViolations, ...runtimeViolations]
    violations.push(...stepViolations)

    const shouldCapture = options.captureAllScreenshots || stepViolations.length > 0
    if (shouldCapture) {
      const shotDir = join(options.outDir, 'screenshots')
      await mkdir(shotDir, { recursive: true })
      const shotName = `${sanitizeFileSegment(options.stateId)}_${options.viewport.label}_${options.theme}_y${desiredScroll}.png`
      const shotPath = join(shotDir, shotName)
      await page.screenshot({ path: shotPath, fullPage: false })
      screenshotPaths.push(shotPath)
    }
  }

  // Restore scroll to 0 before next interaction
  await scrollViewTo(page, 0)

  return {
    stateId: options.stateId,
    route,
    viewport: options.viewport.label,
    theme: options.theme,
    scrollPositionsChecked,
    violations,
    screenshotPaths,
    durationMs: Date.now() - startedAt,
  }
}

async function verifyInputStability(
  page: Page,
  selector: string,
  inputLabel: string,
  typedValue: string,
  ctx: CheckContext,
  waitMs = 500,
): Promise<{ result: InputStabilityResult; violations: QaViolation[] }> {
  const locator = page.locator(selector).first()
  await locator.waitFor({ state: 'visible', timeout: 10_000 })
  await locator.click()
  await locator.fill('')
  await locator.type(typedValue, { delay: 12 })
  await delay(waitMs)
  const observedValue = await locator.inputValue()
  const violations = classifyInputStability(typedValue, observedValue, inputLabel, ctx)
  return {
    result: {
      stateId: ctx.stateId,
      inputLabel,
      viewport: ctx.viewport,
      theme: ctx.theme,
      typedValue,
      observedAfterMs: waitMs,
      observedValue,
      stable: violations.length === 0,
    },
    violations,
  }
}

async function runCrawler(options: CrawlerCliOptions): Promise<CrawlerReport> {
  ensureBuilt()
  const { pw, executablePath } = await loadPlaywright()
  await mkdir(options.outDir, { recursive: true })

  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-qa-crawler-db-'))
  const fixture = seedStressFixture(dataDir)
  const server = await startSeededKovoServer(dataDir)

  let browser: Browser | undefined
  let context: BrowserContext | undefined
  const states: StateAuditResult[] = []
  const inputStability: InputStabilityResult[] = []
  const allViolations: QaViolation[] = []

  try {
    browser = await pw.chromium.launch({
      headless: true,
      executablePath,
      args: ['--no-sandbox'],
    })

    context = await browser.newContext({
      viewport: {
        width: options.viewports[0]!.width,
        height: options.viewports[0]!.height,
      },
    })
    const page = await context.newPage()
    const recorder = attachRuntimeRecorder(page)

    // Bootstrap single-use local session once for the browser context
    await page.goto(`${server.origin}/?bootstrap=${encodeURIComponent(server.bootstrapSecret)}`, {
      waitUntil: 'domcontentloaded',
    })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
    recorder.drain() // Discard any pre-hydration noise

    const recordState = (res: StateAuditResult) => {
      states.push(res)
      allViolations.push(...res.violations)
    }

    const recordSmokeError = (stateId: string, viewport: ViewportSpec, theme: ThemeMode, err: unknown) => {
      const v: QaViolation = {
        severity: 'error',
        rule: 'smoke-navigation',
        message: `Navigation/interaction failed in "${stateId}": ${err instanceof Error ? err.message : String(err)}`,
        stateId,
        route: page.url(),
        viewport: viewport.label,
        theme,
        scrollTop: 0,
      }
      allViolations.push(v)
      states.push({
        stateId,
        route: page.url(),
        viewport: viewport.label,
        theme,
        scrollPositionsChecked: [],
        violations: [v],
        screenshotPaths: [],
        durationMs: 0,
      })
    }

    const doProject = scopeSelected(options.only, 'project')
    const doModals = scopeSelected(options.only, 'modals')
    const doRun = scopeSelected(options.only, 'run')
    const doSettings = scopeSelected(options.only, 'settings')

    for (const viewport of options.viewports) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height })

      for (const theme of options.themes) {
        await applyTheme(page, theme)

        // --- 1. PROJECT TABS (+ Inventory search input stability) ---
        if (doProject) {
          const projectUrl = `${server.origin}/projects/${fixture.projectId}`
          try {
            await page.goto(projectUrl, { waitUntil: 'domcontentloaded' })
            await page.getByRole('tablist', { name: 'Project sections' }).waitFor({ state: 'visible', timeout: 15_000 })
            await applyTheme(page, theme)

            const projectTabs: Array<{ id: string; tabRegex: RegExp }> = [
              { id: 'project.overview', tabRegex: /^Overview/ },
              { id: 'project.runs', tabRegex: /^Runs/ },
              { id: 'project.inventory', tabRegex: /^Inventory/ },
              { id: 'project.personas', tabRegex: /^Test Accounts/ },
              { id: 'project.sources', tabRegex: /^Source & Specs/ },
              { id: 'project.guardrails', tabRegex: /^Guardrails & Lab/ },
            ]

            for (const tab of projectTabs) {
              try {
                await page.getByRole('tab', { name: tab.tabRegex }).click()
                await delay(180)
                recordState(await auditCurrentState(page, recorder, {
                  stateId: tab.id,
                  viewport,
                  theme,
                  outDir: options.outDir,
                  captureAllScreenshots: options.screenshots,
                }))

                if (tab.id === 'project.inventory') {
                  const stability = await verifyInputStability(
                    page,
                    'input[aria-label="Search hosts"]',
                    'Inventory search hosts',
                    'billing.acme',
                    {
                      stateId: 'project.inventory',
                      route: `/projects/${fixture.projectId}?tab=inventory`,
                      viewport: viewport.label,
                      theme,
                      scrollTop: 0,
                    },
                    500,
                  )
                  inputStability.push(stability.result)
                  allViolations.push(...stability.violations)
                  // Clear search after test
                  await page.locator('input[aria-label="Search hosts"]').fill('')
                }
              } catch (err) {
                recordSmokeError(tab.id, viewport, theme, err)
              }
            }
          } catch (err) {
            recordSmokeError('project.entry', viewport, theme, err)
          }
        }

        // --- 2. MODALS (Add test account + input stability, New run) ---
        if (doModals) {
          // 2a. Add test account modal
          try {
            await page.goto(`${server.origin}/projects/${fixture.projectId}?tab=personas`, {
              waitUntil: 'domcontentloaded',
            })
            await applyTheme(page, theme)
            await page.getByRole('button', { name: 'Add test account' }).first().click()
            const personaDialog = page.getByRole('dialog')
            await personaDialog.waitFor({ state: 'visible', timeout: 10_000 })

            recordState(await auditCurrentState(page, recorder, {
              stateId: 'modal.add-test-account',
              viewport,
              theme,
              outDir: options.outDir,
              captureAllScreenshots: options.screenshots,
            }))

            const stability = await verifyInputStability(
              page,
              '[role="dialog"] input[name="roleLabel"]',
              'Add test account label',
              'QA Reviewer C',
              {
                stateId: 'modal.add-test-account',
                route: `/projects/${fixture.projectId}?tab=personas`,
                viewport: viewport.label,
                theme,
                scrollTop: 0,
              },
              500,
            )
            inputStability.push(stability.result)
            allViolations.push(...stability.violations)

            await personaDialog.getByRole('button', { name: 'Cancel', exact: true }).click()
            await personaDialog.waitFor({ state: 'hidden', timeout: 5_000 })
          } catch (err) {
            recordSmokeError('modal.add-test-account', viewport, theme, err)
          }

          // 2b. New run modal
          try {
            await page.goto(`${server.origin}/projects/${fixture.projectId}`, {
              waitUntil: 'domcontentloaded',
            })
            await applyTheme(page, theme)
            await page.getByRole('button', { name: 'New run', exact: true }).first().click()
            const newRunDialog = page.getByRole('dialog')
            await newRunDialog.waitFor({ state: 'visible', timeout: 10_000 })

            recordState(await auditCurrentState(page, recorder, {
              stateId: 'modal.new-run',
              viewport,
              theme,
              outDir: options.outDir,
              captureAllScreenshots: options.screenshots,
            }))

            await newRunDialog.getByRole('button', { name: 'Cancel', exact: true }).click()
            await newRunDialog.waitFor({ state: 'hidden', timeout: 5_000 })
          } catch (err) {
            recordSmokeError('modal.new-run', viewport, theme, err)
          }
        }

        // --- 3. RUN VIEWS (consent, overview, workflow, queue, findings, report, Approval leases popover) ---
        if (doRun) {
          const runChecks: Array<{ stateId: string; path: string; waitText?: string }> = [
            { stateId: 'run.consent', path: `/runs/${fixture.runs.scopeReview}?view=overview`, waitText: 'Proposed scope' },
            { stateId: 'run.overview.threat-model', path: `/runs/${fixture.runs.threatModel}?view=overview` },
            { stateId: 'run.overview.fresh-zero-findings', path: `/runs/${fixture.runs.freshRunning}?view=overview` },
            { stateId: 'run.queue', path: `/runs/${fixture.runs.investigation}?view=queue` },
            { stateId: 'run.workflow', path: `/runs/${fixture.runs.investigation}?view=workflow` },
            { stateId: 'run.findings', path: `/runs/${fixture.runs.complete}?view=findings` },
            { stateId: 'run.report', path: `/runs/${fixture.runs.complete}?view=report` },
          ]

          for (const check of runChecks) {
            try {
              await page.goto(`${server.origin}${check.path}`, { waitUntil: 'domcontentloaded' })
              await applyTheme(page, theme)
              if (check.waitText) {
                await page.getByText(check.waitText).first().waitFor({ state: 'visible', timeout: 10_000 })
              } else {
                await page.locator('main[aria-label="Run"]').waitFor({ state: 'visible', timeout: 10_000 })
              }
              recordState(await auditCurrentState(page, recorder, {
                stateId: check.stateId,
                viewport,
                theme,
                outDir: options.outDir,
                captureAllScreenshots: options.screenshots,
              }))
            } catch (err) {
              recordSmokeError(check.stateId, viewport, theme, err)
            }
          }

          // Approval leases popover on the Investigation run (which has 2 active leases)
          try {
            await page.goto(`${server.origin}/runs/${fixture.runs.investigation}?view=queue`, {
              waitUntil: 'domcontentloaded',
            })
            await applyTheme(page, theme)
            await page.locator('main[aria-label="Run"]').waitFor({ state: 'visible', timeout: 10_000 })

            // Open via header Leases pill if visible, otherwise via More actions menu -> Approval leases…
            const directLeasesBtn = page.locator('button[title*="approval leases" i]').first()
            if (await directLeasesBtn.isVisible().catch(() => false)) {
              await directLeasesBtn.click()
            } else {
              await page.getByRole('button', { name: 'More actions', exact: true }).click()
              await page.locator('[role="menu"] button', { hasText: /Approval leases/ }).click()
            }
            await page.getByTestId('approval-leases-list').waitFor({ state: 'visible', timeout: 10_000 })

            recordState(await auditCurrentState(page, recorder, {
              stateId: 'run.popover.approval-leases',
              viewport,
              theme,
              outDir: options.outDir,
              captureAllScreenshots: options.screenshots,
            }))
          } catch (err) {
            recordSmokeError('run.popover.approval-leases', viewport, theme, err)
          }
        }

        // --- 4. SETTINGS ---
        if (doSettings) {
          try {
            await page.goto(`${server.origin}/settings`, { waitUntil: 'domcontentloaded' })
            await applyTheme(page, theme)
            await page.getByRole('heading', { name: 'Settings', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
            recordState(await auditCurrentState(page, recorder, {
              stateId: 'settings.main',
              viewport,
              theme,
              outDir: options.outDir,
              captureAllScreenshots: options.screenshots,
            }))
          } catch (err) {
            recordSmokeError('settings.main', viewport, theme, err)
          }
        }
      }
    }
  } finally {
    if (context) await context.close().catch(() => {})
    if (browser) await browser.close().catch(() => {})
    await server.stop().catch(() => {})
    await rm(dataDir, { recursive: true, force: true }).catch(() => {})
  }

  const byRule: Record<string, number> = {}
  let errorCount = 0
  let warnCount = 0
  for (const v of allViolations) {
    byRule[v.rule] = (byRule[v.rule] ?? 0) + 1
    if (v.severity === 'error') errorCount += 1
    else warnCount += 1
  }

  const inputChecksPassed = inputStability.filter(r => r.stable).length
  const inputChecksFailed = inputStability.length - inputChecksPassed
  const passed = !shouldFailRun(allViolations, options.failOnWarn)

  const report: CrawlerReport = {
    generatedAt: new Date().toISOString(),
    options: {
      only: options.only,
      viewports: options.viewports.map(v => v.label),
      themes: options.themes,
      outDir: options.outDir,
      failOnWarn: options.failOnWarn,
      screenshots: options.screenshots,
    },
    fixture,
    summary: {
      statesVisited: states.length,
      checksExecuted: states.reduce((acc, s) => acc + s.scrollPositionsChecked.length, 0),
      errorCount,
      warnCount,
      inputChecksPassed,
      inputChecksFailed,
      passed,
      byRule,
    },
    inputStability,
    violations: allViolations,
    states,
  }

  const reportPath = join(options.outDir, 'report.json')
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n', 'utf8')
  return report
}

function printHelp(): void {
  console.log([
    'Usage: node scripts/qa-ui-crawler.ts [options]',
    '',
    'Options:',
    '  --only=all|project|run|modals|settings   Selective crawl scope (default: all)',
    '  --viewports=1280x720,1440x900,1024x640   Viewports to audit (default: 1280x720,1440x900)',
    '  --themes=light,dark                      Themes to audit (default: light,dark)',
    '  --out-dir <path>                         Output directory for report.json & screenshots (default: TMPDIR/kovo-qa-ui)',
    '  --fail-on-warn                           Exit 1 on warnings in addition to errors',
    '  --screenshots                            Capture screenshots for all states (default: only on violation)',
    '  -h, --help                               Show this help',
  ].join('\n'))
}

async function main(): Promise<void> {
  const options = parseCliArgs(process.argv.slice(2))
  if (options.help) {
    printHelp()
    return
  }

  const report = await runCrawler(options)
  const { summary } = report
  const statusTag = summary.passed ? 'PASS' : 'FAIL'
  console.log(
    `[qa:ui] ${statusTag} | states=${summary.statesVisited} checks=${summary.checksExecuted} errors=${summary.errorCount} warns=${summary.warnCount} inputs=${summary.inputChecksPassed}/${summary.inputChecksPassed + summary.inputChecksFailed}`,
  )
  console.log(`[qa:ui] report: ${join(options.outDir, 'report.json')}`)

  if (report.violations.length > 0) {
    console.log('[qa:ui] violations by rule:', JSON.stringify(summary.byRule))
    for (const v of report.violations.slice(0, 25)) {
      console.log(`  - [${v.severity}] (${v.rule}) ${v.stateId} @ ${v.viewport} ${v.theme} y=${v.scrollTop}: ${v.message}`)
    }
    if (report.violations.length > 25) {
      console.log(`  ... and ${report.violations.length - 25} more (see report.json)`)
    }
  }

  if (!summary.passed) {
    process.exitCode = 1
  }
}

const isDirectEntry = Boolean(
  process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href,
)

if (isDirectEntry) {
  main().catch(err => {
    console.error('[qa:ui] fatal error:', err instanceof Error ? err.stack ?? err.message : String(err))
    process.exit(1)
  })
}
