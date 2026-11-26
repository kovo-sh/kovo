import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { describe, it } from 'node:test'
import {
  classifyGeometrySnapshot,
  classifyInputStability,
  classifyRuntimeEvents,
  detectBrokenCopyTokens,
  isBenignAbortedStream,
  parseCliArgs,
  parseViewportToken,
  rectsOverlap,
  scopeSelected,
  shouldFailRun,
} from '../scripts/qa-ui-crawler.ts'
import type { CheckContext, DomGeometrySnapshot, RectBox } from '../scripts/qa-ui-crawler.ts'

const baseCtx: CheckContext = {
  stateId: 'project.inventory',
  route: '/projects/proj-1?tab=inventory',
  viewport: '1280x720',
  theme: 'light',
  scrollTop: 0,
}

function makeRect(left: number, top: number, width: number, height: number): RectBox {
  return { left, top, right: left + width, bottom: top + height, width, height }
}

function cleanSnapshot(overrides: Partial<DomGeometrySnapshot> = {}): DomGeometrySnapshot {
  return {
    viewport: { width: 1280, height: 720 },
    scrollTop: 0,
    docScrollWidth: 1280,
    docClientWidth: 1280,
    overflowContainers: [
      { label: 'Project inventory', selector: 'section[aria-label="Project inventory"]', scrollWidth: 960, clientWidth: 960, overflowX: 'visible' },
    ],
    landmarks: [
      {
        kind: 'header',
        label: 'Header',
        selector: 'header',
        rect: makeRect(0, 0, 1280, 44),
        visible: true,
        scrollWidth: 1280,
        clientWidth: 1280,
        scrollHeight: 44,
        clientHeight: 44,
        overflowX: 'visible',
        overflowY: 'visible',
      },
      {
        kind: 'tablist',
        label: 'Project sections',
        selector: 'nav[role="tablist"]',
        rect: makeRect(0, 44, 1280, 40),
        visible: true,
        scrollWidth: 600,
        clientWidth: 1280,
        scrollHeight: 40,
        clientHeight: 40,
        overflowX: 'visible',
        overflowY: 'visible',
      },
      {
        kind: 'button',
        label: 'New run',
        selector: 'button',
        rect: makeRect(1140, 9, 88, 26),
        visible: true,
        isPrimaryCta: true,
        scrollWidth: 88,
        clientWidth: 88,
        scrollHeight: 26,
        clientHeight: 26,
        overflowX: 'hidden',
        overflowY: 'hidden',
      },
    ],
    cards: [],
    siblingGroups: [
      {
        containerLabel: 'nav[role="tablist"]',
        items: [
          { label: 'Overview', tag: 'button', rect: makeRect(20, 50, 72, 26) },
          { label: 'Runs', tag: 'button', rect: makeRect(96, 50, 58, 26) },
          { label: 'Inventory', tag: 'button', rect: makeRect(158, 50, 82, 26) },
        ],
      },
    ],
    textNodes: [
      { text: 'Acme Enterprise SaaS', tag: 'h1', isCodeElement: false },
      { text: 'Approved in scope (24)', tag: 'h3', isCodeElement: false },
    ],
    ...overrides,
  }
}

describe('qa-ui-crawler CLI parser', () => {
  it('applies documented defaults when no flags are passed', () => {
    const opts = parseCliArgs([], { TMPDIR: '/tmp/qa-test-env' })
    assert.deepEqual(opts.only, ['all'])
    assert.deepEqual(opts.viewports.map(v => v.label), ['1280x720', '1440x900'])
    assert.deepEqual(opts.themes, ['light', 'dark'])
    assert.equal(opts.outDir, resolve('/tmp/qa-test-env/kovo-qa-ui'))
    assert.equal(opts.failOnWarn, false)
    assert.equal(opts.screenshots, false)
    assert.equal(opts.help, false)
  })

  it('parses selective flags with both = and space syntax', () => {
    const opts = parseCliArgs([
      '--only=project',
      '--viewports=1280x720,1024x640',
      '--themes=dark',
      '--out-dir',
      '/tmp/custom-qa-out',
      '--fail-on-warn',
      '--screenshots',
    ])
    assert.deepEqual(opts.only, ['project'])
    assert.deepEqual(opts.viewports, [
      { width: 1280, height: 720, label: '1280x720' },
      { width: 1024, height: 640, label: '1024x640' },
    ])
    assert.deepEqual(opts.themes, ['dark'])
    assert.equal(opts.outDir, resolve('/tmp/custom-qa-out'))
    assert.equal(opts.failOnWarn, true)
    assert.equal(opts.screenshots, true)
    assert.equal(scopeSelected(opts.only, 'project'), true)
    assert.equal(scopeSelected(opts.only, 'run'), false)
  })

  it('rejects invalid scopes, themes, viewports, and unknown flags', () => {
    assert.throws(() => parseCliArgs(['--only=bogus']), /Invalid --only scope/)
    assert.throws(() => parseCliArgs(['--themes=sepia']), /Invalid --themes entry/)
    assert.throws(() => parseViewportToken('wide'), /Invalid viewport/)
    assert.throws(() => parseViewportToken('100x100'), /too small/)
    assert.throws(() => parseCliArgs(['--unknown-flag']), /Unknown CLI argument/)
  })
})

describe('qa-ui-crawler geometry & anomaly classifiers', () => {
  it('passes a clean geometry snapshot with zero violations', () => {
    const violations = classifyGeometrySnapshot(cleanSnapshot(), baseCtx)
    assert.deepEqual(violations, [])
    assert.equal(shouldFailRun(violations, false), false)
  })

  it('catches 0px collapsed tablists and <20px squashed buttons', () => {
    const snap = cleanSnapshot({
      landmarks: [
        {
          kind: 'tablist',
          label: 'Project sections',
          selector: 'nav[role="tablist"]',
          rect: makeRect(0, 44, 1280, 0),
          visible: true,
          scrollWidth: 1280,
          clientWidth: 1280,
          scrollHeight: 0,
          clientHeight: 0,
          overflowX: 'visible',
          overflowY: 'visible',
        },
        {
          kind: 'button',
          label: 'Squashed CTA',
          selector: 'button',
          rect: makeRect(20, 100, 100, 16),
          visible: true,
          scrollWidth: 100,
          clientWidth: 100,
          scrollHeight: 16,
          clientHeight: 16,
          overflowX: 'hidden',
          overflowY: 'hidden',
        },
      ],
    })
    const violations = classifyGeometrySnapshot(snap, baseCtx)
    const collapsed = violations.filter(v => v.rule === 'collapsed-control')
    assert.equal(collapsed.length, 2)
    assert.match(collapsed[0]!.message, /tablist/)
    assert.match(collapsed[1]!.message, /Squashed CTA/)
  })

  it('catches horizontal overflow on document and non-scrollable containers while allowing overflow-x-auto', () => {
    const snap = cleanSnapshot({
      docScrollWidth: 1320,
      docClientWidth: 1280,
      overflowContainers: [
        { label: 'Scrollable table', selector: 'div', scrollWidth: 1600, clientWidth: 900, overflowX: 'auto' },
        { label: 'Broken modal body', selector: '[data-slot="dialog-body"]', scrollWidth: 740, clientWidth: 600, overflowX: 'hidden' },
      ],
    })
    const violations = classifyGeometrySnapshot(snap, baseCtx)
    const overflow = violations.filter(v => v.rule === 'horizontal-overflow')
    assert.equal(overflow.length, 2)
    assert.match(overflow[0]!.message, /Document horizontal overflow/)
    assert.match(overflow[1]!.message, /Broken modal body/)
  })

  it('catches vertically clipped text on buttons and cards', () => {
    const snap = cleanSnapshot({
      landmarks: [
        {
          kind: 'button',
          label: 'Wrapped mode button',
          selector: 'button',
          rect: makeRect(20, 100, 120, 26),
          visible: true,
          scrollWidth: 120,
          clientWidth: 120,
          scrollHeight: 48,
          clientHeight: 26,
          overflowX: 'hidden',
          overflowY: 'hidden',
        },
      ],
      cards: [
        {
          label: 'Supervised Scan card',
          selector: '[role="radio"]',
          rect: makeRect(20, 150, 200, 40),
          scrollWidth: 200,
          clientWidth: 200,
          scrollHeight: 72,
          clientHeight: 40,
          overflowX: 'hidden',
          overflowY: 'hidden',
        },
      ],
    })
    const violations = classifyGeometrySnapshot(snap, baseCtx)
    const clipped = violations.filter(v => v.rule === 'clipped-text')
    assert.equal(clipped.length, 2)
  })

  it('catches overlapping sibling interactive controls and ignores adjacent controls', () => {
    assert.equal(rectsOverlap(makeRect(0, 0, 100, 30), makeRect(100, 0, 100, 30)).overlaps, false)
    assert.equal(rectsOverlap(makeRect(0, 0, 100, 30), makeRect(85, 10, 100, 30)).overlaps, true)

    const snap = cleanSnapshot({
      siblingGroups: [
        {
          containerLabel: 'div.actions',
          items: [
            { label: 'Cancel', tag: 'button', rect: makeRect(500, 600, 90, 32) },
            { label: 'Save test account', tag: 'button', rect: makeRect(560, 600, 140, 32) },
          ],
        },
      ],
    })
    const violations = classifyGeometrySnapshot(snap, baseCtx)
    const overlaps = violations.filter(v => v.rule === 'sibling-overlap')
    assert.equal(overlaps.length, 1)
    assert.match(overlaps[0]!.message, /Cancel.*Save test account/)
  })

  it('catches primary CTA and dialog outside viewport bounds', () => {
    const snap = cleanSnapshot({
      landmarks: [
        {
          kind: 'dialog',
          label: 'New run',
          selector: '[role="dialog"]',
          rect: makeRect(400, 50, 950, 720),
          visible: true,
          scrollWidth: 950,
          clientWidth: 950,
          scrollHeight: 720,
          clientHeight: 720,
          overflowX: 'hidden',
          overflowY: 'hidden',
        },
        {
          kind: 'button',
          label: 'Start run',
          selector: 'button',
          rect: makeRect(1100, 740, 110, 32),
          visible: true,
          isPrimaryCta: true,
          insideDialog: true,
          scrollWidth: 110,
          clientWidth: 110,
          scrollHeight: 32,
          clientHeight: 32,
          overflowX: 'hidden',
          overflowY: 'hidden',
        },
      ],
    })
    const violations = classifyGeometrySnapshot(snap, baseCtx)
    assert.equal(violations.some(v => v.rule === 'dialog-outside-viewport'), true)
    assert.equal(violations.some(v => v.rule === 'cta-outside-viewport'), true)
  })

  it('detects standalone broken copy tokens without false positives on normal words or JSON null in code blocks', () => {
    const hits = detectBrokenCopyTokens([
      { text: 'Nullable field check passed cleanly', tag: 'p', isCodeElement: false },
      { text: 'User undefined · 0 findings', tag: 'span', isCodeElement: false },
      { text: 'null', tag: 'td', isCodeElement: false },
      { text: 'Score: NaN%', tag: 'span', isCodeElement: false },
      { text: 'Header: [object Object]', tag: 'div', isCodeElement: false },
      { text: '{"optional": null}', tag: 'code', isCodeElement: true },
      { text: '{"broken": undefined}', tag: 'code', isCodeElement: true },
    ])
    assert.deepEqual(
      hits.map(h => h.token),
      ['undefined', 'null', 'NaN', '[object Object]', 'undefined'],
    )
  })

  it('classifies console.error, pageerror, 5xx, and failed fetches while ignoring benign aborted SSE streams', () => {
    assert.equal(
      isBenignAbortedStream({
        url: 'http://127.0.0.1:4123/api/runs/abc/events',
        method: 'GET',
        errorText: 'net::ERR_ABORTED',
        resourceType: 'eventsource',
      }),
      true,
    )
    const violations = classifyRuntimeEvents(
      {
        consoleErrors: ['Hydration mismatch'],
        pageErrors: ['TypeError: Cannot read properties of undefined'],
        failedRequests: [
          { url: 'http://127.0.0.1:4123/api/runs/abc/events', method: 'GET', errorText: 'net::ERR_ABORTED', resourceType: 'eventsource' },
          { url: 'http://127.0.0.1:4123/_serverFn/projectData', method: 'POST', status: 500 },
          { url: 'http://127.0.0.1:4123/_kovo/auth/status', method: 'GET', errorText: 'net::ERR_CONNECTION_REFUSED', resourceType: 'fetch' },
        ],
      },
      baseCtx,
    )
    assert.deepEqual(
      violations.map(v => v.rule),
      ['console-error', 'page-error', 'http-5xx', 'failed-fetch'],
    )
  })

  it('classifies input stability and fail-on-warn exit semantics', () => {
    assert.deepEqual(classifyInputStability('billing.acme', 'billing.acme', 'Search hosts', baseCtx), [])
    const clobbered = classifyInputStability('billing.acme', '', 'Search hosts', baseCtx)
    assert.equal(clobbered.length, 1)
    assert.equal(clobbered[0]!.rule, 'input-clobbered')

    const warnOnly = [{ ...clobbered[0]!, severity: 'warn' as const }]
    assert.equal(shouldFailRun(warnOnly, false), false)
    assert.equal(shouldFailRun(warnOnly, true), true)
    assert.equal(shouldFailRun(clobbered, false), true)
  })

  it('ignores non-primary secondary buttons below the fold while still checking primary CTAs at scrollTop=0', () => {
    const snap = cleanSnapshot({
      landmarks: [
        {
          kind: 'button',
          label: 'Save',
          selector: 'button',
          rect: makeRect(40, 920, 80, 28),
          visible: true,
          isPrimaryCta: false,
          scrollWidth: 80,
          clientWidth: 80,
          scrollHeight: 28,
          clientHeight: 28,
          overflowX: 'hidden',
          overflowY: 'hidden',
        },
      ],
    })
    assert.deepEqual(classifyGeometrySnapshot(snap, baseCtx), [])
  })
})
