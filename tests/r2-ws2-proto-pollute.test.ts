import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'
import { BrokerDenied } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from '../src/server/broker.ts'
import {
  assertSafeParamName,
  hasForbiddenProtoSegment,
  injectUniversalParam,
  isForbiddenProtoSegment,
  setJsonPath,
  surfaceParamLocations,
  toSafeJsonContainer,
} from '../src/server/probes/context.ts'
import type { DiffContext, ProbeRuntime } from '../src/server/probes/context.ts'
import { diffMassAssignment } from '../src/server/probes/mass-assignment.ts'
import { probeDifferential, probeSurface } from '../src/server/surface-engine.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const DUNDER_PROTO = `${'__'}proto${'__'}`
const CTOR = 'constructor'
const PROTO = 'prototype'
const MARKER = 'r2Ws2CanaryFlag'

const DISALLOWED_PATHS = [
  DUNDER_PROTO,
  CTOR,
  PROTO,
  `${DUNDER_PROTO}.${MARKER}`,
  `${CTOR}.${PROTO}.${MARKER}`,
  `nested.${DUNDER_PROTO}.${MARKER}`,
  `nested.${CTOR}.${PROTO}.${MARKER}`,
  `a.b.${DUNDER_PROTO}`,
  `a.b.${CTOR}`,
  `a.b.${PROTO}`,
  `${DUNDER_PROTO}[${MARKER}]`,
  `a[${CTOR}][${PROTO}][${MARKER}]`,
]

function assertCleanObjectPrototype() {
  assert.strictEqual((Object.prototype as Record<string, unknown>)[MARKER], undefined)
  assert.strictEqual(({} as Record<string, unknown>)[MARKER], undefined)
  assert.strictEqual(({} as Record<string, unknown>).allowLocalLab, undefined)
  assert.deepStrictEqual(Object.keys(Object.prototype), [])
}

function makeRecordingBroker(responder?: (req: BrokerHttpRequest) => Partial<BrokerExchangeResult>) {
  const sent: BrokerHttpRequest[] = []
  const broker = {
    async executeHttp(req: BrokerHttpRequest): Promise<BrokerExchangeResult> {
      sent.push(req)
      const override = responder?.(req) ?? {}
      return {
        exchangeId: `ex-${sent.length}`,
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"ok":true,"role":"user"}',
        bodyBytes: 25,
        bodySha256: `sha-${sent.length}`,
        mediaType: 'application/json',
        durationMs: 1,
        method: req.method ?? 'GET',
        url: `${req.origin}${req.pathAndQuery}`,
        ...override,
      } as BrokerExchangeResult
    },
  } as unknown as RequestBroker
  const grant = {
    tier: 2,
    approvedOrigins: ['https://example.test'],
    environment: 'public',
    capabilityTier: 2,
    canRead: (origin: string) => origin === 'https://example.test',
    audit: () => undefined,
  } as unknown as Grant
  return { broker, grant, sent }
}

test('R2-C-2: segment helpers reject reserved object accessor keys and accept normal dotted paths', () => {
  assert.strictEqual(isForbiddenProtoSegment(DUNDER_PROTO), true)
  assert.strictEqual(isForbiddenProtoSegment(CTOR), true)
  assert.strictEqual(isForbiddenProtoSegment(PROTO), true)
  assert.strictEqual(isForbiddenProtoSegment('user'), false)

  for (const bad of DISALLOWED_PATHS) {
    assert.strictEqual(hasForbiddenProtoSegment(bad), true, `expected rejection for ${bad}`)
    assert.throws(() => assertSafeParamName(bad), BrokerDenied, `expected BrokerDenied for ${bad}`)
  }

  for (const good of ['q', 'user.profile.name', 'items.0.title', 'filter[status]', 'x-request-mode']) {
    assert.strictEqual(hasForbiddenProtoSegment(good), false, `expected acceptance for ${good}`)
    assert.doesNotThrow(() => assertSafeParamName(good))
  }
  assertCleanObjectPrototype()
})

test('R2-C-2: setJsonPath blocks reserved prototype keys at every depth and preserves safe dotted paths', () => {
  for (const bad of DISALLOWED_PATHS) {
    const target: Record<string, unknown> = {}
    assert.throws(() => setJsonPath(target, bad, true), BrokerDenied, `setJsonPath should reject ${bad}`)
    assertCleanObjectPrototype()
  }

  // Empty segments and excessive nesting depth are also rejected.
  assert.throws(() => setJsonPath({}, '', 'v'), BrokerDenied)
  assert.throws(() => setJsonPath({}, 'a..b', 'v'), BrokerDenied)
  assert.throws(() => setJsonPath({}, '.a', 'v'), BrokerDenied)
  assert.throws(() => setJsonPath({}, Array.from({ length: 40 }, (_, i) => `k${i}`).join('.'), 'v'), BrokerDenied)

  // Normal dotted and indexed paths build null-prototype intermediate containers and serialize cleanly.
  const target: Record<string, unknown> = Object.create(null) as Record<string, unknown>
  setJsonPath(target, 'user.profile.name', 'alice')
  setJsonPath(target, 'user.tags.0.label', 'staff')
  assert.strictEqual(Object.getPrototypeOf(target.user), null)
  assert.strictEqual(Object.getPrototypeOf((target.user as Record<string, unknown>).profile), null)
  assert.deepStrictEqual(JSON.parse(JSON.stringify(target)), {
    user: {
      profile: { name: 'alice' },
      tags: [{ label: 'staff' }],
    },
  })
  assertCleanObjectPrototype()
})

test('R2-C-2: injectUniversalParam rejects reserved prototype paths across all parameter locations', () => {
  const probePaths = [
    `${DUNDER_PROTO}.${MARKER}`,
    `${DUNDER_PROTO}.allowLocalLab`,
    `${CTOR}.${PROTO}.${MARKER}`,
    `profile.${DUNDER_PROTO}.${MARKER}`,
    `profile.${CTOR}.${PROTO}.${MARKER}`,
  ]

  for (const location of surfaceParamLocations) {
    for (const badParam of probePaths) {
      assert.throws(
        () =>
          injectUniversalParam({
            pathAndQuery: '/api/settings',
            param: badParam,
            paramLocation: location,
            value: true,
            method: 'POST',
          }),
        BrokerDenied,
        `expected BrokerDenied for location=${location} param=${badParam}`,
      )
      assertCleanObjectPrototype()
    }
  }

  // Safe normal dotted paths work cleanly in json and graphql_var and sanitize untrusted jsonBody keys.
  const untrustedJsonBody = JSON.parse(`{"${DUNDER_PROTO}":{"${MARKER}":true},"existing":"ok"}`) as Record<string, unknown>
  const jsonReq = injectUniversalParam({
    pathAndQuery: '/api/profile',
    param: 'user.profile.name',
    paramLocation: 'json',
    value: 'alice',
    method: 'PATCH',
    jsonBody: untrustedJsonBody,
  })
  assert.deepStrictEqual(JSON.parse(jsonReq.body ?? '{}'), {
    existing: 'ok',
    user: { profile: { name: 'alice' } },
  })

  const gqlReq = injectUniversalParam({
    pathAndQuery: '/graphql',
    param: 'input.profile.name',
    paramLocation: 'graphql_var',
    value: 'bob',
    jsonBody: untrustedJsonBody,
  })
  const parsedGql = JSON.parse(gqlReq.body ?? '{}') as { variables: Record<string, unknown> }
  assert.deepStrictEqual(parsedGql.variables, {
    input: { profile: { name: 'bob' } },
  })

  // toSafeJsonContainer strips reserved keys recursively and returns null-prototype objects.
  const safeClone = toSafeJsonContainer(untrustedJsonBody) as Record<string, unknown>
  assert.strictEqual(Object.getPrototypeOf(safeClone), null)
  assert.strictEqual(Object.hasOwn(safeClone, DUNDER_PROTO), false)
  assert.strictEqual(safeClone.existing, 'ok')
  assertCleanObjectPrototype()
})

test('R2-C-2: probeDifferential and diffMassAssignment block reserved field names before any network send', async () => {
  const { broker, grant, sent } = makeRecordingBroker()
  const ac = new AbortController()

  await assert.rejects(
    () =>
      probeDifferential(
        {
          probeClass: 'sqli_boolean',
          origin: 'https://example.test',
          pathAndQuery: '/api/items',
          param: `${DUNDER_PROTO}.${MARKER}`,
          paramLocation: 'json',
        },
        broker,
        grant,
        undefined,
        ac.signal,
      ),
    BrokerDenied,
  )
  assert.strictEqual(sent.length, 0)

  await assert.rejects(
    () =>
      probeDifferential(
        {
          probeClass: 'mass_assignment',
          origin: 'https://example.test',
          pathAndQuery: '/api/users/me',
          candidateFields: [`${CTOR}.${PROTO}.isAdmin`],
          paramLocation: 'json',
        },
        broker,
        grant,
        undefined,
        ac.signal,
      ),
    BrokerDenied,
  )
  assert.strictEqual(sent.length, 0)

  // Direct diffMassAssignment call also rejects reserved candidateFields without touching Object.prototype.
  let directSends = 0
  const fakeRunner: ProbeRuntime = {
    stopReason: null,
    async send() {
      directSends += 1
      return { ok: false, kind: 'error', message: 'unused' }
    },
    stage: () => undefined,
    stop() {
      throw new Error('stopped')
    },
  }
  const directCtx: DiffContext = {
    req: {
      probeClass: 'mass_assignment',
      origin: 'https://example.test',
      pathAndQuery: '/api/users/me',
      candidateFields: [`nested.${DUNDER_PROTO}.isAdmin`],
      paramLocation: 'json',
    },
    origin: 'https://example.test',
    runner: fakeRunner,
    notes: [],
    anomalies: [],
    send: async () => {
      directSends += 1
      return null
    },
  }
  await assert.rejects(() => diffMassAssignment(directCtx), BrokerDenied)
  assert.strictEqual(directSends, 0)
  assertCleanObjectPrototype()
})

test('R2-C-2: probeSurface params mode filters reserved prototype keys and uses null-prototype bodies', async () => {
  const { broker, grant, sent } = makeRecordingBroker()
  const ac = new AbortController()
  const result = await probeSurface(
    {
      mode: 'params',
      origin: 'https://example.test',
      basePath: '/api/search',
      paramLocation: 'json',
      params: [DUNDER_PROTO, CTOR, PROTO, `${DUNDER_PROTO}.${MARKER}`, 'user.profile.name'],
      maxRequests: 10,
    },
    broker,
    grant,
    ac.signal,
  )
  assert.strictEqual(result.candidates, 1)
  for (const req of sent) {
    if (!req.body) continue
    assert.strictEqual(req.body.includes(DUNDER_PROTO), false)
    assert.strictEqual(req.body.includes(CTOR), false)
    assert.strictEqual(req.body.includes(PROTO), false)
  }
  assertCleanObjectPrototype()
})

test('WS-2: hardened Node flags pass serve/cli startup self-check, seal Object.prototype, and bound backtracking regexes under 50 ms', () => {
  const hardenedFlags = [
    '--disable-proto=delete',
    '--enable-experimental-regexp-engine-on-excessive-backtracks',
    '--regexp-backtracks-before-fallback=10000',
  ]

  // Verify serve.ts + cli.ts hardening self-checks succeed under required flags and seal Object.prototype.
  const script = `
    import { hardenHostProcess } from './scripts/serve.ts';
    import { hardenCliProcess } from './scripts/cli.ts';
    const hostStatus = hardenHostProcess({ requireFlags: true, quiet: true });
    const cliStatus = hardenCliProcess({ requireFlags: true, quiet: true });
    let addBlocked = false;
    try { Object.prototype.${MARKER} = true; } catch { addBlocked = true; }
    const parsed = JSON.parse('{"${DUNDER_PROTO}":{"${MARKER}":true}}');
    Object.assign({}, parsed);
    const t0 = performance.now();
    /(a+)+b/.test('a'.repeat(35) + '!');
    const regexMs = performance.now() - t0;
    console.log(JSON.stringify({
      hostStatus,
      cliStatus,
      addBlocked,
      protoDescUndefined: Object.getOwnPropertyDescriptor(Object.prototype, '${DUNDER_PROTO}') === undefined,
      dunderProtoRead: ({}).${DUNDER_PROTO},
      sealed: Object.isSealed(Object.prototype),
      canaryAfter: ({}).${MARKER},
      regexMs,
    }));
  `
  const stdout = execFileSync(process.execPath, [...hardenedFlags, '--input-type=module', '-e', script], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 15_000,
  })
  const parsed = JSON.parse(stdout.trim()) as {
    hostStatus: {
      prototypeClean: boolean
      prototypeSealed: boolean
      disableProtoDelete: boolean
      linearRegexpFallback: boolean
      regexpSelfCheckMs: number
      warnings: string[]
    }
    cliStatus: {
      prototypeClean: boolean
      prototypeSealed: boolean
      disableProtoDelete: boolean
      linearRegexpFallback: boolean
      regexpSelfCheckMs: number
      warnings: string[]
    }
    addBlocked: boolean
    protoDescUndefined: boolean
    dunderProtoRead: unknown
    sealed: boolean
    canaryAfter: unknown
    regexMs: number
  }

  assert.strictEqual(parsed.hostStatus.prototypeClean, true)
  assert.strictEqual(parsed.hostStatus.prototypeSealed, true)
  assert.strictEqual(parsed.hostStatus.disableProtoDelete, true)
  assert.strictEqual(parsed.hostStatus.linearRegexpFallback, true)
  assert.ok(parsed.hostStatus.regexpSelfCheckMs < 50, `expected self-check < 50ms, got ${parsed.hostStatus.regexpSelfCheckMs}`)
  assert.deepStrictEqual(parsed.hostStatus.warnings, [])

  assert.strictEqual(parsed.cliStatus.prototypeClean, true)
  assert.strictEqual(parsed.cliStatus.prototypeSealed, true)
  assert.strictEqual(parsed.cliStatus.disableProtoDelete, true)
  assert.strictEqual(parsed.cliStatus.linearRegexpFallback, true)
  assert.deepStrictEqual(parsed.cliStatus.warnings, [])

  assert.strictEqual(parsed.addBlocked, true)
  assert.strictEqual(parsed.protoDescUndefined, true)
  assert.strictEqual(parsed.dunderProtoRead, undefined)
  assert.strictEqual(parsed.sealed, true)
  assert.strictEqual(parsed.canaryAfter, undefined)
  assert.ok(parsed.regexMs < 50, `expected exponential regex < 50ms under linear fallback, got ${parsed.regexMs}`)

  // Verify scripts/cli.ts runs cleanly under the hardened flags.
  const cliHelp = execFileSync(process.execPath, [...hardenedFlags, 'scripts/cli.ts', '--help'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 15_000,
  })
  assert.match(cliHelp, /Kovo Headless Security Scanner CLI/)

  // Verify Dockerfile enables Node hardening flags and enforces startup self-check.
  const dockerfile = readFileSync(resolve(REPO_ROOT, 'Dockerfile'), 'utf8')
  assert.match(dockerfile, /KOVO_REQUIRE_HARDENED_NODE=1/)
  assert.match(dockerfile, /--disable-proto=delete/)
  assert.doesNotMatch(dockerfile, /--disable-proto=throw/)
  assert.match(dockerfile, /--enable-experimental-regexp-engine-on-excessive-backtracks/)
  assert.match(dockerfile, /--regexp-backtracks-before-fallback=10000/)
})

test('WS-2 regression: hardened Node flags allow playwright-core formatCallLog errors without ERR_PROTO_ACCESS while blocking __proto__ pollution', () => {
  const hardenedFlags = [
    '--disable-proto=delete',
    '--enable-experimental-regexp-engine-on-excessive-backtracks',
    '--regexp-backtracks-before-fallback=10000',
  ]

  const script = `
    import { createRequire } from 'node:module';
    import { hardenHostProcess } from './scripts/serve.ts';
    const status = hardenHostProcess({ requireFlags: true, quiet: true });
    const require = createRequire(import.meta.url);
    const { chromium } = require('playwright-core');
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage();
      let clickErr = null;
      try {
        await page.locator('#r2-ws2-nonexistent-selector').click({ timeout: 50 });
      } catch (err) {
        clickErr = {
          name: err?.name ?? null,
          code: err?.code ?? null,
          message: err?.message ?? String(err),
        };
      }
      let gotoErr = null;
      try {
        await page.goto('http://127.0.0.1:1', { timeout: 250 });
      } catch (err) {
        gotoErr = {
          name: err?.name ?? null,
          code: err?.code ?? null,
          message: err?.message ?? String(err),
        };
      }
      const pollutedAttempt = JSON.parse('{"${DUNDER_PROTO}":{"${MARKER}":true}}');
      Object.assign({}, pollutedAttempt);
      console.log(JSON.stringify({
        status,
        clickErr,
        gotoErr,
        dunderProto: ({}).${DUNDER_PROTO},
        canary: ({}).${MARKER},
        sealed: Object.isSealed(Object.prototype),
        protoKeys: Object.keys(Object.prototype),
      }));
    } finally {
      await browser.close();
    }
  `

  const stdout = execFileSync(process.execPath, [...hardenedFlags, '--input-type=module', '-e', script], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 30_000,
  })
  const parsed = JSON.parse(stdout.trim()) as {
    status: {
      disableProtoDelete: boolean
      prototypeSealed: boolean
      warnings: string[]
    }
    clickErr: { name: string | null; code: string | null; message: string } | null
    gotoErr: { name: string | null; code: string | null; message: string } | null
    dunderProto: unknown
    canary: unknown
    sealed: boolean
    protoKeys: string[]
  }

  assert.strictEqual(parsed.status.disableProtoDelete, true)
  assert.strictEqual(parsed.status.prototypeSealed, true)
  assert.deepStrictEqual(parsed.status.warnings, [])

  assert.ok(parsed.clickErr, 'expected selector timeout error')
  assert.strictEqual(parsed.clickErr.name, 'TimeoutError')
  assert.notStrictEqual(parsed.clickErr.code, 'ERR_PROTO_ACCESS')
  assert.doesNotMatch(parsed.clickErr.message, /ERR_PROTO_ACCESS|--disable-proto=throw/)
  assert.match(parsed.clickErr.message, /Call log:/)

  assert.ok(parsed.gotoErr, 'expected unsafe-port navigation error')
  assert.notStrictEqual(parsed.gotoErr.code, 'ERR_PROTO_ACCESS')
  assert.doesNotMatch(parsed.gotoErr.message, /ERR_PROTO_ACCESS|--disable-proto=throw/)
  assert.match(parsed.gotoErr.message, /Call log:/)

  assert.strictEqual(parsed.dunderProto, undefined)
  assert.strictEqual(parsed.canary, undefined)
  assert.strictEqual(parsed.sealed, true)
  assert.deepStrictEqual(parsed.protoKeys, [])
})
