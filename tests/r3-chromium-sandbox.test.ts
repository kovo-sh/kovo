import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import {
  buildFormChromiumLaunchOptions,
  isChromiumSandboxFailure,
  launchDefaultChromium,
  launchPlaywrightChromium,
  type PlaywrightChromiumLaunchOptions,
  type PlaywrightFormBrowserLike,
} from '../src/server/persona-auth.ts'
import {
  buildChromiumLaunchOptions,
  launchChromium,
  type PlaywrightBrowserLike,
} from '../src/server/scoped-browser.ts'

describe('R3-H-6 Chromium sandbox enforcement', () => {
  test('default launch options in scoped-browser and persona-auth set chromiumSandbox: true without --no-sandbox', () => {
    const pinnedHosts = new Map<string, readonly string[]>([['app.example.com', ['93.184.216.34']]])

    for (const env of [{}, { KOVO_INSECURE_NO_SANDBOX: '' }, { KOVO_INSECURE_NO_SANDBOX: '0' }, { KOVO_INSECURE_NO_SANDBOX: 'true' }]) {
      const scoped = buildChromiumLaunchOptions({ env })
      assert.equal(scoped.headless, true)
      assert.equal(scoped.chromiumSandbox, true)
      assert.equal(scoped.args.some(a => a === '--no-sandbox' || a.startsWith('--no-sandbox=')), false)

      const form = buildFormChromiumLaunchOptions({ pinnedHosts, env })
      assert.equal(form.headless, true)
      assert.equal(form.chromiumSandbox, true)
      assert.equal(form.args.some(a => a === '--no-sandbox' || a.startsWith('--no-sandbox=')), false)
      assert.ok(form.args.some(a => a.includes('MAP app.example.com 93.184.216.34')))
    }
  })

  test('KOVO_INSECURE_NO_SANDBOX=1 explicitly opts into chromiumSandbox: false', t => {
    const prev = process.env.KOVO_INSECURE_NO_SANDBOX
    t.after(() => {
      if (prev === undefined) delete process.env.KOVO_INSECURE_NO_SANDBOX
      else process.env.KOVO_INSECURE_NO_SANDBOX = prev
    })

    process.env.KOVO_INSECURE_NO_SANDBOX = '1'
    const scoped = buildChromiumLaunchOptions()
    assert.equal(scoped.chromiumSandbox, false)
    assert.equal(scoped.args.includes('--no-sandbox'), true)

    const form = buildFormChromiumLaunchOptions()
    assert.equal(form.chromiumSandbox, false)
    assert.equal(form.args.includes('--no-sandbox'), true)

    delete process.env.KOVO_INSECURE_NO_SANDBOX
    assert.equal(buildChromiumLaunchOptions().chromiumSandbox, true)
    assert.equal(buildFormChromiumLaunchOptions().chromiumSandbox, true)
  })

  test('launchChromium and launchDefaultChromium pass chromiumSandbox: true to Playwright by default and false only on opt-in', async () => {
    const scopedCalls: PlaywrightChromiumLaunchOptions[] = []
    const fakeScopedBrowser = { newContext: async () => ({}) as never, close: async () => undefined } as PlaywrightBrowserLike

    await launchChromium({
      env: {},
      launch: async opts => {
        scopedCalls.push(opts)
        return fakeScopedBrowser
      },
    })
    await launchChromium({
      env: { KOVO_INSECURE_NO_SANDBOX: '1' },
      launch: async opts => {
        scopedCalls.push(opts)
        return fakeScopedBrowser
      },
    })

    assert.equal(scopedCalls.length, 2)
    assert.equal(scopedCalls[0]!.chromiumSandbox, true)
    assert.equal(scopedCalls[0]!.args.includes('--no-sandbox'), false)
    assert.equal(scopedCalls[1]!.chromiumSandbox, false)
    assert.equal(scopedCalls[1]!.args.includes('--no-sandbox'), true)

    const formCalls: PlaywrightChromiumLaunchOptions[] = []
    const fakeFormBrowser = { newContext: async () => ({}) as never, close: async () => undefined } as PlaywrightFormBrowserLike
    const pinnedHosts = new Map<string, readonly string[]>([['login.example.com', ['93.184.216.34']]])

    await launchDefaultChromium(pinnedHosts, {
      env: {},
      launch: async opts => {
        formCalls.push(opts)
        return fakeFormBrowser
      },
    })
    await launchDefaultChromium(pinnedHosts, {
      env: { KOVO_INSECURE_NO_SANDBOX: '1' },
      launch: async opts => {
        formCalls.push(opts)
        return fakeFormBrowser
      },
    })

    assert.equal(formCalls.length, 2)
    assert.equal(formCalls[0]!.chromiumSandbox, true)
    assert.equal(formCalls[0]!.args.includes('--no-sandbox'), false)
    assert.ok(formCalls[0]!.args.some(a => a.includes('MAP login.example.com 93.184.216.34')))
    assert.equal(formCalls[1]!.chromiumSandbox, false)
    assert.equal(formCalls[1]!.args.includes('--no-sandbox'), true)
  })

  test('Playwright resolved final Chromium argv omits --no-sandbox when using Kovo launch builders and includes it when chromiumSandbox is omitted', async t => {
    const coreName = 'playwright-core'
    const pw = await import(/* @vite-ignore */ coreName) as {
      chromium: { launch: (opts: Record<string, unknown>) => Promise<unknown> }
    }
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-chromium-argv-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const outFile = join(dir, 'argv.txt')
    const stubPath = join(dir, 'fake-chromium.sh')
    writeFileSync(
      stubPath,
      `#!/usr/bin/env bash\nprintf '%s\\n' "$@" > "${outFile}"\nexit 1\n`,
      { mode: 0o755 },
    )

    const captureFinalArgv = async (opts: Record<string, unknown>): Promise<string[]> => {
      try { unlinkSync(outFile) } catch { /* ignore */ }
      await assert.rejects(() => pw.chromium.launch({ ...opts, executablePath: stubPath }))
      return readFileSync(outFile, 'utf8').trim().split('\n').filter(Boolean)
    }

    // Control: omitting chromiumSandbox causes Playwright to silently append --no-sandbox.
    const omittedArgv = await captureFinalArgv({ headless: true, args: ['--disable-quic'] })
    assert.equal(
      omittedArgv.includes('--no-sandbox'),
      true,
      'Control assertion failed: Playwright should append --no-sandbox when chromiumSandbox is omitted',
    )

    // ScopedBrowser default launch options must NOT have --no-sandbox in final Chromium argv.
    const scopedDefaultArgv = await captureFinalArgv(buildChromiumLaunchOptions({ env: {} }) as unknown as Record<string, unknown>)
    assert.ok(scopedDefaultArgv.length > 0, 'Expected Playwright to invoke the Chromium binary with resolved args')
    assert.equal(
      scopedDefaultArgv.includes('--no-sandbox'),
      false,
      'ScopedBrowser default launch must not include --no-sandbox in Playwright final argv',
    )
    assert.ok(scopedDefaultArgv.includes('--disable-quic'))

    // PersonaAuth default launch options must NOT have --no-sandbox in final Chromium argv.
    const pinnedHosts = new Map<string, readonly string[]>([['auth.example.com', ['93.184.216.34']]])
    const formDefaultArgv = await captureFinalArgv(
      buildFormChromiumLaunchOptions({ pinnedHosts, env: {} }) as unknown as Record<string, unknown>,
    )
    assert.equal(
      formDefaultArgv.includes('--no-sandbox'),
      false,
      'PersonaAuth default launch must not include --no-sandbox in Playwright final argv',
    )
    assert.ok(formDefaultArgv.some(a => a.includes('MAP auth.example.com 93.184.216.34')))

    // Explicit opt-in KOVO_INSECURE_NO_SANDBOX=1 adds --no-sandbox.
    const insecureArgv = await captureFinalArgv(
      buildChromiumLaunchOptions({ env: { KOVO_INSECURE_NO_SANDBOX: '1' } }) as unknown as Record<string, unknown>,
    )
    assert.equal(insecureArgv.includes('--no-sandbox'), true)
  })

  test('sandbox startup failures fail closed with actionable guidance and never silently retry without sandbox', async () => {
    const sandboxErrors = [
      'browserType.launch: Target page, context or browser has been closed\n[FATAL:zygote_host_impl_linux.cc(127)] No usable sandbox! Update your kernel or see https://chromium.googlesource.com/chromium/src/+/main/docs/linux/suid_sandbox_development.md',
      'The SUID sandbox helper binary was found, but is not configured correctly.',
      'Chromium sandboxing failed!\nTo avoid the sandboxing issue, configure your environment',
      'FATAL: Running as root without --no-sandbox is not supported. See https://crbug.com/638180.',
    ]

    for (const rawMsg of sandboxErrors) {
      assert.equal(isChromiumSandboxFailure(new Error(rawMsg)), true)

      let scopedAttempts = 0
      await assert.rejects(
        () => launchChromium({
          env: {},
          launch: async opts => {
            scopedAttempts += 1
            assert.equal(opts.chromiumSandbox, true)
            throw new Error(rawMsg)
          },
        }),
        (err: unknown) => {
          assert.ok(err instanceof Error)
          assert.match(err.message, /refusing to silently retry without sandbox/i)
          assert.match(err.message, /unprivileged user namespaces/i)
          assert.match(err.message, /seccomp/i)
          assert.match(err.message, /KOVO_INSECURE_NO_SANDBOX=1/)
          assert.ok(err.cause instanceof Error)
          return true
        },
      )
      assert.equal(scopedAttempts, 1, 'launchChromium must never silently retry without sandbox')

      let formAttempts = 0
      await assert.rejects(
        () => launchDefaultChromium(undefined, {
          env: {},
          launch: async opts => {
            formAttempts += 1
            assert.equal(opts.chromiumSandbox, true)
            throw new Error(rawMsg)
          },
        }),
        (err: unknown) => {
          assert.ok(err instanceof Error)
          assert.match(err.message, /refusing to silently retry without sandbox/i)
          assert.match(err.message, /KOVO_INSECURE_NO_SANDBOX=1/)
          return true
        },
      )
      assert.equal(formAttempts, 1, 'launchDefaultChromium must never silently retry without sandbox')
    }

    // Non-sandbox errors pass through untouched and without retrying.
    let nonSandboxAttempts = 0
    await assert.rejects(
      () => launchChromium({
        env: {},
        launch: async () => {
          nonSandboxAttempts += 1
          throw new Error('Executable does not exist at /missing/chrome')
        },
      }),
      /Executable does not exist/,
    )
    assert.equal(nonSandboxAttempts, 1)

    // Defense-in-depth: refuse contradictory options where chromiumSandbox is true but --no-sandbox is present.
    let contradictoryAttempts = 0
    await assert.rejects(
      () => launchPlaywrightChromium(
        { headless: true, chromiumSandbox: true, args: ['--no-sandbox'] },
        async () => {
          contradictoryAttempts += 1
          return {}
        },
      ),
      /Refusing to launch Chromium with --no-sandbox while chromiumSandbox is enabled/,
    )
    assert.equal(contradictoryAttempts, 0)
  })

  test('static guard: scoped-browser.ts and persona-auth.ts have no bypass of launchPlaywrightChromium', () => {
    const stripComments = (src: string) =>
      src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
    const scopedSrc = stripComments(readFileSync(new URL('../src/server/scoped-browser.ts', import.meta.url), 'utf8'))
    const personaSrc = stripComments(readFileSync(new URL('../src/server/persona-auth.ts', import.meta.url), 'utf8'))

    // Neither file should call launchPersistentContext or raw *.chromium.launch outside launchPlaywrightChromium.
    assert.equal(/launchPersistentContext\s*\(/.test(scopedSrc), false)
    assert.equal(/launchPersistentContext\s*\(/.test(personaSrc), false)
    assert.equal(/\bchromium\.launch\s*\(/.test(scopedSrc), false)
    assert.equal(/\.chromium\.launch\s*\(/.test(personaSrc), false)
    // Only the single centralized call inside launchPlaywrightChromium should exist.
    const launchMatches = personaSrc.match(/\bchromium\.launch\s*\(/g) ?? []
    assert.equal(launchMatches.length, 1, 'Expected exactly one centralized chromium.launch call in persona-auth.ts')
  })
})
