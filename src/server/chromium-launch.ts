/**
 * Single authoritative Chromium launch-argument builder and Playwright dynamic loader (R2-22).
 *
 * Shared by `persona-auth.ts`, `browser-session-auth.ts`, and `scoped-browser.ts` so
 * sandboxing, DNS pinning, WebRTC/QUIC hardening, and Playwright resolution error handling
 * never drift across browser entrypoints.
 */

/** Playwright launch options produced by Kovo's authoritative Chromium launch builders. */
export interface PlaywrightChromiumLaunchOptions {
  headless: true
  /**
   * Explicitly passed to Playwright (`chromiumSandbox: true` by default).
   * Playwright silently appends `--no-sandbox` whenever `chromiumSandbox !== true`,
   * so omitting this option disables the Chromium sandbox even when `--no-sandbox`
   * is absent from `args`.
   */
  chromiumSandbox: boolean
  args: string[]
}

export interface ChromiumPlaywrightLauncher<TBrowser> {
  launch: (options: PlaywrightChromiumLaunchOptions) => Promise<TBrowser>
}

export interface ChromiumLaunchArgOptions {
  /** Explicit insecure opt-in (`KOVO_INSECURE_NO_SANDBOX=1`). */
  insecureNoSandbox?: boolean
  /** Optional environment override (used when `insecureNoSandbox` is omitted). */
  env?: NodeJS.ProcessEnv
  /**
   * Optional hostname -> validated addresses map resolved once before launch.
   * Chromium is pinned to the first validated address with `--host-resolver-rules`;
   * every other name fails closed to `~NOTFOUND` while allowing the host loopback proxy (`127.0.0.1`).
   */
  pinnedHosts?: ReadonlyMap<string, readonly string[]>
}

const CHROMIUM_SANDBOX_FAILURE_RE =
  /no usable sandbox|suid sandbox|setuid sandbox|chromium sandboxing failed|crbug\.com\/(?:638180|357670)|failed to move to new namespace|clone_newuser|unprivileged_userns|running as root without --no-sandbox/i

/** Whether `KOVO_INSECURE_NO_SANDBOX=1` explicitly disables Chromium's sandbox. */
export function isInsecureNoSandboxEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.KOVO_INSECURE_NO_SANDBOX === '1'
}

function chromiumResolverTarget(address: string): string {
  const bare = address.replace(/^\[|\]$/g, '')
  return bare.includes(':') ? `[${bare}]` : bare
}

/**
 * Build `--host-resolver-rules` pinning validated hosts (when provided), failing closed
 * for unknown names (`MAP * ~NOTFOUND`), and allowing only the local loopback proxy (`EXCLUDE 127.0.0.1`).
 */
export function buildChromiumResolverRules(
  pinnedHosts?: ReadonlyMap<string, readonly string[]>,
): string {
  const rules: string[] = []
  for (const [host, addresses] of pinnedHosts ?? []) {
    const address = addresses[0]
    if (!host || !address) continue
    rules.push(`MAP ${host} ${chromiumResolverTarget(address)}`)
  }
  rules.push('MAP * ~NOTFOUND')
  rules.push('EXCLUDE 127.0.0.1')
  return rules.join(', ')
}

/**
 * Single authoritative Chromium CLI argument builder.
 * Sandboxing is on by default; `--no-sandbox` is appended ONLY when explicitly opted in.
 */
export function buildChromiumLaunchArgs(options: ChromiumLaunchArgOptions = {}): string[] {
  const insecureNoSandbox =
    options.insecureNoSandbox ?? (options.env !== undefined ? isInsecureNoSandboxEnabled(options.env) : false)
  const args = [
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    `--host-resolver-rules=${buildChromiumResolverRules(options.pinnedHosts)}`,
    // Force even loopback targets through the authenticated host loopback proxy (zero direct bypass).
    '--proxy-bypass-list=<-loopback>',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--webrtc-ip-handling-policy=disable_non_proxied_udp',
    // WebTransport is HTTP/3 over UDP and bypasses HTTP interception and WebRTC flags.
    '--disable-quic',
    '--disable-features=WebTransport',
  ]
  if (insecureNoSandbox) {
    args.push('--no-sandbox')
  }
  return args
}

/**
 * Build the authoritative Playwright `chromium.launch(...)` options.
 * Explicitly sets `chromiumSandbox: true` by default because Playwright silently appends
 * `--no-sandbox` whenever `chromiumSandbox !== true`.
 */
export function buildPlaywrightChromiumLaunchOptions(
  options: ChromiumLaunchArgOptions = {},
): PlaywrightChromiumLaunchOptions {
  const insecureNoSandbox = options.insecureNoSandbox ?? isInsecureNoSandboxEnabled(options.env)
  return {
    headless: true,
    chromiumSandbox: !insecureNoSandbox,
    args: buildChromiumLaunchArgs({
      insecureNoSandbox,
      pinnedHosts: options.pinnedHosts,
    }),
  }
}

/** Detect Chromium/Playwright launch failures caused by missing kernel/userns sandbox support. */
export function isChromiumSandboxFailure(error: unknown): boolean {
  if (!error) return false
  const parts: string[] = []
  if (error instanceof Error) {
    parts.push(error.message)
    const cause = (error as { cause?: unknown }).cause
    if (cause instanceof Error) parts.push(cause.message)
    else if (cause != null) parts.push(String(cause))
  } else {
    parts.push(String(error))
  }
  return CHROMIUM_SANDBOX_FAILURE_RE.test(parts.join('\n'))
}

/** Wrap a Chromium sandbox launch failure into a fail-closed, actionable error. */
export function formatChromiumSandboxError(error: unknown): Error {
  const detail = error instanceof Error ? error.message : String(error ?? 'unknown error')
  return new Error(
    `Chromium sandbox failed to start (chromiumSandbox: true; refusing to fall back to --no-sandbox / refusing to silently retry without sandbox). ` +
      `Enable unprivileged user namespaces (e.g. sysctl kernel.unprivileged_userns_clone=1 or an AppArmor/seccomp container profile permitting userns), ` +
      `or for local development only set KOVO_INSECURE_NO_SANDBOX=1. Underlying error: ${detail}`,
    { cause: error instanceof Error ? error : undefined },
  )
}

/**
 * Dynamically load Playwright's `chromium` launcher, preferring `playwright-core` and falling back
 * to `@playwright/test` ONLY when `playwright-core` itself cannot be resolved (`MODULE_NOT_FOUND` /
 * `ERR_MODULE_NOT_FOUND`). Real runtime/permission/syntax errors are always rethrown.
 */
export async function loadPlaywrightChromium<TBrowser>(deps?: {
  importModule?: (specifier: string) => Promise<unknown>
}): Promise<ChromiumPlaywrightLauncher<TBrowser>> {
  const importMod = deps?.importModule ?? ((specifier: string) => import(/* @vite-ignore */ specifier))
  try {
    const coreMod = await importMod('playwright-core') as {
      chromium?: ChromiumPlaywrightLauncher<TBrowser>
    }
    if (coreMod?.chromium) return coreMod.chromium
  } catch (err) {
    const code = (err as { code?: string } | null)?.code
    if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') {
      throw err
    }
  }
  const pw = await importMod('@playwright/test') as {
    chromium?: ChromiumPlaywrightLauncher<TBrowser>
  }
  if (!pw?.chromium) {
    throw new Error('Playwright chromium launcher is unavailable from both playwright-core and @playwright/test.')
  }
  return pw.chromium
}

/**
 * Shared Playwright Chromium launcher with fail-closed sandbox enforcement.
 * Never silently retries without the sandbox when `chromiumSandbox: true` fails to start.
 */
export async function launchPlaywrightChromium<TBrowser>(
  launchOptions: PlaywrightChromiumLaunchOptions,
  launcher?: ChromiumPlaywrightLauncher<TBrowser>['launch'],
): Promise<TBrowser> {
  if (!launchOptions.chromiumSandbox) {
    console.warn('WARNING: Chromium sandbox disabled (KOVO_INSECURE_NO_SANDBOX=1). Detection fidelity is reduced.')
  } else if (launchOptions.args.some(arg => arg === '--no-sandbox' || arg.startsWith('--no-sandbox='))) {
    throw new Error('Refusing to launch Chromium with --no-sandbox while chromiumSandbox is enabled.')
  }
  let launchFn = launcher
  if (!launchFn) {
    const chromium = await loadPlaywrightChromium<TBrowser>()
    launchFn = opts => chromium.launch(opts)
  }
  try {
    return await launchFn(launchOptions)
  } catch (err) {
    if (launchOptions.chromiumSandbox && isChromiumSandboxFailure(err)) {
      throw formatChromiumSandboxError(err)
    }
    throw err
  }
}
