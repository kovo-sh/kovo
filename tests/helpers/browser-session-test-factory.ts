/**
 * R3-08 Test-Only Browser Session Refresher Factory.
 *
 * Production `refreshBrowserSession(...)` requires explicit host-derived security inputs
 * (`scopePolicy`, `requireScopePolicy: true`, `modifiedPaths`, `verifyPathModifiedByRun`) with
 * zero optional bypasses or `allowUnscopedRefreshForTest` switches.
 *
 * Unit tests that exercise lower-level refresher behavior directly may use this helper to
 * construct a scoped synthetic `ScopePolicy` and default run-modification guard inputs.
 *
 * Boundary invariant (enforced statically by `scripts/check-security-optional.ts` and
 * `tests/security-entry-guards.test.ts`): NO file under `src/` may ever import this helper
 * or any module under `tests/`.
 */
import {
  refreshBrowserSession,
  type RefreshBrowserSessionOptions,
  type RefreshedBrowserSession,
} from '../../src/server/browser-session-auth.ts'
import type { ScopePolicy } from '../../src/server/scope-policy.ts'

export type TestRefreshBrowserSessionOptions = Omit<
  RefreshBrowserSessionOptions,
  'scopePolicy' | 'requireScopePolicy' | 'modifiedPaths' | 'verifyPathModifiedByRun'
> & {
  scopePolicy?: ScopePolicy
  modifiedPaths?: readonly string[] | ReadonlySet<string>
  verifyPathModifiedByRun?: boolean
}

export function buildTestBrowserRefreshScopePolicy(params: {
  targetOrigin: string
  originAllowlist?: readonly string[]
  idpOrigins?: readonly string[]
  allowLocalLab?: boolean
  routeDenylist?: readonly string[]
}): ScopePolicy {
  const targetOrigin = new URL(params.targetOrigin.trim()).origin
  const targetOrigins = [...new Set([targetOrigin, ...(params.originAllowlist ?? [])])]
  return {
    mode: params.allowLocalLab ? 'ephemeral_lab' : 'staging_isolated',
    targetOrigins,
    authOrigins: [...new Set(params.idpOrigins ?? [])],
    ...(params.routeDenylist ? { routeDenylist: [...params.routeDenylist] } : {}),
  }
}

export function createTestBrowserRefreshOptions(
  options: TestRefreshBrowserSessionOptions,
): RefreshBrowserSessionOptions {
  const scopePolicy = options.scopePolicy ?? buildTestBrowserRefreshScopePolicy({
    targetOrigin: options.targetOrigin,
    originAllowlist: options.originAllowlist,
    idpOrigins: options.idpOrigins,
    allowLocalLab: options.allowLocalLab,
  })
  return {
    ...options,
    scopePolicy,
    requireScopePolicy: true,
    modifiedPaths: options.modifiedPaths ?? [],
    verifyPathModifiedByRun: options.verifyPathModifiedByRun ?? false,
  }
}

export async function refreshBrowserSessionForTest(
  options: TestRefreshBrowserSessionOptions,
): Promise<RefreshedBrowserSession> {
  return await refreshBrowserSession(createTestBrowserRefreshOptions(options))
}
