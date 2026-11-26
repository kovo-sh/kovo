import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { and, desc, eq, inArray, lt, sql } from 'drizzle-orm'
import ts from 'typescript'
import {
  buildBoundedRunProjection,
  computeServerScopeRanking,
} from '../src/actions.ts'
import * as tables from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  autoAdmitAnchorForOrigin,
  matchesAutoAdmitAnchor,
  rankScopeAssets,
} from '../src/server/subdomain-discovery.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const ACTIONS_PATH = join(REPO_ROOT, 'src', 'actions.ts')
const CONSENT_PATH = join(REPO_ROOT, 'src', 'components', 'run', 'views', 'consent.tsx')

const RANKING_DEPS = {
  rankScopeAssets,
  autoAdmitAnchorForOrigin,
  matchesAutoAdmitAnchor,
}

const PROJECTION_DEPS = {
  ...RANKING_DEPS,
  tables,
  and,
  desc,
  eq,
  inArray,
  lt,
  sql,
}

function extractFunctionSource(fileSource: string, fnName: string): string {
  const sf = ts.createSourceFile('file.tsx', fileSource, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === fnName) {
      return fileSource.slice(stmt.getStart(sf), stmt.getEnd())
    }
  }
  throw new Error(`Expected function ${fnName}`)
}

function loadConsentScopeHelpers() {
  const consentSrc = readFileSync(CONSENT_PATH, 'utf8')
  const start = consentSrc.indexOf('const PSL_RULES')
  const end = consentSrc.indexOf('/** Hosts and default selection')
  assert.ok(start > 0 && end > start, 'Expected PSL/scope helper block in consent.tsx')
  const slice = consentSrc
    .slice(start, end)
    .replaceAll('export function ', 'function ')
    .replaceAll('export const ', 'const ')
  const js = ts.transpileModule(slice, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText
  const factory = new Function(
    `${js}\nreturn { defaultScopeAssetIds, isSameApexOutsideAnchor };`,
  )
  return factory() as {
    defaultScopeAssetIds: (
      run: {
        scopeRevision: number
        approved: readonly string[]
        candidates: readonly {
          id: string
          origin: string
          source?: string
          thirdParty: boolean
          includeSubdomains?: boolean
          dnsSource?: unknown
        }[]
      },
      projectDefaultScope: readonly string[],
      options?: {
        includeSubdomainOrigins?: readonly string[]
        maxAutoSelect?: number
        serverRecommendedIds?: readonly string[]
      },
    ) => string[]
    isSameApexOutsideAnchor: (
      candidate: { id: string; origin: string; thirdParty: boolean; source?: string },
      rankedById: ReadonlyMap<string, { sameApexAsSeed: boolean; sameApexOutsideAnchor?: boolean }>,
      seedOrigins: readonly string[],
    ) => boolean
  }
}

test('R3-H-8: unlisted multi-tenant vendor seed pre-selects ONLY seed and *.seedhost, surfacing sibling tenants unchecked with outside-anchor badge', () => {
  const candidates = [
    {
      id: 'seed-tenant-a',
      origin: 'https://tenant-a.unlisted-saas.example',
      source: 'Project seed',
      thirdParty: false,
      includeSubdomains: true,
    },
    {
      id: 'sub-tenant-a-api',
      origin: 'https://api.tenant-a.unlisted-saas.example',
      source: 'phase0_ct_discovery',
      thirdParty: false,
      dnsSource: { zone: 'unlisted-saas.example' },
    },
    {
      id: 'sibling-tenant-b',
      origin: 'https://tenant-b.unlisted-saas.example',
      source: 'phase0_ct_discovery',
      thirdParty: false,
      dnsSource: { zone: 'unlisted-saas.example' },
    },
    {
      id: 'sibling-admin',
      origin: 'https://admin.unlisted-saas.example',
      source: 'subdomain_discovery',
      thirdParty: false,
      dnsSource: { zone: 'unlisted-saas.example' },
    },
    {
      id: 'vendor-apex',
      origin: 'https://unlisted-saas.example',
      source: 'subdomain_discovery',
      thirdParty: false,
      dnsSource: { zone: 'unlisted-saas.example' },
    },
    {
      id: 'tenant-a-docs-3p',
      origin: 'https://docs.tenant-a.unlisted-saas.example',
      source: 'subdomain_discovery',
      thirdParty: true,
      dnsSource: { externalAliases: ['hosting.gitbook.io'] },
    },
  ]

  // 1. Fresh review run (no saved defaultScope)
  const fresh = computeServerScopeRanking(
    { scopeRevision: 0, approved: [], candidates },
    { seeds: ['https://tenant-a.unlisted-saas.example'], defaultScope: [] },
    ['https://tenant-a.unlisted-saas.example'],
    RANKING_DEPS,
  )

  assert.deepEqual(
    fresh.recommendedScopeAssetIds,
    ['seed-tenant-a', 'sub-tenant-a-api'],
    'ONLY seed and *.seedhost may be pre-selected for an unlisted multi-tenant vendor',
  )
  assert.deepEqual(
    fresh.highSignalScopeAssetIds,
    ['seed-tenant-a', 'sub-tenant-a-api'],
    'High-signal quick-select MUST also stay strictly inside *.seedhost',
  )

  // Every discovered sibling host remains visible in rankedAssets with clear same-apex / outside-anchor flags
  const byId = new Map(fresh.rankedAssets.map(a => [a.id, a]))
  assert.equal(byId.size, candidates.length, 'All candidates must remain visible for explicit operator opt-in')

  for (const siblingId of ['sibling-tenant-b', 'sibling-admin', 'vendor-apex']) {
    const entry = byId.get(siblingId)
    assert.ok(entry, `Expected ${siblingId} in rankedAssets`)
    assert.equal(entry.sameApexAsSeed, true, `${siblingId} shares the registrable apex`)
    assert.equal(entry.sameApexOutsideAnchor, true, `${siblingId} must be flagged sameApexOutsideAnchor=true`)
  }
  assert.equal(byId.get('seed-tenant-a')?.sameApexOutsideAnchor, false)
  assert.equal(byId.get('sub-tenant-a-api')?.sameApexOutsideAnchor, false)
  assert.equal(byId.get('tenant-a-docs-3p')?.sameApexOutsideAnchor, false, 'Third-party hosts get 3P badge, not same-apex sibling badge')

  // 2. Saved project defaultScope (`extraSubs` path) MUST NOT re-widen via registrableApex
  const withDefaultScope = computeServerScopeRanking(
    { scopeRevision: 0, approved: [], candidates },
    {
      seeds: ['https://tenant-a.unlisted-saas.example'],
      defaultScope: ['https://tenant-a.unlisted-saas.example'],
    },
    ['https://tenant-a.unlisted-saas.example'],
    RANKING_DEPS,
  )
  assert.deepEqual(
    withDefaultScope.recommendedScopeAssetIds,
    ['seed-tenant-a', 'sub-tenant-a-api'],
    'extraSubs on top of saved defaultScope MUST strictly match autoAdmitAnchorForOrigin',
  )
})

test('R3-H-8: www. seed strips leading www. only; subdomain seed never widens to sibling hosts; shared PaaS refuses auto-admit', () => {
  // www.corp.example -> anchor corp.example -> admits api.corp.example
  const wwwRanking = computeServerScopeRanking(
    {
      scopeRevision: 0,
      approved: [],
      candidates: [
        { id: 'seed-www', origin: 'https://www.corp.example', source: 'Project seed', thirdParty: false, includeSubdomains: true },
        { id: 'api-corp', origin: 'https://api.corp.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
      ],
    },
    { seeds: ['https://www.corp.example'], defaultScope: [] },
    ['https://www.corp.example'],
    RANKING_DEPS,
  )
  assert.deepEqual(wwwRanking.recommendedScopeAssetIds, ['seed-www', 'api-corp'])
  assert.equal(wwwRanking.rankedAssets.find(a => a.id === 'api-corp')?.sameApexOutsideAnchor, false)

  // app.corp.example -> anchor app.corp.example -> admits v2.app.corp.example, leaves api.corp.example unchecked & badged
  const subSeedRanking = computeServerScopeRanking(
    {
      scopeRevision: 0,
      approved: [],
      candidates: [
        { id: 'seed-app', origin: 'https://app.corp.example', source: 'Project seed', thirdParty: false, includeSubdomains: true },
        { id: 'v2-app', origin: 'https://v2.app.corp.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
        { id: 'sibling-api', origin: 'https://api.corp.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
      ],
    },
    { seeds: ['https://app.corp.example'], defaultScope: [] },
    ['https://app.corp.example'],
    RANKING_DEPS,
  )
  assert.deepEqual(subSeedRanking.recommendedScopeAssetIds, ['seed-app', 'v2-app'])
  assert.equal(subSeedRanking.rankedAssets.find(a => a.id === 'sibling-api')?.sameApexOutsideAnchor, true)
  assert.equal(subSeedRanking.rankedAssets.find(a => a.id === 'v2-app')?.sameApexOutsideAnchor, false)

  // Shared PaaS seed refuses auto-admit anchor completely
  const paasRanking = computeServerScopeRanking(
    {
      scopeRevision: 0,
      approved: [],
      candidates: [
        { id: 'seed-paas', origin: 'https://my-app.vercel.app', source: 'Project seed', thirdParty: false, includeSubdomains: true },
        { id: 'sub-paas', origin: 'https://api.my-app.vercel.app', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
        { id: 'other-paas', origin: 'https://other.vercel.app', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
      ],
    },
    { seeds: ['https://my-app.vercel.app'], defaultScope: [] },
    ['https://my-app.vercel.app'],
    RANKING_DEPS,
  )
  assert.deepEqual(paasRanking.recommendedScopeAssetIds, ['seed-paas'])
})

test('R3-H-8: buildBoundedRunProjection end-to-end returns strictly anchored recommendations and sameApexOutsideAnchor flags', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-scope-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const db = new Store(dir, { ftsMode: 'preview' })
  t.after(() => db.close())

  const proj = db.createProject({
    requestId: randomUUID(),
    name: 'Tenant A Unlisted SaaS',
    seeds: ['https://tenant-a.unlisted-saas.example'],
    environment: 'public',
    includeSubdomains: true,
  })
  const run = db.createRun({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: 'Verify tenant-a scope anchoring',
    sourceMode: 'public',
    capabilityTier: 1,
    approvalPolicy: 'auto_review',
    budgetUsd: 5,
    budgetRequests: 500,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })

  // Inject seed + discovered subdomain candidates into review run
  db.suggestCandidateHost(db.run(run.id), 'https://tenant-a.unlisted-saas.example', 'Project seed', false)
  db.suggestCandidateHost(db.run(run.id), 'https://api.tenant-a.unlisted-saas.example', 'phase0_ct_discovery', false)
  db.suggestCandidateHost(db.run(run.id), 'https://tenant-b.unlisted-saas.example', 'phase0_ct_discovery', false)
  db.suggestCandidateHost(db.run(run.id), 'https://admin.unlisted-saas.example', 'phase0_ct_discovery', false)

  const projected = buildBoundedRunProjection(db, run.id, PROJECTION_DEPS)
  const candByOrigin = new Map(projected.run.candidates.map(c => [c.origin, c]))
  const seedId = candByOrigin.get('https://tenant-a.unlisted-saas.example')!.id
  const apiId = candByOrigin.get('https://api.tenant-a.unlisted-saas.example')!.id
  const tenantBId = candByOrigin.get('https://tenant-b.unlisted-saas.example')!.id
  const adminId = candByOrigin.get('https://admin.unlisted-saas.example')!.id

  assert.deepEqual(
    [...projected.recommendedScopeAssetIds].sort(),
    [seedId, apiId].sort(),
    'Server projection must pre-select only seed and *.seedhost',
  )
  assert.deepEqual(
    [...projected.highSignalScopeAssetIds].sort(),
    [seedId, apiId].sort(),
    'Server projection high-signal list must pre-select only seed and *.seedhost',
  )

  const rankedById = new Map(projected.rankedAssets.map(a => [a.id, a]))
  assert.equal(rankedById.get(tenantBId)?.sameApexOutsideAnchor, true)
  assert.equal(rankedById.get(adminId)?.sameApexOutsideAnchor, true)
  assert.equal(rankedById.get(seedId)?.sameApexOutsideAnchor, false)
  assert.equal(rankedById.get(apiId)?.sameApexOutsideAnchor, false)
})

test('R3-H-8: consent.tsx client fallback & outside-anchor badge classification match server anchor semantics', () => {
  const { defaultScopeAssetIds, isSameApexOutsideAnchor } = loadConsentScopeHelpers()

  const candidates = [
    { id: 'seed-a', origin: 'https://tenant-a.unlisted-saas.example', source: 'Project seed', thirdParty: false, includeSubdomains: true },
    { id: 'api-a', origin: 'https://api.tenant-a.unlisted-saas.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
    { id: 'tenant-b', origin: 'https://tenant-b.unlisted-saas.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
    { id: 'admin-v', origin: 'https://admin.unlisted-saas.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
    { id: 'docs-3p', origin: 'https://docs.unlisted-saas.example', source: 'subdomain_discovery', thirdParty: true, dnsSource: {} },
  ]

  // Without serverRecommendedIds (fallback path)
  const fallbackPicked = defaultScopeAssetIds(
    { scopeRevision: 0, approved: [], candidates },
    [],
    { includeSubdomainOrigins: ['https://tenant-a.unlisted-saas.example'] },
  )
  assert.deepEqual(fallbackPicked, ['seed-a', 'api-a'])

  // With saved defaultScope (extraSubs fallback path)
  const fallbackDefaultScope = defaultScopeAssetIds(
    { scopeRevision: 0, approved: [], candidates },
    ['https://tenant-a.unlisted-saas.example'],
    { includeSubdomainOrigins: ['https://tenant-a.unlisted-saas.example'] },
  )
  assert.deepEqual(fallbackDefaultScope, ['seed-a', 'api-a'])

  // Badge helper prefers server rankedAssets metadata and agrees on fallback
  const serverRanking = computeServerScopeRanking(
    { scopeRevision: 0, approved: [], candidates },
    { seeds: ['https://tenant-a.unlisted-saas.example'], defaultScope: [] },
    ['https://tenant-a.unlisted-saas.example'],
    RANKING_DEPS,
  )
  const rankedById = new Map(serverRanking.rankedAssets.map(a => [a.id, a]))
  const emptyMap = new Map<string, { sameApexAsSeed: boolean; sameApexOutsideAnchor?: boolean }>()
  const seeds = ['https://tenant-a.unlisted-saas.example']

  for (const map of [rankedById, emptyMap]) {
    assert.equal(isSameApexOutsideAnchor(candidates[0]!, map, seeds), false)
    assert.equal(isSameApexOutsideAnchor(candidates[1]!, map, seeds), false)
    assert.equal(isSameApexOutsideAnchor(candidates[2]!, map, seeds), true)
    assert.equal(isSameApexOutsideAnchor(candidates[3]!, map, seeds), true)
    assert.equal(isSameApexOutsideAnchor(candidates[4]!, map, seeds), false)
  }

  // consent.tsx renders the compact outside-anchor pill for same-apex sibling hosts
  const consentSrc = readFileSync(CONSENT_PATH, 'utf8')
  assert.match(consentSrc, /data-testid="scope-apex-sibling-badge"/, 'consent.tsx must render an identifiable same-apex sibling badge')
  assert.match(consentSrc, /Same apex \(different host\)/, 'consent.tsx badge tooltip must clearly warn same-apex different host')
})

test('R3-H-8 static regression lint: registrableApex MUST NOT be called in scope pre-selection logic (actions.ts / consent.tsx)', () => {
  const actionsSrc = readFileSync(ACTIONS_PATH, 'utf8')
  const computeFnSrc = extractFunctionSource(actionsSrc, 'computeServerScopeRanking')

  assert.equal(
    /\bregistrableApex\b/.test(actionsSrc),
    false,
    'src/actions.ts must NOT import or call registrableApex (use autoAdmitAnchorForOrigin / matchesAutoAdmitAnchor)',
  )
  assert.equal(
    /\bregistrableApex\b/.test(computeFnSrc),
    false,
    'computeServerScopeRanking must NOT reference registrableApex',
  )
  assert.match(
    computeFnSrc,
    /\bautoAdmitAnchorForOrigin\b/,
    'computeServerScopeRanking must anchor seeds with autoAdmitAnchorForOrigin',
  )
  assert.match(
    computeFnSrc,
    /\bmatchesAutoAdmitAnchor\b/,
    'computeServerScopeRanking must filter subdomains with matchesAutoAdmitAnchor',
  )

  const consentSrc = readFileSync(CONSENT_PATH, 'utf8')
  const defaultScopeFnSrc = extractFunctionSource(consentSrc, 'defaultScopeAssetIds')
  assert.equal(
    /\bregistrableApex\b/.test(defaultScopeFnSrc),
    false,
    'defaultScopeAssetIds in consent.tsx must NOT call registrableApex for auto-selection',
  )
  assert.equal(
    /\bwildcardApexes\b/.test(defaultScopeFnSrc),
    false,
    'defaultScopeAssetIds in consent.tsx must NOT widen via wildcardApexes',
  )
})
