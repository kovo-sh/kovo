/**
 * Move P3 Cut A — floor-heuristics dedup (branch opencode/arch-p3-cut3-diet).
 *
 * Commits dcee42a + 371d842 extracted the heuristic vocabulary that had drifted into inline
 * duplicates across `floor-recipe-engine.ts`, `floor-recipes.ts`, `deterministic-specs.ts` and
 * `deterministic-engine.ts` into the single source `src/server/floor-heuristics.ts`; 7f3315e
 * additionally retired the shadowing `proofReceiptMode` wrapper in `floor-recipe-engine.ts`.
 *
 * This file pins three properties of that diet:
 *   1. the shared helpers behave as documented (field classification, identifier validation,
 *      privileged path/action hints, mutation/readback selection);
 *   2. the deduplicated routing/exports are wired: re-exports are the *same* objects as
 *      floor-heuristics (no shadow copies), and every consumer imports the shared module;
 *   3. a static guard so the removed inline heuristic regexes are not reintroduced across the
 *      four consumer files (and no dynamic `new RegExp(` or benchmark literals creep into the
 *      routing modules).
 *
 * The pre-existing receipt-hardening failures in tests/v7-cut3* and tests/v7-floor-recipes.test.ts
 * (stale two-arm fixtures rejected by the >=5-arm timing / triangle boolean requirements) are
 * owned by those suites and predate this branch; nothing here loosens them.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import * as floorHeuristics from '../src/server/floor-heuristics.ts'
import type { AuthzMatrixRow, BaselineWrite } from '../src/server/floor-heuristics.ts'
import {
  bogusIdFor,
  CONSERVED_AMOUNT_FIELD_RE,
  CONSERVED_BALANCE_FIELD_RE,
  CONSERVED_ECHO_FIELD_RE,
  escalatePrivilegeBody,
  fillResourceId,
  hasDynamicIdSegment,
  IDENTITY_ASSUMPTION_ROUTE_RE,
  isAuthzMatrixHitAdmissible,
  isIdentityAssignmentField,
  isSafeFieldName,
  isSafeIdentifier,
  isSafePersonaHandle,
  isSafeResourceId,
  pathHasNounSegment,
  pathHasPrivilegedHint,
  pickBaselineWrite,
  PRIVILEGED_ACTION_RE,
  privilegeBaselineFor,
  resolveAuthzReadbackTemplate,
  rolePrivilegeRank,
  SENSITIVE_READ_ROUTE_RE,
  withoutIdentityFields,
} from '../src/server/floor-heuristics.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { bogusIdFor as specBogusIdFor, synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import * as engine from '../src/server/deterministic-engine.ts'
import * as specs from '../src/server/deterministic-specs.ts'
import {
  hasDynamicIdSegment as engineHasDynamicIdSegment,
  IDENTITY_ASSUMPTION_ROUTE_RE as ENGINE_IDENTITY_ASSUMPTION_ROUTE_RE,
  isIdentityAssignmentField as engineIsIdentityAssignmentField,
  pathHasPrivilegedHint as enginePathHasPrivilegedHint,
  withoutIdentityFields as engineWithoutIdentityFields,
} from '../src/server/deterministic-engine.ts'
import { classifyRetestHealth, planFloorRecipe, proofReceiptMode, receiptVulnClassFor } from '../src/server/floor-recipe-engine.ts'
import { wiredRecipeForSpecKind } from '../src/server/floor-recipes.ts'
import type { FloorRecipeExecution, PersistedMutationArgs } from '../src/server/floor-recipes.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

const serverFile = (name: string): string =>
  readFileSync(new URL(`../src/server/${name}`, import.meta.url), 'utf8')

// ---------------------------------------------------------------------------------------------
// 1. Shared field classification
// ---------------------------------------------------------------------------------------------

test('floor-heuristics: baseline field classification prefers strong numerics, then text, then booleans', () => {
  // Strong numeric beats text even when the text field is declared first.
  const strong = floorHeuristics.pickBaselineWrite({ description: 'doc', amount: 5 })!
  assert.equal(strong.field, 'amount')
  assert.equal(typeof strong.baselineValue, 'number')
  const strongBase = strong.baselineValue as number
  assert.ok(strongBase >= 424_242 && strongBase <= 425_241)
  assert.equal(strong.probeValue, strongBase + 1)
  assert.equal((strong.baselineBody as Record<string, unknown>).amount, strong.baselineValue)
  assert.equal((strong.baselineBody as Record<string, unknown>).description, 'doc')

  const text = floorHeuristics.pickBaselineWrite({ name: 'old-name', page: 3 })!
  assert.equal(text.field, 'name')
  assert.match(String(text.baselineValue), /^kovo-baseline-[0-9a-f]{8}$/)
  assert.match(String(text.probeValue), /^kovo-probe-[0-9a-f]{8}$/)
  assert.notEqual(text.probeValue, text.baselineValue)

  const bool = floorHeuristics.pickBaselineWrite({ archived: false })!
  assert.equal(bool.field, 'archived')
  assert.equal(bool.baselineValue, true)
  assert.equal(bool.probeValue, false)

  // A numeric-looking string still takes the numeric branch.
  const numericString = floorHeuristics.pickBaselineWrite({ price: '10' })!
  assert.equal(numericString.field, 'price')
  assert.equal(typeof numericString.baselineValue, 'number')

  // Excluded/selector-only bodies yield no baseline, but a state field is still a valid fallback.
  assert.equal(floorHeuristics.pickBaselineWrite({ id: '9', owner_id: 'o1' }), null)
  assert.equal(floorHeuristics.pickBaselineWrite({}), null)
  const state = floorHeuristics.pickBaselineWrite({ id: '9', status: 'live' })!
  assert.equal(state.field, 'status')
  // Unsafe field names are skipped, never chosen.
  const safeNameOnly = floorHeuristics.pickBaselineWrite({ 'bad field': 'x', name: 'y' })!
  assert.equal(safeNameOnly.field, 'name')
})

test('floor-heuristics: pickBaselineWrite never mutates the caller body and only copies scalars', () => {
  const body: Record<string, unknown> = { amount: 1, nested: { deep: true } }
  const snapshot = JSON.stringify(body)
  const write: BaselineWrite | null = floorHeuristics.pickBaselineWrite(body)
  assert.ok(write)
  assert.equal(JSON.stringify(body), snapshot, 'input body must be untouched')
  assert.deepEqual(Object.keys(write.baselineBody), ['amount', 'nested'])
})

test('floor-heuristics: excluded / selector / state / privilege-target field families are distinct', () => {
  // Excluded fields never enter the primary baseline pool.
  for (const field of ['owner_id', 'email', 'created_at', 'status', 'token', 'x-password-y']) {
    assert.ok(floorHeuristics.BASELINE_EXCLUDED_FIELD_RE.test(field), `excluded: ${field}`)
  }
  // Selector fields change which record is addressed; `status` is content, not a selector.
  assert.ok(floorHeuristics.BASELINE_SELECTOR_FIELD_RE.test('tenant_id'))
  assert.ok(!floorHeuristics.BASELINE_SELECTOR_FIELD_RE.test('status'))
  // State fields are mutable lifecycle content.
  assert.ok(floorHeuristics.BASELINE_STATE_FIELD_RE.test('fulfilment_state'))
  assert.ok(floorHeuristics.BASELINE_STATE_FIELD_RE.test('archived'))
  assert.ok(!floorHeuristics.BASELINE_STATE_FIELD_RE.test('name'))
  // Privilege targets are the escalation columns; plain content is never one.
  assert.ok(floorHeuristics.PRIVILEGE_TARGET_FIELD_RE.test('account_type'))
  assert.ok(floorHeuristics.PRIVILEGE_TARGET_FIELD_RE.test('is_staff'))
  assert.ok(!floorHeuristics.PRIVILEGE_TARGET_FIELD_RE.test('description'))
  // Privilege literals name an elevated entitlement only.
  assert.ok(floorHeuristics.PRIVILEGE_LITERAL_RE.test('SuperUser'))
  assert.ok(!floorHeuristics.PRIVILEGE_LITERAL_RE.test('member'))
  assert.ok(!floorHeuristics.PRIVILEGE_LITERAL_RE.test('viewer'))
  // Weak numerics are the last resort pool.
  assert.ok(floorHeuristics.BASELINE_WEAK_NUMERIC_FIELD_RE.test('rating'))
  assert.ok(!floorHeuristics.BASELINE_WEAK_NUMERIC_FIELD_RE.test('ratings'))
})

test('floor-heuristics: identity assignment fields are recognized across naming styles and dropped shallow+deep', () => {
  for (const field of ['role', 'isAdmin', 'tenantId', 'workspace_id', 'act_as', 'owner', 'subject']) {
    assert.ok(floorHeuristics.isIdentityAssignmentField(field), `identity: ${field}`)
  }
  for (const field of ['title', 'description', 'note', 'roleplay']) {
    assert.ok(!floorHeuristics.isIdentityAssignmentField(field), `content: ${field}`)
  }
  const cleaned = floorHeuristics.withoutIdentityFields({
    name: 'keep',
    role: 'admin',
    org_id: 7,
    profile: { bio: 'keep', user_id: 2, inner: { team_id: 3, ok: 1 } },
    tags: [{ user_id: 4 }],
  })
  assert.deepEqual(cleaned, {
    name: 'keep',
    profile: { bio: 'keep', inner: { ok: 1 } },
    tags: [{ user_id: 4 }], // arrays are preserved as-is (never recursed)
  })
})

// ---------------------------------------------------------------------------------------------
// 2. Safe identifier / resource-id guards
// ---------------------------------------------------------------------------------------------

test('floor-heuristics: resource-id, field, persona and identifier guards accept only bounded safe shapes', () => {
  assert.ok(floorHeuristics.isSafeResourceId('inv_42-1.0:9'))
  assert.ok(!floorHeuristics.isSafeResourceId('has space'))
  assert.ok(!floorHeuristics.isSafeResourceId('a/b'))
  assert.ok(!floorHeuristics.isSafeResourceId('x'.repeat(129)))
  assert.ok(!floorHeuristics.isSafeResourceId(42))
  assert.ok(!floorHeuristics.isSafeResourceId(null))

  assert.ok(floorHeuristics.isSafeFieldName('line_items.qty'))
  assert.ok(!floorHeuristics.isSafeFieldName('bad field'))
  assert.ok(!floorHeuristics.isSafeFieldName('x'.repeat(65)))

  assert.ok(floorHeuristics.isSafePersonaHandle('peer-1'))
  assert.ok(!floorHeuristics.isSafePersonaHandle('Peer'))
  assert.ok(!floorHeuristics.isSafePersonaHandle('a'.repeat(33)))

  assert.ok(floorHeuristics.isSafeIdentifier('_foo1'))
  assert.ok(!floorHeuristics.isSafeIdentifier('1foo'))
  assert.ok(!floorHeuristics.isSafeIdentifier('has-dash'))

  assert.equal(
    floorHeuristics.fillResourceId('/api/a/{{id}}/b?x={{id}}', 'v 1'),
    '/api/a/v%201/b?x=v%201',
  )
})

test('floor-heuristics: bogusIdFor derives a syntactically valid, never-equal negative control', () => {
  const samples = ['42', '9000043', '12345678-4321-4321-4321-123456789ab0',
    '12345678-4321-4321-4321-123456789abc', 'peer_7', 'tenant-9', '!!', '999999999999']
  for (const id of samples) {
    const bogus = floorHeuristics.bogusIdFor(id)
    assert.ok(typeof bogus === 'string' && bogus.length > 0)
    assert.notEqual(bogus, id, 'bogus id must never equal the real id')
    assert.ok(floorHeuristics.SAFE_RESOURCE_ID_RE.test(bogus), `bogus must stay a safe id: ${bogus}`)
  }
  assert.equal(floorHeuristics.bogusIdFor('42'), '9000043')
  assert.equal(floorHeuristics.bogusIdFor('12345678-4321-4321-4321-123456789ab0'),
    '12345678-4321-4321-4321-123456789ab1')
  assert.equal(floorHeuristics.bogusIdFor('12345678-4321-4321-4321-123456789abc'),
    '12345678-4321-4321-4321-123456789ab0')
  assert.equal(floorHeuristics.bogusIdFor('peer_7'), 'peer_gx9000001')
  assert.match(floorHeuristics.bogusIdFor('!!'), /^gx[0-9a-f]{16}$/)
})

// ---------------------------------------------------------------------------------------------
// 3. Privileged path / action hints
// ---------------------------------------------------------------------------------------------

test('floor-heuristics: privileged, sensitive-read and identity-assumption route hints', () => {
  assert.ok(floorHeuristics.pathHasPrivilegedHint('/api/admin/users'))
  assert.ok(floorHeuristics.pathHasPrivilegedHint('/settings/feature-flags'))
  assert.ok(floorHeuristics.pathHasPrivilegedHint('/api/v1/staff/grants'))
  assert.ok(!floorHeuristics.pathHasPrivilegedHint('/api/users'))
  assert.ok(!floorHeuristics.pathHasPrivilegedHint('/api/administrivia'))

  assert.ok(floorHeuristics.SENSITIVE_READ_ROUTE_RE.test('/api/v1/apikeys'))
  assert.ok(floorHeuristics.SENSITIVE_READ_ROUTE_RE.test('/api/tokens'))
  assert.ok(floorHeuristics.SENSITIVE_READ_ROUTE_RE.test('/api/audit-log'))
  assert.ok(!floorHeuristics.SENSITIVE_READ_ROUTE_RE.test('/api/users'))

  assert.ok(floorHeuristics.IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/v2/impersonate'))
  assert.ok(floorHeuristics.IDENTITY_ASSUMPTION_ROUTE_RE.test('/auth/sudo'))
  assert.ok(floorHeuristics.IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/switch-tenant'))
  assert.ok(!floorHeuristics.IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/users'))
})

test('floor-heuristics: dynamic id segment and placeholder detection across route shapes', () => {
  for (const path of ['/api/users/:id', '/api/users/:userId', '/api/users/{{id}}',
    '/api/users/{uuid}', '/api/users/[id]']) {
    assert.ok(floorHeuristics.hasDynamicIdSegment(path), `dynamic: ${path}`)
  }
  for (const path of ['/api/users', '/api/x:id', '/api/users?id=1']) {
    assert.ok(!floorHeuristics.hasDynamicIdSegment(path), `static: ${path}`)
  }
  assert.ok(floorHeuristics.PLACEHOLDER_SEGMENT_RE.test(':id'))
  assert.ok(floorHeuristics.PLACEHOLDER_SEGMENT_RE.test('{uuid}'))
  assert.ok(floorHeuristics.PLACEHOLDER_SEGMENT_RE.test('[id]'))
  assert.ok(!floorHeuristics.PLACEHOLDER_SEGMENT_RE.test('{{id}}'))
  assert.ok(!floorHeuristics.PLACEHOLDER_SEGMENT_RE.test('id'))
})

test('floor-heuristics: per-sink path hints route surface vocabulary', () => {
  assert.ok(floorHeuristics.pathHasFileHint('/api/v1/download'))
  assert.ok(floorHeuristics.pathHasFileHint('/api/billing-docs'))
  assert.ok(!floorHeuristics.pathHasFileHint('/api/users'))

  assert.ok(floorHeuristics.pathHasUrlHint('/api/webhooks'))
  assert.ok(floorHeuristics.pathHasUrlHint('/assets/proxy'))
  assert.ok(!floorHeuristics.pathHasUrlHint('/api/users'))

  assert.ok(floorHeuristics.pathHasXmlHint('/api/soap'))
  assert.ok(floorHeuristics.pathHasXmlHint('/auth/saml'))
  assert.ok(!floorHeuristics.pathHasXmlHint('/api/users'))

  assert.ok(floorHeuristics.pathHasTemplateHint('/api/render'))
  assert.ok(floorHeuristics.pathHasTemplateHint('/api/email-templates'))
  assert.ok(!floorHeuristics.pathHasTemplateHint('/api/users'))

  assert.ok(floorHeuristics.pathHasCommandHint('/api/diag/run'))
  assert.ok(floorHeuristics.pathHasCommandHint('/api/healthcheck'))
  assert.ok(!floorHeuristics.pathHasCommandHint('/api/health'))

  assert.ok(floorHeuristics.pathHasRedirectHint('/api/oauth/authorize'))
  assert.ok(floorHeuristics.pathHasRedirectHint('/auth/callback'))
  assert.ok(!floorHeuristics.pathHasRedirectHint('/api/users'))
})

test('floor-heuristics: noun and search hints match whole segments/tokens only (catalog stays out)', () => {
  assert.ok(floorHeuristics.pathHasNounSegment('/api/v2/invoices/42', 'invoice'))
  assert.ok(floorHeuristics.pathHasNounSegment('/api/invoice', 'invoice'))
  assert.ok(!floorHeuristics.pathHasNounSegment('/api/invoice_items', 'invoice'))
  assert.ok(!floorHeuristics.pathHasNounSegment('/api/invoice/42/items', 'invoice', true))
  assert.ok(floorHeuristics.pathHasNounSegment('/api/invoice/42/items', 'items', true))

  assert.ok(floorHeuristics.pathHasSearchHint('/api/items/search'))
  assert.ok(floorHeuristics.pathHasSearchHint('/api/re-search'))
  assert.ok(floorHeuristics.pathHasSearchHint('/api/item_queries'))
  assert.ok(!floorHeuristics.pathHasSearchHint('/api/research'))
  // `catalog` is a listing noun, not a search surface: it must not spend the SQLi quota.
  assert.ok(!floorHeuristics.pathHasSearchHint('/api/catalog'))
})

// ---------------------------------------------------------------------------------------------
// 4. Mutation / readback selection
// ---------------------------------------------------------------------------------------------

test('floor-heuristics: resolveAuthzReadbackTemplate covers explicit, function-level and object-level shapes', () => {
  const explicit = floorHeuristics.resolveAuthzReadbackTemplate(
    { pathAndQuery: '/api/users/{{id}}', readbackPath: '/api/users/{{id}}/profile', readbackPersona: 'owner' }, false)!
  assert.deepEqual(explicit, { template: '/api/users/{{id}}/profile', persona: 'owner' })
  const explicitNoPersona = floorHeuristics.resolveAuthzReadbackTemplate(
    { pathAndQuery: '/api/users/{{id}}', readbackPath: '/api/audit' }, false)!
  assert.deepEqual(explicitNoPersona, { template: '/api/audit' })
  assert.ok(!('persona' in explicitNoPersona))

  // Function level: only a privileged action reads back through its own surface.
  assert.deepEqual(
    floorHeuristics.resolveAuthzReadbackTemplate({ pathAndQuery: '/api/staff/roles' }, true),
    { template: '/api/staff/roles' })
  assert.equal(
    floorHeuristics.resolveAuthzReadbackTemplate({ pathAndQuery: '/api/users/{{id}}/items' }, true), null)

  // Object level: placeholder in query, trailing placeholder, and action-verb drop.
  assert.deepEqual(
    floorHeuristics.resolveAuthzReadbackTemplate({ pathAndQuery: '/api/invoices?id={{id}}&q=1' }, false),
    { template: '/api/invoices?id={{id}}&q=1' })
  assert.deepEqual(
    floorHeuristics.resolveAuthzReadbackTemplate({ pathAndQuery: '/api/users/{{id}}' }, false),
    { template: '/api/users/{{id}}' })
  assert.deepEqual(
    floorHeuristics.resolveAuthzReadbackTemplate({ pathAndQuery: '/api/users/{{id}}/grant-role' }, false),
    { template: '/api/users/{{id}}' })
  assert.equal(
    floorHeuristics.resolveAuthzReadbackTemplate({ pathAndQuery: '/api/users/{{id}}/items' }, false), null)
  assert.equal(
    floorHeuristics.resolveAuthzReadbackTemplate({ pathAndQuery: '/api/users' }, false), null)
})

test('floor-heuristics: privilege baseline and escalation only touch fields the body already carries', () => {
  // Demotion baseline for an admin requirement is member, otherwise viewer.
  assert.deepEqual(floorHeuristics.privilegeBaselineFor({ role: 'admin' }, 'admin'), {
    field: 'role', baselineValue: 'member', probeValue: 'admin', baselineBody: { role: 'member' },
  })
  assert.deepEqual(floorHeuristics.privilegeBaselineFor({ plan: 'owner' }), {
    field: 'plan', baselineValue: 'viewer', probeValue: 'owner', baselineBody: { plan: 'viewer' },
  })
  // Case preserved on the probe value; already-demoted bodies need no baseline.
  const cased = floorHeuristics.privilegeBaselineFor({ role: 'Admin' })!
  assert.equal(cased.probeValue, 'Admin')
  assert.equal(floorHeuristics.privilegeBaselineFor({ role: 'member' }, 'admin'), null)
  assert.equal(floorHeuristics.privilegeBaselineFor({ name: 'x' }, 'admin'), null)
  assert.equal(floorHeuristics.privilegeBaselineFor('nope'), null)
  assert.equal(floorHeuristics.privilegeBaselineFor(['arr']), null)

  assert.deepEqual(floorHeuristics.escalatePrivilegeBody({ role: 'viewer' }, 'admin'), { role: 'admin' })
  assert.deepEqual(floorHeuristics.escalatePrivilegeBody({ plan: 2 }, 'owner'), { plan: 'owner' })
  assert.equal(floorHeuristics.escalatePrivilegeBody({ role: 'admin' }, 'admin'), null)
  assert.equal(floorHeuristics.escalatePrivilegeBody({ role: 'Admin' }, 'admin'), null)
  assert.equal(floorHeuristics.escalatePrivilegeBody({ name: 'x' }, 'admin'), null)
  assert.equal(floorHeuristics.escalatePrivilegeBody({ role: 'viewer' }, null), null)

  // Neither helper mutates the caller's body template.
  const body: Record<string, unknown> = { role: 'viewer', note: 'n' }
  const snap = JSON.stringify(body)
  floorHeuristics.escalatePrivilegeBody(body, 'admin')
  floorHeuristics.privilegeBaselineFor(body)
  assert.equal(JSON.stringify(body), snap)
})

test('floor-heuristics: authz matrix admissibility demands an owner, a served probe, and no public veto', () => {
  const owner = (over: Partial<AuthzMatrixRow>): AuthzMatrixRow =>
    ({ resourceId: 'r1', actor: 'owner', accessible: true, status: 200, bodyBytes: 100,
      bodySha256: 'h-owner', similarityToOwner: 1, ...over })
  const probe = (over: Partial<AuthzMatrixRow>): AuthzMatrixRow =>
    ({ resourceId: 'r1', actor: 'other_persona', accessible: true, status: 200, bodyBytes: 100,
      bodySha256: 'h-probe', similarityToOwner: 0.95, ...over })

  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(null, { resourceId: 'r1' }, { mutating: false, functionLevel: false }), true)

  const hit = { resourceId: 'r1', actor: 'someone' }
  const readOpts = { mutating: false, functionLevel: false } as const
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible([probe({})], hit, readOpts), false) // no owner row
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({ accessible: false }), probe({})], hit, readOpts), false) // owner denied
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({ status: 500 }), probe({})], hit, readOpts), false) // owner 5xx
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({ bodyBytes: 2 }), probe({})], hit, readOpts), false) // owner body too small
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible([owner({})], hit, readOpts), false) // no probe row
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({}), probe({ accessible: false })], hit, readOpts), false) // probe denied
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({}), probe({ similarityToOwner: 0.5 })], hit, readOpts), false) // probe unsimilar
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({}), probe({}), { resourceId: 'r1', actor: 'anonymous', accessible: true, bodySha256: 'h-owner' }],
    hit, readOpts), false) // anonymous public veto (same body as owner)
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({}), probe({})], hit, readOpts), true)
  // Rows for other resource ids are not consulted at object level.
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({ resourceId: 'other' }), probe({ resourceId: 'other' }), owner({}), probe({})],
    hit, readOpts), true)
  // Mutating hits skip the similarity floor and the publicness veto.
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({}), probe({ similarityToOwner: 0.1 })], hit, { mutating: true, functionLevel: false }), true)
  // Function-level hits read the whole matrix, not just the hit's resource id.
  assert.equal(floorHeuristics.isAuthzMatrixHitAdmissible(
    [owner({ resourceId: 'other' }), probe({ resourceId: 'other' })],
    hit, { mutating: false, functionLevel: true }), true)
})

test('floor-heuristics: role privilege ranks are prototype-safe and monotonic', () => {
  assert.equal(floorHeuristics.rolePrivilegeRank('admin'), floorHeuristics.rolePrivilegeRank('owner'))
  assert.ok((floorHeuristics.rolePrivilegeRank('owner') ?? 0) > (floorHeuristics.rolePrivilegeRank('member') ?? 0))
  assert.ok((floorHeuristics.rolePrivilegeRank('member') ?? 0) > (floorHeuristics.rolePrivilegeRank('viewer') ?? 0))
  assert.equal(floorHeuristics.rolePrivilegeRank(null), null)
  assert.equal(floorHeuristics.rolePrivilegeRank(undefined), null)
  // hasOwnProperty guard: prototype keys never resolve to a rank.
  assert.ok(!Object.prototype.hasOwnProperty.call(floorHeuristics.ROLE_PRIVILEGE_RANK, 'toString'))
  assert.ok(!Object.prototype.hasOwnProperty.call(floorHeuristics.ROLE_PRIVILEGE_RANK, 'constructor'))

  assert.ok(floorHeuristics.POSTURE_CWES.has('CWE-285'))
  assert.ok(floorHeuristics.POSTURE_CWES.has('CWE-862'))
  assert.ok(!floorHeuristics.POSTURE_CWES.has('CWE-89'))
  assert.ok(floorHeuristics.POSTURE_CATEGORY_RE.test('unauthenticated_access_bypass'))
  assert.ok(!floorHeuristics.POSTURE_CATEGORY_RE.test('cross_site_scripting'))
})

// ---------------------------------------------------------------------------------------------
// 5. Deduplicated routing / exports across the four consumers
// ---------------------------------------------------------------------------------------------

test('dedup routing: deterministic-engine re-exports are the same objects as floor-heuristics', () => {
  const reExported = [
    'hasDynamicIdSegment', 'isIdentityAssignmentField', 'withoutIdentityFields',
    'pathHasCommandHint', 'pathHasFileHint', 'pathHasPrivilegedHint', 'pathHasRedirectHint',
    'pathHasSearchHint', 'pathHasTemplateHint', 'pathHasUrlHint', 'pathHasXmlHint',
  ] as const
  for (const name of reExported) {
    assert.ok((engine as Record<string, unknown>)[name], `engine must re-export ${name}`)
    assert.equal((engine as Record<string, unknown>)[name], (floorHeuristics as Record<string, unknown>)[name],
      `${name} must be the very same function object, not a shadow copy`)
  }
  assert.equal(engine.IDENTITY_ASSUMPTION_ROUTE_RE, floorHeuristics.IDENTITY_ASSUMPTION_ROUTE_RE)
  assert.equal(engine.IDENTITY_ASSUMPTION_ROUTE_RE.source, floorHeuristics.IDENTITY_ASSUMPTION_ROUTE_RE.source)

  // The re-exported helpers actually resolve (behavioral spot, not just identity).
  assert.equal(engine.pathHasPrivilegedHint('/admin/users'), true)
  assert.equal(engine.hasDynamicIdSegment('/api/users/:id'), true)
  assert.equal(engine.pathHasSearchHint('/api/catalog'), false)
})

test('dedup routing: deterministic-specs re-exports bogusIdFor from floor-heuristics', () => {
  assert.equal(specs.bogusIdFor, floorHeuristics.bogusIdFor)
  assert.equal(specs.bogusIdFor('42'), '9000043')
})

test('dedup routing: every heuristic consumer imports the single source, no local re-declaration', () => {
  const heuristicsConsumers = ['floor-recipe-engine.ts', 'deterministic-specs.ts', 'deterministic-engine.ts']
  for (const file of heuristicsConsumers) {
    assert.match(serverFile(file), /from '\.\/floor-heuristics\.ts'/,
      `${file} must route heuristics through the shared module`)
  }
  // Legacy-shadow bug class guard: no consumer re-declares a heuristic const of its own.
  for (const file of heuristicsConsumers) {
    const src = serverFile(file)
    assert.ok(!/^const PRIVILEGED_ACTION_RE\b/m.test(src), `${file} must not shadow PRIVILEGED_ACTION_RE`)
    assert.ok(!/^const SENSITIVE_READ_ROUTE_RE\b/m.test(src), `${file} must not shadow SENSITIVE_READ_ROUTE_RE`)
  }

  // Recipe layer routing: the planner consumes the typed recipe library, the spec synthesizer the
  // recipe browser-sink envelope, and the engine both planners and the recipe engine.
  assert.match(serverFile('floor-recipe-engine.ts'), /\{[^}]*brokerFloorRecipeDeps[^}]*\}\s*from\s*'\.\/floor-recipes\.ts'/s)
  assert.match(serverFile('deterministic-specs.ts'), /\{[^}]*browserSinkEnvelopeFromSteps[^}]*\}\s*from\s*'\.\/floor-recipes\.ts'/s)
  assert.match(serverFile('deterministic-engine.ts'), /\{[^}]*synthesizeEngineSpecs[^}]*\}\s*from\s*'\.\/deterministic-specs\.ts'/s)
  assert.match(serverFile('deterministic-engine.ts'), /\{[^}]*planFloorRecipe[^}]*\}\s*from\s*'\.\/floor-recipe-engine\.ts'/s)
})

// ---------------------------------------------------------------------------------------------
// 6. Static guard: deduplicated heuristic regexes must not be re-inlined
// ---------------------------------------------------------------------------------------------

const DEDUP_CONSUMERS = ['floor-recipe-engine.ts', 'floor-recipes.ts', 'deterministic-specs.ts', 'deterministic-engine.ts']

/** Strip regex-literal escapes so a re-inlined `\/` cannot hide a duplicate. */
const unescaped = (text: string): string => text.replaceAll('\\', '')

test('static guard: canonical heuristic regex sources live only in floor-heuristics.ts', () => {
  const guardPatterns: ReadonlyArray<{ name: string; re: RegExp }> = [
    { name: 'PRIVILEGED_ACTION_RE', re: floorHeuristics.PRIVILEGED_ACTION_RE },
    { name: 'SENSITIVE_READ_ROUTE_RE', re: floorHeuristics.SENSITIVE_READ_ROUTE_RE },
    { name: 'IDENTITY_ASSUMPTION_ROUTE_RE', re: floorHeuristics.IDENTITY_ASSUMPTION_ROUTE_RE },
    { name: 'DYNAMIC_ID_SEGMENT_RE', re: floorHeuristics.DYNAMIC_ID_SEGMENT_RE },
    { name: 'PLACEHOLDER_SEGMENT_RE', re: floorHeuristics.PLACEHOLDER_SEGMENT_RE },
    { name: 'BASELINE_STRONG_NUMERIC_FIELD_RE', re: floorHeuristics.BASELINE_STRONG_NUMERIC_FIELD_RE },
    { name: 'BASELINE_TEXT_FIELD_RE', re: floorHeuristics.BASELINE_TEXT_FIELD_RE },
    { name: 'BASELINE_WEAK_NUMERIC_FIELD_RE', re: floorHeuristics.BASELINE_WEAK_NUMERIC_FIELD_RE },
    { name: 'BASELINE_EXCLUDED_FIELD_RE', re: floorHeuristics.BASELINE_EXCLUDED_FIELD_RE },
    { name: 'BASELINE_SELECTOR_FIELD_RE', re: floorHeuristics.BASELINE_SELECTOR_FIELD_RE },
    { name: 'BASELINE_STATE_FIELD_RE', re: floorHeuristics.BASELINE_STATE_FIELD_RE },
    { name: 'PRIVILEGE_TARGET_FIELD_RE', re: floorHeuristics.PRIVILEGE_TARGET_FIELD_RE },
    { name: 'PRIVILEGE_LITERAL_RE', re: floorHeuristics.PRIVILEGE_LITERAL_RE },
    { name: 'CONSERVED_BALANCE_FIELD_RE', re: floorHeuristics.CONSERVED_BALANCE_FIELD_RE },
    { name: 'CONSERVED_ECHO_FIELD_RE', re: floorHeuristics.CONSERVED_ECHO_FIELD_RE },
    { name: 'CONSERVED_AMOUNT_FIELD_RE', re: floorHeuristics.CONSERVED_AMOUNT_FIELD_RE },
    { name: 'SAFE_RESOURCE_ID_RE', re: floorHeuristics.SAFE_RESOURCE_ID_RE },
    { name: 'SAFE_FIELD_NAME_RE', re: floorHeuristics.SAFE_FIELD_NAME_RE },
    { name: 'SAFE_PERSONA_HANDLE_RE', re: floorHeuristics.SAFE_PERSONA_HANDLE_RE },
    { name: 'SAFE_IDENTIFIER_RE', re: floorHeuristics.SAFE_IDENTIFIER_RE },
    { name: 'POSTURE_CATEGORY_RE', re: floorHeuristics.POSTURE_CATEGORY_RE },
  ]
  const heuristicsSource = unescaped(serverFile('floor-heuristics.ts'))
  const consumerSources = DEDUP_CONSUMERS.map(name => ({ name, text: unescaped(serverFile(name)) }))
  for (const { name, re } of guardPatterns) {
    const needle = unescaped(re.source)
    assert.ok(heuristicsSource.includes(needle),
      `guard honesty: ${name} no longer matches floor-heuristics.ts; update this test`)
    for (const consumer of consumerSources) {
      assert.ok(!consumer.text.includes(needle),
        `${consumer.name} re-inlines the deduplicated ${name}; import it from floor-heuristics.ts instead`)
    }
  }
})

test('static guard: heuristic vocabulary fragments (incl. the historical inline variants) are not re-inlined', () => {
  // Contiguous fragments shared by the current canonical patterns and the pre-dedup inline
  // variants, so pasting either old copy back is caught even though it differs from the canonical.
  const fragments: ReadonlyArray<string> = [
    'superuser|privileged|backoffice',
    'admin|administrator|owner|superuser|root|staff',
    'role|role_name|user_role|account_role|account_type|membership|plan|tier|level|scope|is_admin|is_owner|is_staff',
    'amount|total|price|value|cents|balance|qty|quantity|count|seats?|credits?',
    'name|title|label|description|note|notes|body|text|summary|message|subject|comment|company|address',
    'number|num|limit|score|rating|page|size|order',
    'status|state|stage|phase|payment_state|fulfil?lment_state|lifecycle|visibility|priority|archived?|active',
    'diag|diagnostics?|exec|execute|command|cmd|shell|ping|nslookup',
    'whois|healthcheck|system',
    'redirect|return|callback|continue|resume|sso|oauth|authorize|checkout|download|export|next',
    'billing[-_]?docs',
    'is_?_?admin',
    'act_as',
    'proxies',
    'wsdl',
    'snippet|snippets',
    'gx9000001',
    'kovo-baseline-',
    'superadmin: 5',
    'CWE-1004',
  ]
  const heuristicsSource = unescaped(serverFile('floor-heuristics.ts'))
  const consumerSources = DEDUP_CONSUMERS.map(name => ({ name, text: unescaped(serverFile(name)) }))
  for (const fragment of fragments) {
    const needle = unescaped(fragment)
    assert.ok(heuristicsSource.includes(needle),
      `guard honesty: fragment ${JSON.stringify(needle.slice(0, 40))} no longer lives in floor-heuristics.ts; update this test`)
    for (const consumer of consumerSources) {
      assert.ok(!consumer.text.includes(needle),
        `${consumer.name} re-inlines heuristic vocabulary (${needle.slice(0, 40)}...); add it to floor-heuristics.ts instead`)
    }
  }
})

test('static guard: no dynamic RegExp construction grows in the deduplicated routing modules', () => {
  // floor-recipe-engine.ts keeps exactly its two pre-existing, non-heuristic compilations
  // (a numeric status assertion filter and the rule-selector table); every other routing module
  // stays at zero dynamic RegExp construction.
  const counts = DEDUP_CONSUMERS.map(name => ({
    name,
    count: (serverFile(name).match(/new RegExp\(/g) ?? []).length,
  }))
  for (const { name, count } of counts) {
    const ceiling = name === 'floor-recipe-engine.ts' ? 2 : 0
    assert.ok(count <= ceiling,
      `${name} grew dynamic RegExp construction (${count} > ${ceiling}); use a static literal or floor-heuristics.ts`)
  }
})

// ---------------------------------------------------------------------------------------------
// 7. Concurrent-stream coverage (from 7f3315e) kept verbatim: end-to-end spec synthesis and
//    recipe planning through the shared heuristics, retest-health fail-closed routing, and the
//    benchmark-literals guard.
// ---------------------------------------------------------------------------------------------

const origin = 'http://fixture.invalid'
const hypothesis = (): EngineHypothesis => ({
  key: 'authz|widget|w-1',
  endpoint: { id: 'ep-widget', origin, method: 'PATCH', pathTemplate: '/api/widgets/{{id}}/promote', params: [] },
  probeClass: 'authz_matrix',
  intent: 'authz',
  method: 'PATCH',
  pathAndQuery: '/api/widgets/{{id}}/promote',
  ownerPersona: 'owner',
  otherPersona: 'viewer',
  resourceIds: ['w-1'],
  jsonBody: { role: 'admin', title: 'alpha' },
  readbackPath: '/api/widgets/{{id}}',
  authzRequiredRole: 'admin',
  risk: 80,
})
const authzSignal = (): DifferentialResult => ({
  probeClass: 'authz_matrix', origin, pathAndQuery: '/api/widgets/{{id}}/promote', verdict: 'signal',
  summary: 'cross-actor mutation', requestsSent: 0, exchangeIds: [], stoppedReason: null, notes: [], durationMs: 1,
  anomalies: [{ type: 'unauthorized_access', method: 'PATCH', resourceId: 'w-1', actor: 'other_persona', similarityToOwner: 1, bodyTemplate: { role: 'admin', title: 'alpha' } }],
  details: { matrix: [
    { resourceId: 'w-1', actor: 'owner', accessible: true, status: 200, bodyBytes: 32 },
    { resourceId: 'w-1', actor: 'other_persona', accessible: true, status: 200, bodyBytes: 32, similarityToOwner: 1 },
  ] },
} as DifferentialResult)

test('P3 Cut A: shared route, field, template, and conserved-value classifiers stay linear and bounded', () => {
  assert.ok(PRIVILEGED_ACTION_RE.test('/api/administrator/feature-flags'))
  assert.ok(SENSITIVE_READ_ROUTE_RE.test('/api/audit-log'))
  assert.ok(IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/switch-tenant'))
  assert.ok(hasDynamicIdSegment('/api/widgets/:widgetId?view=full'))
  assert.ok(pathHasNounSegment('/api/products/42', 'product'))
  assert.ok(pathHasNounSegment('/api/products', 'product', true))
  assert.equal(pathHasNounSegment('/api/product-archive', 'product'), false)
  assert.ok(CONSERVED_BALANCE_FIELD_RE.test('remaining_quantity'))
  assert.ok(CONSERVED_ECHO_FIELD_RE.test('reserved_qty'))
  assert.ok(CONSERVED_AMOUNT_FIELD_RE.test('item_amount'))
  assert.ok(isIdentityAssignmentField('tenantId'))
  assert.deepEqual(withoutIdentityFields({ role: 'admin', profile: { tenantId: 't-2', name: 'kept' } }), { profile: { name: 'kept' } })
  assert.ok(isSafeResourceId('widget:42') && !isSafeResourceId('widget/42'))
  assert.ok(isSafeFieldName('display_name') && !isSafeFieldName('display name'))
  assert.ok(isSafePersonaHandle('viewer_1') && !isSafePersonaHandle('Viewer'))
  assert.ok(isSafeIdentifier('_claim1') && !isSafeIdentifier('1claim'))
  assert.equal(rolePrivilegeRank('admin')! > rolePrivilegeRank('viewer')!, true)
})

test('P3 Cut A: baseline, privilege, and readback helpers preserve non-idempotent safe writes', () => {
  const baseline = pickBaselineWrite({ tenantId: 't-1', enabled: false })!
  assert.equal(baseline.field, 'enabled')
  assert.deepEqual(baseline.baselineBody, { tenantId: 't-1', enabled: true })
  assert.equal(privilegeBaselineFor({ role: 'admin' }, 'admin')?.baselineValue, 'member')
  assert.deepEqual(escalatePrivilegeBody({ role: 'member', title: 'alpha' }, 'admin'), { role: 'admin', title: 'alpha' })
  assert.equal(escalatePrivilegeBody({ title: 'alpha' }, 'admin'), null)
  assert.deepEqual(resolveAuthzReadbackTemplate({ pathAndQuery: '/api/admin/widgets/{{id}}/promote' }, false), { template: '/api/admin/widgets/{{id}}' })
  assert.deepEqual(resolveAuthzReadbackTemplate({ pathAndQuery: '/api/admin/promote', readbackPath: '/api/profile', readbackPersona: 'viewer' }, true), { template: '/api/profile', persona: 'viewer' })
  assert.equal(fillResourceId('/api/widgets/{{id}}', 'a/b'), '/api/widgets/a%2Fb')
  assert.notEqual(bogusIdFor('42'), '42')
})

test('P3 Cut A: deterministic spec and engine consume the same authorization evidence', () => {
  const hyp = hypothesis()
  const signal = authzSignal()
  const matrix = signal.details.matrix as Record<string, unknown>[]
  assert.equal(isAuthzMatrixHitAdmissible(matrix, signal.anomalies[0]!, { mutating: true, functionLevel: false }), true)
  const publicMatrix = [...matrix, { resourceId: 'w-1', actor: 'anonymous', accessible: true, status: 200, bodySha256: 'same', similarityToOwner: 1 }]
  assert.equal(isAuthzMatrixHitAdmissible(publicMatrix, { ...signal.anomalies[0], method: 'GET' }, { mutating: false, functionLevel: false }), false)

  const candidate = synthesizeEngineSpecs(hyp, signal)[0]!
  assert.ok(candidate)
  assert.equal(wiredRecipeForSpecKind(candidate.kind, candidate.vulnClass), 'access_boundary')
  const plan = planFloorRecipe({ hypothesis: hyp, probe: signal, specKind: candidate.kind, vulnClass: candidate.vulnClass, personas: [
    { handle: 'owner', roleLabel: 'admin', privilege: 'admin' },
    { handle: 'viewer', roleLabel: 'viewer', privilege: 'viewer' },
  ] })
  assert.equal(plan?.recipeId, 'persisted_mutation')
  assert.equal(plan?.skipReason, undefined)
  const args = plan!.args as PersistedMutationArgs
  assert.equal(args.readbackPathAndQuery, '/api/widgets/w-1')
  assert.equal(pickBaselineWrite(hyp.jsonBody)?.field, 'title')
  assert.match(String(args.baselineWrite?.body.title ?? ''), /^kovo-baseline-[a-f0-9]{8}$/)
  assert.equal(specBogusIdFor, bogusIdFor)
  assert.equal(engineHasDynamicIdSegment, hasDynamicIdSegment)
  assert.equal(ENGINE_IDENTITY_ASSUMPTION_ROUTE_RE, IDENTITY_ASSUMPTION_ROUTE_RE)
  assert.equal(engineIsIdentityAssignmentField, isIdentityAssignmentField)
  assert.equal(engineWithoutIdentityFields, withoutIdentityFields)
  assert.equal(enginePathHasPrivilegedHint, pathHasPrivilegedHint)
})

test('P3 Cut A: retest health, CWE-first routing, and envelope default-deny remain fail-closed', () => {
  const execution = (status: number): FloorRecipeExecution => ({
    result: { recipeId: 'access_boundary', confirmed: false, exchangeIds: ['c', 'p'], oobEventIds: [], transcript: { entries: [] }, verification: { rule: 'impact', confirmed: false, reason: 'denied' }, steps: [
      { exchangeId: 'c', role: 'entitled_read', arm: 'control', method: 'GET', pathAndQuery: '/x', status: 200, durationMs: 1 },
      { exchangeId: 'p', role: 'cross_actor', arm: 'probe', method: 'GET', pathAndQuery: '/x', status, durationMs: 1 },
    ] },
    receipt: { vulnClass: 'bola', target: { origin, method: 'GET' }, exchangeIds: ['c', 'p'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'control' },
  } as unknown as FloorRecipeExecution)
  assert.equal(classifyRetestHealth(execution(403)).healthy, true)
  assert.equal(classifyRetestHealth(execution(500)).code, 'probe_status_unhealthy')
  assert.equal(classifyRetestHealth(execution(200)).code, 'access_probe_not_denied')
  const spec = { kind: 'http_chain', cwe: 'CWE-89', category: 'sqli', title: 'SQL injection', impact: 'query injection' } as DeclarativeReplaySpec
  assert.equal(receiptVulnClassFor(spec), 'injection')
  assert.equal(receiptVulnClassFor({ ...spec, title: 'SSRF in search parameter' } as DeclarativeReplaySpec), null)
  assert.equal(proofReceiptMode({}), 'strict')
  const verifier = readFileSync(new URL('../src/server/replay-verifier.ts', import.meta.url), 'utf8')
  assert.ok(verifier.includes("params.envelopeTrust === 'host_persisted' ? 'host_persisted' : 'untrusted'"))
})

test('P3 Cut A: duplicated legacy builders and dynamic engine regexes are retired', () => {
  const specs = readFileSync(new URL('../src/server/deterministic-specs.ts', import.meta.url), 'utf8')
  const engine = readFileSync(new URL('../src/server/deterministic-engine.ts', import.meta.url), 'utf8')
  const recipeEngine = readFileSync(new URL('../src/server/floor-recipe-engine.ts', import.meta.url), 'utf8')
  const recipes = readFileSync(new URL('../src/server/floor-recipes.ts', import.meta.url), 'utf8')
  const heuristics = readFileSync(new URL('../src/server/floor-heuristics.ts', import.meta.url), 'utf8')
  const consumers = `${specs}\n${engine}\n${recipeEngine}\n${recipes}`
  assert.doesNotMatch(consumers, /function (?:bogusIdFor|authzReadbackTemplate|authzReadback|baselineWriteFor|isIdentityAssignmentField|withoutIdentityFields|pathHasPrivilegedHint|specClassFamily)\b/)
  assert.doesNotMatch(consumers, /(?:const|export const) (?:PRIVILEGED_ACTION_RE|BASELINE_STRONG_NUMERIC_FIELD_RE)\s*=/)
  assert.doesNotMatch(consumers, /\^\[A-Za-z0-9_\.:-\]\{1,128\}\$/)
  assert.doesNotMatch(engine, /new\s+RegExp/)
  assert.doesNotMatch(heuristics, /new\s+RegExp/)
  assert.doesNotMatch(`${consumers}\n${heuristics}`, /paygrid|shipforge|nexusiam|connecthub/i)
})
