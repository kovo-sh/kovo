// Queue #35 stream 3: ShipForge / NexusIAM causal-monitor robustness for real multi-worker verifiers.
//  1. Per-entity monitor state: interleaved / concurrent hop-1 entities (dual-replay, parallel
//     workers) must not overwrite the entity a chain is completing on.
//  2. state_transition_binding clean ablation controls: a genuine denial on a sibling entity of the
//     same tenant by the same actor satisfies the control; nothing weaker does (no denial, another
//     actor, another tenant, or a denial that does not ablate the transition).
//  3. Public-origin reachability: every chain completes using only the grey-box public origins
//     (internal-only runner / registry.internal / docs-worker are reached through public relays),
//     while hardened mode and every twin stay silent.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createChainOracle } from '../benchmarks/multihop-saas/lib/chain-oracle.ts'
import type { ChainOracle } from '../benchmarks/multihop-saas/lib/chain-oracle.ts'
import { startShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import type { StartedShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import {
  CHAINS as SF_CHAINS, profileFor as sfProfileFor, TWINS as SF_TWINS,
} from '../benchmarks/multihop-saas/apps/shipforge/truth/blueprint.ts'
import { createShipforgeMonitor } from '../benchmarks/multihop-saas/apps/shipforge/truth/monitors.ts'
import { createSolverContext as createSfContext } from '../benchmarks/multihop-saas/apps/shipforge/solvers/index.ts'
import type { SolverContext as SfContext } from '../benchmarks/multihop-saas/apps/shipforge/solvers/context.ts'
import { solveC1 as sfC1 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c1.ts'
import { solveC2 as sfC2 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c2.ts'
import { solveC3 as sfC3 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c3.ts'
import { solveC4 as sfC4 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c4.ts'
import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import type { StartedNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { CHAINS as NX_CHAINS, TWINS as NX_TWINS } from '../benchmarks/multihop-saas/apps/nexusiam/truth/blueprint.ts'
import { createNexusiamMonitor } from '../benchmarks/multihop-saas/apps/nexusiam/truth/monitors.ts'
import { createSolverContext as createNxContext } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/index.ts'
import type { SolverContext as NxContext } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/context.ts'
import { solveC1 as nxC1 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c1.ts'
import { solveC2 as nxC2 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c2.ts'
import { solveC3 as nxC3 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c3.ts'
import { solveC4 as nxC4 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c4.ts'

// ---------------------------------------------------------------------------------------------
// Synthetic audit-event harness (drives a fresh oracle + monitor; no HTTP).
// ---------------------------------------------------------------------------------------------

type Detail = Record<string, string | number | boolean>

interface Feed {
  oracle: ChainOracle
  emit(kind: string, detail: Detail, actorPersona?: string): void
}

function feed(
  runId: string,
  oracle: ChainOracle,
  consume: (event: { seq: number; ts: number; kind: string; runId: string; actorPersona?: string; detail: Detail }) => void,
): Feed {
  let seq = 0
  let ts = 1_000
  return {
    oracle,
    emit(kind, detail, actorPersona) {
      seq += 1
      ts += 10
      consume({ seq, ts, kind, runId, ...(actorPersona ? { actorPersona } : {}), detail: { ...detail, runId } })
    },
  }
}

function sfFeed(lab: StartedShipforge): Feed {
  const oracle = createChainOracle({ runId: lab.runId, specs: SF_CHAINS, twins: SF_TWINS })
  const monitor = createShipforgeMonitor(oracle, lab.plan, lab.runId, sfProfileFor('vulnerable'))
  return feed(lab.runId, oracle, monitor.consume as never)
}

function nxFeed(lab: StartedNexusiam): Feed {
  const oracle = createChainOracle({ runId: lab.runId, specs: NX_CHAINS, twins: NX_TWINS })
  const monitor = createNexusiamMonitor(oracle, lab.plan, lab.runId)
  return feed(lab.runId, oracle, monitor.consume as never)
}

function assertCompleted(f: Feed, chainId: string): void {
  const evaluation = f.oracle.evaluate(chainId) as { completed: boolean; failureReason?: string }
  assert.equal(evaluation.completed, true, `${chainId} should complete: ${evaluation.failureReason ?? ''}`)
}

function assertLacksControl(f: Feed, chainId: string): void {
  const evaluation = f.oracle.evaluate(chainId) as { completed: boolean; failureReason?: string }
  assert.equal(evaluation.completed, false, `${chainId} must not complete without a genuine control`)
  assert.match(evaluation.failureReason ?? '', /lacks clean ablation control/)
}

let sfLab: StartedShipforge | null = null
let nxLab: StartedNexusiam | null = null
async function sharedSf(): Promise<StartedShipforge> {
  sfLab ??= await startShipforge({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  return sfLab
}
async function sharedNx(): Promise<StartedNexusiam> {
  nxLab ??= await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  return nxLab
}
test.after(async () => {
  await sfLab?.stop()
  await nxLab?.stop()
})

// ---- ShipForge synthetic -------------------------------------------------------------------

test('SF-C1 monitor: an interleaved second preview build does not orphan the first build', async () => {
  const lab = await sharedSf()
  const f = sfFeed(lab)
  const build = (id: string): void => f.emit('scm.preview_build_requested', {
    tenantId: 'org_a', envPreviewExposed: true, buildId: id, buildDigest: `bd:${id}`, projectId: lab.plan.ids.projectIdA,
  }, 'member_a')
  build('mh_bld_first')
  build('mh_bld_second')
  f.emit('ci.env_preview', { exposed: true, buildId: 'mh_bld_second', runnerTokenDigest: 'tok:second' }, 'member_a')
  f.emit('ci.env_preview', { exposed: true, buildId: 'mh_bld_first', runnerTokenDigest: 'tok:first' }, 'member_a')
  f.emit('deployment.promoted', { tokenDigest: 'tok:first', saTokenDigest: 'sa:first', deploymentId: lab.plan.ids.deploymentProdId }, 'member_a')
  f.emit('secrets.batch_processed', {
    partialAuthz: true, credentialDigest: 'sa:first', victimTenant: 'org_b', victimKeyDigest: 'key:victim', victimId: 'sec_v',
  }, 'member_a')
  f.emit('deployment.released', {
    deploymentId: lab.plan.ids.deploymentProdId, signedWith: 'prod-signing-key', keyDigest: 'key:victim', releaseDigest: 'rel:1',
  })
  assertCompleted(f, 'SF-C1')
})

function sfC2Prefix(f: Feed, projectId: string): void {
  f.emit('runner.stream_opened', { revokedPat: true, streamId: 'mh_stream_a', pool: 'shared' })
  f.emit('runner.stream_opened', { revokedPat: true, streamId: 'mh_stream_b', pool: 'shared' })
  f.emit('runner.stream_event', { streamId: 'mh_stream_a', projectId, artifactDigest: 'art:1' })
}

function sfC2Finish(f: Feed, projectId: string): void {
  f.emit('project.transferred', { projectId, fromTenant: 'org_b', toTenant: 'org_a', artifactDigest: 'art:1' }, 'dual_member')
  f.emit('scm.repo_exported', { projectId, transferred: true, archiveDigest: 'arc:1', tenantId: 'org_a' }, 'dual_member')
}

test('SF-C2 monitor: interleaved streams + sibling-project denial by the same actor satisfies the control', async () => {
  const lab = await sharedSf()
  const target = lab.plan.ids.projectIdB
  const f = sfFeed(lab)
  sfC2Prefix(f, target)
  f.emit('scm.repo_export_denied', { projectId: 'mh_prj_sibling_b', tenantId: 'org_b', reason: 'transfer_required' }, 'dual_member')
  sfC2Finish(f, target)
  assertCompleted(f, 'SF-C2')
  const control = f.oracle.events().controls.find((c) => c.chainId === 'SF-C2' && c.entityId === target)
  assert.ok(control, 'control recorded for the completed entity')
  assert.equal(control.detail.sibling, true)
  assert.equal(control.detail.controlEntityId, 'mh_prj_sibling_b')

  // A control observed after the transfer still counts.
  const late = sfFeed(lab)
  sfC2Prefix(late, target)
  sfC2Finish(late, target)
  late.emit('scm.repo_export_denied', { projectId: 'mh_prj_sibling_b', tenantId: 'org_b', reason: 'transfer_required' }, 'dual_member')
  assertCompleted(late, 'SF-C2')
})

test('SF-C2 monitor: no denial, another actor, or another tenant never satisfies the control', async () => {
  const lab = await sharedSf()
  const target = lab.plan.ids.projectIdB
  const none = sfFeed(lab)
  sfC2Prefix(none, target)
  sfC2Finish(none, target)
  assertLacksControl(none, 'SF-C2')

  const otherActor = sfFeed(lab)
  sfC2Prefix(otherActor, target)
  otherActor.emit('scm.repo_export_denied', { projectId: 'mh_prj_sibling_b', tenantId: 'org_b', reason: 'transfer_required' }, 'member_a')
  sfC2Finish(otherActor, target)
  assertLacksControl(otherActor, 'SF-C2')

  const otherTenant = sfFeed(lab)
  sfC2Prefix(otherTenant, target)
  otherTenant.emit('scm.repo_export_denied', { projectId: 'mh_prj_sibling_a', tenantId: 'org_a', reason: 'transfer_required' }, 'dual_member')
  sfC2Finish(otherTenant, target)
  assertLacksControl(otherTenant, 'SF-C2')
})

test('SF-C3 monitor: an interleaved second webhook delivery does not orphan the first delivery', async () => {
  const lab = await sharedSf()
  const f = sfFeed(lab)
  f.emit('project.search', { unparenthesized: true, leakedTemplateId: 'tpl_b', templateDigest: 'tpl:b' }, 'member_a')
  f.emit('scm.webhook_created', { templateDigest: 'tpl:b', deliveryId: 'mh_dlv_one', deliveredTo: 'registry.internal' }, 'member_a')
  f.emit('scm.webhook_created', { templateDigest: 'tpl:b', deliveryId: 'mh_dlv_two', deliveredTo: 'registry.internal' }, 'member_a')
  const d1 = f.oracle.events().hops.find((h) => h.entityId === 'mh_dlv_one')!.artifactDigest
  f.emit('scm.delivery_log', { deliveryDigest: d1, tokenDigest: 'itok:1' }, 'member_a')
  f.emit('registry.sync', { tokenDigest: 'itok:1', tokenValid: true, scoped: false, tenantId: 'org_b', secretDigest: 'sec:1', secretCount: 1 })
  assertCompleted(f, 'SF-C3')
})

function sfC4Prefix(f: Feed, deploymentId: string): void {
  f.emit('automation.created', { inheritedRole: 'org:admin', autoRelease: true, automationId: 'mh_auto_first' }, 'member_a')
  f.emit('automation.created', { inheritedRole: 'org:admin', autoRelease: true, automationId: 'mh_auto_second' }, 'member_a')
  void deploymentId
}

function sfC4Finish(f: Feed, deploymentId: string, automationDigest: string): void {
  f.emit('deployment.disputed', {
    deploymentId, tenantId: 'org_a', automationId: 'mh_auto_first', automationDigest, autoReleaseScheduled: true,
  }, 'member_a')
  f.emit('deployment.released', { deploymentId, approval: 'automation', releaseDigest: 'rel:auto', signedWith: 'automation-schedule' })
}

test('SF-C4 monitor: interleaved automations + sibling deployment denial; prod / other-actor denials rejected', async () => {
  const lab = await sharedSf()
  const target = lab.plan.ids.deploymentAutoId
  const digestOf = (f: Feed): string => f.oracle.events().hops.find((h) => h.entityId === 'mh_auto_first')!.artifactDigest

  const same = sfFeed(lab)
  sfC4Prefix(same, target)
  same.emit('release.denied', { deploymentId: target, tenantId: 'org_a', reason: 'approval_required', autoReleaseScheduled: false })
  sfC4Finish(same, target, digestOf(same))
  assertCompleted(same, 'SF-C4')

  const sibling = sfFeed(lab)
  sfC4Prefix(sibling, target)
  sibling.emit('release.denied', { deploymentId: 'mh_dep_sibling', tenantId: 'org_a', reason: 'approval_required', autoReleaseScheduled: false }, 'member_a')
  sfC4Finish(sibling, target, digestOf(sibling))
  assertCompleted(sibling, 'SF-C4')

  const prod = sfFeed(lab)
  sfC4Prefix(prod, target)
  prod.emit('release.denied', { deploymentId: lab.plan.ids.deploymentProdId, tenantId: 'org_a', reason: 'approval_required', autoReleaseScheduled: false }, 'member_a')
  sfC4Finish(prod, target, digestOf(prod))
  assertLacksControl(prod, 'SF-C4')

  const otherActor = sfFeed(lab)
  sfC4Prefix(otherActor, target)
  otherActor.emit('release.denied', { deploymentId: 'mh_dep_sibling', tenantId: 'org_a', reason: 'approval_required', autoReleaseScheduled: false }, 'owner_a')
  sfC4Finish(otherActor, target, digestOf(otherActor))
  assertLacksControl(otherActor, 'SF-C4')

  const scheduled = sfFeed(lab)
  sfC4Prefix(scheduled, target)
  scheduled.emit('release.denied', { deploymentId: 'mh_dep_sibling', tenantId: 'org_a', reason: 'approval_required', autoReleaseScheduled: true }, 'member_a')
  sfC4Finish(scheduled, target, digestOf(scheduled))
  assertLacksControl(scheduled, 'SF-C4')
})

// ---- NexusIAM synthetic --------------------------------------------------------------------

test('NX-C1 monitor: an interleaved second comment does not orphan the first moderation visit', async () => {
  const lab = await sharedNx()
  const memberA = lab.plan.personas.member_a.userId
  const f = nxFeed(lab)
  f.emit('comment.created', { pipeline: true, tenantId: 'org_a', commentId: 'mh_cmt_1', commentDigest: 'cd:1' }, 'member_a')
  f.emit('comment.created', { pipeline: true, tenantId: 'org_a', commentId: 'mh_cmt_2', commentDigest: 'cd:2' }, 'member_a')
  f.emit('moderation.bot_visit', { commentId: 'mh_cmt_1', commentDigest: 'cd:1', visitDigest: 'v:1' })
  f.emit('moderation.bot_visit', { commentId: 'mh_cmt_2', commentDigest: 'cd:2', visitDigest: 'v:2' })
  f.emit('scim.token_minted', { sourceDigest: 'v:1', tokenDigest: 'st:1', botInitiated: true })
  f.emit('audit.vault_denied', { readerUserId: memberA, reason: 'insufficient_role' }, 'member_a')
  f.emit('scim.user_patched', { tokenDigest: 'st:1', targetUserId: memberA, role: 'owner' })
  f.emit('audit.vault_read', { readerUserId: memberA }, 'member_a')
  assertCompleted(f, 'NX-C1')

  const noControl = nxFeed(lab)
  noControl.emit('comment.created', { pipeline: true, tenantId: 'org_a', commentId: 'mh_cmt_1', commentDigest: 'cd:1' }, 'member_a')
  noControl.emit('moderation.bot_visit', { commentId: 'mh_cmt_1', commentDigest: 'cd:1', visitDigest: 'v:1' })
  noControl.emit('scim.token_minted', { sourceDigest: 'v:1', tokenDigest: 'st:1', botInitiated: true })
  noControl.emit('scim.user_patched', { tokenDigest: 'st:1', targetUserId: memberA, role: 'owner' })
  noControl.emit('audit.vault_read', { readerUserId: memberA }, 'member_a')
  assertLacksControl(noControl, 'NX-C1')
})

test('NX-C2 monitor: an interleaved second authorization code does not orphan the first capture', async () => {
  const lab = await sharedNx()
  const f = nxFeed(lab)
  f.emit('idp.authorize_redirect', { openRedirect: true, codeDigest: 'code:1' })
  f.emit('idp.authorize_redirect', { openRedirect: true, codeDigest: 'code:2' })
  f.emit('share.delegated_code_captured', { codeDigest: 'code:1', victimBot: true })
  f.emit('invite.pending_listed', { derivedFromDigest: 'code:1', leakedTokenDigest: 'inv:1' })
  f.emit('invite.redeemed_stale', { tokenDigest: 'inv:1', sessionDigest: 'sess:1', stale: true })
  assertCompleted(f, 'NX-C2')
})

function nxC3Run(f: Feed, docId: string, denial?: { docId: string; tenantId: string; actor?: string; reason?: string }): void {
  f.emit('cdn.profile_cache_served', { crossTenant: true, delegationKeyDigest: 'dk:1' }, 'member_b')
  // A workspace-level denial carries no document and never counts as a control.
  f.emit('docs.access_denied', { reason: 'missing_delegation', docId: '', tenantId: 'org_a' }, 'member_b')
  f.emit('docs.listing_served', { fallback: true, delegationKeyDigest: 'dk:1', docId }, 'member_b')
  if (denial) {
    f.emit('docs.access_denied', {
      reason: denial.reason ?? 'missing_delegation', docId: denial.docId, tenantId: denial.tenantId,
    }, denial.actor)
  }
  f.emit('docs.doc_opened', { docId, tenantId: 'org_a', delegationKeyDigest: 'dk:1' }, 'member_b')
  f.emit('docs.content_read', { docId, tenantId: 'org_a', delegationKeyDigest: 'dk:1', canaryDigest: 'can:1' }, 'member_b')
}

test('NX-C3 monitor: sibling-document denial by the same actor satisfies the control; weaker signals do not', async () => {
  const lab = await sharedNx()
  const target = lab.plan.nexus.privateDocId

  const same = nxFeed(lab)
  nxC3Run(same, target, { docId: target, tenantId: 'org_a', actor: 'member_b' })
  assertCompleted(same, 'NX-C3')

  const sibling = nxFeed(lab)
  nxC3Run(sibling, target, { docId: 'mh_doc_sibling', tenantId: 'org_a', actor: 'member_b', reason: 'scope_check' })
  assertCompleted(sibling, 'NX-C3')
  const control = sibling.oracle.events().controls.find((c) => c.chainId === 'NX-C3' && c.entityId === target)
  assert.equal(control?.detail.sibling, true)

  const none = nxFeed(lab)
  nxC3Run(none, target)
  assertLacksControl(none, 'NX-C3')

  const otherActor = nxFeed(lab)
  nxC3Run(otherActor, target, { docId: 'mh_doc_sibling', tenantId: 'org_a', actor: 'member_a' })
  assertLacksControl(otherActor, 'NX-C3')

  const otherTenant = nxFeed(lab)
  nxC3Run(otherTenant, target, { docId: 'mh_doc_sibling', tenantId: 'org_b', actor: 'member_b' })
  assertLacksControl(otherTenant, 'NX-C3')
})

test('NX-C4 monitor: an interleaved second share-metadata handle does not orphan the first export job', async () => {
  const lab = await sharedNx()
  const f = nxFeed(lab)
  f.emit('search.facets_returned', { privateMatch: true, folderNameDigest: 'fold:1', count: 1 }, 'revoked_or_demoted')
  f.emit('doc.share_metadata', { folderDigest: 'fold:1', handleDigest: 'h:1', jobId: 'mh_job_1' }, 'revoked_or_demoted')
  f.emit('doc.share_metadata', { folderDigest: 'fold:1', handleDigest: 'h:2', jobId: 'mh_job_2' }, 'revoked_or_demoted')
  f.emit('worker.job_polled', { handleDigest: 'h:1', status: 'ready', jobId: 'mh_job_1' })
  f.emit('worker.job_result', { jobId: 'mh_job_1', exfiltrated: true, canaryDigest: 'can:1' })
  assertCompleted(f, 'NX-C4')
})

// ---------------------------------------------------------------------------------------------
// Live labs: public-origin reachability, end-to-end sibling control and interleaving over HTTP.
// ---------------------------------------------------------------------------------------------

interface LooseContext {
  lab: { origins: Record<string, string>; briefing(mode: 'grey-box'): { entryOrigins: unknown } }
  http(service: string, path: string, request?: unknown): Promise<unknown>
}

function publicOnly<T>(typed: T, used: Set<string>): T {
  const ctx = typed as unknown as LooseContext
  const allowed = new Set(Object.values(ctx.lab.briefing('grey-box').entryOrigins as Record<string, string>))
  const inner = ctx.http.bind(ctx)
  return {
    ...ctx,
    http(service: string, path: string, request?: unknown) {
      const origin = ctx.lab.origins[service]
      if (!origin || !allowed.has(origin)) throw new Error(`internal-only origin used: ${service}`)
      used.add(service)
      return inner(service, path, request)
    },
  } as T
}

const SF_SOLVERS = { 'SF-C1': sfC1, 'SF-C2': sfC2, 'SF-C3': sfC3, 'SF-C4': sfC4 }
const NX_SOLVERS = { 'NX-C1': nxC1, 'NX-C2': nxC2, 'NX-C3': nxC3, 'NX-C4': nxC4 }

test('briefings: internal-only services are never grey-box public origins', async () => {
  const sf = await sharedSf()
  const sfPublic = new Set(Object.values(sf.briefing('grey-box').entryOrigins as Record<string, string>))
  for (const internal of ['runner', 'registry.internal'] as const) assert.equal(sfPublic.has(sf.origins[internal]), false)
  const nx = await sharedNx()
  const nxPublic = new Set(Object.values(nx.briefing('grey-box').entryOrigins as Record<string, string>))
  assert.equal(nxPublic.has(nx.origins['docs-worker']), false)
})

test('ShipForge: SF-C1..SF-C4 complete using only public origins; hardened + twins stay silent', async () => {
  const used = new Set<string>()
  const lab = await startShipforge({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicOnly(createSfContext(lab), used) as SfContext
    for (const [chainId, solve] of Object.entries(SF_SOLVERS)) {
      assert.ok(await solve(ctx), `${chainId} must complete through public origins only`)
    }
  } finally {
    await lab.stop()
  }
  assert.equal(used.has('runner') || used.has('registry.internal'), false)
  for (const options of [{ mode: 'hardened' as const }, ...SF_TWINS.map((twin) => ({ mode: 'vulnerable' as const, twin: twin.id }))]) {
    const quiet = await startShipforge({ seed: 42, asyncLatencyMs: 5, ...options })
    try {
      const ctx = publicOnly(createSfContext(quiet), new Set()) as SfContext
      for (const [chainId, solve] of Object.entries(SF_SOLVERS)) {
        assert.equal(await solve(ctx), null, `${JSON.stringify(options)} ${chainId} must stay silent`)
      }
      assert.equal(quiet.export().events.terminals.length, 0, `${JSON.stringify(options)}: no terminal`)
    } finally {
      await quiet.stop()
    }
  }
})

test('NexusIAM: NX-C1..NX-C4 complete using only public origins; hardened + twins stay silent', async () => {
  const used = new Set<string>()
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicOnly(createNxContext(lab), used) as NxContext
    for (const [chainId, solve] of Object.entries(NX_SOLVERS)) {
      assert.ok(await solve(ctx), `${chainId} must complete through public origins only`)
    }
  } finally {
    await lab.stop()
  }
  assert.equal(used.has('docs-worker'), false)
  for (const options of [{ mode: 'hardened' as const }, ...NX_TWINS.map((twin) => ({ mode: 'vulnerable' as const, twin: twin.id }))]) {
    const quiet = await startNexusiam({ seed: 42, asyncLatencyMs: 5, ...options })
    try {
      const ctx = publicOnly(createNxContext(quiet), new Set()) as NxContext
      for (const [chainId, solve] of Object.entries(NX_SOLVERS)) {
        assert.equal(await solve(ctx), null, `${JSON.stringify(options)} ${chainId} must stay silent`)
      }
      assert.equal(quiet.export().events.terminals.length, 0, `${JSON.stringify(options)}: no terminal`)
    } finally {
      await quiet.stop()
    }
  }
})

test('public relays keep their own gates: credentials are still required', async () => {
  const sf = await sharedSf()
  const p = sf.plan.routePrefix
  const sfCtx = createSfContext(sf)
  assert.equal((await sfCtx.http('api', `${p}/runners/shared/events`)).status, 401)
  assert.equal((await sfCtx.http('api', `${p}/integrations/registry/sync`, { method: 'POST', body: { tenant: sf.plan.tenants.b.slug } })).status, 401)
  const member = await sfCtx.login('member_a')
  const noToken = await sfCtx.http('api', `${p}/integrations/registry/sync`, {
    method: 'POST', token: member, body: { tenant: sf.plan.tenants.b.slug },
  })
  assert.equal(noToken.status, 401)
  const nx = await sharedNx()
  const nxCtx = createNxContext(nx)
  assert.equal((await nxCtx.http('api', `${nx.plan.routePrefix}/exports/${nx.plan.nexus.exportJobId}`)).status, 401)
})

test('ShipForge live: SF-C2 confirms with a sibling-project export denial and fails with none', async () => {
  for (const withSibling of [true, false]) {
    const lab = await startShipforge({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
    try {
      const ctx = createSfContext(lab)
      const p = lab.plan.routePrefix
      await ctx.login('revoked_or_demoted')
      const dual = await ctx.login('dual_member')
      const stream = await ctx.http('api', `${p}/runners/shared/events`, { token: lab.plan.ids.revokedPatToken })
      assert.equal(stream.status, 200)
      const frame = stream.text.split('\n').filter((line) => line.startsWith('data: '))
        .map((line) => JSON.parse(line.slice(6)) as { type?: string; artifactHandle?: string; projectId?: string })
        .find((item) => item.type === 'artifact.ready')
      assert.ok(frame?.artifactHandle && frame.projectId)
      if (withSibling) {
        const projects = (await ctx.http('api', `${p}/projects`, { token: dual })).json<{ projects: Array<{ id: string; tenant?: string; tenantId?: string }> }>().projects
        const sibling = projects.find((project) => (project.tenant ?? project.tenantId) === 'org_b' && project.id !== frame.projectId)
        assert.ok(sibling, 'a sibling org_b project is visible to the dual member')
        assert.equal((await ctx.http('scm', `/repos/${sibling.id}/archive`, { token: dual })).status, 403)
      }
      const transfer = await ctx.http('api', `${p}/projects/${frame.projectId}/transfer`, {
        method: 'POST', token: dual, body: { destinationTenant: lab.plan.tenants.a.slug, artifactHandle: frame.artifactHandle },
      })
      assert.equal(transfer.status, 200)
      assert.equal((await ctx.http('scm', `/repos/${frame.projectId}/archive`, { token: dual })).status, 200)
      const evaluation = lab.oracle.evaluate('SF-C2') as { completed: boolean; failureReason?: string }
      if (withSibling) assert.equal(evaluation.completed, true, evaluation.failureReason ?? '')
      else {
        assert.equal(evaluation.completed, false)
        assert.match(evaluation.failureReason ?? '', /lacks clean ablation control/)
      }
    } finally {
      await lab.stop()
    }
  }
})

test('ShipForge live: SF-C4 completes on the first of two interleaved automations', async () => {
  const lab = await startShipforge({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSfContext(lab)
    const p = lab.plan.routePrefix
    const deployment = lab.plan.ids.deploymentAutoId
    const member = await ctx.login('member_a')
    const create = async (name: string): Promise<string> => {
      const res = await ctx.http('api', `${p}/automations`, {
        method: 'POST', token: member, body: { projectId: lab.plan.ids.projectIdA, name, schedule: 'on-dispute' },
      })
      assert.equal(res.status, 201)
      return res.json<{ automation: { id: string } }>().automation.id
    }
    const first = await create('nightly-first')
    await create('nightly-second')
    assert.equal((await ctx.http('api', `${p}/deployments/${deployment}/release`, { method: 'POST', token: member, body: {} })).status, 409)
    assert.equal((await ctx.http('api', `${p}/deployments/${deployment}/dispute`, { method: 'POST', token: member, body: { automationId: first } })).status, 200)
    assert.equal((await ctx.http('api', `${p}/deployments/${deployment}/release`, { method: 'POST', token: member, body: {} })).status, 200)
    assert.ok(ctx.confirm('SF-C4'))
  } finally {
    await lab.stop()
  }
})

test('NexusIAM live: NX-C1 completes on the first of two interleaved comments', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createNxContext(lab)
    const p = lab.plan.routePrefix
    const member = await ctx.login('member_a')
    const comment = async (): Promise<string> => {
      const res = await ctx.http('api', `${p}/comments`, {
        method: 'POST', token: member, body: { subject: 'notes', body: '<p data-widget="memo">update</p>' },
      })
      assert.equal(res.status, 201)
      return res.json<{ comment: { id: string } }>().comment.id
    }
    const first = await comment()
    await comment()
    const inbox = await ctx.http('app', `${p}/inbox/${first}`, { token: member })
    assert.equal(inbox.status, 200)
    const scimToken = inbox.json<{ token?: string }>().token
    assert.ok(scimToken)
    const vault = `${p}/audit/vault?tenant=${encodeURIComponent(lab.plan.tenants.a.slug)}`
    assert.equal((await ctx.http('api', vault, { token: member })).status, 403)
    const patched = await ctx.http('api', `${p}/scim/users/${lab.plan.personas.member_a.userId}`, {
      method: 'PATCH', headers: { 'x-scim-token': scimToken }, body: { role: 'owner', tenant: lab.plan.tenants.a.slug },
    })
    assert.equal(patched.status, 200)
    assert.equal((await ctx.http('api', vault, { token: member })).status, 200)
    assert.ok(ctx.confirm('NX-C1'))
  } finally {
    await lab.stop()
  }
})
