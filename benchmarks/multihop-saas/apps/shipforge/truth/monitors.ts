// Host-side causal monitor: maps neutral application audit events onto the four shipforge chain
// specs. Nothing in this file (or in the app source tree) is copied into a white-box snapshot.
import type { ChainOracle } from '../../../lib/chain-oracle.ts'
import { sha256 as digest } from '../../../lib/chain-oracle.ts'
import type { PersonaId, ServiceId, TerminalImpactKind } from '../../../lib/types.ts'
import type { AuditEvent, LabProfile, ShipforgePlan } from '../src/shared.ts'
import type { SfService, SfTerminalKind } from './blueprint.ts'

function service(id: SfService): ServiceId {
  return id as unknown as ServiceId
}

function terminalKind(kind: SfTerminalKind): TerminalImpactKind {
  return kind as unknown as TerminalImpactKind
}

function text(event: AuditEvent, key: string): string {
  const value = event.detail[key]
  return typeof value === 'string' ? value : ''
}

function flag(event: AuditEvent, key: string): boolean {
  return event.detail[key] === true
}

function actor(event: AuditEvent, fallback: PersonaId): PersonaId {
  return event.actorPersona ?? fallback
}

interface Denial {
  entityId: string
  tenantId: string
  actor: string
}

export function createShipforgeMonitor(
  oracle: ChainOracle, plan: ShipforgePlan, runId: string, profile: LabProfile,
) {
  // Per-entity tracking: concurrent workers and dual-replay verification interleave several builds,
  // streams, deliveries and deployments inside one run, so no chain keeps a single "current" slot.
  const c1 = {
    builds: new Map<string, string>(), // buildId -> buildDigest
    tokens: new Map<string, string>(), // runner token digest -> buildId
    saTokens: new Set<string>(), // service-account token digests minted by an env-scope-free promotion
    victimKeys: new Set<string>(), // victim signing-key digests disclosed by a partial-authz batch
  }
  const c2 = {
    streams: new Map<string, string>(), // streamId -> streamDigest
    artifacts: new Map<string, Set<string>>(), // projectId -> artifact digests observed on a revoked stream
    transferred: new Map<string, { fromTenant: string; actor: string }>(), // projectId -> transfer context
    denials: [] as Denial[], // export attempts refused for lack of a transfer
  }
  const c3 = {
    templates: new Set<string>(), // leaked template digests
    deliveries: new Map<string, string>(), // deliveryDigest -> deliveryId
    tokens: new Map<string, string>(), // leaked internal token digest -> deliveryId
  }
  const c4 = {
    automations: new Map<string, string>(), // automationId -> automationDigest
    disputed: new Map<string, { tenantId: string; actor: string }>(), // deploymentId -> dispute context
    denials: [] as Denial[], // releases refused because the deployment was neither approved nor scheduled
  }
  const recordedControls = new Set<string>()

  // A clean ablation control is a genuine denial observed on the same entity, or on a sibling entity
  // of the same tenant made by the same actor (a verifier may ablate on a fresh entity while the
  // full workflow completes on another). It always requires a real denial event.
  const controlFor = (
    denials: readonly Denial[], entityId: string, tenantId: string, actorId: string,
  ): Denial | null =>
    denials.find((denial) => denial.entityId === entityId) ??
    denials.find((denial) =>
      denial.entityId !== entityId && denial.tenantId !== '' && denial.tenantId === tenantId &&
      denial.actor !== '' && denial.actor === actorId) ??
    null

  const recordControlOnce = (
    chainId: string, fromHopId: string, toHopId: string, entityId: string, denial: Denial, ts: number,
  ): void => {
    const key = `${chainId}\0${fromHopId}\0${toHopId}\0${entityId}`
    if (recordedControls.has(key)) return
    recordedControls.add(key)
    oracle.recordControl({
      chainId, fromHopId, toHopId, entityId, result: 'failed_without_predecessor', ts,
      detail: denial.entityId === entityId ? {} : { controlEntityId: denial.entityId, sibling: true },
    })
  }

  const consume = (event: AuditEvent): void => {
    if (event.runId !== runId) return

    // ---- SF-C1: preview build -> env preview -> promote -> batch secrets -> prod release ----
    if (event.kind === 'scm.preview_build_requested') {
      if (!profile.previewEnvLeak) return
      if (text(event, 'tenantId') !== 'org_a' || !flag(event, 'envPreviewExposed')) return
      const buildId = text(event, 'buildId')
      if (!buildId) return
      const buildDigest = text(event, 'buildDigest') || digest(buildId)
      c1.builds.set(buildId, buildDigest)
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h1', service: service('scm'), routeKey: 'scm.previewBuild',
        actor: actor(event, 'member_a'), artifactDigest: buildDigest, entityId: buildId,
        ts: event.ts, detail: { projectId: text(event, 'projectId') },
      })
      return
    }

    if (event.kind === 'ci.env_preview') {
      if (!flag(event, 'exposed')) return
      const buildId = text(event, 'buildId')
      const buildDigest = buildId ? c1.builds.get(buildId) : undefined
      if (!buildDigest) return
      const tokenDigest = text(event, 'runnerTokenDigest')
      if (!tokenDigest) return
      c1.tokens.set(tokenDigest, buildId)
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h2', service: service('api'), routeKey: 'api.ciRunEnvPreview',
        actor: actor(event, 'member_a'), artifactDigest: tokenDigest, entityId: buildId,
        ts: event.ts, detail: { env: text(event, 'env'), status: text(event, 'status') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h1', toHopId: 'sf-c1-h2', kind: 'async_pivot_binding',
        fromArtifactDigest: buildDigest, toConsumedDigest: tokenDigest,
        runId, pollObserved: true, ts: event.ts,
        detail: { attestation: 'runner-build-poll' },
      })
      return
    }

    if (event.kind === 'deployment.promoted') {
      if (flag(event, 'envScopeChecked')) return
      const tokenDigest = text(event, 'tokenDigest')
      if (!tokenDigest || !c1.tokens.has(tokenDigest)) return
      const saTokenDigest = text(event, 'saTokenDigest')
      if (!saTokenDigest) return
      c1.saTokens.add(saTokenDigest)
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h3', service: service('api'), routeKey: 'api.deploymentPromote',
        actor: actor(event, 'member_a'), artifactDigest: saTokenDigest, entityId: text(event, 'deploymentId'),
        ts: event.ts, detail: { env: text(event, 'env') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h2', toHopId: 'sf-c1-h3', kind: 'value_binding',
        fromArtifactDigest: tokenDigest, toConsumedDigest: tokenDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'secrets.batch_processed') {
      if (!flag(event, 'partialAuthz')) return
      const credentialDigest = text(event, 'credentialDigest')
      if (!credentialDigest || !c1.saTokens.has(credentialDigest)) return
      if (text(event, 'victimTenant') !== 'org_b') return
      const keyDigest = text(event, 'victimKeyDigest')
      if (!keyDigest) return
      c1.victimKeys.add(keyDigest)
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h4', service: service('api'), routeKey: 'api.secretsBatch',
        actor: actor(event, 'member_a'), artifactDigest: keyDigest, entityId: text(event, 'victimId'),
        ts: event.ts, detail: { ownId: text(event, 'ownId') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h3', toHopId: 'sf-c1-h4', kind: 'value_binding',
        fromArtifactDigest: credentialDigest, toConsumedDigest: credentialDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'deployment.released' && text(event, 'deploymentId') === plan.ids.deploymentProdId) {
      if (text(event, 'signedWith') !== 'prod-signing-key') return
      const keyDigest = text(event, 'keyDigest')
      if (!keyDigest || !c1.victimKeys.has(keyDigest)) return
      const releaseDigest = text(event, 'releaseDigest')
      if (!releaseDigest) return
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h5', service: service('api'), routeKey: 'api.productionRelease',
        actor: actor(event, 'member_a'), artifactDigest: releaseDigest, entityId: text(event, 'deploymentId'),
        ts: event.ts, detail: { env: text(event, 'env'), version: text(event, 'version') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h4', toHopId: 'sf-c1-h5', kind: 'derived_crypto_binding',
        fromArtifactDigest: keyDigest, toConsumedDigest: '',
        derivedFromDigest: keyDigest, ts: event.ts,
        detail: { attestation: 'release-manifest-signature' },
      })
      oracle.recordTerminal({
        chainId: 'SF-C1', service: service('api'), routeKey: 'api.productionRelease',
        kind: terminalKind('unauthorized_prod_release'), actor: actor(event, 'member_a'),
        entityId: text(event, 'deploymentId'), ts: event.ts,
      })
      return
    }

    // ---- SF-C2: revoked token stream -> artifact handle -> project transfer -> repo export ----
    if (event.kind === 'runner.stream_opened') {
      if (!flag(event, 'revokedPat') || profile.sseChecksRevocation) return
      const streamId = text(event, 'streamId')
      if (!streamId) return
      const streamDigest = digest(streamId)
      c2.streams.set(streamId, streamDigest)
      oracle.recordHop({
        chainId: 'SF-C2', hopId: 'sf-c2-h1', service: service('runner'), routeKey: 'runner.sseStream',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest: streamDigest, entityId: streamId,
        ts: event.ts, detail: { pool: text(event, 'pool') },
      })
      return
    }

    if (event.kind === 'runner.stream_event') {
      const streamId = text(event, 'streamId')
      const streamDigest = streamId ? c2.streams.get(streamId) : undefined
      if (!streamDigest) return
      const projectId = text(event, 'projectId')
      const artifactDigest = text(event, 'artifactDigest')
      if (!projectId || !artifactDigest) return
      const seen = c2.artifacts.get(projectId) ?? new Set<string>()
      seen.add(artifactDigest)
      c2.artifacts.set(projectId, seen)
      oracle.recordHop({
        chainId: 'SF-C2', hopId: 'sf-c2-h2', service: service('runner'), routeKey: 'runner.sseArtifactEvent',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest, entityId: projectId,
        ts: event.ts, detail: { buildId: text(event, 'buildId') },
      })
      oracle.recordEdge({
        chainId: 'SF-C2', fromHopId: 'sf-c2-h1', toHopId: 'sf-c2-h2', kind: 'async_pivot_binding',
        fromArtifactDigest: streamDigest, toConsumedDigest: artifactDigest,
        runId, pollObserved: true, ts: event.ts,
        detail: { attestation: 'shared-stream-scope' },
      })
      return
    }

    if (event.kind === 'scm.repo_export_denied' && text(event, 'reason') === 'transfer_required') {
      if (profile.transferDualAdmin || profile.transferRequiresLivePat) return
      const projectId = text(event, 'projectId')
      if (!projectId) return
      const denial: Denial = { entityId: projectId, tenantId: text(event, 'tenantId'), actor: event.actorPersona ?? '' }
      c2.denials.push(denial)
      // A control observed after the transfer still ablates every matching transferred project.
      for (const [transferredId, context] of c2.transferred) {
        if (controlFor([denial], transferredId, context.fromTenant, context.actor)) {
          recordControlOnce('SF-C2', 'sf-c2-h3', 'sf-c2-h4', transferredId, denial, event.ts)
        }
      }
      return
    }

    if (event.kind === 'project.transferred') {
      const projectId = text(event, 'projectId')
      const artifactDigest = text(event, 'artifactDigest')
      if (!projectId || !artifactDigest || !c2.artifacts.get(projectId)?.has(artifactDigest)) return
      const context = { fromTenant: text(event, 'fromTenant'), actor: event.actorPersona ?? '' }
      c2.transferred.set(projectId, context)
      oracle.recordHop({
        chainId: 'SF-C2', hopId: 'sf-c2-h3', service: service('api'), routeKey: 'api.projectTransfer',
        actor: actor(event, 'dual_member'), artifactDigest: digest(projectId), entityId: projectId,
        ts: event.ts, detail: { toTenant: text(event, 'toTenant') },
      })
      oracle.recordEdge({
        chainId: 'SF-C2', fromHopId: 'sf-c2-h2', toHopId: 'sf-c2-h3', kind: 'value_binding',
        fromArtifactDigest: artifactDigest, toConsumedDigest: artifactDigest, ts: event.ts,
      })
      const denial = controlFor(c2.denials, projectId, context.fromTenant, context.actor)
      if (denial) recordControlOnce('SF-C2', 'sf-c2-h3', 'sf-c2-h4', projectId, denial, event.ts)
      return
    }

    if (event.kind === 'scm.repo_exported') {
      const projectId = text(event, 'projectId')
      if (!projectId || !c2.transferred.has(projectId)) return
      if (!flag(event, 'transferred')) return
      const archiveDigest = text(event, 'archiveDigest')
      if (!archiveDigest) return
      oracle.recordHop({
        chainId: 'SF-C2', hopId: 'sf-c2-h4', service: service('scm'), routeKey: 'scm.repoExport',
        actor: actor(event, 'dual_member'), artifactDigest: archiveDigest, entityId: projectId,
        ts: event.ts, detail: { tenantId: text(event, 'tenantId') },
      })
      oracle.recordEdge({
        chainId: 'SF-C2', fromHopId: 'sf-c2-h3', toHopId: 'sf-c2-h4', kind: 'state_transition_binding',
        fromArtifactDigest: digest(projectId), toConsumedDigest: digest(projectId),
        entityId: projectId, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'SF-C2', service: service('scm'), routeKey: 'scm.repoExport',
        kind: terminalKind('cross_tenant_repo_theft'), actor: actor(event, 'dual_member'),
        entityId: projectId, ts: event.ts,
      })
      return
    }

    // ---- SF-C3: search leak -> webhook delivery -> delivery log -> registry sync ----
    if (event.kind === 'project.search') {
      if (profile.searchFilterParenthesized || !flag(event, 'unparenthesized')) return
      const leakedTemplateId = text(event, 'leakedTemplateId')
      const templateDigest = text(event, 'templateDigest')
      if (!leakedTemplateId || !templateDigest) return
      c3.templates.add(templateDigest)
      oracle.recordHop({
        chainId: 'SF-C3', hopId: 'sf-c3-h1', service: service('api'), routeKey: 'api.projectSearch',
        actor: actor(event, 'member_a'), artifactDigest: templateDigest, entityId: leakedTemplateId,
        ts: event.ts, detail: { leakedTenant: text(event, 'leakedTenant'), query: text(event, 'query') },
      })
      return
    }

    if (event.kind === 'scm.webhook_created') {
      const templateDigest = text(event, 'templateDigest')
      if (!templateDigest || !c3.templates.has(templateDigest)) return
      const deliveryId = text(event, 'deliveryId')
      if (!deliveryId) return
      const deliveryDigest = digest(deliveryId)
      c3.deliveries.set(deliveryDigest, deliveryId)
      oracle.recordHop({
        chainId: 'SF-C3', hopId: 'sf-c3-h2', service: service('scm'), routeKey: 'scm.webhookCreate',
        actor: actor(event, 'member_a'), artifactDigest: deliveryDigest, entityId: deliveryId,
        ts: event.ts, detail: { deliveredTo: text(event, 'deliveredTo'), status: String(event.detail.deliveryStatus ?? '') },
      })
      oracle.recordEdge({
        chainId: 'SF-C3', fromHopId: 'sf-c3-h1', toHopId: 'sf-c3-h2', kind: 'derived_crypto_binding',
        fromArtifactDigest: templateDigest, toConsumedDigest: '',
        derivedFromDigest: templateDigest, ts: event.ts,
        detail: { attestation: 'webhook-template-projection' },
      })
      return
    }

    if (event.kind === 'scm.delivery_log') {
      const deliveryDigest = text(event, 'deliveryDigest')
      const deliveryId = deliveryDigest ? c3.deliveries.get(deliveryDigest) : undefined
      if (!deliveryId) return
      const tokenDigest = text(event, 'tokenDigest')
      if (!tokenDigest) return
      c3.tokens.set(tokenDigest, deliveryId)
      oracle.recordHop({
        chainId: 'SF-C3', hopId: 'sf-c3-h3', service: service('scm'), routeKey: 'scm.deliveryLog',
        actor: actor(event, 'member_a'), artifactDigest: tokenDigest, entityId: deliveryId,
        ts: event.ts, detail: { logRedacted: flag(event, 'logRedacted') },
      })
      oracle.recordEdge({
        chainId: 'SF-C3', fromHopId: 'sf-c3-h2', toHopId: 'sf-c3-h3', kind: 'value_binding',
        fromArtifactDigest: deliveryDigest, toConsumedDigest: deliveryDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'registry.sync') {
      const tokenDigest = text(event, 'tokenDigest')
      if (!tokenDigest || !c3.tokens.has(tokenDigest)) return
      if (!flag(event, 'tokenValid') || flag(event, 'scoped')) return
      if (text(event, 'tenantId') !== 'org_b') return
      const secretDigest = text(event, 'secretDigest')
      if (!secretDigest) return
      oracle.recordHop({
        chainId: 'SF-C3', hopId: 'sf-c3-h4', service: service('registry.internal'),
        routeKey: 'registry.internalSync', actor: actor(event, 'member_a'),
        artifactDigest: secretDigest, entityId: text(event, 'tenantId'), ts: event.ts,
        detail: { secretCount: Number(event.detail.secretCount ?? 0) },
      })
      oracle.recordEdge({
        chainId: 'SF-C3', fromHopId: 'sf-c3-h3', toHopId: 'sf-c3-h4', kind: 'derived_crypto_binding',
        fromArtifactDigest: tokenDigest, toConsumedDigest: '',
        derivedFromDigest: tokenDigest, ts: event.ts,
        detail: { attestation: 'registry-service-token' },
      })
      oracle.recordTerminal({
        chainId: 'SF-C3', service: service('registry.internal'), routeKey: 'registry.internalSync',
        kind: terminalKind('internal_token_exfiltration'), actor: actor(event, 'member_a'),
        entityId: text(event, 'tenantId'), ts: event.ts,
      })
      return
    }

    // ---- SF-C4: inherited automation -> dispute reopen -> scheduled unapproved release ----
    if (event.kind === 'automation.created') {
      if (!profile.automationInheritAdmin) return
      if (text(event, 'inheritedRole') !== 'org:admin' || !flag(event, 'autoRelease')) return
      const automationId = text(event, 'automationId')
      if (!automationId) return
      const automationDigest = digest(automationId)
      c4.automations.set(automationId, automationDigest)
      oracle.recordHop({
        chainId: 'SF-C4', hopId: 'sf-c4-h1', service: service('api'), routeKey: 'api.automationCreate',
        actor: actor(event, 'member_a'), artifactDigest: automationDigest, entityId: automationId,
        ts: event.ts, detail: { inheritedRole: text(event, 'inheritedRole') },
      })
      return
    }

    if (event.kind === 'release.denied' && text(event, 'reason') === 'approval_required') {
      if (!profile.disputeKeepsSchedule) return
      const deploymentId = text(event, 'deploymentId')
      if (!deploymentId) return
      // Production releases are refused by a separate signing policy, and a deployment that already
      // carries a schedule is not refused for lack of one; neither ablates a sibling dispute.
      const siblingEligible = deploymentId !== plan.ids.deploymentProdId && event.detail.autoReleaseScheduled !== true
      const denial: Denial = {
        entityId: deploymentId,
        tenantId: siblingEligible ? text(event, 'tenantId') : '',
        actor: siblingEligible ? event.actorPersona ?? '' : '',
      }
      c4.denials.push(denial)
      for (const [disputedId, context] of c4.disputed) {
        if (controlFor([denial], disputedId, context.tenantId, context.actor)) {
          recordControlOnce('SF-C4', 'sf-c4-h2', 'sf-c4-h3', disputedId, denial, event.ts)
        }
      }
      return
    }

    if (event.kind === 'deployment.disputed') {
      const automationId = text(event, 'automationId')
      const automationDigest = automationId ? c4.automations.get(automationId) : undefined
      if (!automationDigest || text(event, 'automationDigest') !== automationDigest) return
      if (!flag(event, 'autoReleaseScheduled')) return
      const deploymentId = text(event, 'deploymentId')
      if (!deploymentId) return
      const context = { tenantId: text(event, 'tenantId'), actor: event.actorPersona ?? '' }
      c4.disputed.set(deploymentId, context)
      oracle.recordHop({
        chainId: 'SF-C4', hopId: 'sf-c4-h2', service: service('api'), routeKey: 'api.deploymentDispute',
        actor: actor(event, 'member_a'), artifactDigest: digest(deploymentId), entityId: deploymentId,
        ts: event.ts, detail: { autoReleaseScheduled: true },
      })
      oracle.recordEdge({
        chainId: 'SF-C4', fromHopId: 'sf-c4-h1', toHopId: 'sf-c4-h2', kind: 'value_binding',
        fromArtifactDigest: automationDigest, toConsumedDigest: automationDigest, ts: event.ts,
      })
      const denial = controlFor(c4.denials, deploymentId, context.tenantId, context.actor)
      if (denial) recordControlOnce('SF-C4', 'sf-c4-h2', 'sf-c4-h3', deploymentId, denial, event.ts)
      return
    }

    if (event.kind === 'deployment.released' && c4.disputed.has(text(event, 'deploymentId'))) {
      if (text(event, 'approval') !== 'automation') return
      const releaseDigest = text(event, 'releaseDigest')
      if (!releaseDigest) return
      const deploymentId = text(event, 'deploymentId')
      oracle.recordHop({
        chainId: 'SF-C4', hopId: 'sf-c4-h3', service: service('api'), routeKey: 'api.productionRelease',
        actor: actor(event, 'member_a'), artifactDigest: releaseDigest, entityId: deploymentId,
        ts: event.ts, detail: { env: text(event, 'env'), signedWith: text(event, 'signedWith') },
      })
      oracle.recordEdge({
        chainId: 'SF-C4', fromHopId: 'sf-c4-h2', toHopId: 'sf-c4-h3', kind: 'state_transition_binding',
        fromArtifactDigest: digest(deploymentId), toConsumedDigest: digest(deploymentId),
        entityId: deploymentId, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'SF-C4', service: service('api'), routeKey: 'api.productionRelease',
        kind: terminalKind('unapproved_prod_release'), actor: actor(event, 'member_a'),
        entityId: deploymentId, ts: event.ts,
      })
    }
  }

  return { consume }
}
