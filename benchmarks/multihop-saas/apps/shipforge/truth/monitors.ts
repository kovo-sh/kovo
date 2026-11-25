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

export function createShipforgeMonitor(
  oracle: ChainOracle, plan: ShipforgePlan, runId: string, profile: LabProfile,
) {
  const c1 = {
    buildId: '', buildDigest: '', tokenDigest: '', saTokenDigest: '', victimKeyDigest: '',
    h2: false, h3: false, h4: false,
  }
  const c2 = { streamId: '', streamDigest: '', projectId: '', artifactDigest: '', controlProject: '', h2: false, h3: false }
  const c3 = { templateDigest: '', deliveryId: '', deliveryDigest: '', tokenDigest: '', h2: false, h3: false }
  const c4 = { automationId: '', automationDigest: '', deploymentId: '', controlDeployment: '', h2: false }

  const consume = (event: AuditEvent): void => {
    if (event.runId !== runId) return

    // ---- SF-C1: preview build -> env preview -> promote -> batch secrets -> prod release ----
    if (event.kind === 'scm.preview_build_requested') {
      if (!profile.previewEnvLeak) return
      if (text(event, 'tenantId') !== 'org_a' || !flag(event, 'envPreviewExposed')) return
      const buildId = text(event, 'buildId')
      if (!buildId) return
      c1.buildId = buildId
      c1.buildDigest = text(event, 'buildDigest') || digest(buildId)
      c1.h2 = false
      c1.h3 = false
      c1.h4 = false
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h1', service: service('scm'), routeKey: 'scm.previewBuild',
        actor: actor(event, 'member_a'), artifactDigest: c1.buildDigest, entityId: buildId,
        ts: event.ts, detail: { projectId: text(event, 'projectId') },
      })
      return
    }

    if (event.kind === 'ci.env_preview') {
      if (!flag(event, 'exposed')) return
      if (!c1.buildId || text(event, 'buildId') !== c1.buildId) return
      const tokenDigest = text(event, 'runnerTokenDigest')
      if (!tokenDigest) return
      c1.tokenDigest = tokenDigest
      c1.h2 = true
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h2', service: service('api'), routeKey: 'api.ciRunEnvPreview',
        actor: actor(event, 'member_a'), artifactDigest: tokenDigest, entityId: c1.buildId,
        ts: event.ts, detail: { env: text(event, 'env'), status: text(event, 'status') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h1', toHopId: 'sf-c1-h2', kind: 'async_pivot_binding',
        fromArtifactDigest: c1.buildDigest, toConsumedDigest: tokenDigest,
        runId, pollObserved: true, ts: event.ts,
        detail: { attestation: 'runner-build-poll' },
      })
      return
    }

    if (event.kind === 'deployment.promoted') {
      if (!c1.h2 || flag(event, 'envScopeChecked')) return
      if (text(event, 'tokenDigest') !== c1.tokenDigest) return
      const saTokenDigest = text(event, 'saTokenDigest')
      if (!saTokenDigest) return
      c1.saTokenDigest = saTokenDigest
      c1.h3 = true
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h3', service: service('api'), routeKey: 'api.deploymentPromote',
        actor: actor(event, 'member_a'), artifactDigest: saTokenDigest, entityId: text(event, 'deploymentId'),
        ts: event.ts, detail: { env: text(event, 'env') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h2', toHopId: 'sf-c1-h3', kind: 'value_binding',
        fromArtifactDigest: c1.tokenDigest, toConsumedDigest: c1.tokenDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'secrets.batch_processed') {
      if (!c1.h3 || !flag(event, 'partialAuthz')) return
      if (text(event, 'credentialDigest') !== c1.saTokenDigest) return
      if (text(event, 'victimTenant') !== 'org_b') return
      const keyDigest = text(event, 'victimKeyDigest')
      if (!keyDigest) return
      c1.victimKeyDigest = keyDigest
      c1.h4 = true
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h4', service: service('api'), routeKey: 'api.secretsBatch',
        actor: actor(event, 'member_a'), artifactDigest: keyDigest, entityId: text(event, 'victimId'),
        ts: event.ts, detail: { ownId: text(event, 'ownId') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h3', toHopId: 'sf-c1-h4', kind: 'value_binding',
        fromArtifactDigest: c1.saTokenDigest, toConsumedDigest: c1.saTokenDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'deployment.released' && text(event, 'deploymentId') === plan.ids.deploymentProdId) {
      if (!c1.h4 || text(event, 'signedWith') !== 'prod-signing-key') return
      if (text(event, 'keyDigest') !== c1.victimKeyDigest) return
      const releaseDigest = text(event, 'releaseDigest')
      if (!releaseDigest) return
      oracle.recordHop({
        chainId: 'SF-C1', hopId: 'sf-c1-h5', service: service('api'), routeKey: 'api.productionRelease',
        actor: actor(event, 'member_a'), artifactDigest: releaseDigest, entityId: text(event, 'deploymentId'),
        ts: event.ts, detail: { env: text(event, 'env'), version: text(event, 'version') },
      })
      oracle.recordEdge({
        chainId: 'SF-C1', fromHopId: 'sf-c1-h4', toHopId: 'sf-c1-h5', kind: 'derived_crypto_binding',
        fromArtifactDigest: c1.victimKeyDigest, toConsumedDigest: '',
        derivedFromDigest: c1.victimKeyDigest, ts: event.ts,
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
      c2.streamId = streamId
      c2.streamDigest = digest(streamId)
      c2.projectId = ''
      c2.artifactDigest = ''
      c2.controlProject = ''
      c2.h2 = false
      c2.h3 = false
      oracle.recordHop({
        chainId: 'SF-C2', hopId: 'sf-c2-h1', service: service('runner'), routeKey: 'runner.sseStream',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest: c2.streamDigest, entityId: streamId,
        ts: event.ts, detail: { pool: text(event, 'pool') },
      })
      return
    }

    if (event.kind === 'runner.stream_event') {
      if (!c2.streamId || text(event, 'streamId') !== c2.streamId) return
      const projectId = text(event, 'projectId')
      const artifactDigest = text(event, 'artifactDigest')
      if (!projectId || !artifactDigest) return
      c2.projectId = projectId
      c2.artifactDigest = artifactDigest
      c2.h2 = true
      oracle.recordHop({
        chainId: 'SF-C2', hopId: 'sf-c2-h2', service: service('runner'), routeKey: 'runner.sseArtifactEvent',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest, entityId: projectId,
        ts: event.ts, detail: { buildId: text(event, 'buildId') },
      })
      oracle.recordEdge({
        chainId: 'SF-C2', fromHopId: 'sf-c2-h1', toHopId: 'sf-c2-h2', kind: 'async_pivot_binding',
        fromArtifactDigest: c2.streamDigest, toConsumedDigest: artifactDigest,
        runId, pollObserved: true, ts: event.ts,
        detail: { attestation: 'shared-stream-scope' },
      })
      return
    }

    if (event.kind === 'scm.repo_export_denied' && text(event, 'reason') === 'transfer_required') {
      if (profile.transferDualAdmin || profile.transferRequiresLivePat) return
      c2.controlProject = text(event, 'projectId')
      return
    }

    if (event.kind === 'project.transferred') {
      if (!c2.h2 || text(event, 'projectId') !== c2.projectId) return
      if (text(event, 'artifactDigest') !== c2.artifactDigest) return
      c2.h3 = true
      const projectId = c2.projectId
      oracle.recordHop({
        chainId: 'SF-C2', hopId: 'sf-c2-h3', service: service('api'), routeKey: 'api.projectTransfer',
        actor: actor(event, 'dual_member'), artifactDigest: digest(projectId), entityId: projectId,
        ts: event.ts, detail: { toTenant: text(event, 'toTenant') },
      })
      oracle.recordEdge({
        chainId: 'SF-C2', fromHopId: 'sf-c2-h2', toHopId: 'sf-c2-h3', kind: 'value_binding',
        fromArtifactDigest: c2.artifactDigest, toConsumedDigest: c2.artifactDigest, ts: event.ts,
      })
      if (c2.controlProject === projectId) {
        oracle.recordControl({
          chainId: 'SF-C2', fromHopId: 'sf-c2-h3', toHopId: 'sf-c2-h4', entityId: projectId,
          result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      return
    }

    if (event.kind === 'scm.repo_exported') {
      if (!c2.h3 || text(event, 'projectId') !== c2.projectId) return
      if (!flag(event, 'transferred')) return
      const archiveDigest = text(event, 'archiveDigest')
      if (!archiveDigest) return
      const projectId = c2.projectId
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
      c3.templateDigest = templateDigest
      c3.deliveryId = ''
      c3.deliveryDigest = ''
      c3.tokenDigest = ''
      c3.h2 = false
      c3.h3 = false
      oracle.recordHop({
        chainId: 'SF-C3', hopId: 'sf-c3-h1', service: service('api'), routeKey: 'api.projectSearch',
        actor: actor(event, 'member_a'), artifactDigest: templateDigest, entityId: leakedTemplateId,
        ts: event.ts, detail: { leakedTenant: text(event, 'leakedTenant'), query: text(event, 'query') },
      })
      return
    }

    if (event.kind === 'scm.webhook_created') {
      if (!c3.templateDigest || text(event, 'templateDigest') !== c3.templateDigest) return
      const deliveryId = text(event, 'deliveryId')
      if (!deliveryId) return
      c3.deliveryId = deliveryId
      c3.deliveryDigest = digest(deliveryId)
      c3.h2 = true
      oracle.recordHop({
        chainId: 'SF-C3', hopId: 'sf-c3-h2', service: service('scm'), routeKey: 'scm.webhookCreate',
        actor: actor(event, 'member_a'), artifactDigest: c3.deliveryDigest, entityId: deliveryId,
        ts: event.ts, detail: { deliveredTo: text(event, 'deliveredTo'), status: String(event.detail.deliveryStatus ?? '') },
      })
      oracle.recordEdge({
        chainId: 'SF-C3', fromHopId: 'sf-c3-h1', toHopId: 'sf-c3-h2', kind: 'derived_crypto_binding',
        fromArtifactDigest: c3.templateDigest, toConsumedDigest: '',
        derivedFromDigest: c3.templateDigest, ts: event.ts,
        detail: { attestation: 'webhook-template-projection' },
      })
      return
    }

    if (event.kind === 'scm.delivery_log') {
      if (!c3.h2 || text(event, 'deliveryDigest') !== c3.deliveryDigest) return
      const tokenDigest = text(event, 'tokenDigest')
      if (!tokenDigest) return
      c3.tokenDigest = tokenDigest
      c3.h3 = true
      oracle.recordHop({
        chainId: 'SF-C3', hopId: 'sf-c3-h3', service: service('scm'), routeKey: 'scm.deliveryLog',
        actor: actor(event, 'member_a'), artifactDigest: tokenDigest, entityId: c3.deliveryId,
        ts: event.ts, detail: { logRedacted: flag(event, 'logRedacted') },
      })
      oracle.recordEdge({
        chainId: 'SF-C3', fromHopId: 'sf-c3-h2', toHopId: 'sf-c3-h3', kind: 'value_binding',
        fromArtifactDigest: c3.deliveryDigest, toConsumedDigest: c3.deliveryDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'registry.sync') {
      if (!c3.h3 || text(event, 'tokenDigest') !== c3.tokenDigest) return
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
        fromArtifactDigest: c3.tokenDigest, toConsumedDigest: '',
        derivedFromDigest: c3.tokenDigest, ts: event.ts,
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
      c4.automationId = automationId
      c4.automationDigest = digest(automationId)
      c4.deploymentId = ''
      c4.controlDeployment = ''
      c4.h2 = false
      oracle.recordHop({
        chainId: 'SF-C4', hopId: 'sf-c4-h1', service: service('api'), routeKey: 'api.automationCreate',
        actor: actor(event, 'member_a'), artifactDigest: c4.automationDigest, entityId: automationId,
        ts: event.ts, detail: { inheritedRole: text(event, 'inheritedRole') },
      })
      return
    }

    if (event.kind === 'release.denied' && text(event, 'reason') === 'approval_required') {
      if (!profile.disputeKeepsSchedule) return
      c4.controlDeployment = text(event, 'deploymentId')
      return
    }

    if (event.kind === 'deployment.disputed') {
      if (!c4.automationId || text(event, 'automationId') !== c4.automationId) return
      if (text(event, 'automationDigest') !== c4.automationDigest) return
      if (!flag(event, 'autoReleaseScheduled')) return
      const deploymentId = text(event, 'deploymentId')
      if (!deploymentId) return
      c4.deploymentId = deploymentId
      c4.h2 = true
      oracle.recordHop({
        chainId: 'SF-C4', hopId: 'sf-c4-h2', service: service('api'), routeKey: 'api.deploymentDispute',
        actor: actor(event, 'member_a'), artifactDigest: digest(deploymentId), entityId: deploymentId,
        ts: event.ts, detail: { autoReleaseScheduled: true },
      })
      oracle.recordEdge({
        chainId: 'SF-C4', fromHopId: 'sf-c4-h1', toHopId: 'sf-c4-h2', kind: 'value_binding',
        fromArtifactDigest: c4.automationDigest, toConsumedDigest: c4.automationDigest, ts: event.ts,
      })
      if (c4.controlDeployment === deploymentId) {
        oracle.recordControl({
          chainId: 'SF-C4', fromHopId: 'sf-c4-h2', toHopId: 'sf-c4-h3', entityId: deploymentId,
          result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      return
    }

    if (event.kind === 'deployment.released' && text(event, 'deploymentId') === c4.deploymentId) {
      if (!c4.h2 || text(event, 'approval') !== 'automation') return
      const releaseDigest = text(event, 'releaseDigest')
      if (!releaseDigest) return
      const deploymentId = c4.deploymentId
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
