// Host-side causal monitor: maps neutral application audit events onto the four chain specs.
// Nothing in this file (or in the app source tree) is copied into a white-box snapshot.
import type { ChainOracle } from '../../../lib/chain-oracle.ts'
import { sha256 as digest } from '../../../lib/chain-oracle.ts'
import type { DomainVariant, PersonaId } from '../../../lib/types.ts'
import type { AuditEvent } from '../src/shared.ts'

function text(event: AuditEvent, key: string): string {
  const value = event.detail[key]
  return typeof value === 'string' ? value : ''
}

function flag(event: AuditEvent, key: string): boolean {
  return event.detail[key] === true
}

function numberValue(event: AuditEvent, key: string): number {
  const value = event.detail[key]
  return typeof value === 'number' ? value : 0
}

function actor(event: AuditEvent, fallback: PersonaId): PersonaId {
  return event.actorPersona ?? fallback
}

export function createPaygridMonitor(oracle: ChainOracle, plan: DomainVariant, runId: string) {
  const c1 = { pendingDigest: '', sessionDigest: '', payoutId: '', controlPayoutId: '', h2: false, h3: false }
  const c2 = { templateId: '', jobId: '', saltDigest: '', h2: false, h3: false }
  const c3 = {
    cacheKey: '', jobId: '', urlHandleDigest: '', h2: false, h3: false, h4: false, controlKey: '',
  }
  const c4 = { orderId: '', controlOrder: '', h2: false, h3: false }

  const consume = (event: AuditEvent): void => {
    if (event.runId !== runId) return

    if (event.kind === 'directory.public_view') {
      if (text(event, 'tenantId') !== 'org_a') return
      const pending = text(event, 'pendingEmailDigest')
      if (!pending) return
      c1.pendingDigest = pending
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h1', service: 'edge', routeKey: 'directory.orgPublic',
        actor: actor(event, 'member_b'), artifactDigest: pending, ts: event.ts,
        detail: { slug: text(event, 'slug') },
      })
      return
    }

    if (event.kind === 'invite.resolved') {
      if (!flag(event, 'viaNfkc') || text(event, 'tenantId') !== 'org_a' || text(event, 'role') !== 'finance') return
      if (!c1.pendingDigest || text(event, 'pendingEmailDigest') !== c1.pendingDigest) return
      c1.sessionDigest = text(event, 'sessionDigest')
      c1.h2 = true
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h2', service: 'idp', routeKey: 'idp.inviteResolve',
        actor: actor(event, 'member_b'), artifactDigest: c1.sessionDigest, ts: event.ts,
        effectiveRole: 'finance', detail: { inviteId: text(event, 'inviteId') },
      })
      oracle.recordEdge({
        chainId: 'PG-C1', fromHopId: 'pg-c1-h1', toHopId: 'pg-c1-h2', kind: 'derived_crypto_binding',
        fromArtifactDigest: c1.pendingDigest, toConsumedDigest: '',
        derivedFromDigest: c1.pendingDigest, ts: event.ts,
        detail: { attestation: 'idp-invite-resolution' },
      })
      return
    }

    if (event.kind === 'payout.rebound') {
      if (!c1.sessionDigest || text(event, 'sessionDigest') !== c1.sessionDigest) return
      c1.payoutId = text(event, 'payoutId')
      if (!c1.payoutId) return
      c1.h3 = true
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h3', service: 'api', routeKey: 'api.payoutRebind',
        actor: actor(event, 'member_b'), artifactDigest: digest(c1.payoutId), entityId: c1.payoutId,
        ts: event.ts, effectiveRole: 'finance',
      })
      oracle.recordEdge({
        chainId: 'PG-C1', fromHopId: 'pg-c1-h2', toHopId: 'pg-c1-h3', kind: 'value_binding',
        fromArtifactDigest: c1.sessionDigest, toConsumedDigest: text(event, 'sessionDigest'), ts: event.ts,
      })
      return
    }

    if (event.kind === 'payout.approve_denied' && text(event, 'reason') === 'insufficient_role') {
      c1.controlPayoutId = text(event, 'payoutId')
      return
    }

    if (event.kind === 'payout.settled') {
      if (!c1.h3 || text(event, 'payoutId') !== c1.payoutId || !flag(event, 'makerCheckerBypassed')) return
      if (text(event, 'sessionDigest') !== c1.sessionDigest) return
      const entityId = c1.payoutId
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h4', service: 'api', routeKey: 'api.payoutApprove',
        actor: actor(event, 'member_b'), artifactDigest: digest(`${entityId}:settled`), entityId,
        ts: event.ts, effectiveRole: 'finance',
      })
      oracle.recordEdge({
        chainId: 'PG-C1', fromHopId: 'pg-c1-h3', toHopId: 'pg-c1-h4', kind: 'state_transition_binding',
        fromArtifactDigest: digest(entityId), toConsumedDigest: digest(entityId), entityId, ts: event.ts,
      })
      if (c1.controlPayoutId === entityId) {
        oracle.recordControl({
          chainId: 'PG-C1', fromHopId: 'pg-c1-h3', toHopId: 'pg-c1-h4', entityId,
          result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      oracle.recordTerminal({
        chainId: 'PG-C1', service: 'api', routeKey: 'api.payoutApprove', kind: 'self_approved_payout',
        actor: actor(event, 'member_b'), entityId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'template.updated') {
      if (!flag(event, 'rawStored') || text(event, 'tenantId') !== 'org_a') return
      c2.templateId = text(event, 'templateId')
      if (!c2.templateId) return
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h1', service: 'api', routeKey: 'api.templateUpdate',
        actor: actor(event, 'member_a'), artifactDigest: digest(c2.templateId), entityId: c2.templateId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'worker.job_created') {
      if (text(event, 'kind') !== 'pdf' || text(event, 'templateId') !== c2.templateId) return
      c2.jobId = text(event, 'jobId')
      if (!c2.jobId) return
      c2.h2 = true
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h2', service: 'worker', routeKey: 'worker.jobRender',
        actor: actor(event, 'member_a'), artifactDigest: digest(c2.jobId), entityId: c2.jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C2', fromHopId: 'pg-c2-h1', toHopId: 'pg-c2-h2', kind: 'async_pivot_binding',
        fromArtifactDigest: digest(c2.templateId), toConsumedDigest: digest(c2.jobId),
        runId, pollObserved: true, ts: event.ts,
      })
      return
    }

    if (event.kind === 'worker.job_trace') {
      if (!c2.h2 || text(event, 'jobId') !== c2.jobId) return
      const leaked = text(event, 'leakedSecret')
      if (!leaked) return
      c2.saltDigest = digest(leaked)
      c2.h3 = true
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h3', service: 'worker', routeKey: 'worker.jobTrace',
        actor: actor(event, 'member_a'), artifactDigest: c2.saltDigest, entityId: c2.jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C2', fromHopId: 'pg-c2-h2', toHopId: 'pg-c2-h3', kind: 'value_binding',
        fromArtifactDigest: digest(c2.jobId), toConsumedDigest: digest(c2.jobId), ts: event.ts,
      })
      return
    }

    if (event.kind === 'vault.webhook_accepted') {
      if (!c2.h3 || text(event, 'derivedFromDigest') !== c2.saltDigest) return
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h4', service: 'vault.internal', routeKey: 'vault.settlementWebhook',
        actor: actor(event, 'member_a'), artifactDigest: digest(`webhook:${c2.saltDigest}`), ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C2', fromHopId: 'pg-c2-h3', toHopId: 'pg-c2-h4', kind: 'derived_crypto_binding',
        fromArtifactDigest: c2.saltDigest, toConsumedDigest: '',
        derivedFromDigest: c2.saltDigest, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'PG-C2', service: 'vault.internal', routeKey: 'vault.settlementWebhook',
        kind: 'forged_settlement', actor: actor(event, 'member_a'), ts: event.ts,
      })
      return
    }

    if (event.kind === 'permission.cache_primed') {
      if (flag(event, 'scoped') || text(event, 'tenantId') !== 'org_a') return
      c3.cacheKey = text(event, 'cacheKey')
      if (!c3.cacheKey) return
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h1', service: 'api', routeKey: 'api.permissionsPrime',
        actor: actor(event, 'dual_member'), artifactDigest: digest(c3.cacheKey), entityId: c3.cacheKey, ts: event.ts,
      })
      return
    }

    if (event.kind === 'export.denied') {
      if (text(event, 'tenantId') !== 'org_b') return
      c3.controlKey = text(event, 'cacheKey')
      return
    }

    if (event.kind === 'export.job_created') {
      if (!c3.cacheKey || !flag(event, 'viaCache') || text(event, 'tenantId') !== 'org_b') return
      if (text(event, 'cacheKey') !== c3.cacheKey) return
      c3.jobId = text(event, 'jobId')
      if (!c3.jobId) return
      c3.h2 = true
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h2', service: 'api', routeKey: 'api.exportCreate',
        actor: actor(event, 'dual_member'), artifactDigest: digest(c3.jobId), entityId: c3.cacheKey, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h1', toHopId: 'pg-c3-h2', kind: 'state_transition_binding',
        fromArtifactDigest: digest(c3.cacheKey), toConsumedDigest: digest(c3.cacheKey),
        entityId: c3.cacheKey, ts: event.ts,
      })
      if (c3.controlKey === c3.cacheKey) {
        oracle.recordControl({
          chainId: 'PG-C3', fromHopId: 'pg-c3-h1', toHopId: 'pg-c3-h2', entityId: c3.cacheKey,
          result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      return
    }

    if (event.kind === 'worker.job_polled') {
      if (!c3.h2 || text(event, 'kind') !== 'export' || text(event, 'jobId') !== c3.jobId) return
      if (text(event, 'status') !== 'ready' || c3.h3) return
      c3.h3 = true
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h3', service: 'worker', routeKey: 'worker.jobPoll',
        actor: actor(event, 'dual_member'), artifactDigest: digest(c3.jobId), entityId: c3.jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h2', toHopId: 'pg-c3-h3', kind: 'async_pivot_binding',
        fromArtifactDigest: digest(c3.jobId), toConsumedDigest: digest(c3.jobId),
        runId, pollObserved: true, ts: event.ts,
      })
      return
    }

    if (event.kind === 'export.signed_url') {
      if (!c3.h3 || text(event, 'jobId') !== c3.jobId) return
      c3.urlHandleDigest = text(event, 'urlHandleDigest')
      if (!c3.urlHandleDigest) return
      c3.h4 = true
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h4', service: 'api', routeKey: 'api.exportSignedUrl',
        actor: actor(event, 'dual_member'), artifactDigest: c3.urlHandleDigest, entityId: c3.jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h3', toHopId: 'pg-c3-h4', kind: 'value_binding',
        fromArtifactDigest: digest(c3.jobId), toConsumedDigest: digest(c3.jobId), ts: event.ts,
      })
      return
    }

    if (event.kind === 'file.downloaded') {
      if (!c3.h4 || text(event, 'tenantSlug') !== plan.tenants.c.slug) return
      if (text(event, 'signedTenant') !== plan.tenants.b.slug) return
      if (text(event, 'urlHandleDigest') !== c3.urlHandleDigest) return
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h5', service: 'edge', routeKey: 'file.treasuryDownload',
        actor: actor(event, 'dual_member'), artifactDigest: digest(text(event, 'path')),
        entityId: c3.jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h4', toHopId: 'pg-c3-h5', kind: 'value_binding',
        fromArtifactDigest: c3.urlHandleDigest, toConsumedDigest: text(event, 'urlHandleDigest'), ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'PG-C3', service: 'edge', routeKey: 'file.treasuryDownload',
        kind: 'cross_tenant_export', actor: actor(event, 'dual_member'), entityId: c3.jobId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'order.draft_created') {
      if (!flag(event, 'duplicateKey') || text(event, 'tenantId') !== 'org_a') return
      if (numberValue(event, 'amountCents') <= numberValue(event, 'capCents')) return
      if (numberValue(event, 'edgeAmount') > numberValue(event, 'capCents')) return
      c4.orderId = text(event, 'orderId')
      if (!c4.orderId) return
      oracle.recordHop({
        chainId: 'PG-C4', hopId: 'pg-c4-h1', service: 'api', routeKey: 'api.orderCreate',
        actor: actor(event, 'member_a'), artifactDigest: digest(c4.orderId), entityId: c4.orderId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'order.rebound') {
      if (!c4.orderId || text(event, 'orderId') !== c4.orderId || text(event, 'status') !== 'authorized') return
      c4.h2 = true
      oracle.recordHop({
        chainId: 'PG-C4', hopId: 'pg-c4-h2', service: 'api', routeKey: 'api.orderRebind',
        actor: actor(event, 'member_a'), artifactDigest: digest(c4.orderId), entityId: c4.orderId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C4', fromHopId: 'pg-c4-h1', toHopId: 'pg-c4-h2', kind: 'value_binding',
        fromArtifactDigest: digest(c4.orderId), toConsumedDigest: digest(c4.orderId), ts: event.ts,
      })
      return
    }

    if (event.kind === 'settlement.control_denied' && text(event, 'reason') === 'state_not_authorized') {
      c4.controlOrder = text(event, 'orderId')
      return
    }

    if (event.kind === 'settlement.race') {
      if (!c4.h2 || text(event, 'orderId') !== c4.orderId || numberValue(event, 'credits') < 2) return
      if (c4.h3) return
      c4.h3 = true
      oracle.recordHop({
        chainId: 'PG-C4', hopId: 'pg-c4-h3', service: 'api', routeKey: 'api.orderSettleRace',
        actor: actor(event, 'member_a'), artifactDigest: digest(`${c4.orderId}:credited`),
        entityId: c4.orderId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C4', fromHopId: 'pg-c4-h2', toHopId: 'pg-c4-h3', kind: 'state_transition_binding',
        fromArtifactDigest: digest(c4.orderId), toConsumedDigest: digest(c4.orderId),
        entityId: c4.orderId, ts: event.ts,
      })
      if (c4.controlOrder === c4.orderId) {
        oracle.recordControl({
          chainId: 'PG-C4', fromHopId: 'pg-c4-h2', toHopId: 'pg-c4-h3', entityId: c4.orderId,
          result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      oracle.recordTerminal({
        chainId: 'PG-C4', service: 'api', routeKey: 'api.orderSettleRace',
        kind: 'ledger_overcredit', actor: actor(event, 'member_a'), entityId: c4.orderId, ts: event.ts,
      })
    }
  }

  return { consume }
}
