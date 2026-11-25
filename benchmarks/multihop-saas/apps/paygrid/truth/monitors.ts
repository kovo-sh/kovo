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
  const recordedControls = new Set<string>()
  const emitControlOnce = (
    chainId: 'PG-C1' | 'PG-C3' | 'PG-C4',
    fromHopId: string,
    toHopId: string,
    entityId: string,
    ts: number,
  ): void => {
    const key = `${chainId}\0${entityId}`
    if (recordedControls.has(key)) return
    recordedControls.add(key)
    oracle.recordControl({
      chainId,
      fromHopId,
      toHopId,
      entityId,
      result: 'failed_without_predecessor',
      ts,
    })
  }

  const c1 = {
    pendingDigests: new Set<string>(),
    sessions: new Map<string, { pendingDigest: string; tenantId: string }>(),
    reboundPayouts: new Map<string, { sessions: Set<string>; tenantId: string }>(),
    controlPayoutIds: new Set<string>(),
    controlTenants: new Set<string>(),
    controlActorsWithoutTenant: new Set<PersonaId>(),
    transitions: new Map<string, { entityId: string; tenantId: string; actor: PersonaId }>(),
  }

  const c2 = {
    templates: new Set<string>(),
    jobs: new Map<string, { templateId: string }>(),
    saltDigests: new Set<string>(),
  }

  const c3 = {
    cacheKeys: new Set<string>(),
    jobs: new Map<string, { cacheKey: string; polled: boolean }>(),
    urlHandles: new Map<string, string>(),
    controlKeys: new Set<string>(),
    controlOrgBActors: new Set<PersonaId>(),
    transitions: new Map<string, { cacheKey: string; actor: PersonaId }>(),
  }

  const c4 = {
    orders: new Map<string, { tenantId: string; h2: boolean; h3: boolean }>(),
    controlOrderIds: new Set<string>(),
    controlScopes: new Set<string>(),
    transitions: new Map<string, { orderId: string; tenantId: string; actor: PersonaId }>(),
  }

  const c1HasMatchingControl = (entityId: string, tenantId: string, transitionActor: PersonaId): boolean =>
    c1.controlPayoutIds.has(entityId)
    || (tenantId !== '' && c1.controlTenants.has(tenantId))
    || c1.controlActorsWithoutTenant.has(transitionActor)

  const c3HasMatchingControl = (cacheKey: string, transitionActor: PersonaId): boolean =>
    c3.controlKeys.has(cacheKey) || c3.controlOrgBActors.has(transitionActor)

  const c4HasMatchingControl = (orderId: string, tenantId: string, transitionActor: PersonaId): boolean =>
    c4.controlOrderIds.has(orderId) || (tenantId !== '' && c4.controlScopes.has(`${tenantId}\0${transitionActor}`))

  const consume = (event: AuditEvent): void => {
    if (event.runId !== runId) return

    if (event.kind === 'directory.public_view') {
      if (text(event, 'tenantId') !== 'org_a') return
      const pending = text(event, 'pendingEmailDigest')
      if (!pending) return
      c1.pendingDigests.add(pending)
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h1', service: 'edge', routeKey: 'directory.orgPublic',
        actor: actor(event, 'member_b'), artifactDigest: pending, ts: event.ts,
        detail: { slug: text(event, 'slug') },
      })
      return
    }

    if (event.kind === 'invite.resolved') {
      if (!flag(event, 'viaNfkc') || text(event, 'tenantId') !== 'org_a' || text(event, 'role') !== 'finance') return
      const pending = text(event, 'pendingEmailDigest')
      if (!pending || !c1.pendingDigests.has(pending)) return
      const sessionDigest = text(event, 'sessionDigest')
      if (!sessionDigest) return
      c1.sessions.set(sessionDigest, { pendingDigest: pending, tenantId: 'org_a' })
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h2', service: 'idp', routeKey: 'idp.inviteResolve',
        actor: actor(event, 'member_b'), artifactDigest: sessionDigest, ts: event.ts,
        effectiveRole: 'finance', detail: { inviteId: text(event, 'inviteId') },
      })
      oracle.recordEdge({
        chainId: 'PG-C1', fromHopId: 'pg-c1-h1', toHopId: 'pg-c1-h2', kind: 'derived_crypto_binding',
        fromArtifactDigest: pending, toConsumedDigest: '',
        derivedFromDigest: pending, ts: event.ts,
        detail: { attestation: 'idp-invite-resolution' },
      })
      return
    }

    if (event.kind === 'payout.rebound') {
      const sessionDigest = text(event, 'sessionDigest')
      const session = sessionDigest ? c1.sessions.get(sessionDigest) : undefined
      if (!session) return
      const payoutId = text(event, 'payoutId')
      if (!payoutId) return
      const tenantId = text(event, 'tenantId') || session.tenantId
      const existing = c1.reboundPayouts.get(payoutId)
      if (existing) {
        existing.sessions.add(sessionDigest)
      } else {
        c1.reboundPayouts.set(payoutId, { sessions: new Set([sessionDigest]), tenantId })
      }
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h3', service: 'api', routeKey: 'api.payoutRebind',
        actor: actor(event, 'member_b'), artifactDigest: digest(payoutId), entityId: payoutId,
        ts: event.ts, effectiveRole: 'finance',
      })
      oracle.recordEdge({
        chainId: 'PG-C1', fromHopId: 'pg-c1-h2', toHopId: 'pg-c1-h3', kind: 'value_binding',
        fromArtifactDigest: sessionDigest, toConsumedDigest: sessionDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'payout.approve_denied' && text(event, 'reason') === 'insufficient_role') {
      const controlPayoutId = text(event, 'payoutId')
      const controlTenantId = text(event, 'tenantId')
      const controlActor = event.actorPersona
      if (controlPayoutId) c1.controlPayoutIds.add(controlPayoutId)
      if (controlTenantId) c1.controlTenants.add(controlTenantId)
      else if (controlActor) c1.controlActorsWithoutTenant.add(controlActor)
      for (const transition of c1.transitions.values()) {
        if (c1HasMatchingControl(transition.entityId, transition.tenantId, transition.actor)) {
          emitControlOnce('PG-C1', 'pg-c1-h3', 'pg-c1-h4', transition.entityId, event.ts)
        }
      }
      return
    }

    if (event.kind === 'payout.settled') {
      const payoutId = text(event, 'payoutId')
      const sessionDigest = text(event, 'sessionDigest')
      const rebound = payoutId ? c1.reboundPayouts.get(payoutId) : undefined
      if (!rebound || !flag(event, 'makerCheckerBypassed')) return
      if (!sessionDigest || !rebound.sessions.has(sessionDigest)) return
      const entityId = payoutId
      const tenantId = text(event, 'tenantId') || rebound.tenantId
      const transitionActor = actor(event, 'member_b')
      oracle.recordHop({
        chainId: 'PG-C1', hopId: 'pg-c1-h4', service: 'api', routeKey: 'api.payoutApprove',
        actor: transitionActor, artifactDigest: digest(`${entityId}:settled`), entityId,
        ts: event.ts, effectiveRole: 'finance',
      })
      oracle.recordEdge({
        chainId: 'PG-C1', fromHopId: 'pg-c1-h3', toHopId: 'pg-c1-h4', kind: 'state_transition_binding',
        fromArtifactDigest: digest(entityId), toConsumedDigest: digest(entityId), entityId, ts: event.ts,
      })
      c1.transitions.set(`${entityId}\0${tenantId}\0${transitionActor}`, { entityId, tenantId, actor: transitionActor })
      if (c1HasMatchingControl(entityId, tenantId, transitionActor)) {
        emitControlOnce('PG-C1', 'pg-c1-h3', 'pg-c1-h4', entityId, event.ts)
      }
      oracle.recordTerminal({
        chainId: 'PG-C1', service: 'api', routeKey: 'api.payoutApprove', kind: 'self_approved_payout',
        actor: transitionActor, entityId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'template.updated') {
      if (!flag(event, 'rawStored') || text(event, 'tenantId') !== 'org_a') return
      const templateId = text(event, 'templateId')
      if (!templateId) return
      c2.templates.add(templateId)
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h1', service: 'api', routeKey: 'api.templateUpdate',
        actor: actor(event, 'member_a'), artifactDigest: digest(templateId), entityId: templateId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'worker.job_created') {
      if (text(event, 'kind') !== 'pdf') return
      const templateId = text(event, 'templateId')
      if (!templateId || !c2.templates.has(templateId)) return
      const jobId = text(event, 'jobId')
      if (!jobId) return
      c2.jobs.set(jobId, { templateId })
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h2', service: 'worker', routeKey: 'worker.jobRender',
        actor: actor(event, 'member_a'), artifactDigest: digest(jobId), entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C2', fromHopId: 'pg-c2-h1', toHopId: 'pg-c2-h2', kind: 'async_pivot_binding',
        fromArtifactDigest: digest(templateId), toConsumedDigest: digest(jobId),
        runId, pollObserved: true, ts: event.ts,
      })
      return
    }

    if (event.kind === 'worker.job_trace') {
      const jobId = text(event, 'jobId')
      if (!jobId || !c2.jobs.has(jobId)) return
      const leaked = text(event, 'leakedSecret')
      if (!leaked) return
      const saltDigest = digest(leaked)
      c2.saltDigests.add(saltDigest)
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h3', service: 'worker', routeKey: 'worker.jobTrace',
        actor: actor(event, 'member_a'), artifactDigest: saltDigest, entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C2', fromHopId: 'pg-c2-h2', toHopId: 'pg-c2-h3', kind: 'value_binding',
        fromArtifactDigest: digest(jobId), toConsumedDigest: digest(jobId), ts: event.ts,
      })
      return
    }

    if (event.kind === 'vault.webhook_accepted') {
      const derivedFromDigest = text(event, 'derivedFromDigest')
      if (!derivedFromDigest || !c2.saltDigests.has(derivedFromDigest)) return
      oracle.recordHop({
        chainId: 'PG-C2', hopId: 'pg-c2-h4', service: 'vault.internal', routeKey: 'vault.settlementWebhook',
        actor: actor(event, 'member_a'), artifactDigest: digest(`webhook:${derivedFromDigest}`), ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C2', fromHopId: 'pg-c2-h3', toHopId: 'pg-c2-h4', kind: 'derived_crypto_binding',
        fromArtifactDigest: derivedFromDigest, toConsumedDigest: '',
        derivedFromDigest, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'PG-C2', service: 'vault.internal', routeKey: 'vault.settlementWebhook',
        kind: 'forged_settlement', actor: actor(event, 'member_a'), ts: event.ts,
      })
      return
    }

    if (event.kind === 'permission.cache_primed') {
      if (flag(event, 'scoped') || text(event, 'tenantId') !== 'org_a') return
      const cacheKey = text(event, 'cacheKey')
      if (!cacheKey) return
      c3.cacheKeys.add(cacheKey)
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h1', service: 'api', routeKey: 'api.permissionsPrime',
        actor: actor(event, 'dual_member'), artifactDigest: digest(cacheKey), entityId: cacheKey, ts: event.ts,
      })
      return
    }

    if (event.kind === 'export.denied') {
      if (text(event, 'tenantId') !== 'org_b') return
      const controlKey = text(event, 'cacheKey')
      const controlActor = actor(event, 'dual_member')
      if (controlKey) c3.controlKeys.add(controlKey)
      c3.controlOrgBActors.add(controlActor)
      for (const transition of c3.transitions.values()) {
        if (c3HasMatchingControl(transition.cacheKey, transition.actor)) {
          emitControlOnce('PG-C3', 'pg-c3-h1', 'pg-c3-h2', transition.cacheKey, event.ts)
        }
      }
      return
    }

    if (event.kind === 'export.job_created') {
      if (!flag(event, 'viaCache') || text(event, 'tenantId') !== 'org_b') return
      const cacheKey = text(event, 'cacheKey')
      if (!cacheKey || !c3.cacheKeys.has(cacheKey)) return
      const jobId = text(event, 'jobId')
      if (!jobId) return
      const transitionActor = actor(event, 'dual_member')
      if (!c3.jobs.has(jobId)) {
        c3.jobs.set(jobId, { cacheKey, polled: false })
      }
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h2', service: 'api', routeKey: 'api.exportCreate',
        actor: transitionActor, artifactDigest: digest(jobId), entityId: cacheKey, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h1', toHopId: 'pg-c3-h2', kind: 'state_transition_binding',
        fromArtifactDigest: digest(cacheKey), toConsumedDigest: digest(cacheKey),
        entityId: cacheKey, ts: event.ts,
      })
      c3.transitions.set(`${cacheKey}\0${transitionActor}`, { cacheKey, actor: transitionActor })
      if (c3HasMatchingControl(cacheKey, transitionActor)) {
        emitControlOnce('PG-C3', 'pg-c3-h1', 'pg-c3-h2', cacheKey, event.ts)
      }
      return
    }

    if (event.kind === 'worker.job_polled') {
      if (text(event, 'kind') !== 'export' || text(event, 'status') !== 'ready') return
      const jobId = text(event, 'jobId')
      const job = jobId ? c3.jobs.get(jobId) : undefined
      if (!job || job.polled) return
      job.polled = true
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h3', service: 'worker', routeKey: 'worker.jobPoll',
        actor: actor(event, 'dual_member'), artifactDigest: digest(jobId), entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h2', toHopId: 'pg-c3-h3', kind: 'async_pivot_binding',
        fromArtifactDigest: digest(jobId), toConsumedDigest: digest(jobId),
        runId, pollObserved: true, ts: event.ts,
      })
      return
    }

    if (event.kind === 'export.signed_url') {
      const jobId = text(event, 'jobId')
      const job = jobId ? c3.jobs.get(jobId) : undefined
      if (!job || !job.polled) return
      const urlHandleDigest = text(event, 'urlHandleDigest')
      if (!urlHandleDigest) return
      c3.urlHandles.set(urlHandleDigest, jobId)
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h4', service: 'api', routeKey: 'api.exportSignedUrl',
        actor: actor(event, 'dual_member'), artifactDigest: urlHandleDigest, entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h3', toHopId: 'pg-c3-h4', kind: 'value_binding',
        fromArtifactDigest: digest(jobId), toConsumedDigest: digest(jobId), ts: event.ts,
      })
      return
    }

    if (event.kind === 'file.downloaded') {
      if (text(event, 'tenantSlug') !== plan.tenants.c.slug) return
      if (text(event, 'signedTenant') !== plan.tenants.b.slug) return
      const urlHandleDigest = text(event, 'urlHandleDigest')
      const jobId = urlHandleDigest ? c3.urlHandles.get(urlHandleDigest) : undefined
      if (!jobId) return
      oracle.recordHop({
        chainId: 'PG-C3', hopId: 'pg-c3-h5', service: 'edge', routeKey: 'file.treasuryDownload',
        actor: actor(event, 'dual_member'), artifactDigest: digest(text(event, 'path')),
        entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C3', fromHopId: 'pg-c3-h4', toHopId: 'pg-c3-h5', kind: 'value_binding',
        fromArtifactDigest: urlHandleDigest, toConsumedDigest: urlHandleDigest, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'PG-C3', service: 'edge', routeKey: 'file.treasuryDownload',
        kind: 'cross_tenant_export', actor: actor(event, 'dual_member'), entityId: jobId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'order.draft_created') {
      if (!flag(event, 'duplicateKey') || text(event, 'tenantId') !== 'org_a') return
      if (numberValue(event, 'amountCents') <= numberValue(event, 'capCents')) return
      if (numberValue(event, 'edgeAmount') > numberValue(event, 'capCents')) return
      const orderId = text(event, 'orderId')
      if (!orderId) return
      if (!c4.orders.has(orderId)) {
        c4.orders.set(orderId, { tenantId: 'org_a', h2: false, h3: false })
      }
      oracle.recordHop({
        chainId: 'PG-C4', hopId: 'pg-c4-h1', service: 'api', routeKey: 'api.orderCreate',
        actor: actor(event, 'member_a'), artifactDigest: digest(orderId), entityId: orderId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'order.rebound') {
      const orderId = text(event, 'orderId')
      const order = orderId ? c4.orders.get(orderId) : undefined
      if (!order || text(event, 'status') !== 'authorized') return
      order.h2 = true
      oracle.recordHop({
        chainId: 'PG-C4', hopId: 'pg-c4-h2', service: 'api', routeKey: 'api.orderRebind',
        actor: actor(event, 'member_a'), artifactDigest: digest(orderId), entityId: orderId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C4', fromHopId: 'pg-c4-h1', toHopId: 'pg-c4-h2', kind: 'value_binding',
        fromArtifactDigest: digest(orderId), toConsumedDigest: digest(orderId), ts: event.ts,
      })
      return
    }

    if (event.kind === 'settlement.control_denied' && text(event, 'reason') === 'state_not_authorized') {
      const controlOrderId = text(event, 'orderId')
      const controlTenantId = text(event, 'tenantId')
      const controlActor = actor(event, 'member_a')
      if (controlOrderId) c4.controlOrderIds.add(controlOrderId)
      if (controlTenantId) c4.controlScopes.add(`${controlTenantId}\0${controlActor}`)
      for (const transition of c4.transitions.values()) {
        if (c4HasMatchingControl(transition.orderId, transition.tenantId, transition.actor)) {
          emitControlOnce('PG-C4', 'pg-c4-h2', 'pg-c4-h3', transition.orderId, event.ts)
        }
      }
      return
    }

    if (event.kind === 'settlement.race') {
      const orderId = text(event, 'orderId')
      const order = orderId ? c4.orders.get(orderId) : undefined
      if (!order || !order.h2 || numberValue(event, 'credits') < 2) return
      if (order.h3) return
      order.h3 = true
      const tenantId = text(event, 'tenantId') || order.tenantId
      const transitionActor = actor(event, 'member_a')
      oracle.recordHop({
        chainId: 'PG-C4', hopId: 'pg-c4-h3', service: 'api', routeKey: 'api.orderSettleRace',
        actor: transitionActor, artifactDigest: digest(`${orderId}:credited`),
        entityId: orderId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'PG-C4', fromHopId: 'pg-c4-h2', toHopId: 'pg-c4-h3', kind: 'state_transition_binding',
        fromArtifactDigest: digest(orderId), toConsumedDigest: digest(orderId),
        entityId: orderId, ts: event.ts,
      })
      c4.transitions.set(`${orderId}\0${tenantId}\0${transitionActor}`, { orderId, tenantId, actor: transitionActor })
      if (c4HasMatchingControl(orderId, tenantId, transitionActor)) {
        emitControlOnce('PG-C4', 'pg-c4-h2', 'pg-c4-h3', orderId, event.ts)
      }
      oracle.recordTerminal({
        chainId: 'PG-C4', service: 'api', routeKey: 'api.orderSettleRace',
        kind: 'ledger_overcredit', actor: transitionActor, entityId: orderId, ts: event.ts,
      })
    }
  }

  return { consume }
}
