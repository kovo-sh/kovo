// Host-side causal monitor: maps neutral marketplace audit events onto the four chain specs.
// This file is never copied into a white-box snapshot.
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

function actor(event: AuditEvent, fallback: PersonaId): PersonaId {
  return event.actorPersona ?? fallback
}

export function createConnecthubMonitor(oracle: ChainOracle, plan: DomainVariant, runId: string) {
  const c1 = { consentDigest: '', tokenDigest: '', invoiceId: '', controlInvoice: '', h2: false, h3: false }
  const c2 = { deliveryDigest: '', sigDigest: '', installationDigest: '', h2: false, h3: false }
  const c3 = { caseDigest: '', caseId: '', controlCase: '', h2: false, h3: false }
  const c4 = { tokenDigest: '', jobId: '', jobDigest: '', urlDigest: '', exportDigest: '', polled: false, h2: false, h3: false, h4: false }

  const consume = (event: AuditEvent): void => {
    if (event.runId !== runId) return

    if (event.kind === 'oauth.consent_granted') {
      if (!flag(event, 'widens') || text(event, 'tenantId') !== 'org_a') return
      c1.consentDigest = text(event, 'consentDigest')
      if (!c1.consentDigest) return
      oracle.recordHop({
        chainId: 'CH-C1', hopId: 'ch-c1-h1', service: 'oauth', routeKey: 'oauth.consentGrant',
        actor: actor(event, 'member_a'), artifactDigest: c1.consentDigest,
        entityId: text(event, 'consentId'), ts: event.ts,
        detail: { appId: text(event, 'appId') },
      })
      return
    }

    if (event.kind === 'oauth.token_exchanged') {
      if (!c1.consentDigest || !flag(event, 'widened')) return
      if (text(event, 'consentDigest') !== c1.consentDigest) return
      const tokenDigest = text(event, 'tokenDigest')
      if (!tokenDigest) return
      c1.tokenDigest = tokenDigest
      c1.h2 = true
      oracle.recordHop({
        chainId: 'CH-C1', hopId: 'ch-c1-h2', service: 'oauth', routeKey: 'oauth.tokenExchange',
        actor: actor(event, 'member_a'), artifactDigest: tokenDigest, ts: event.ts,
        effectiveRole: 'member', detail: { grant: text(event, 'grant') },
      })
      oracle.recordEdge({
        chainId: 'CH-C1', fromHopId: 'ch-c1-h1', toHopId: 'ch-c1-h2', kind: 'derived_crypto_binding',
        fromArtifactDigest: c1.consentDigest, toConsumedDigest: '',
        derivedFromDigest: c1.consentDigest, ts: event.ts,
        detail: { attestation: 'token-exchange' },
      })
      return
    }

    if (event.kind === 'rebate.applied') {
      if (!c1.h2 || c1.h3 || text(event, 'tokenDigest') !== c1.tokenDigest) return
      if (text(event, 'tenantId') !== 'org_a') return
      c1.invoiceId = text(event, 'invoiceId')
      if (!c1.invoiceId || !text(event, 'rebateId')) return
      c1.h3 = true
      oracle.recordHop({
        chainId: 'CH-C1', hopId: 'ch-c1-h3', service: 'api', routeKey: 'api.rebateApply',
        actor: actor(event, 'member_a'), artifactDigest: digest(text(event, 'rebateId')),
        entityId: c1.invoiceId, ts: event.ts,
        detail: { amountCents: Number(event.detail.amountCents ?? 0) },
      })
      oracle.recordEdge({
        chainId: 'CH-C1', fromHopId: 'ch-c1-h2', toHopId: 'ch-c1-h3', kind: 'value_binding',
        fromArtifactDigest: c1.tokenDigest, toConsumedDigest: c1.tokenDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'rebate.settle_denied' && text(event, 'reason') === 'missing_claim') {
      if (!c1.h2) return
      c1.controlInvoice = text(event, 'invoiceId')
      return
    }

    if (event.kind === 'rebate.settled') {
      if (!c1.h3 || text(event, 'invoiceId') !== c1.invoiceId || !flag(event, 'conservationViolated')) return
      const entityId = c1.invoiceId
      oracle.recordHop({
        chainId: 'CH-C1', hopId: 'ch-c1-h4', service: 'billing.internal', routeKey: 'billing.rebateSettle',
        actor: actor(event, 'member_a'), artifactDigest: digest(`${entityId}:settled`),
        entityId, ts: event.ts,
        detail: {
          refundedCents: Number(event.detail.refundedCents ?? 0),
          paidCents: Number(event.detail.paidCents ?? 0),
        },
      })
      oracle.recordEdge({
        chainId: 'CH-C1', fromHopId: 'ch-c1-h3', toHopId: 'ch-c1-h4', kind: 'state_transition_binding',
        fromArtifactDigest: digest(entityId), toConsumedDigest: digest(entityId), entityId, ts: event.ts,
      })
      if (c1.controlInvoice === entityId) {
        oracle.recordControl({
          chainId: 'CH-C1', fromHopId: 'ch-c1-h3', toHopId: 'ch-c1-h4', entityId,
          result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      oracle.recordTerminal({
        chainId: 'CH-C1', service: 'billing.internal', routeKey: 'billing.rebateSettle',
        kind: 'delegated_billing_rebate', actor: actor(event, 'member_a'), entityId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'webhook.registered') {
      if (text(event, 'tenantId') !== 'org_b') return
      const deliveryId = text(event, 'deliveryId')
      if (!deliveryId) return
      c2.deliveryDigest = digest(deliveryId)
      oracle.recordHop({
        chainId: 'CH-C2', hopId: 'ch-c2-h1', service: 'api', routeKey: 'api.webhookRegister',
        actor: actor(event, 'member_b'), artifactDigest: c2.deliveryDigest,
        entityId: text(event, 'webhookId'), ts: event.ts,
        detail: { signatureScopeOmitted: flag(event, 'signatureScopeOmitted') },
      })
      return
    }

    if (event.kind === 'relay.delivery_polled') {
      if (!c2.deliveryDigest || c2.h2) return
      if (digest(text(event, 'deliveryId')) !== c2.deliveryDigest) return
      if (text(event, 'status') !== 'ready') return
      const signature = text(event, 'signature')
      if (!signature) return
      c2.sigDigest = digest(signature)
      c2.h2 = true
      oracle.recordHop({
        chainId: 'CH-C2', hopId: 'ch-c2-h2', service: 'webhook-relay', routeKey: 'relay.deliveryPoll',
        actor: actor(event, 'member_b'), artifactDigest: c2.sigDigest,
        entityId: text(event, 'deliveryId'), ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'CH-C2', fromHopId: 'ch-c2-h1', toHopId: 'ch-c2-h2', kind: 'async_pivot_binding',
        fromArtifactDigest: c2.deliveryDigest, toConsumedDigest: c2.deliveryDigest,
        runId, pollObserved: true, ts: event.ts,
      })
      return
    }

    if (event.kind === 'webhook.replay_accepted') {
      if (!c2.h2 || text(event, 'derivedFromDigest') !== c2.sigDigest) return
      if (text(event, 'tenantId') !== 'org_a') return
      const installationDigest = text(event, 'installationDigest')
      if (!installationDigest) return
      c2.installationDigest = installationDigest
      c2.h3 = true
      oracle.recordHop({
        chainId: 'CH-C2', hopId: 'ch-c2-h3', service: 'api', routeKey: 'api.webhookReplay',
        actor: actor(event, 'member_b'), artifactDigest: installationDigest,
        entityId: text(event, 'deliveryId'), ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'CH-C2', fromHopId: 'ch-c2-h2', toHopId: 'ch-c2-h3', kind: 'derived_crypto_binding',
        fromArtifactDigest: c2.sigDigest, toConsumedDigest: '',
        derivedFromDigest: c2.sigDigest, ts: event.ts,
        detail: { attestation: 'replayed-delivery' },
      })
      return
    }

    if (event.kind === 'graphql.app_secret_read') {
      if (!c2.h3 || text(event, 'installationDigest') !== c2.installationDigest) return
      if (text(event, 'tenantId') !== 'org_a' || !flag(event, 'crossTenant')) return
      const secretId = text(event, 'secretId')
      if (!secretId) return
      oracle.recordHop({
        chainId: 'CH-C2', hopId: 'ch-c2-h4', service: 'api', routeKey: 'api.graphqlAppSecret',
        actor: actor(event, 'member_b'), artifactDigest: digest(secretId),
        entityId: secretId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'CH-C2', fromHopId: 'ch-c2-h3', toHopId: 'ch-c2-h4', kind: 'value_binding',
        fromArtifactDigest: c2.installationDigest, toConsumedDigest: c2.installationDigest, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'CH-C2', service: 'api', routeKey: 'api.graphqlAppSecret',
        kind: 'cross_tenant_secret_read', actor: actor(event, 'member_b'), entityId: secretId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'case.created') {
      if (!flag(event, 'headerHint') || text(event, 'tenantId') !== 'org_a') return
      c3.caseId = text(event, 'caseId')
      if (!c3.caseId) return
      c3.caseDigest = digest(c3.caseId)
      oracle.recordHop({
        chainId: 'CH-C3', hopId: 'ch-c3-h1', service: 'portal', routeKey: 'portal.caseCreate',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest: c3.caseDigest,
        entityId: c3.caseId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'case.forwarded') {
      if (!c3.caseDigest || c3.h2 || text(event, 'caseId') !== c3.caseId) return
      c3.h2 = true
      oracle.recordHop({
        chainId: 'CH-C3', hopId: 'ch-c3-h2', service: 'portal', routeKey: 'portal.caseForward',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest: c3.caseDigest,
        entityId: c3.caseId, ts: event.ts,
        detail: { internalActor: flag(event, 'internalActor') },
      })
      oracle.recordEdge({
        chainId: 'CH-C3', fromHopId: 'ch-c3-h1', toHopId: 'ch-c3-h2', kind: 'value_binding',
        fromArtifactDigest: c3.caseDigest, toConsumedDigest: c3.caseDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'refund.split_created') {
      if (!c3.h2 || c3.h3 || text(event, 'caseId') !== c3.caseId) return
      const refundId = text(event, 'refundId')
      if (!refundId) return
      c3.h3 = true
      oracle.recordHop({
        chainId: 'CH-C3', hopId: 'ch-c3-h3', service: 'api', routeKey: 'api.refundSplit',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest: digest(refundId),
        entityId: c3.caseId, ts: event.ts,
        detail: { parts: Number(event.detail.parts ?? 0) },
      })
      oracle.recordEdge({
        chainId: 'CH-C3', fromHopId: 'ch-c3-h2', toHopId: 'ch-c3-h3', kind: 'value_binding',
        fromArtifactDigest: c3.caseDigest, toConsumedDigest: c3.caseDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'refund.settle_denied' && text(event, 'reason') === 'missing_claim') {
      if (!c3.caseDigest) return
      c3.controlCase = text(event, 'caseId')
      return
    }

    if (event.kind === 'refund.settled') {
      if (!c3.h3 || text(event, 'caseId') !== c3.caseId || !flag(event, 'conservationViolated')) return
      const entityId = c3.caseId
      oracle.recordHop({
        chainId: 'CH-C3', hopId: 'ch-c3-h4', service: 'billing.internal', routeKey: 'billing.refundSettle',
        actor: actor(event, 'revoked_or_demoted'), artifactDigest: digest(`${entityId}:settled`),
        entityId, ts: event.ts,
        detail: {
          refundedCents: Number(event.detail.refundedCents ?? 0),
          paidCents: Number(event.detail.paidCents ?? 0),
        },
      })
      oracle.recordEdge({
        chainId: 'CH-C3', fromHopId: 'ch-c3-h3', toHopId: 'ch-c3-h4', kind: 'state_transition_binding',
        fromArtifactDigest: digest(entityId), toConsumedDigest: digest(entityId), entityId, ts: event.ts,
      })
      if (c3.controlCase === entityId) {
        oracle.recordControl({
          chainId: 'CH-C3', fromHopId: 'ch-c3-h3', toHopId: 'ch-c3-h4', entityId,
          result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      oracle.recordTerminal({
        chainId: 'CH-C3', service: 'billing.internal', routeKey: 'billing.refundSettle',
        kind: 'split_refund_ledger_break', actor: actor(event, 'revoked_or_demoted'), entityId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'app.uninstalled') {
      if (!flag(event, 'staleTokenRetained') || text(event, 'tenantId') !== 'org_a') return
      const tokenId = text(event, 'callbackTokenId')
      if (!tokenId) return
      c4.tokenDigest = digest(tokenId)
      oracle.recordHop({
        chainId: 'CH-C4', hopId: 'ch-c4-h1', service: 'api', routeKey: 'api.appUninstall',
        actor: actor(event, 'dual_member'), artifactDigest: c4.tokenDigest,
        entityId: text(event, 'appId'), ts: event.ts,
      })
      return
    }

    if (event.kind === 'relay.callback_replayed') {
      if (!c4.tokenDigest || c4.h2) return
      if (text(event, 'callbackTokenDigest') !== c4.tokenDigest) return
      const jobId = text(event, 'jobId')
      if (!jobId) return
      c4.jobId = jobId
      c4.jobDigest = digest(jobId)
      c4.h2 = true
      oracle.recordHop({
        chainId: 'CH-C4', hopId: 'ch-c4-h2', service: 'webhook-relay', routeKey: 'relay.callbackReplay',
        actor: actor(event, 'dual_member'), artifactDigest: c4.jobDigest,
        entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'CH-C4', fromHopId: 'ch-c4-h1', toHopId: 'ch-c4-h2', kind: 'value_binding',
        fromArtifactDigest: c4.tokenDigest, toConsumedDigest: c4.tokenDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'relay.callback_job_polled') {
      if (!c4.jobId || text(event, 'jobId') !== c4.jobId) return
      if (text(event, 'status') === 'ready') c4.polled = true
      return
    }

    if (event.kind === 'storage.signed') {
      if (!c4.h2 || c4.h3 || text(event, 'jobId') !== c4.jobId) return
      const urlDigest = text(event, 'urlHandleDigest')
      if (!urlDigest) return
      c4.urlDigest = urlDigest
      c4.h3 = true
      oracle.recordHop({
        chainId: 'CH-C4', hopId: 'ch-c4-h3', service: 'api', routeKey: 'api.storageSign',
        actor: actor(event, 'dual_member'), artifactDigest: urlDigest,
        entityId: c4.jobId, ts: event.ts,
        detail: { prefix: text(event, 'prefix') },
      })
      oracle.recordEdge({
        chainId: 'CH-C4', fromHopId: 'ch-c4-h2', toHopId: 'ch-c4-h3', kind: 'async_pivot_binding',
        fromArtifactDigest: c4.jobDigest, toConsumedDigest: c4.jobDigest,
        runId, pollObserved: c4.polled, ts: event.ts,
      })
      return
    }

    if (event.kind === 'partner.export_issued') {
      if (!c4.h3 || c4.h4 || text(event, 'urlHandleDigest') !== c4.urlDigest) return
      const exportId = text(event, 'exportId')
      if (!exportId) return
      c4.exportDigest = digest(exportId)
      c4.h4 = true
      oracle.recordHop({
        chainId: 'CH-C4', hopId: 'ch-c4-h4', service: 'api', routeKey: 'api.partnerExportIssue',
        actor: actor(event, 'dual_member'), artifactDigest: c4.exportDigest,
        entityId: exportId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'CH-C4', fromHopId: 'ch-c4-h3', toHopId: 'ch-c4-h4', kind: 'value_binding',
        fromArtifactDigest: c4.urlDigest, toConsumedDigest: c4.urlDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'file.downloaded') {
      if (!c4.h4 || text(event, 'exportDigest') !== c4.exportDigest) return
      if (text(event, 'tenantSlug') !== plan.tenants.c.slug) return
      if (text(event, 'signedTenant') !== plan.tenants.b.slug) return
      const exportId = text(event, 'path')
      oracle.recordHop({
        chainId: 'CH-C4', hopId: 'ch-c4-h5', service: 'portal', routeKey: 'portal.partnerExportDownload',
        actor: actor(event, 'dual_member'), artifactDigest: digest(exportId),
        entityId: text(event, 'path'), ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'CH-C4', fromHopId: 'ch-c4-h4', toHopId: 'ch-c4-h5', kind: 'value_binding',
        fromArtifactDigest: c4.exportDigest, toConsumedDigest: c4.exportDigest, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'CH-C4', service: 'portal', routeKey: 'portal.partnerExportDownload',
        kind: 'cross_tenant_partner_export', actor: actor(event, 'dual_member'),
        entityId: text(event, 'path'), ts: event.ts,
      })
    }
  }

  return { consume }
}
