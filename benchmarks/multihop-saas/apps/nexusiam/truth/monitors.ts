// Host-side causal monitor: maps neutral application audit events onto the four nexusiam chain
// specs. Nothing in this file (or in the app source tree) is copied into a white-box snapshot.
import type { ChainOracle } from '../../../lib/chain-oracle.ts'
import { sha256 as digest } from '../../../lib/chain-oracle.ts'
import type { PersonaId, ServiceId, TerminalImpactKind } from '../../../lib/types.ts'
import type { AuditEvent, NexusPlan, ServiceName } from '../src/shared.ts'

function text(event: AuditEvent, key: string): string {
  const value = event.detail[key]
  return typeof value === 'string' ? value : ''
}

function flag(event: AuditEvent, key: string): boolean {
  return event.detail[key] === true
}

function sid(name: ServiceName): ServiceId {
  return name as unknown as ServiceId
}

function impact(name: string): TerminalImpactKind {
  return name as unknown as TerminalImpactKind
}

function actor(event: AuditEvent, fallback: PersonaId): PersonaId {
  return event.actorPersona ?? fallback
}

interface Denial {
  entityId: string
  tenantId: string
  actor: string
  reason?: string
}

export function createNexusiamMonitor(oracle: ChainOracle, plan: NexusPlan, runId: string) {
  // Per-entity tracking: concurrent workers and dual-replay verification interleave several
  // comments, codes, documents and export jobs inside one run, so no chain keeps a single
  // "current" slot that a second entity could overwrite.
  const c1 = {
    comments: new Map<string, string>(), // commentId -> commentDigest
    visits: new Set<string>(), // moderation visit digests
    tokens: new Set<string>(), // bot-minted SCIM token digests
    promoted: new Map<string, string>(), // userId -> role granted through a bot-minted token
    deniedUsers: new Set<string>(), // readers refused by the audit vault
  }
  const c2 = {
    codes: new Set<string>(), // redirected authorization code digests
    captured: new Set<string>(), // code digests captured through the share preview
    inviteTokens: new Set<string>(), // leaked pending-invite token digests
  }
  const c3 = {
    delegations: new Set<string>(), // cross-tenant cached delegation key digests
    listed: new Map<string, Set<string>>(), // docId -> delegation digests that listed it
    opened: new Map<string, { tenantId: string; actor: string; delegations: Set<string> }>(), // docId -> open context
    denials: [] as Denial[], // private-document reads refused without a delegation / scope
  }
  const c4 = {
    folders: new Set<string>(), // private folder name digests disclosed by facets
    handles: new Map<string, string>(), // export handle digest -> jobId
    polled: new Set<string>(), // jobIds observed ready through a disclosed handle
  }
  const recordedControls = new Set<string>()

  // A clean ablation control is a genuine denial observed on the same entity, or on a sibling entity
  // of the same tenant made by the same actor. It always requires a real denial event.
  const controlFor = (
    denials: readonly Denial[], entityId: string, tenantId: string, actorId: string,
  ): Denial | null =>
    denials.find((denial) => denial.entityId === entityId) ??
    denials.find((denial) =>
      denial.entityId !== entityId && denial.tenantId !== '' && denial.tenantId === tenantId &&
      denial.actor !== '' && denial.actor === actorId) ??
    null

  const recordControlOnce = (
    chainId: string, fromHopId: string, toHopId: string, entityId: string, ts: number,
    detail: Record<string, string | number | boolean>,
  ): void => {
    const key = `${chainId}\0${fromHopId}\0${toHopId}\0${entityId}`
    if (recordedControls.has(key)) return
    recordedControls.add(key)
    oracle.recordControl({
      chainId, fromHopId, toHopId, entityId, result: 'failed_without_predecessor', ts, detail,
    })
  }

  const recordC3Control = (docId: string, denial: Denial, ts: number): void => {
    const detail: Record<string, string | number | boolean> = { reason: denial.reason ?? '' }
    if (denial.entityId !== docId) {
      detail.controlEntityId = denial.entityId
      detail.sibling = true
    }
    recordControlOnce('NX-C3', 'nx-c3-h3', 'nx-c3-h4', docId, ts, detail)
  }

  const consume = (event: AuditEvent): void => {
    if (event.runId !== runId) return

    if (event.kind === 'comment.created') {
      if (!flag(event, 'pipeline') || text(event, 'tenantId') !== 'org_a') return
      const commentId = text(event, 'commentId')
      const commentDigest = text(event, 'commentDigest')
      if (!commentId || !commentDigest) return
      c1.comments.set(commentId, commentDigest)
      oracle.recordHop({
        chainId: 'NX-C1', hopId: 'nx-c1-h1', service: sid('api'), routeKey: 'api.commentCreate',
        actor: actor(event, 'member_a'), artifactDigest: commentDigest, entityId: commentId, ts: event.ts,
        detail: { rawStored: flag(event, 'rawStored') },
      })
      return
    }

    if (event.kind === 'moderation.bot_visit') {
      const commentId = text(event, 'commentId')
      const commentDigest = commentId ? c1.comments.get(commentId) : undefined
      if (!commentDigest) return
      const visitDigest = text(event, 'visitDigest')
      if (!visitDigest) return
      c1.visits.add(visitDigest)
      oracle.recordHop({
        chainId: 'NX-C1', hopId: 'nx-c1-h2', service: sid('app'), routeKey: 'app.moderationRender',
        actor: 'member_a', artifactDigest: visitDigest, entityId: commentId, ts: event.ts,
        detail: { renderedRaw: flag(event, 'renderedRaw') },
      })
      oracle.recordEdge({
        chainId: 'NX-C1', fromHopId: 'nx-c1-h1', toHopId: 'nx-c1-h2', kind: 'value_binding',
        fromArtifactDigest: commentDigest, toConsumedDigest: text(event, 'commentDigest'), ts: event.ts,
      })
      return
    }

    if (event.kind === 'scim.token_minted') {
      const sourceDigest = text(event, 'sourceDigest')
      if (!sourceDigest || !c1.visits.has(sourceDigest)) return
      const tokenDigest = text(event, 'tokenDigest')
      if (!tokenDigest) return
      c1.tokens.add(tokenDigest)
      oracle.recordHop({
        chainId: 'NX-C1', hopId: 'nx-c1-h3', service: sid('api'), routeKey: 'api.scimTokenMint',
        actor: 'member_a', artifactDigest: tokenDigest, ts: event.ts,
        detail: { botInitiated: flag(event, 'botInitiated') },
      })
      oracle.recordEdge({
        chainId: 'NX-C1', fromHopId: 'nx-c1-h2', toHopId: 'nx-c1-h3', kind: 'value_binding',
        fromArtifactDigest: sourceDigest, toConsumedDigest: sourceDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'scim.user_patched') {
      const tokenDigest = text(event, 'tokenDigest')
      if (!tokenDigest || !c1.tokens.has(tokenDigest)) return
      const targetUserId = text(event, 'targetUserId')
      // The audit vault admits owners and admins, so either promotion completes the escalation.
      const role = text(event, 'role')
      if (targetUserId !== plan.personas.member_a.userId || (role !== 'owner' && role !== 'admin')) return
      c1.promoted.set(targetUserId, role)
      const artifact = digest(`role:${targetUserId}:${role}`)
      oracle.recordHop({
        chainId: 'NX-C1', hopId: 'nx-c1-h4', service: sid('api'), routeKey: 'api.scimUserPatch',
        actor: 'member_a', artifactDigest: artifact, entityId: targetUserId, ts: event.ts,
        effectiveRole: role === 'admin' ? 'admin' : 'owner',
      })
      oracle.recordEdge({
        chainId: 'NX-C1', fromHopId: 'nx-c1-h3', toHopId: 'nx-c1-h4', kind: 'value_binding',
        fromArtifactDigest: tokenDigest, toConsumedDigest: tokenDigest, ts: event.ts,
      })
      return
    }

    // The NX-C1 shared entity is the reader itself, so a denial for that reader is the
    // same-entity control; it is recorded whenever it happens relative to the promotion.
    if (event.kind === 'audit.vault_denied') {
      const readerUserId = text(event, 'readerUserId')
      if (readerUserId !== plan.personas.member_a.userId) return
      c1.deniedUsers.add(readerUserId)
      oracle.recordControl({
        chainId: 'NX-C1', fromHopId: 'nx-c1-h4', toHopId: 'nx-c1-h5',
        entityId: readerUserId, result: 'failed_without_predecessor', ts: event.ts,
        detail: { reason: text(event, 'reason') },
      })
      return
    }

    if (event.kind === 'audit.vault_read') {
      const readerUserId = text(event, 'readerUserId')
      if (readerUserId !== plan.personas.member_a.userId) return
      const role = c1.promoted.get(readerUserId)
      if (!role) return
      const artifact = digest(`audit:${readerUserId}`)
      oracle.recordHop({
        chainId: 'NX-C1', hopId: 'nx-c1-h5', service: sid('api'), routeKey: 'api.auditVaultRead',
        actor: 'member_a', artifactDigest: artifact, entityId: readerUserId, ts: event.ts,
        effectiveRole: role === 'admin' ? 'admin' : 'owner',
      })
      oracle.recordEdge({
        chainId: 'NX-C1', fromHopId: 'nx-c1-h4', toHopId: 'nx-c1-h5', kind: 'state_transition_binding',
        fromArtifactDigest: digest(`role:${readerUserId}:${role}`),
        toConsumedDigest: artifact, entityId: readerUserId, ts: event.ts,
      })
      if (c1.deniedUsers.has(readerUserId)) {
        oracle.recordControl({
          chainId: 'NX-C1', fromHopId: 'nx-c1-h4', toHopId: 'nx-c1-h5',
          entityId: readerUserId, result: 'failed_without_predecessor', ts: event.ts,
        })
      }
      oracle.recordTerminal({
        chainId: 'NX-C1', service: sid('api'), routeKey: 'api.auditVaultRead',
        kind: impact('privilege_escalation'), actor: 'member_a', entityId: readerUserId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'idp.authorize_redirect') {
      if (!flag(event, 'openRedirect')) return
      const codeDigest = text(event, 'codeDigest')
      if (!codeDigest) return
      c2.codes.add(codeDigest)
      oracle.recordHop({
        chainId: 'NX-C2', hopId: 'nx-c2-h1', service: sid('idp'), routeKey: 'idp.authorizeRedirect',
        actor: 'member_b', artifactDigest: codeDigest, ts: event.ts,
        detail: { redirect: text(event, 'redirect') },
      })
      return
    }

    if (event.kind === 'share.delegated_code_captured') {
      const codeDigest = text(event, 'codeDigest')
      if (!codeDigest || !c2.codes.has(codeDigest)) return
      c2.captured.add(codeDigest)
      oracle.recordHop({
        chainId: 'NX-C2', hopId: 'nx-c2-h2', service: sid('app'), routeKey: 'app.shareLinkCapture',
        actor: 'member_b', artifactDigest: codeDigest, ts: event.ts,
        detail: { victimBot: flag(event, 'victimBot') },
      })
      oracle.recordEdge({
        chainId: 'NX-C2', fromHopId: 'nx-c2-h1', toHopId: 'nx-c2-h2', kind: 'value_binding',
        fromArtifactDigest: codeDigest, toConsumedDigest: codeDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'invite.pending_listed') {
      const codeDigest = text(event, 'derivedFromDigest')
      if (!codeDigest || !c2.captured.has(codeDigest)) return
      const leaked = text(event, 'leakedTokenDigest')
      if (!leaked) return
      c2.inviteTokens.add(leaked)
      oracle.recordHop({
        chainId: 'NX-C2', hopId: 'nx-c2-h3', service: sid('idp'), routeKey: 'idp.pendingInvites',
        actor: 'member_b', artifactDigest: leaked, ts: event.ts,
        detail: { inviteId: text(event, 'inviteId') },
      })
      oracle.recordEdge({
        chainId: 'NX-C2', fromHopId: 'nx-c2-h2', toHopId: 'nx-c2-h3', kind: 'derived_crypto_binding',
        fromArtifactDigest: codeDigest, toConsumedDigest: '', derivedFromDigest: codeDigest, ts: event.ts,
        detail: { attestation: 'delegated-code-exchange' },
      })
      return
    }

    if (event.kind === 'invite.redeemed_stale') {
      const inviteTokenDigest = text(event, 'tokenDigest')
      if (!inviteTokenDigest || !c2.inviteTokens.has(inviteTokenDigest)) return
      const sessionDigest = text(event, 'sessionDigest')
      if (!sessionDigest) return
      oracle.recordHop({
        chainId: 'NX-C2', hopId: 'nx-c2-h4', service: sid('idp'), routeKey: 'idp.inviteRedeem',
        actor: 'member_b', artifactDigest: sessionDigest, ts: event.ts,
        effectiveRole: 'admin', detail: { stale: flag(event, 'stale') },
      })
      oracle.recordEdge({
        chainId: 'NX-C2', fromHopId: 'nx-c2-h3', toHopId: 'nx-c2-h4', kind: 'derived_crypto_binding',
        fromArtifactDigest: inviteTokenDigest, toConsumedDigest: '',
        derivedFromDigest: inviteTokenDigest, ts: event.ts,
        detail: { attestation: 'stale-invite-session' },
      })
      oracle.recordTerminal({
        chainId: 'NX-C2', service: sid('idp'), routeKey: 'idp.inviteRedeem',
        kind: impact('stale_privilege_use'), actor: 'member_b', ts: event.ts,
      })
      return
    }

    if (event.kind === 'cdn.profile_cache_served') {
      if (!flag(event, 'crossTenant')) return
      const delegationDigest = text(event, 'delegationKeyDigest')
      if (!delegationDigest) return
      c3.delegations.add(delegationDigest)
      oracle.recordHop({
        chainId: 'NX-C3', hopId: 'nx-c3-h1', service: sid('cdn'), routeKey: 'cdn.profileCacheRead',
        actor: 'member_b', artifactDigest: delegationDigest, ts: event.ts,
        detail: { cacheOwnerTenant: text(event, 'cacheOwnerTenant') },
      })
      return
    }

    if (event.kind === 'docs.listing_served') {
      if (!flag(event, 'fallback')) return
      const delegationDigest = text(event, 'delegationKeyDigest')
      if (!delegationDigest || !c3.delegations.has(delegationDigest)) return
      const docId = text(event, 'docId')
      if (!docId) return
      const listedWith = c3.listed.get(docId) ?? new Set<string>()
      listedWith.add(delegationDigest)
      c3.listed.set(docId, listedWith)
      const artifact = digest(docId)
      oracle.recordHop({
        chainId: 'NX-C3', hopId: 'nx-c3-h2', service: sid('api'), routeKey: 'api.docsWorkspaceFallback',
        actor: 'member_b', artifactDigest: artifact, entityId: docId, ts: event.ts,
        detail: { workspaceId: text(event, 'workspaceId') },
      })
      oracle.recordEdge({
        chainId: 'NX-C3', fromHopId: 'nx-c3-h1', toHopId: 'nx-c3-h2', kind: 'value_binding',
        fromArtifactDigest: delegationDigest, toConsumedDigest: delegationDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'docs.doc_opened') {
      const docId = text(event, 'docId')
      const delegationDigest = text(event, 'delegationKeyDigest')
      if (!docId || !delegationDigest || !c3.listed.get(docId)?.has(delegationDigest)) return
      const opened = c3.opened.get(docId) ?? {
        tenantId: text(event, 'tenantId'), actor: event.actorPersona ?? '', delegations: new Set<string>(),
      }
      opened.delegations.add(delegationDigest)
      c3.opened.set(docId, opened)
      const artifact = digest(`doc:${docId}`)
      oracle.recordHop({
        chainId: 'NX-C3', hopId: 'nx-c3-h3', service: sid('api'), routeKey: 'api.docPrivateOpen',
        actor: 'member_b', artifactDigest: artifact, entityId: docId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'NX-C3', fromHopId: 'nx-c3-h2', toHopId: 'nx-c3-h3', kind: 'value_binding',
        fromArtifactDigest: digest(docId), toConsumedDigest: digest(docId), ts: event.ts,
      })
      const denial = controlFor(c3.denials, docId, opened.tenantId, opened.actor)
      if (denial) recordC3Control(docId, denial, event.ts)
      return
    }

    if (event.kind === 'docs.access_denied') {
      const docId = text(event, 'docId')
      if (!docId) return
      const reason = text(event, 'reason')
      if (reason !== 'missing_delegation' && reason !== 'scope_check') return
      const denial: Denial = { entityId: docId, tenantId: text(event, 'tenantId'), actor: event.actorPersona ?? '', reason }
      c3.denials.push(denial)
      // Credit every opened document this denial ablates (same document, or same-tenant sibling
      // refused for the same actor), whichever order the control and the open arrive in.
      for (const [openedId, opened] of c3.opened) {
        if (controlFor([denial], openedId, opened.tenantId, opened.actor)) recordC3Control(openedId, denial, event.ts)
      }
      return
    }

    if (event.kind === 'docs.content_read') {
      const docId = text(event, 'docId')
      const opened = docId ? c3.opened.get(docId) : undefined
      if (!opened) return
      if (!text(event, 'canaryDigest')) return
      const artifact = digest(`content:${docId}`)
      oracle.recordHop({
        chainId: 'NX-C3', hopId: 'nx-c3-h4', service: sid('api'), routeKey: 'api.docContentRead',
        actor: 'member_b', artifactDigest: artifact, entityId: docId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'NX-C3', fromHopId: 'nx-c3-h3', toHopId: 'nx-c3-h4', kind: 'state_transition_binding',
        fromArtifactDigest: digest(`doc:${docId}`), toConsumedDigest: artifact,
        entityId: docId, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'NX-C3', service: sid('api'), routeKey: 'api.docContentRead',
        kind: impact('cross_tenant_document_read'), actor: 'member_b', entityId: docId, ts: event.ts,
      })
      return
    }

    if (event.kind === 'search.facets_returned') {
      if (!flag(event, 'privateMatch')) return
      const folderDigest = text(event, 'folderNameDigest')
      if (!folderDigest) return
      c4.folders.add(folderDigest)
      oracle.recordHop({
        chainId: 'NX-C4', hopId: 'nx-c4-h1', service: sid('api'), routeKey: 'api.searchFacets',
        actor: 'revoked_or_demoted', artifactDigest: folderDigest, ts: event.ts,
        detail: { count: event.detail.count ?? 0 },
      })
      return
    }

    if (event.kind === 'doc.share_metadata') {
      const folderDigest = text(event, 'folderDigest')
      if (!folderDigest || !c4.folders.has(folderDigest)) return
      const handleDigest = text(event, 'handleDigest')
      if (!handleDigest) return
      const jobId = text(event, 'jobId')
      c4.handles.set(handleDigest, jobId)
      oracle.recordHop({
        chainId: 'NX-C4', hopId: 'nx-c4-h2', service: sid('api'), routeKey: 'api.shareMetadata',
        actor: 'revoked_or_demoted', artifactDigest: handleDigest, entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'NX-C4', fromHopId: 'nx-c4-h1', toHopId: 'nx-c4-h2', kind: 'value_binding',
        fromArtifactDigest: folderDigest, toConsumedDigest: folderDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'worker.job_polled') {
      const handleDigest = text(event, 'handleDigest')
      const jobId = handleDigest ? c4.handles.get(handleDigest) : undefined
      if (jobId === undefined) return
      if (text(event, 'status') !== 'ready') return
      c4.polled.add(jobId)
      const artifact = digest(`job:${jobId}`)
      oracle.recordHop({
        chainId: 'NX-C4', hopId: 'nx-c4-h3', service: sid('docs-worker'), routeKey: 'docsWorker.jobPoll',
        actor: 'revoked_or_demoted', artifactDigest: artifact, entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'NX-C4', fromHopId: 'nx-c4-h2', toHopId: 'nx-c4-h3', kind: 'value_binding',
        fromArtifactDigest: handleDigest, toConsumedDigest: handleDigest, ts: event.ts,
      })
      return
    }

    if (event.kind === 'worker.job_result') {
      const jobId = text(event, 'jobId')
      if (!c4.polled.has(jobId)) return
      if (!flag(event, 'exfiltrated') || !text(event, 'canaryDigest')) return
      const artifact = digest(`result:${jobId}`)
      oracle.recordHop({
        chainId: 'NX-C4', hopId: 'nx-c4-h4', service: sid('docs-worker'), routeKey: 'docsWorker.jobResult',
        actor: 'revoked_or_demoted', artifactDigest: artifact, entityId: jobId, ts: event.ts,
      })
      oracle.recordEdge({
        chainId: 'NX-C4', fromHopId: 'nx-c4-h3', toHopId: 'nx-c4-h4', kind: 'async_pivot_binding',
        fromArtifactDigest: digest(`job:${jobId}`), toConsumedDigest: artifact,
        runId, pollObserved: true, ts: event.ts,
      })
      oracle.recordTerminal({
        chainId: 'NX-C4', service: sid('docs-worker'), routeKey: 'docsWorker.jobResult',
        kind: impact('cross_tenant_exfiltration'), actor: 'revoked_or_demoted', entityId: jobId, ts: event.ts,
      })
    }
  }

  return { consume }
}
