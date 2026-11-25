// Billing and ledger surfaces: payouts, maker/checker approval, orders and settlement capture.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { readBody, parseJson, sendJson, runIdOf, match, parseUrl, header } from './http.ts'
import type { LabState, OrderRecord, SessionRecord } from './shared.ts'
import { authenticate, digest, firstJsonNumber, lastJsonNumber, roleOf, sessionTenantOk } from './policy.ts'

function auth(state: LabState, req: IncomingMessage, res: ServerResponse) {
  const session = authenticate(state, req)
  if (!session) {
    sendJson(res, 401, { error: 'session required' })
    return null
  }
  if (!sessionTenantOk(state.profile, session)) {
    state.emit('session.rejected', { reason: 'unverified_session', tenantId: session.tenantId }, session.originPersona)
    sendJson(res, 403, { error: 'session not verified for this tenant' })
    return null
  }
  return session
}

/** Reads (`GET`) on order and ledger data require a verified session. */
function requireVerified(session: SessionRecord, res: ServerResponse): boolean {
  if (session.emailVerified) return true
  sendJson(res, 403, { error: 'verified session required' })
  return false
}

/** Order mutations are not available to the read-only viewer role. */
function requireWriteRole(state: LabState, session: SessionRecord, res: ServerResponse): boolean {
  if (roleOf(state, session, session.tenantId) !== 'viewer') return true
  sendJson(res, 403, { error: 'write role required' })
  return false
}

/** True only when the request was forwarded by the edge service of this lab instance. */
function fromEdge(state: LabState, req: IncomingMessage): boolean {
  const presented = Buffer.from(header(req, 'x-edge-bridge'))
  const expected = Buffer.from(state.edgeBridgeToken)
  return presented.length === expected.length && timingSafeEqual(presented, expected)
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function handleBilling(
  req: IncomingMessage, res: ServerResponse, state: LabState,
): Promise<boolean> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)
  const p = state.plan.routePrefix
  const at = (path: string): string => `${p}${path}`

  if (match(url, method, at('/payouts'))) {
    const session = auth(state, req, res)
    if (!session) return true
    sendJson(res, 200, {
      payouts: state.payouts.filter((payout) => payout.tenantId === session.tenantId),
    })
    return true
  }

  const payoutById = match(url, method, at('/payouts/:id'))
  if (payoutById) {
    const session = auth(state, req, res)
    if (!session) return true
    const payout = state.payouts.find((item) => item.id === payoutById[0])
    if (!payout || payout.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown payout' })
      return true
    }
    sendJson(res, 200, { payout })
    return true
  }

  const rebind = match(url, method, at('/payouts/:id/rebind'))
  if (rebind) {
    const session = auth(state, req, res)
    if (!session) return true
    const payout = state.payouts.find((item) => item.id === rebind[0])
    if (!payout || payout.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown payout' })
      return true
    }
    const role = roleOf(state, session, payout.tenantId)
    if (role !== 'finance' && role !== 'admin' && role !== 'owner') {
      state.emit('payout.rebind_denied', { payoutId: payout.id, reason: 'insufficient_role', runId }, session.originPersona)
      sendJson(res, 403, { error: 'finance role required' })
      return true
    }
    if (payout.status !== 'draft') {
      sendJson(res, 409, { error: 'payout is not a draft' })
      return true
    }
    const prior = payout.createdBy
    payout.createdBy = session.userId
    payout.rebound = true
    state.emit('payout.rebound', {
      payoutId: payout.id,
      tenantId: payout.tenantId,
      priorCreatedBy: prior,
      createdBy: session.userId,
      status: payout.status,
      sessionDigest: digest(session.token),
      runId,
    }, session.originPersona)
    sendJson(res, 200, { payout })
    return true
  }

  const approve = match(url, method, at('/payouts/:id/approve'))
  if (approve) {
    const session = auth(state, req, res)
    if (!session) return true
    const payout = state.payouts.find((item) => item.id === approve[0])
    if (!payout || payout.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown payout' })
      return true
    }
    const role = roleOf(state, session, payout.tenantId)
    if (role !== 'finance' && role !== 'admin' && role !== 'owner') {
      state.emit('payout.approve_denied', {
        payoutId: payout.id,
        tenantId: payout.tenantId,
        reason: 'insufficient_role',
        sessionDigest: digest(session.token),
        runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'finance role required' })
      return true
    }
    if (payout.status !== 'draft') {
      sendJson(res, 409, { error: 'payout is not a draft' })
      return true
    }
    // An unverified session may only act on drafts it owns; ownership must be rebound first.
    if (!session.emailVerified && payout.createdBy !== session.userId) {
      state.emit('payout.approve_denied', {
        payoutId: payout.id,
        tenantId: payout.tenantId,
        reason: 'rebind_required',
        sessionDigest: digest(session.token),
        runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'rebind required before approval' })
      return true
    }
    // Verified staff sessions always go through the separation-of-duties check.
    const legacyApprovalPath = state.profile.makerCheckerBypass && !session.emailVerified
    if (payout.createdBy === session.userId && !legacyApprovalPath) {
      state.emit('payout.approve_denied', {
        payoutId: payout.id,
        tenantId: payout.tenantId,
        reason: 'maker_checker',
        sessionDigest: digest(session.token),
        runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'maker and checker must differ' })
      return true
    }
    payout.status = 'settled'
    payout.approvedBy = session.userId
    state.ledger.push({
      id: `mh_led_${state.ledger.length + 1}`,
      tenantId: payout.tenantId,
      amountCents: -payout.amountCents,
      memo: `payout:${payout.id}`,
      runId,
      ts: Date.now(),
    })
    state.emit('payout.settled', {
      payoutId: payout.id,
      tenantId: payout.tenantId,
      amountCents: payout.amountCents,
      createdBy: payout.createdBy,
      approvedBy: session.userId,
      makerCheckerBypassed: payout.createdBy === session.userId,
      sessionDigest: digest(session.token),
      runId,
    }, session.originPersona)
    sendJson(res, 200, { payout })
    return true
  }

  if (match(url, method, at('/orders'))) {
    const session = auth(state, req, res)
    if (!session) return true
    if (method === 'GET' ? !requireVerified(session, res) : !requireWriteRole(state, session, res)) return true
    const raw = await readBody(req)
    const first = firstJsonNumber(raw, 'amountCents')
    const last = lastJsonNumber(raw, 'amountCents')
    // The edge-computed amount is only honoured on requests the edge actually forwarded.
    const edgeHeader = fromEdge(state, req) ? Number(header(req, 'x-lab-edge-amount')) : Number.NaN
    const edgeAmount = Number.isFinite(edgeHeader) && edgeHeader > 0 ? edgeHeader : last
    const duplicated = first !== null && last !== null && first !== last
    if (duplicated && !state.profile.duplicateKeyCapRelaxed) {
      state.emit('order.duplicate_rejected', { tenantId: session.tenantId, runId }, session.originPersona)
      sendJson(res, 400, { error: 'duplicate json key rejected' })
      return true
    }
    const amount = first ?? last ?? 0
    if (amount <= 0) {
      sendJson(res, 400, { error: 'amountCents required' })
      return true
    }
    // When a field repeats, the amount already validated at the edge is authoritative for the cap.
    const capCheckedAmount = duplicated && state.profile.duplicateKeyCapRelaxed ? (edgeAmount ?? amount) : amount
    if (capCheckedAmount > state.plan.economics.payoutCapCents) {
      state.emit('order.cap_rejected', { amountCents: amount, capCents: state.plan.economics.payoutCapCents, runId }, session.originPersona)
      sendJson(res, 422, { error: 'payout cap exceeded' })
      return true
    }
    const body = parseJson<{ beneficiary?: string }>(raw) ?? {}
    const order: OrderRecord = {
      id: `mh_ord_${state.orders.length + 1}_${digest(`${runId}:${amount}`).slice(0, 6)}`,
      tenantId: session.tenantId,
      amountCents: amount,
      beneficiary: body.beneficiary ?? 'acct_default',
      status: 'draft',
      createdBy: session.userId,
      rebound: false,
      settled: false,
      captureSeq: 0,
      runId,
    }
    state.orders.push(order)
    state.emit('order.draft_created', {
      orderId: order.id,
      tenantId: order.tenantId,
      amountCents: amount,
      capCents: state.plan.economics.payoutCapCents,
      edgeAmount: edgeAmount ?? 0,
      apiAmount: first ?? amount,
      duplicateKey: duplicated,
      sessionDigest: digest(session.token),
      runId,
    }, session.originPersona)
    sendJson(res, 201, { order })
    return true
  }

  const orderById = match(url, method, at('/orders/:id'))
  if (orderById) {
    const session = auth(state, req, res)
    if (!session) return true
    if (!requireVerified(session, res)) return true
    const order = state.orders.find((item) => item.id === orderById[0])
    if (!order || order.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown order' })
      return true
    }
    sendJson(res, 200, { order })
    return true
  }

  const orderRebind = match(url, method, at('/orders/:id/rebind'))
  if (orderRebind) {
    const session = auth(state, req, res)
    if (!session) return true
    if (!requireWriteRole(state, session, res)) return true
    const order = state.orders.find((item) => item.id === orderRebind[0])
    if (!order || order.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown order' })
      return true
    }
    if (order.status === 'settled') {
      sendJson(res, 409, { error: 'order already settled' })
      return true
    }
    if (order.status === 'authorized' && !state.profile.rebindAfterAuthorization) {
      sendJson(res, 409, { error: 'order already authorized' })
      return true
    }
    const body = parseJson<{ beneficiary?: string }>(await readBody(req))
    const prior = order.beneficiary
    if (body?.beneficiary) order.beneficiary = body.beneficiary
    order.status = 'authorized'
    order.rebound = true
    state.emit('order.rebound', {
      orderId: order.id,
      tenantId: order.tenantId,
      priorBeneficiary: prior,
      beneficiary: order.beneficiary,
      status: order.status,
      sessionDigest: digest(session.token),
      runId,
    }, session.originPersona)
    sendJson(res, 200, { order })
    return true
  }

  const settleRace = match(url, method, at('/orders/:id/settle-race'))
  if (settleRace) {
    const session = auth(state, req, res)
    if (!session) return true
    if (!requireWriteRole(state, session, res)) return true
    const order = state.orders.find((item) => item.id === settleRace[0])
    if (!order || order.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown order' })
      return true
    }
    if (order.status !== 'authorized') {
      state.emit('settlement.control_denied', {
        orderId: order.id,
        tenantId: order.tenantId,
        reason: 'state_not_authorized',
        runId,
      }, session.originPersona)
      sendJson(res, 409, { error: 'order not authorized for capture' })
      return true
    }
    // Standard captures are claimed synchronously (idempotent); high-value orders use the treasury
    // capture path.
    const treasuryCapture = state.profile.concurrentSettlement
      && order.amountCents > state.plan.economics.payoutCapCents
    if (!treasuryCapture && order.settled) {
      sendJson(res, 409, { error: 'order already captured' })
      return true
    }
    if (!treasuryCapture) order.settled = true // claim the capture synchronously before any await
    const seen = order.captureSeq
    if (treasuryCapture) await delay(6)
    order.captureSeq = treasuryCapture ? order.captureSeq + 1 : seen + 1
    order.settled = true
    order.status = 'settled'
    state.ledger.push({
      id: `mh_led_${state.ledger.length + 1}`,
      tenantId: order.tenantId,
      amountCents: state.plan.economics.raceCreditCents,
      memo: `capture:${order.id}`,
      runId,
      ts: Date.now(),
    })
    if (order.captureSeq >= 2) {
      state.emit('settlement.race', {
        orderId: order.id,
        tenantId: order.tenantId,
        credits: order.captureSeq,
        expectedCredits: 1,
        creditedCents: state.plan.economics.raceCreditCents * order.captureSeq,
        sessionDigest: digest(session.token),
        runId,
      }, session.originPersona)
    }
    sendJson(res, 200, { order, capture: order.captureSeq })
    return true
  }

  if (match(url, method, at('/ledger'))) {
    const session = auth(state, req, res)
    if (!session) return true
    if (!requireVerified(session, res)) return true
    sendJson(res, 200, { entries: state.ledger.filter((entry) => entry.tenantId === session.tenantId) })
    return true
  }

  if (match(url, method, at('/balance'))) {
    const session = auth(state, req, res)
    if (!session) return true
    if (!requireVerified(session, res)) return true
    const total = state.ledger
      .filter((entry) => entry.tenantId === session.tenantId)
      .reduce((sum, entry) => sum + entry.amountCents, 0)
    sendJson(res, 200, { tenant: session.tenantId, balanceCents: state.plan.economics.payoutCapCents * 10 + total })
    return true
  }

  return false
}
