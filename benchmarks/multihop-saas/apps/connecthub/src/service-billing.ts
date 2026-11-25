// Internal billing service: rebate and refund settlement, ledger conservation readback.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { parseJson, readBody, runIdOf, sendJson, match, parseUrl } from './http.ts'
import type { LabState } from './shared.ts'
import { digest, serviceTokenOk } from './policy.ts'
import { invoiceById, ledgerTotal, seededJitter } from './state.ts'

export async function handleBilling(req: IncomingMessage, res: ServerResponse, state: LabState): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'billing.internal', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      ledgerEntries: state.ledger.length,
      rebates: state.rebates.length,
      refunds: state.refunds.length,
      exports: state.exports.length,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/rebates/settle')) {
    if (!serviceTokenOk(state, req)) {
      sendJson(res, 401, { error: 'service token required' })
      return
    }
    const body = parseJson<{ invoiceId?: string }>(await readBody(req))
    const invoice = invoiceById(state, body?.invoiceId ?? '')
    if (!invoice) {
      sendJson(res, 404, { error: 'unknown invoice' })
      return
    }
    const claims = state.rebates.filter((claim) => claim.invoiceId === invoice.id)
    if (claims.length === 0) {
      state.emit('rebate.settle_denied', {
        invoiceId: invoice.id, reason: 'missing_claim', tenantId: invoice.tenantId, runId,
      })
      sendJson(res, 403, { error: 'no rebate claim for this invoice' })
      return
    }
    const refundedCents = ledgerTotal(state, invoice.id)
    const conservationViolated = refundedCents > invoice.amountCents
    state.emit('rebate.settled', {
      invoiceId: invoice.id,
      tenantId: invoice.tenantId,
      refundedCents,
      paidCents: invoice.amountCents,
      claims: claims.length,
      conservationViolated,
      runId,
    })
    sendJson(res, 200, {
      invoiceId: invoice.id, refundedCents, paidCents: invoice.amountCents, conservationViolated,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/refunds/settle')) {
    if (!serviceTokenOk(state, req)) {
      sendJson(res, 401, { error: 'service token required' })
      return
    }
    const body = parseJson<{ caseId?: string }>(await readBody(req))
    const caseId = body?.caseId ?? ''
    const refunds = state.refunds.filter((refund) => refund.caseId === caseId)
    if (refunds.length === 0) {
      const supportCase = state.cases.find((item) => item.id === caseId)
      state.emit('refund.settle_denied', {
        caseId, tenantId: supportCase?.tenantId ?? 'org_a', reason: 'missing_claim', runId,
      })
      sendJson(res, 403, { error: 'no split refund for this case' })
      return
    }
    const paidCents = state.invoices.find((invoice) => invoice.tenantId === refunds[0]!.tenantId)?.amountCents ??
      state.plan.economics.invoiceAmountCents
    const refundedCents = ledgerTotal(state, caseId)
    const conservationViolated = refundedCents > paidCents
    for (const refund of refunds) refund.status = 'settled'
    state.emit('refund.settled', {
      caseId,
      tenantId: refunds[0]!.tenantId,
      refundedCents,
      paidCents,
      claims: refunds.length,
      conservationViolated,
      runId,
    })
    sendJson(res, 200, { caseId, refundedCents, paidCents, conservationViolated })
    return
  }

  if (match(url, method, '/ledger')) {
    sendJson(res, 200, { ledger: state.ledger })
    return
  }

  const conservation = match(url, method, '/conservation/:id')
  if (conservation) {
    const subjectId = conservation[0]!
    const invoice = invoiceById(state, subjectId)
    const paidCents = invoice?.amountCents ??
      state.invoices.find((item) => item.tenantId === 'org_a')?.amountCents ??
      state.plan.economics.invoiceAmountCents
    const refundedCents = ledgerTotal(state, subjectId)
    sendJson(res, 200, {
      subjectId, refundedCents, paidCents, conservationViolated: refundedCents > paidCents,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/keys/rotate')) {
    sendJson(res, 200, { rotated: true, jitterMs: seededJitter(state.plan, 'rotate') })
    return
  }

  if (method === 'POST' && match(url, method, '/reset')) {
    const cleared = {
      ledger: state.ledger.length,
      rebates: state.rebates.length,
      refunds: state.refunds.length,
      exports: state.exports.length,
    }
    state.ledger.length = 0
    state.rebates.length = 0
    state.refunds.length = 0
    state.exports.length = 0
    state.signatures.length = 0
    sendJson(res, 200, { reset: true, cleared })
    return
  }

  const benign: Record<string, unknown> = {
    '/partners': { partners: [{ id: 'mh_partner_1', tier: 'gold' }] },
    '/balances': { balances: [{ currency: 'USD', amountCents: state.plan.economics.payoutCapCents }] },
    '/statements': { statements: [{ id: 'mh_stmt_1', period: '2026-10' }] },
    '/remittances': { remittances: [{ id: 'mh_remit_1', status: 'scheduled' }] },
    '/taxes': { taxes: [{ region: 'us', percent: 0 }] },
    '/currencies': { currencies: ['USD', 'EUR'] },
    '/reconciliation': { reconciled: true },
    '/audit': { events: state.audit.slice(-50).map((event) => ({ kind: event.kind, ts: event.ts })) },
    '/digest': { value: digest(`${state.runId}:${state.seq}`) },
  }
  for (const [path, payload] of Object.entries(benign)) {
    if (match(url, method, path)) {
      sendJson(res, 200, payload)
      return
    }
  }

  sendJson(res, 404, { error: 'not found', service: 'billing.internal' })
}
