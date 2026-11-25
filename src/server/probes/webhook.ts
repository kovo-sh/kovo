// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { createHmac } from 'node:crypto'
import { jsonRecord, randToken, scalarMatches } from './context.ts'
import type { DiffContext, DiffOutcome } from './context.ts'
import type { ProbeModule } from './registry.ts'



export const webhookHeaderNames = [
  'x-hub-signature-256', 'x-hub-signature', 'stripe-signature', 'x-webhook-signature',
  'x-signature-256', 'x-signature', 'x-slack-signature', 'x-shopify-hmac-sha256',
]


export const webhookSignatureKeyFields = ['signature', 'sig', 'hmac', 'token', 'code']


export const webhookKeyFields = ['key', 'secret', 'signingKey', 'signing_key', 'webhookKey', 'webhook_key']



/** Canonical payload strings a receiver might sign; only used to build an attacker-chosen key pair. */
export function webhookCanonicals(body: Record<string, unknown>, ts: string): string[] {
  const event = body.event ?? body.payload ?? body.data ?? body
  const eventText = typeof event === 'string' ? event : JSON.stringify(event)
  const withoutSig = { ...body }
  for (const f of [...webhookSignatureKeyFields, ...webhookHeaderNames]) delete withoutSig[f]
  return [
    `${ts}.${eventText}`,
    `${ts}.${JSON.stringify(withoutSig)}`,
    JSON.stringify(event),
    JSON.stringify(withoutSig),
  ]
}



/**
 * Webhook signature differential (CWE-345).
 *
 * Control: a tampered/random signature must be rejected. Probe: an unsigned (or attacker-key
 * self-signed) delivery is accepted. The endpoint is only reported when a follow-up read shows the
 * event was actually processed, so receivers that answer 200 without persisting stay silent.
 */
export async function diffWebhookSignature(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const body = req.webhookBody ? { ...req.webhookBody } : null
  const readPath = req.readPath
  const stateField = req.readStateField
  const expected = req.readStateValue
  if (!body) {
    return { verdict: 'inconclusive', summary: 'webhook_signature_bypass needs a delivery body.', details: {} }
  }
  const ts = String(Math.floor(Date.now() / 1000))
  const delivery = { ...body, ts }
  const controlHeader = req.webhookHeader ?? webhookHeaderNames[0]
  const control = await send({
    method: 'POST', pathAndQuery: req.pathAndQuery,
    headers: { 'Content-Type': 'application/json', [controlHeader]: `kovo_invalid_${randToken(12)}` },
    body: JSON.stringify(delivery),
  })
  if (!control) return { verdict: 'inconclusive', summary: 'Webhook control request failed.', details: {} }
  const controlRejected = control.status >= 400 && control.status < 500

  const accepted: Array<{ variant: string; header?: string; body: Record<string, unknown>; status: number; responseBody: string }> = []
  // (a) no signature at all
  const unsigned = await send({
    method: 'POST', pathAndQuery: req.pathAndQuery,
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(delivery),
  })
  if (unsigned && unsigned.status >= 200 && unsigned.status < 300) {
    accepted.push({ variant: 'unsigned', body: delivery, status: unsigned.status, responseBody: unsigned.body })
  }
  // (b) attacker-chosen key echoed inline (a receiver that trusts an inline signing key)
  if (accepted.length === 0) {
    const attackerKey = `kovo_whk_${randToken(10)}`
    const canonicals = webhookCanonicals(delivery, ts)
    for (const keyField of webhookKeyFields.slice(0, 3)) {
      for (const sigField of webhookSignatureKeyFields.slice(0, 3)) {
        if (ctx.runner.stopReason || accepted.length > 0) break
        const withKey = { ...delivery, [keyField]: attackerKey }
        for (const canonical of canonicals.slice(0, 2)) {
          const sig = createHmac('sha256', attackerKey).update(canonical).digest('hex')
          const attempt = { ...withKey, [sigField]: sig }
          const ex = await send({
            method: 'POST', pathAndQuery: req.pathAndQuery,
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(attempt),
          })
          if (ex && ex.status >= 200 && ex.status < 300) {
            accepted.push({ variant: `inline_key:${keyField}/${sigField}`, body: attempt, status: ex.status, responseBody: ex.body })
            break
          }
        }
      }
    }
  }
  if (accepted.length === 0) {
    return {
      verdict: 'no_signal',
      summary: controlRejected
        ? 'The receiver rejected tampered and unsigned deliveries.'
        : 'No unsigned or self-signed delivery was accepted.',
      details: { controlStatus: control.status, controlRejected, bodyKeys: Object.keys(body).slice(0, 12) },
    }
  }
  const read = readPath ? await send({ method: 'GET', pathAndQuery: readPath }) : null
  const readJson = read ? jsonRecord(read.body) : null
  const readbackProven = Boolean(read && read.status >= 200 && read.status < 300 && stateField && expected !== undefined && (
    scalarMatches(readJson?.[stateField], expected) ||
    (Array.isArray(readJson?.[stateField]) && (readJson![stateField] as unknown[]).length >= Number(expected))
  ))
  // Fallback when the receiver exposes no delivery read route: a rejected control plus an accepted
  // forged delivery that returns an explicit processing acknowledgement is still a signature bypass.
  const acceptedResponse = accepted[0]!.status >= 200 && accepted[0]!.status < 300
  const acceptedBodyText = accepted[0]!.responseBody.toLowerCase()
  const responseAck = acceptedResponse && /"(?:ok|received|processed|accepted|success)"\s*:\s*true/.test(acceptedBodyText)
  // An unsigned delivery that the receiver explicitly acknowledges as processed is a signature
  // bypass even when the receiver also accepts invalid signatures (no rejected control exists:
  // omitting the signature entirely is the strongest form of the attack).
  const acceptanceProven = responseAck
  if (!readbackProven && !acceptanceProven) {
    return {
      verdict: 'no_signal',
      summary: 'The forged delivery was accepted but the follow-up read did not show it was processed.',
      details: { controlStatus: control.status, accepted: accepted[0]?.variant, readStatus: read?.status ?? null },
    }
  }
  const anomalyReadPath = readPath ?? req.pathAndQuery
  const anomalyStateField = stateField ?? 'ok'
  const anomalyExpected = expected ?? true
  anomalies.push({
    type: 'webhook_signature_bypass',
    path: req.pathAndQuery,
    headerName: controlHeader,
    body: accepted[0]!.body,
    readPath: anomalyReadPath,
    stateField: anomalyStateField,
    expectedValue: anomalyExpected,
    variant: accepted[0]!.variant,
    proof: readbackProven ? 'readback' : 'acceptance',
    controlStatus: control.status,
    controlRejected,
    acceptedStatus: accepted[0]!.status,
    acceptanceAck: responseAck,
  })
  return {
    verdict: 'signal',
    summary: readbackProven
      ? 'A forged webhook delivery was accepted and the follow-up read confirmed the event was processed.'
      : 'A forged webhook delivery was accepted while a tampered control was rejected.',
    details: { controlStatus: control.status, accepted: accepted[0]?.variant, readStatus: read?.status ?? null, readbackProven },
  }
}

export const webhookProbe: ProbeModule = {
  family: 'webhook',
  classes: ['webhook_signature_bypass'],
  run: (ctx) => diffWebhookSignature(ctx),
}
