/**
 * v7 M4 Production Operations — Portable ProofReceipt Export.
 *
 * Produces a self-contained, deterministic, cryptographically signed JSON bundle
 * for a run containing:
 *  - Redacted (and optionally ZDR/PII-scrubbed) host-recorded transcript slices,
 *  - Each finding's ProofReceipt + verification summary + per-record SHA-256,
 *  - Minimal deterministic reproducer metadata (redacted steps + placeholder curl template),
 *  - Patch-retest proof verdicts (`retest_runs`),
 *  - Honest operational coverage-gap summary (`CoverageGapReport`).
 */
import { createHash, createHmac, sign as cryptoSign, timingSafeEqual, verify as cryptoVerify } from 'node:crypto'
import type { KeyLike } from 'node:crypto'
import { desc, eq } from 'drizzle-orm'
import { buildCoverageGapReport } from './coverage-gaps.ts'
import type { CoverageGapReport } from './coverage-gaps.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import type { ProofReceipt } from './proof-receipt.ts'
import { isZdrModeEnabled, redact, redactHeaders, redactPii } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { brokerExchanges, findings as findingsTable, replaySpecs, retestRuns } from './schema.ts'
import { canonicalJson } from './scope-policy.ts'
import type { Store } from './store.ts'

export type ReceiptBundleAlgorithm = 'hmac-sha256' | 'ed25519'

export type ReceiptBundleSignOptions =
  | { algorithm: 'hmac-sha256'; secret: string | Buffer; keyId?: string }
  | { algorithm: 'ed25519'; privateKey: KeyLike | string | Buffer; keyId?: string }

export interface ReceiptBundleVerifyOptions {
  algorithm?: ReceiptBundleAlgorithm
  secret?: string | Buffer
  publicKey?: KeyLike | string | Buffer
}

export interface PortableTranscriptSlice {
  exchangeId: string
  origin: string
  finalOrigin: string
  method: string
  pathAndQuery: string
  personaHandle: string | null
  status: number
  mediaType: string
  reqHeaders: Record<string, string>
  respHeaders: Record<string, string>
  bodyPreview: string
  bodySha256: string
  durationMs: number
  capturedAt: string
}

export interface PortableReproducerStep {
  method: string
  origin: string
  pathAndQuery: string
  personaHandle: string | null
  headers: Record<string, string>
  observedStatus: number
}

export interface PortablePatchRetestProof {
  retestId: string
  verdict: 'reproduced' | 'fixed' | 'inconclusive'
  summary: string
  exchangeIds: string[]
  testedAt: string
}

export interface PortableReceiptRecord {
  findingId: string
  title: string
  severity: string
  cwe: string | null
  status: string
  origin: string
  replaySpecId: string | null
  proofKind: string | null
  proofRuntime: string | null
  proofScriptSha256: string | null
  receipt: ProofReceipt
  verification: {
    confirmed: boolean
    vulnClass: string
    rule: string
    reason: string
    observed: string
    expected: string
  }
  transcriptSlices: PortableTranscriptSlice[]
  reproducer: {
    vulnClass: string
    targetOrigin: string
    steps: PortableReproducerStep[]
    commandHint: string
  }
  patchRetests: PortablePatchRetestProof[]
  recordSha256: string
}

export interface ProofReceiptExportPayload {
  schemaVersion: 1
  exportedAt: string
  runId: string
  tenantId: string
  zdrRedacted: boolean
  receiptCount: number
  records: PortableReceiptRecord[]
  coverageGaps: CoverageGapReport
}

export interface SignedProofReceiptBundle {
  payload: ProofReceiptExportPayload
  payloadSha256: string
  algorithm: ReceiptBundleAlgorithm
  keyId?: string
  signature: string
}

export interface ExportRunReceiptOptions {
  /** When supplied, strictly enforces tenant isolation before reading run data. */
  tenantId?: string
  /** Scrub PII (emails, SSNs, cards, phones) in addition to credentials. Defaults to ZDR env setting. */
  zdr?: boolean
  /** Cryptographic signing configuration. Defaults to HMAC-SHA256 keyed by workspace session/env secret. */
  signing?: ReceiptBundleSignOptions
  /** Actor recorded in the append-only tenant audit log. */
  actor?: string
  now?: number
}

export interface VerifyProofReceiptBundleResult {
  valid: boolean
  reason?: string
  verifiedRecords: number
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function scrubText(value: string, secrets: readonly NamedSecret[], zdr: boolean): string {
  return zdr ? redactPii(value, { secrets }) : redact(value, secrets)
}

function scrubHeaders(headers: Record<string, string>, secrets: readonly NamedSecret[], zdr: boolean): Record<string, string> {
  const base = redactHeaders(headers, secrets)
  if (!zdr) return base
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(base)) {
    out[k] = redactPii(v, { secrets })
  }
  return out
}

function defaultSigningSecret(storage: Store): string {
  const fromEnv = (process.env.GUARDIAN_RECEIPT_SIGNING_KEY ?? '').trim()
  if (fromEnv.length >= 16) return fromEnv
  return createHash('sha256').update(`guardian.receipt-export.v1\0${storage.workspace.id}`).digest('hex')
}

function buildCommandHint(steps: readonly PortableReproducerStep[]): string {
  const primary = steps[steps.length - 1]
  if (!primary) return '# No HTTP exchange recorded for this receipt.'
  const authFlag = primary.personaHandle
    ? ` -H "Authorization: Bearer <token:${primary.personaHandle}>"`
    : ''
  return `curl -i -X ${primary.method}${authFlag} "${primary.origin}${primary.pathAndQuery}"`
}

function recordDigest(record: Omit<PortableReceiptRecord, 'recordSha256'>): string {
  return sha256Hex(`guardian.receipt-record.v1\n${canonicalJson(record)}`)
}

function payloadSigningBytes(payload: ProofReceiptExportPayload, payloadSha256: string): Buffer {
  return Buffer.from(`guardian.receipt-bundle.v1\n${payloadSha256}\n${canonicalJson(payload)}`, 'utf8')
}

/**
 * Build and cryptographically sign a portable JSON bundle of all confirmed ProofReceipts
 * (plus redacted transcripts, minimal reproducer metadata, patch-retest proofs, and honest
 * coverage gaps) for one run.
 */
export function exportRunReceiptBundle(
  storage: Store,
  runId: string,
  options: ExportRunReceiptOptions = {},
): SignedProofReceiptBundle {
  const run = storage.run(runId)
  const runTenant = storage.getRunTenant(run.id)
  if (options.tenantId !== undefined) {
    storage.assertRunTenantAccess(run.id, options.tenantId)
  }

  const zdr = options.zdr ?? isZdrModeEnabled()
  const nowMs = options.now ?? Date.now()
  const secrets = (() => {
    try {
      return personaSecrets(resolveRunPersonas(storage, run.projectId, run.approvedPersonaIds))
    } catch {
      return [] as NamedSecret[]
    }
  })()

  const findingRows = storage.db.select().from(findingsTable).where(eq(findingsTable.runId, run.id)).all()
  const specRows = storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, run.id)).all()
  const exchangeRows = storage.db.select().from(brokerExchanges).where(eq(brokerExchanges.runId, run.id)).all()
  const retestRows = storage.db.select().from(retestRuns)
    .where(eq(retestRuns.runId, run.id))
    .orderBy(desc(retestRuns.createdAt))
    .all()

  const specsById = new Map(specRows.map(s => [s.id, s]))
  const specsByFindingId = new Map(specRows.map(s => [s.findingId, s]))
  const exchangesById = new Map(exchangeRows.map(e => [e.id, e]))
  const retestsByFinding = new Map<string, typeof retestRows>()
  for (const rt of retestRows) {
    const arr = retestsByFinding.get(rt.findingId) ?? []
    arr.push(rt)
    retestsByFinding.set(rt.findingId, arr)
  }

  const records: PortableReceiptRecord[] = []
  const sortedFindings = [...findingRows].sort((a, b) => a.id.localeCompare(b.id))
  for (const row of sortedFindings) {
    const f = row.finding
    const specRow = (row.replaySpecId ? specsById.get(row.replaySpecId) : undefined) ?? specsByFindingId.get(row.id)
    const persistedReceipt = specRow?.proofReceipt
    if (f.status !== 'confirmed' && !persistedReceipt) continue

    const rawExchangeIds = persistedReceipt?.receipt.exchangeIds?.length
      ? persistedReceipt.receipt.exchangeIds
      : (f.exchangeIds ?? [])

    const receipt: ProofReceipt = persistedReceipt
      ? {
          vulnClass: persistedReceipt.receipt.vulnClass,
          target: {
            origin: persistedReceipt.receipt.target.origin,
            ...(persistedReceipt.receipt.target.method ? { method: persistedReceipt.receipt.target.method } : {}),
            ...(persistedReceipt.receipt.target.pathAndQuery
              ? { pathAndQuery: scrubText(persistedReceipt.receipt.target.pathAndQuery, secrets, zdr) }
              : {}),
            ...(persistedReceipt.receipt.target.param ? { param: persistedReceipt.receipt.target.param } : {}),
          },
          exchangeIds: [...persistedReceipt.receipt.exchangeIds],
          oobEventIds: [...persistedReceipt.receipt.oobEventIds],
          browserTraceIds: [...persistedReceipt.receipt.browserTraceIds],
          claimedDelta: scrubText(persistedReceipt.receipt.claimedDelta, secrets, zdr),
          ...(persistedReceipt.receipt.oracleEvents ? { oracleEvents: [...persistedReceipt.receipt.oracleEvents] } : {}),
          ...(persistedReceipt.receipt.resourceTenant ? { resourceTenant: persistedReceipt.receipt.resourceTenant } : {}),
          ...(persistedReceipt.receipt.expectControlDenied !== undefined
            ? { expectControlDenied: persistedReceipt.receipt.expectControlDenied }
            : {}),
        }
      : {
          vulnClass: f.category || 'unknown',
          target: { origin: f.origin },
          exchangeIds: [...rawExchangeIds],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: scrubText(f.reason || f.title, secrets, zdr),
        }

    const verification = persistedReceipt
      ? {
          confirmed: persistedReceipt.verification.confirmed,
          vulnClass: persistedReceipt.verification.vulnClass,
          rule: persistedReceipt.verification.rule,
          reason: scrubText(persistedReceipt.verification.reason, secrets, zdr),
          observed: scrubText(persistedReceipt.verification.observed, secrets, zdr),
          expected: scrubText(persistedReceipt.verification.expected, secrets, zdr),
        }
      : {
          confirmed: f.status === 'confirmed',
          vulnClass: receipt.vulnClass,
          rule: 'replay',
          reason: scrubText(f.verification ?? f.reason, secrets, zdr),
          observed: scrubText(f.check?.observed ?? f.reason, secrets, zdr),
          expected: scrubText(f.check?.expected ?? 'denied or safe control behavior', secrets, zdr),
        }

    const transcriptSlices: PortableTranscriptSlice[] = []
    const reproSteps: PortableReproducerStep[] = []
    for (const exId of new Set(rawExchangeIds)) {
      const ex = exchangesById.get(exId)
      if (!ex) continue
      const safePath = scrubText(ex.pathAndQuery, secrets, zdr)
      const safeReqHeaders = scrubHeaders(ex.reqHeaders, secrets, zdr)
      const safeRespHeaders = scrubHeaders(ex.respHeaders, secrets, zdr)
      const safePreview = scrubText(ex.bodyPreview.slice(0, 2048), secrets, zdr)
      transcriptSlices.push({
        exchangeId: ex.id,
        origin: ex.origin,
        finalOrigin: ex.finalOrigin,
        method: ex.method,
        pathAndQuery: safePath,
        personaHandle: ex.personaHandle,
        status: ex.status,
        mediaType: ex.mediaType,
        reqHeaders: safeReqHeaders,
        respHeaders: safeRespHeaders,
        bodyPreview: safePreview,
        bodySha256: ex.bodySha256,
        durationMs: ex.durationMs,
        capturedAt: new Date(ex.createdAt).toISOString(),
      })
      reproSteps.push({
        method: ex.method,
        origin: ex.origin,
        pathAndQuery: safePath,
        personaHandle: ex.personaHandle,
        headers: safeReqHeaders,
        observedStatus: ex.status,
      })
    }

    const patchRetests: PortablePatchRetestProof[] = (retestsByFinding.get(row.id) ?? []).map(rt => ({
      retestId: rt.id,
      verdict: rt.verdict,
      summary: scrubText(rt.summary, secrets, zdr),
      exchangeIds: [...rt.exchangeIds],
      testedAt: new Date(rt.createdAt).toISOString(),
    }))

    const baseRecord: Omit<PortableReceiptRecord, 'recordSha256'> = {
      findingId: row.id,
      title: scrubText(f.title, secrets, zdr),
      severity: f.severity,
      cwe: f.cwe ?? null,
      status: f.status,
      origin: f.origin,
      replaySpecId: specRow?.id ?? null,
      proofKind: specRow?.proofKind ?? null,
      proofRuntime: specRow?.proofRuntime ?? null,
      proofScriptSha256: specRow?.proofScriptSha256 ?? null,
      receipt,
      verification,
      transcriptSlices,
      reproducer: {
        vulnClass: receipt.vulnClass,
        targetOrigin: receipt.target.origin,
        steps: reproSteps,
        commandHint: buildCommandHint(reproSteps),
      },
      patchRetests,
    }
    records.push({
      ...baseRecord,
      recordSha256: recordDigest(baseRecord),
    })
  }

  const coverageGaps = buildCoverageGapReport(storage, run.id, { secrets, zdr, now: nowMs })
  const payload: ProofReceiptExportPayload = {
    schemaVersion: 1,
    exportedAt: new Date(nowMs).toISOString(),
    runId: run.id,
    tenantId: runTenant,
    zdrRedacted: zdr,
    receiptCount: records.length,
    records,
    coverageGaps,
  }
  const payloadSha256 = sha256Hex(canonicalJson(payload))
  const signing: ReceiptBundleSignOptions = options.signing ?? {
    algorithm: 'hmac-sha256',
    secret: defaultSigningSecret(storage),
    keyId: `workspace:${storage.workspace.id.slice(0, 8)}`,
  }
  const bytes = payloadSigningBytes(payload, payloadSha256)
  const signature = signing.algorithm === 'hmac-sha256'
    ? createHmac('sha256', signing.secret).update(bytes).digest('base64url')
    : cryptoSign(null, bytes, signing.privateKey).toString('base64url')

  storage.appendTenantAuditLog({
    tenantId: runTenant,
    runId: run.id,
    actor: options.actor ?? 'operator',
    action: 'receipt.exported',
    resourceKind: 'run',
    resourceId: run.id,
    outcome: 'exported',
    detail: { receiptCount: records.length, zdrRedacted: zdr, algorithm: signing.algorithm },
    now: nowMs,
  })

  return {
    payload,
    payloadSha256,
    algorithm: signing.algorithm,
    ...(signing.keyId ? { keyId: signing.keyId } : {}),
    signature,
  }
}

/**
 * Independently verify a portable `SignedProofReceiptBundle` — checks every record SHA-256,
 * the bundle payload SHA-256, and the cryptographic signature (HMAC-SHA256 or Ed25519).
 */
export function verifyProofReceiptBundle(
  bundle: unknown,
  options: ReceiptBundleVerifyOptions,
): VerifyProofReceiptBundleResult {
  if (!bundle || typeof bundle !== 'object') {
    return { valid: false, reason: 'Receipt bundle must be a JSON object.', verifiedRecords: 0 }
  }
  const candidate = bundle as Partial<SignedProofReceiptBundle>
  if (
    !candidate.payload ||
    typeof candidate.payload !== 'object' ||
    candidate.payload.schemaVersion !== 1 ||
    !Array.isArray(candidate.payload.records) ||
    typeof candidate.payloadSha256 !== 'string' ||
    typeof candidate.signature !== 'string' ||
    (candidate.algorithm !== 'hmac-sha256' && candidate.algorithm !== 'ed25519')
  ) {
    return { valid: false, reason: 'Receipt bundle is malformed.', verifiedRecords: 0 }
  }
  if (options.algorithm && candidate.algorithm !== options.algorithm) {
    return { valid: false, reason: `Bundle algorithm "${candidate.algorithm}" does not match expected "${options.algorithm}".`, verifiedRecords: 0 }
  }

  const computedPayloadHash = sha256Hex(canonicalJson(candidate.payload))
  if (computedPayloadHash !== candidate.payloadSha256) {
    return { valid: false, reason: 'Bundle payload SHA-256 mismatch (payload was modified).', verifiedRecords: 0 }
  }

  for (const rec of candidate.payload.records) {
    const { recordSha256, ...rest } = rec
    const expectedRecHash = recordDigest(rest)
    if (expectedRecHash !== recordSha256) {
      return { valid: false, reason: `Record SHA-256 mismatch for finding ${rec.findingId}.`, verifiedRecords: 0 }
    }
  }

  const providedSig = Buffer.from(candidate.signature, 'base64url')
  if (providedSig.length === 0) {
    return { valid: false, reason: 'Bundle signature is empty.', verifiedRecords: 0 }
  }
  const bytes = payloadSigningBytes(candidate.payload, candidate.payloadSha256)
  if (candidate.algorithm === 'hmac-sha256') {
    if (!options.secret) {
      return { valid: false, reason: 'HMAC secret is required to verify receipt bundle.', verifiedRecords: 0 }
    }
    const expectedSig = createHmac('sha256', options.secret).update(bytes).digest()
    if (expectedSig.length !== providedSig.length || !timingSafeEqual(expectedSig, providedSig)) {
      return { valid: false, reason: 'Bundle HMAC signature verification failed.', verifiedRecords: 0 }
    }
  } else {
    if (!options.publicKey) {
      return { valid: false, reason: 'Ed25519 public key is required to verify receipt bundle.', verifiedRecords: 0 }
    }
    let ok = false
    try {
      ok = cryptoVerify(null, bytes, options.publicKey, providedSig)
    } catch {
      ok = false
    }
    if (!ok) {
      return { valid: false, reason: 'Bundle Ed25519 signature verification failed.', verifiedRecords: 0 }
    }
  }

  return { valid: true, verifiedRecords: candidate.payload.records.length }
}
