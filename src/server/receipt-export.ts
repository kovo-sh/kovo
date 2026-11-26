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
import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, timingSafeEqual, verify as cryptoVerify } from 'node:crypto'
import type { KeyLike, KeyObject } from 'node:crypto'
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { desc, eq } from 'drizzle-orm'
import { CAUSAL_EDGE_KINDS, REPLAY_MODES, compositeProofReceiptSchema } from './composite-receipt.ts'
import type {
  CausalEdgeBinding,
  CausalEdgeKind,
  CompositeProofReceipt,
  CompositeReceiptVerification,
  HopReceipt,
  HopSurface,
  ReplayMode,
} from './composite-receipt.ts'
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
  receipt: ProofReceipt | null
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

export interface CompositeReceiptExportInput {
  findingId?: string | null
  title?: string | null
  severity?: string | null
  cwe?: string | null
  receipt: CompositeProofReceipt
  verification?: Partial<Pick<CompositeReceiptVerification, 'confirmed' | 'modeBVerified' | 'reason' | 'verifiedEdges'>>
  /** Optional actor persona handles keyed by hopId when known outside broker_exchanges. */
  hopActors?: Readonly<Record<string, string | null>>
  /** Optional hopId where a post-patch DAG retest broke the chain. */
  patchBrokeHopId?: string | null
  /** Optional post-patch retest verdict if retested. */
  patchRetestVerdict?: 'reproduced' | 'fixed' | 'inconclusive' | null
}

export interface PortableCompositeHopSummary {
  hopId: string
  order: number
  surface: HopSurface
  actor: string | null
  origin: string
  method: string | null
  pathAndQuery: string | null
  param: string | null
  claimedDelta: string
  exchangeIds: string[]
  oobEventIds: string[]
  browserTraceIds: string[]
  producedCapabilities: string[]
  consumedCapabilities: string[]
  entityId: string | null
}

export interface PortableCompositeEdgeBinding {
  kind: CausalEdgeKind
  fromHopId: string
  toHopId: string
  verified: boolean | null
  bindingDetail: {
    capabilityHandle?: string
    valueDigest?: string
    sourceExchangeId?: string
    targetExchangeId?: string
    sourceCapabilityId?: string
    derivedCapabilityId?: string
    alg?: string
    entityId?: string
    ablationExchangeIds?: string[]
    mutationKind?: string
    correlationId?: string
    channel?: 'poll_convergence' | 'oob_relay' | 'browser_trace' | 'async_job'
    oobEventId?: string
    browserTraceId?: string
    pollRecordId?: string
  }
}

export interface PortableCompositeReceiptRecord {
  chainId: string
  findingId: string | null
  title: string | null
  severity: string | null
  cwe: string | null
  terminalVulnClass: string
  replayMode: ReplayMode
  confirmed: boolean
  modeBVerified: boolean
  verificationReason: string | null
  hopCount: number
  hops: PortableCompositeHopSummary[]
  causalEdges: PortableCompositeEdgeBinding[]
  terminalImpact: {
    terminalHopId: string
    claimedImpact: string
    preChainControlExchangeIds: string[]
    postChainReadbackExchangeIds: string[]
    modeAFailureExchangeId: string | null
  }
  patchBrokeHopId: string | null
  patchRetestVerdict: 'reproduced' | 'fixed' | 'inconclusive' | null
  transcriptSlices: PortableTranscriptSlice[]
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
  compositeReceipts?: PortableCompositeReceiptRecord[]
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
  /** Optional multi-hop CompositeProofReceipt records to bundle alongside single-hop receipts. */
  compositeReceipts?: readonly CompositeReceiptExportInput[]
  now?: number
}

export interface VerifyProofReceiptBundleResult {
  valid: boolean
  reason?: string
  verifiedRecords: number
  verifiedCompositeRecords?: number
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

const RECEIPT_SIGNING_KEY_FILE = 'receipt-signing.ed25519.pem'
const RECEIPT_SIGNING_PUB_FILE = 'receipt-signing.ed25519.pub.pem'

export interface ReceiptSigningKeyPair {
  privateKey: KeyObject
  publicKey: KeyObject
  keyId: string
  privateKeyPath: string
  publicKeyPath: string
}

function ed25519KeyId(publicKey: KeyObject): string {
  const der = publicKey.export({ type: 'spki', format: 'der' })
  return `ed25519:${createHash('sha256').update(der).digest('hex').slice(0, 16)}`
}

function readValidatedReceiptSigningKey(privateKeyPath: string, publicKeyPath: string): ReceiptSigningKeyPair {
  const st = lstatSync(privateKeyPath)
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error('Receipt signing private key must be a regular file.')
  }
  if ((st.mode & 0o077) !== 0) {
    throw new Error('Receipt signing private key must have owner-only (0600) permissions.')
  }
  const pem = readFileSync(privateKeyPath, 'utf8')
  const privateKey = createPrivateKey(pem)
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('Receipt signing private key must be an Ed25519 key.')
  }
  const publicKey = createPublicKey(privateKey)
  if (!existsSync(publicKeyPath)) {
    try {
      const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
      writeFileSync(publicKeyPath, publicPem, { mode: 0o644 })
    } catch { /* best-effort convenience export */ }
  }
  return {
    privateKey,
    publicKey,
    keyId: ed25519KeyId(publicKey),
    privateKeyPath,
    publicKeyPath,
  }
}

/**
 * Load or generate a random workspace Ed25519 signing keypair persisted with strict `0600`
 * permissions under `<KOVO_DATA_DIR>/credentials/` (M-23). Never derives signing keys from
 * workspace UUIDs or other public identifiers.
 */
export function loadOrCreateReceiptSigningKeyPair(storage: Store): ReceiptSigningKeyPair {
  const credDir = join(storage.directory, 'credentials')
  mkdirSync(credDir, { recursive: true, mode: 0o700 })
  chmodSync(credDir, 0o700)
  const privateKeyPath = join(credDir, RECEIPT_SIGNING_KEY_FILE)
  const publicKeyPath = join(credDir, RECEIPT_SIGNING_PUB_FILE)

  if (existsSync(privateKeyPath)) {
    return readValidatedReceiptSigningKey(privateKeyPath, publicKeyPath)
  }

  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  try {
    writeFileSync(privateKeyPath, privatePem, { mode: 0o600, flag: 'wx' })
    chmodSync(privateKeyPath, 0o600)
  } catch (err) {
    if ((err as { code?: string }).code === 'EEXIST') {
      return readValidatedReceiptSigningKey(privateKeyPath, publicKeyPath)
    }
    throw err
  }
  writeFileSync(publicKeyPath, publicPem, { mode: 0o644 })
  return {
    privateKey,
    publicKey,
    keyId: ed25519KeyId(publicKey),
    privateKeyPath,
    publicKeyPath,
  }
}

/** Return the workspace's Ed25519 public key for verifying default-signed receipt bundles. */
export function getReceiptSigningPublicKey(storage: Store): KeyObject {
  return loadOrCreateReceiptSigningKeyPair(storage).publicKey
}

function resolveDefaultSigningOptions(storage: Store): ReceiptBundleSignOptions {
  const fromEnv = (process.env.KOVO_RECEIPT_SIGNING_KEY ?? '').trim()
  if (fromEnv.length >= 16) {
    if (fromEnv.startsWith('-----BEGIN ')) {
      const privateKey = createPrivateKey(fromEnv)
      if (privateKey.asymmetricKeyType !== 'ed25519') {
        throw new Error('KOVO_RECEIPT_SIGNING_KEY PEM must be an Ed25519 private key.')
      }
      const publicKey = createPublicKey(privateKey)
      return { algorithm: 'ed25519', privateKey, keyId: ed25519KeyId(publicKey) }
    }
    return { algorithm: 'hmac-sha256', secret: fromEnv, keyId: 'env:kovo-receipt-signing-key' }
  }
  const pair = loadOrCreateReceiptSigningKeyPair(storage)
  return { algorithm: 'ed25519', privateKey: pair.privateKey, keyId: pair.keyId }
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
  return sha256Hex(`kovo.receipt-record.v1\n${canonicalJson(record)}`)
}

function compositeRecordDigest(record: Omit<PortableCompositeReceiptRecord, 'recordSha256'>): string {
  return sha256Hex(`kovo.composite-receipt-record.v1\n${canonicalJson(record)}`)
}

const VALID_EDGE_KINDS = new Set<string>(CAUSAL_EDGE_KINDS)
const VALID_REPLAY_MODES = new Set<string>(REPLAY_MODES)

/** Deterministic topological hop ordering for DAG export, Markdown, and SARIF codeFlows. */
export function orderCompositeHops(receipt: CompositeProofReceipt): HopReceipt[] {
  const indexById = new Map<string, number>()
  const hopsById = new Map<string, HopReceipt>()
  for (let i = 0; i < receipt.hops.length; i += 1) {
    const hop = receipt.hops[i]!
    indexById.set(hop.hopId, i)
    hopsById.set(hop.hopId, hop)
  }
  const inDeg = new Map<string, number>(receipt.hops.map(h => [h.hopId, 0]))
  const outAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  for (const edge of receipt.causalEdges) {
    if (!hopsById.has(edge.fromHopId) || !hopsById.has(edge.toHopId) || edge.fromHopId === edge.toHopId) continue
    outAdj.get(edge.fromHopId)!.push(edge.toHopId)
    inDeg.set(edge.toHopId, (inDeg.get(edge.toHopId) ?? 0) + 1)
  }

  const ready = receipt.hops
    .filter(h => (inDeg.get(h.hopId) ?? 0) === 0)
    .map(h => h.hopId)
  const ordered: HopReceipt[] = []
  const visited = new Set<string>()
  while (ready.length > 0) {
    ready.sort((a, b) => (indexById.get(a) ?? 0) - (indexById.get(b) ?? 0))
    const id = ready.shift()!
    if (visited.has(id)) continue
    visited.add(id)
    const hop = hopsById.get(id)
    if (hop) ordered.push(hop)
    for (const next of outAdj.get(id) ?? []) {
      const rem = (inDeg.get(next) ?? 0) - 1
      inDeg.set(next, rem)
      if (rem === 0 && !visited.has(next)) ready.push(next)
    }
  }
  for (const hop of receipt.hops) {
    if (!visited.has(hop.hopId)) ordered.push(hop)
  }
  return ordered
}

export function isPortableCompositeReceiptRecord(value: unknown): value is PortableCompositeReceiptRecord {
  if (!value || typeof value !== 'object') return false
  const obj = value as Record<string, unknown>
  return (
    typeof obj.chainId === 'string' &&
    typeof obj.terminalVulnClass === 'string' &&
    typeof obj.recordSha256 === 'string' &&
    Array.isArray(obj.hops) &&
    Array.isArray(obj.causalEdges) &&
    !!obj.terminalImpact &&
    typeof obj.terminalImpact === 'object'
  )
}

function scrubCausalEdgeBinding(
  edge: CausalEdgeBinding,
  verified: boolean | null,
  secrets: readonly NamedSecret[],
  zdr: boolean,
): PortableCompositeEdgeBinding {
  if (edge.kind === 'value_binding') {
    return {
      kind: edge.kind,
      fromHopId: edge.fromHopId,
      toHopId: edge.toHopId,
      verified,
      bindingDetail: {
        ...(edge.capabilityHandle ? { capabilityHandle: scrubText(edge.capabilityHandle, secrets, zdr) } : {}),
        ...(edge.valueDigest ? { valueDigest: edge.valueDigest.toLowerCase() } : {}),
        ...(edge.sourceExchangeId ? { sourceExchangeId: edge.sourceExchangeId } : {}),
        ...(edge.targetExchangeId ? { targetExchangeId: edge.targetExchangeId } : {}),
      },
    }
  }
  if (edge.kind === 'derived_crypto_binding') {
    return {
      kind: edge.kind,
      fromHopId: edge.fromHopId,
      toHopId: edge.toHopId,
      verified,
      bindingDetail: {
        sourceCapabilityId: scrubText(edge.sourceCapabilityId, secrets, zdr),
        ...(edge.derivedCapabilityId ? { derivedCapabilityId: scrubText(edge.derivedCapabilityId, secrets, zdr) } : {}),
        ...(edge.alg ? { alg: scrubText(edge.alg, secrets, zdr) } : {}),
      },
    }
  }
  if (edge.kind === 'state_transition_binding') {
    return {
      kind: edge.kind,
      fromHopId: edge.fromHopId,
      toHopId: edge.toHopId,
      verified,
      bindingDetail: {
        entityId: scrubText(edge.entityId, secrets, zdr),
        ablationExchangeIds: [...edge.ablationExchangeIds],
        ...(edge.mutationKind ? { mutationKind: scrubText(edge.mutationKind, secrets, zdr) } : {}),
      },
    }
  }
  return {
    kind: edge.kind,
    fromHopId: edge.fromHopId,
    toHopId: edge.toHopId,
    verified,
    bindingDetail: {
      correlationId: scrubText(edge.correlationId, secrets, zdr),
      channel: edge.channel,
      ...(edge.oobEventId ? { oobEventId: edge.oobEventId } : {}),
      ...(edge.browserTraceId ? { browserTraceId: edge.browserTraceId } : {}),
      ...(edge.pollRecordId ? { pollRecordId: edge.pollRecordId } : {}),
    },
  }
}

export interface BuildPortableCompositeContext {
  secrets?: readonly NamedSecret[]
  zdr?: boolean
  exchangesById?: ReadonlyMap<string, typeof brokerExchanges.$inferSelect>
}

/**
 * Normalize, redact (with optional ZDR/PII scrubbing), and digest a `CompositeProofReceipt`
 * into a self-contained `PortableCompositeReceiptRecord`.
 */
export function buildPortableCompositeReceiptRecord(
  input: CompositeReceiptExportInput,
  ctx: BuildPortableCompositeContext = {},
): PortableCompositeReceiptRecord {
  const secrets = ctx.secrets ?? []
  const zdr = ctx.zdr === true
  const exchangesById = ctx.exchangesById
  const receipt = input.receipt
  const orderedHops = orderCompositeHops(receipt)

  const verifiedEdgeByKey = new Map<string, boolean>()
  for (const ve of input.verification?.verifiedEdges ?? []) {
    verifiedEdgeByKey.set(`${ve.fromHopId}->${ve.toHopId}:${ve.kind}`, ve.verified)
  }

  const citedExchangeIds = new Set<string>()
  const hops: PortableCompositeHopSummary[] = orderedHops.map((hop, idx) => {
    for (const exId of hop.exchangeIds) citedExchangeIds.add(exId)
    let rawActor: string | null = input.hopActors?.[hop.hopId] ?? null
    if (rawActor === null && exchangesById) {
      for (const exId of hop.exchangeIds) {
        const ex = exchangesById.get(exId)
        if (ex?.personaHandle) {
          rawActor = ex.personaHandle
          break
        }
      }
    }
    return {
      hopId: hop.hopId,
      order: idx + 1,
      surface: hop.surface,
      actor: rawActor !== null ? scrubText(rawActor, secrets, zdr) : null,
      origin: hop.target.origin,
      method: hop.target.method ?? null,
      pathAndQuery: hop.target.pathAndQuery ? scrubText(hop.target.pathAndQuery, secrets, zdr) : null,
      param: hop.target.param ? scrubText(hop.target.param, secrets, zdr) : null,
      claimedDelta: scrubText(hop.claimedDelta, secrets, zdr),
      exchangeIds: [...hop.exchangeIds],
      oobEventIds: [...hop.oobEventIds],
      browserTraceIds: [...hop.browserTraceIds],
      producedCapabilities: hop.producedCapabilities.map(c => scrubText(c, secrets, zdr)),
      consumedCapabilities: hop.consumedCapabilities.map(c => scrubText(c, secrets, zdr)),
      entityId: hop.entityId ? scrubText(hop.entityId, secrets, zdr) : null,
    }
  })

  const causalEdges: PortableCompositeEdgeBinding[] = receipt.causalEdges.map(edge => {
    if (edge.kind === 'state_transition_binding') {
      for (const abId of edge.ablationExchangeIds) citedExchangeIds.add(abId)
    }
    const key = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
    const verified = verifiedEdgeByKey.has(key) ? (verifiedEdgeByKey.get(key) ?? null) : null
    return scrubCausalEdgeBinding(edge, verified, secrets, zdr)
  })

  for (const exId of receipt.terminalImpact.preChainControlExchangeIds) citedExchangeIds.add(exId)
  for (const exId of receipt.terminalImpact.postChainReadbackExchangeIds) citedExchangeIds.add(exId)
  if (receipt.terminalImpact.modeAFailureExchangeId) citedExchangeIds.add(receipt.terminalImpact.modeAFailureExchangeId)

  const transcriptSlices: PortableTranscriptSlice[] = []
  if (exchangesById) {
    for (const exId of citedExchangeIds) {
      const ex = exchangesById.get(exId)
      if (!ex) continue
      transcriptSlices.push({
        exchangeId: ex.id,
        origin: ex.origin,
        finalOrigin: ex.finalOrigin,
        method: ex.method,
        pathAndQuery: scrubText(ex.pathAndQuery, secrets, zdr),
        personaHandle: ex.personaHandle ? scrubText(ex.personaHandle, secrets, zdr) : null,
        status: ex.status,
        mediaType: ex.mediaType,
        reqHeaders: scrubHeaders(ex.reqHeaders, secrets, zdr),
        respHeaders: scrubHeaders(ex.respHeaders, secrets, zdr),
        bodyPreview: scrubText(ex.bodyPreview.slice(0, 2048), secrets, zdr),
        bodySha256: ex.bodySha256,
        durationMs: ex.durationMs,
        capturedAt: new Date(ex.createdAt).toISOString(),
      })
    }
  }

  const baseRecord: Omit<PortableCompositeReceiptRecord, 'recordSha256'> = {
    chainId: receipt.chainId,
    findingId: input.findingId ?? null,
    title: input.title ? scrubText(input.title, secrets, zdr) : null,
    severity: input.severity ?? null,
    cwe: input.cwe ?? null,
    terminalVulnClass: receipt.terminalVulnClass,
    replayMode: receipt.replayMode,
    confirmed: input.verification?.confirmed ?? false,
    modeBVerified: input.verification?.modeBVerified ?? (receipt.replayMode === 'one_shot_transcript'),
    verificationReason: input.verification?.reason ? scrubText(input.verification.reason, secrets, zdr) : null,
    hopCount: hops.length,
    hops,
    causalEdges,
    terminalImpact: {
      terminalHopId: receipt.terminalImpact.terminalHopId,
      claimedImpact: scrubText(receipt.terminalImpact.claimedImpact, secrets, zdr),
      preChainControlExchangeIds: [...receipt.terminalImpact.preChainControlExchangeIds],
      postChainReadbackExchangeIds: [...receipt.terminalImpact.postChainReadbackExchangeIds],
      modeAFailureExchangeId: receipt.terminalImpact.modeAFailureExchangeId ?? null,
    },
    patchBrokeHopId: input.patchBrokeHopId ? scrubText(input.patchBrokeHopId, secrets, zdr) : null,
    patchRetestVerdict: input.patchRetestVerdict ?? null,
    transcriptSlices,
  }

  return {
    ...baseRecord,
    recordSha256: compositeRecordDigest(baseRecord),
  }
}

const PATCH_BROKE_HOP_RE = /\bpatchBrokeHopId\s*[:=]\s*["']?([A-Za-z0-9._:-]{1,128})["']?/i

/**
 * Best-effort extraction of persisted `CompositeProofReceipt` records from `replaySpecs` and
 * matching `retestRuns` (e.g., `patchBrokeHopId`) without requiring schema migrations.
 */
export function extractStoreCompositeReceipts(
  specRows: ReadonlyArray<typeof replaySpecs.$inferSelect>,
  retestRows: ReadonlyArray<typeof retestRuns.$inferSelect> = [],
  findingsById?: ReadonlyMap<string, { title?: string; severity?: string; cwe?: string | null }>,
): CompositeReceiptExportInput[] {
  const retestsByFinding = new Map<string, Array<typeof retestRuns.$inferSelect>>()
  for (const rt of retestRows) {
    const arr = retestsByFinding.get(rt.findingId) ?? []
    arr.push(rt)
    retestsByFinding.set(rt.findingId, arr)
  }

  const extracted: CompositeReceiptExportInput[] = []
  for (const specRow of specRows) {
    const rawProof = specRow.proofReceipt as unknown
    if (!rawProof || typeof rawProof !== 'object') continue
    const obj = rawProof as Record<string, unknown>
    const candidate = obj.compositeReceipt ?? (Array.isArray(obj.hops) && typeof obj.chainId === 'string' ? obj : undefined)
    if (!candidate) continue
    const parsed = compositeProofReceiptSchema.safeParse(candidate)
    if (!parsed.success) continue

    const findingMeta = findingsById?.get(specRow.findingId)
    const latestRetest = (retestsByFinding.get(specRow.findingId) ?? [])[0]
    let patchBrokeHopId: string | null = typeof obj.patchBrokeHopId === 'string' ? obj.patchBrokeHopId : null
    if (!patchBrokeHopId && latestRetest) {
      const rtAny = latestRetest as unknown as Record<string, unknown>
      if (typeof rtAny.patchBrokeHopId === 'string' && rtAny.patchBrokeHopId.trim()) {
        patchBrokeHopId = rtAny.patchBrokeHopId.trim()
      } else {
        const match = PATCH_BROKE_HOP_RE.exec(latestRetest.summary)
        if (match?.[1]) patchBrokeHopId = match[1]
      }
    }
    const rawVer = obj.compositeVerification as CompositeReceiptExportInput['verification'] | undefined
    const hopActors = (obj.hopActors && typeof obj.hopActors === 'object')
      ? obj.hopActors as Record<string, string | null>
      : undefined

    extracted.push({
      findingId: specRow.findingId,
      title: findingMeta?.title ?? null,
      severity: findingMeta?.severity ?? null,
      cwe: findingMeta?.cwe ?? null,
      receipt: parsed.data,
      ...(rawVer ? { verification: rawVer } : {}),
      ...(hopActors ? { hopActors } : {}),
      ...(patchBrokeHopId ? { patchBrokeHopId } : {}),
      ...(latestRetest ? { patchRetestVerdict: latestRetest.verdict } : {}),
    })
  }
  return extracted
}

function payloadSigningBytes(
  payload: ProofReceiptExportPayload,
  payloadSha256: string,
  envelope: { algorithm: ReceiptBundleAlgorithm; keyId?: string | null },
): Buffer {
  return Buffer.from(
    `kovo.receipt-bundle.v2\n${envelope.algorithm}\n${envelope.keyId ?? ''}\n${payloadSha256}\n${canonicalJson(payload)}`,
    'utf8',
  )
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

    const receipt: ProofReceipt | null = persistedReceipt
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
      : null

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
          confirmed: false,
          vulnClass: f.category || 'unknown',
          rule: 'legacy_unreceipted',
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
        vulnClass: receipt?.vulnClass ?? (f.category || 'unknown'),
        targetOrigin: receipt?.target.origin ?? f.origin,
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

  const findingsMetaById = new Map(
    findingRows.map(row => [row.id, { title: row.finding.title, severity: row.finding.severity, cwe: row.finding.cwe ?? null }]),
  )
  const compositeInputByChain = new Map<string, CompositeReceiptExportInput>()
  for (const extracted of extractStoreCompositeReceipts(specRows, retestRows, findingsMetaById)) {
    compositeInputByChain.set(extracted.receipt.chainId, extracted)
  }
  for (const supplied of options.compositeReceipts ?? []) {
    compositeInputByChain.set(supplied.receipt.chainId, supplied)
  }
  const compositeReceipts: PortableCompositeReceiptRecord[] = [...compositeInputByChain.values()]
    .map(item => buildPortableCompositeReceiptRecord(item, { secrets, zdr, exchangesById }))
    .sort((a, b) => a.chainId.localeCompare(b.chainId))

  const coverageGaps = buildCoverageGapReport(storage, run.id, { secrets, zdr, now: nowMs })
  const payload: ProofReceiptExportPayload = {
    schemaVersion: 1,
    exportedAt: new Date(nowMs).toISOString(),
    runId: run.id,
    tenantId: runTenant,
    zdrRedacted: zdr,
    receiptCount: records.length,
    records,
    ...(compositeReceipts.length > 0 ? { compositeReceipts } : {}),
    coverageGaps,
  }
  const payloadSha256 = sha256Hex(canonicalJson(payload))
  const signing: ReceiptBundleSignOptions = options.signing ?? resolveDefaultSigningOptions(storage)
  const bytes = payloadSigningBytes(payload, payloadSha256, {
    algorithm: signing.algorithm,
    keyId: signing.keyId ?? null,
  })
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
    detail: {
      receiptCount: records.length,
      ...(compositeReceipts.length > 0 ? { compositeReceiptCount: compositeReceipts.length } : {}),
      zdrRedacted: zdr,
      algorithm: signing.algorithm,
    },
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
 * Independently verify a portable `SignedProofReceiptBundle` — checks every single-hop and
 * composite record SHA-256, the bundle payload SHA-256, and the cryptographic signature
 * (HMAC-SHA256 or Ed25519).
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
    (candidate.keyId !== undefined && typeof candidate.keyId !== 'string') ||
    (candidate.algorithm !== 'hmac-sha256' && candidate.algorithm !== 'ed25519')
  ) {
    return { valid: false, reason: 'Receipt bundle is malformed.', verifiedRecords: 0 }
  }
  if (
    typeof candidate.payload.receiptCount !== 'number'
    || !Number.isInteger(candidate.payload.receiptCount)
    || candidate.payload.receiptCount !== candidate.payload.records.length
  ) {
    return {
      valid: false,
      reason: `Bundle receiptCount (${String(candidate.payload.receiptCount)}) does not match records.length (${candidate.payload.records.length}).`,
      verifiedRecords: 0,
    }
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

  const rawComposites = candidate.payload.compositeReceipts
  if (rawComposites !== undefined) {
    if (!Array.isArray(rawComposites)) {
      return { valid: false, reason: 'Composite receipts field is malformed.', verifiedRecords: 0 }
    }
    for (const comp of rawComposites) {
      if (!isPortableCompositeReceiptRecord(comp) || !VALID_REPLAY_MODES.has(comp.replayMode)) {
        return { valid: false, reason: 'Composite receipt record is malformed.', verifiedRecords: 0 }
      }
      for (const edge of comp.causalEdges) {
        if (!edge || typeof edge !== 'object' || !VALID_EDGE_KINDS.has(edge.kind)) {
          return { valid: false, reason: `Composite receipt ${comp.chainId} contains an invalid causal edge kind.`, verifiedRecords: 0 }
        }
      }
      const { recordSha256, ...rest } = comp
      const expectedCompHash = compositeRecordDigest(rest)
      if (expectedCompHash !== recordSha256) {
        return { valid: false, reason: `Composite receipt SHA-256 mismatch for chain ${comp.chainId}.`, verifiedRecords: 0 }
      }
    }
  }

  const providedSig = Buffer.from(candidate.signature, 'base64url')
  if (providedSig.length === 0) {
    return { valid: false, reason: 'Bundle signature is empty.', verifiedRecords: 0 }
  }
  const bytes = payloadSigningBytes(candidate.payload, candidate.payloadSha256, {
    algorithm: candidate.algorithm,
    keyId: candidate.keyId ?? null,
  })
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

  return rawComposites !== undefined
    ? {
        valid: true,
        verifiedRecords: candidate.payload.records.length,
        verifiedCompositeRecords: rawComposites.length,
      }
    : { valid: true, verifiedRecords: candidate.payload.records.length }
}
