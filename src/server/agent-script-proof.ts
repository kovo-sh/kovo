/**
 * Unified agent-script proof execution and retest (v7 M5 + v8 CompositeProofReceipt).
 *
 * One place that runs a Layer-3 `guardian_verify` script for both live execution and patch retest:
 * every attempt opens a real worker session with the attempt's RPC directory mounted, shares an
 * optional run-scoped `DerivedCapabilityVault`, and captures both single-hop `ProofReceipt`s and
 * multi-hop `CompositeProofReceipt`s without monkey-patching `VerifyRpcServer`.
 */
import { createHash } from 'node:crypto'
import { agentScriptProofEnvelopeSchema } from '../replay-spec.ts'
import type { AgentScriptProofEnvelope } from '../replay-spec.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import {
  compositeProofReceiptSchema,
  type CompositeProofReceipt,
  type CompositeReceiptVerification,
  type CompositeVerifyOptions,
  type HostSignedTranscript,
} from './composite-receipt.ts'
import { DerivedCapabilityVault, scrubDerivedSecrets, type DerivedCapabilityMeta } from './derived-custody.ts'
import { buildAgentScriptReceipt, verifyReceipt } from './proof-receipt.ts'
import type { ProofReceipt, ReceiptVerification, ScriptProofExchange } from './proof-receipt.ts'
import {
  TranscriptStore,
  VerifyRpcServer,
  verifyScript,
  type VerifyAttemptSession,
  type VerifyTranscriptRecord,
  type VerifyVerdict,
} from './verify-rpc.ts'
import type { WorkerBackend } from './worker-backend.ts'
import type { ReplayVerificationResult, RetestReplayResult, VerifyReplaySpecParams } from './replay-verifier.ts'

export function persistedAgentScriptOf(spec: unknown): { envelope: AgentScriptProofEnvelope; origin: string } | null {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return null
  const record = spec as Record<string, unknown>
  const parsed = agentScriptProofEnvelopeSchema.safeParse(record.agentScript)
  if (!parsed.success) return null
  return { envelope: parsed.data, origin: typeof record.origin === 'string' ? record.origin : '' }
}

export interface V8CompositeProofBundle {
  receipt: CompositeProofReceipt
  verification: CompositeReceiptVerification
  hopActors: Record<string, string | null>
}

export interface AgentScriptProofParams {
  script: string
  runtime: 'ts' | 'python'
  title?: string
  broker: RequestBroker
  grant: Grant
  backend: WorkerBackend
  runId: string
  assignmentId: string
  targetOrigins: readonly string[]
  signal: AbortSignal
  timeoutMs?: number
  canaryBroker?: CanaryBroker
  /** Shared per-run Layer-1 DerivedCapabilityVault across worker sessions. */
  capabilityVault?: DerivedCapabilityVault
  /** Alias for `capabilityVault`. */
  v8Vault?: DerivedCapabilityVault
  /** Host-enforced composite receipt verification options. */
  compositeVerifyOptions?: Omit<CompositeVerifyOptions, 'signingKey'>
}

export interface AgentScriptProofResult {
  verdict: VerifyVerdict
  /** Host-recorded exchanges of the last passing attempt (empty when no attempt passed). */
  exchanges: ScriptProofExchange[]
  /** Present only when the claims map onto a single-hop receipt rule AND `verifyReceipt` confirms it. */
  receipt: { receipt: ProofReceipt; verification: ReceiptVerification } | null
  /** Present when the script submits a multi-hop `CompositeProofReceipt`. */
  compositeReceipt: V8CompositeProofBundle | null
  vulnClass: string | null
  transcriptDigests: string[]
  sealedCapabilities: DerivedCapabilityMeta[]
  transcriptRecords: VerifyTranscriptRecord[]
  hostTranscript: HostSignedTranscript | null
  /** Script-declared attribution (never evidence by itself). */
  claimTitle: string | null
  severity: string | null
  description: string | null
}

export function safeVaultRunId(runId: string): string {
  return /^[A-Za-z0-9._-]{1,128}$/.test(runId)
    ? runId
    : runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'run'
}

const REDACTED_CAP_PLACEHOLDER_RE = /^\[redacted:(cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+)\]$/
const guardedVaults = new WeakSet<DerivedCapabilityVault>()

/**
 * Prevent double-run / cross-worker re-sealing from overwriting a real derived secret with its own
 * Layer-1 redaction placeholder (`[redacted:cap:hop_<id>:<slot>]`).
 */
export function guardVaultAgainstPlaceholderReseal(vault: DerivedCapabilityVault): DerivedCapabilityVault {
  if (guardedVaults.has(vault)) return vault
  guardedVaults.add(vault)
  const origSeal = vault.seal.bind(vault)
  vault.seal = (input) => {
    const match = typeof input.rawValue === 'string'
      ? REDACTED_CAP_PLACEHOLDER_RE.exec(input.rawValue.trim())
      : null
    if (match?.[1]) {
      const existing = vault.getMeta(match[1])
      if (existing && vault.hasActive(existing.handle)) return existing
    }
    return origSeal(input)
  }
  return vault
}

function extractHopActors(receipt: CompositeProofReceipt, transcript: HostSignedTranscript): Record<string, string | null> {
  const byId = new Map((transcript.entries ?? []).map(entry => [entry.exchangeId, entry]))
  const actors: Record<string, string | null> = {}
  for (const hop of receipt.hops) {
    let persona: string | null = null
    for (const exId of hop.exchangeIds) {
      const entry = byId.get(exId)
      if (entry?.actorPersona) { persona = entry.actorPersona; break }
      if (entry?.step.actor.handle) { persona = entry.step.actor.handle; break }
    }
    actors[hop.hopId] = persona
  }
  return actors
}

function transcriptToScriptExchanges(transcript: TranscriptStore, vault: DerivedCapabilityVault): ScriptProofExchange[] {
  return transcript.list().flatMap(record => {
    if (record.op === 'oob' || record.op === 'browser') return []
    const request = record.request
    if (!request) return []
    const rawBody = transcript.body(record.exchangeId)
    const body = rawBody !== undefined ? scrubDerivedSecrets(rawBody, vault) : undefined
    return [{
      exchangeId: record.exchangeId,
      op: record.op,
      method: request.method,
      pathAndQuery: request.pathAndQuery,
      origin: request.origin,
      status: record.response?.status ?? null,
      durationMs: record.durationMs,
      personaHandle: request.personaHandle ?? null,
      sessionRole: request.sessionRole ?? null,
      actorRoleLabel: request.actorRoleLabel ?? null,
      ...(body !== undefined ? { body } : {}),
      requestHeaders: request.headers ?? null,
      responseHeaders: record.response?.headers ?? null,
    }]
  })
}

/** Subclass capturing host-verified CompositeProofReceipt bundles without instance monkey-patching. */
class CapturingVerifyRpcServer extends VerifyRpcServer {
  private readonly verifiedComposites: V8CompositeProofBundle[] = []

  override verifyComposite(
    rawReceipt: unknown,
    options?: Omit<CompositeVerifyOptions, 'signingKey'>,
  ): CompositeReceiptVerification {
    const verification = super.verifyComposite(rawReceipt, options)
    const parsed = compositeProofReceiptSchema.safeParse(rawReceipt)
    if (parsed.success) {
      const hostTranscript = this.buildHostSignedTranscript()
      this.verifiedComposites.push({
        receipt: parsed.data,
        verification,
        hopActors: extractHopActors(parsed.data, hostTranscript),
      })
    }
    return verification
  }

  getVerifiedComposites(): readonly V8CompositeProofBundle[] {
    return this.verifiedComposites
  }
}

export async function runAgentScriptProof(params: AgentScriptProofParams): Promise<AgentScriptProofResult> {
  const code = params.script.trim()
  if (!code) throw new Error('An agent proof script is required.')
  if (Buffer.byteLength(code) > 64 * 1024) throw new Error('The agent proof script exceeds the 64 KiB limit.')

  const vault = guardVaultAgainstPlaceholderReseal(
    params.capabilityVault ?? params.v8Vault ?? new DerivedCapabilityVault({ runId: safeVaultRunId(params.runId) }),
  )
  const handlesBefore = new Set(vault.list().map(meta => meta.handle))

  type AttemptCapture = {
    claims: Record<string, unknown>[]
    transcript: TranscriptStore
    hostTranscript: HostSignedTranscript | null
    composites: V8CompositeProofBundle[]
    title: string | null
    severity: string | null
    description: string | null
  }
  const attempts = new Map<1 | 2, AttemptCapture>()

  const openAttempt = async (input: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const server = new CapturingVerifyRpcServer({
      broker: params.broker,
      grant: params.grant,
      runId: params.runId,
      assignmentId: params.assignmentId,
      nonce: input.nonce,
      targetOrigins: [...params.targetOrigins],
      capabilityVault: vault,
      ...(params.canaryBroker ? { canary: params.canaryBroker } : {}),
      ...(params.compositeVerifyOptions ? { compositeVerifyOptions: params.compositeVerifyOptions } : {}),
    })
    await server.start()
    let session: Awaited<ReturnType<WorkerBackend['openSession']>>
    try {
      session = await params.backend.openSession(
        `${params.assignmentId}-verify-${input.attempt}`,
        params.signal,
        { rpcMountDir: server.hostDir },
      )
    } catch (error) {
      await server.close().catch(() => undefined)
      throw error
    }
    const verify = session.verifyScript
    if (!verify) {
      await session.close().catch(() => undefined)
      await server.close().catch(() => undefined)
      throw new Error('This worker backend cannot execute Layer-3 verification scripts.')
    }
    return {
      nonce: input.nonce,
      transcript: server.transcript,
      async execute(candidate, signal) {
        const execution = await verify({
          runtime: candidate.runtime,
          code: candidate.code,
          nonce: input.nonce,
          ...(params.timeoutMs ? { timeoutMs: params.timeoutMs } : {}),
        }, signal)
        const resObj = execution.result && typeof execution.result === 'object' && !Array.isArray(execution.result)
          ? execution.result as Record<string, unknown>
          : {}
        if (server.getVerifiedComposites().length === 0) {
          const directComposite = resObj.compositeReceipt ?? resObj.compositeProofReceipt
          if (directComposite && typeof directComposite === 'object') {
            server.verifyComposite(directComposite)
          }
        }
        const claims = Array.isArray(resObj.claims)
          ? resObj.claims.filter((claim): claim is Record<string, unknown> => Boolean(claim) && typeof claim === 'object' && !Array.isArray(claim))
          : []
        attempts.set(input.attempt, {
          claims,
          transcript: server.transcript,
          hostTranscript: server.buildHostSignedTranscript(),
          composites: [...server.getVerifiedComposites()],
          title: typeof resObj.title === 'string' && resObj.title.trim() ? resObj.title.trim() : null,
          severity: typeof resObj.severity === 'string' && resObj.severity.trim() ? resObj.severity.trim() : null,
          description: typeof resObj.description === 'string' && resObj.description.trim() ? resObj.description.trim() : null,
        })
        return {
          result: execution.result,
          stdout: execution.stdout,
          stderr: execution.stderr,
          exitCode: execution.exitCode,
          durationMs: execution.durationMs,
          timedOut: execution.timedOut,
        }
      },
      async close() {
        await session.close().catch(() => undefined)
        await server.close().catch(() => undefined)
      },
    }
  }

  const verdict = await verifyScript({
    candidate: { name: `agent-proof-${params.runId}.${params.runtime === 'python' ? 'py' : 'ts'}`, runtime: params.runtime, code },
    openAttempt,
    signal: params.signal,
  })
  const transcriptDigests = verdict.attempts.map(attempt => attempt.transcriptDigest).filter(Boolean)

  const latestCapture = attempts.get(2) ?? attempts.get(1) ?? null
  const transcriptRecords = latestCapture?.transcript.list() ?? []
  const hostTranscript = latestCapture?.hostTranscript ?? null
  const touchedHandles = new Set<string>()
  for (const cap of attempts.values()) {
    for (const rec of cap.transcript.list()) {
      if (rec.artifact?.capabilityHandle) touchedHandles.add(rec.artifact.capabilityHandle)
      if (rec.artifact?.derivedCapabilityId) touchedHandles.add(rec.artifact.derivedCapabilityId)
    }
  }
  const sealedCapabilities = vault.list().filter(
    meta => !handlesBefore.has(meta.handle) || touchedHandles.has(meta.handle),
  )

  // Multi-hop CompositeProofReceipt path (requires both fresh sessions to verify and agree).
  const a1 = attempts.get(1)
  const a2 = attempts.get(2)
  const r1 = verdict.attempts[0]
  const r2 = verdict.attempts[1]
  const confirmedComp1 = a1?.composites.find(c => c.verification.confirmed) ?? null
  const confirmedComp2 = a2?.composites.find(c => c.verification.confirmed) ?? null
  const sessionsClean = Boolean(
    r1 && r2
    && r1.nonce !== r2.nonce
    && !r1.nonceMismatch && !r2.nonceMismatch
    && r1.exitCode === 0 && r2.exitCode === 0
    && r1.signaturesValid && r2.signaturesValid,
  )

  if (sessionsClean && confirmedComp1 && confirmedComp2) {
    const agrees = confirmedComp1.receipt.chainId === confirmedComp2.receipt.chainId
      && confirmedComp1.receipt.terminalVulnClass === confirmedComp2.receipt.terminalVulnClass
      && confirmedComp1.receipt.hops.length === confirmedComp2.receipt.hops.length
    const chosenCapture = a2 ?? a1!
    const chosenComposite = confirmedComp2
    const exchanges = transcriptToScriptExchanges(chosenCapture.transcript, vault)
    const attribution = {
      claimTitle: chosenCapture.title ?? verdict.claimTitle ?? params.title?.trim() ?? `${chosenComposite.receipt.terminalVulnClass} multi-hop chain`,
      severity: chosenCapture.severity,
      description: chosenCapture.description,
    }
    if (!agrees) {
      return {
        verdict: {
          ...verdict,
          confirmed: false,
          reason: 'transcript_mismatch',
          rejectedBy: 'composite_receipt',
          detail: `Both fresh runs verified CompositeProofReceipt, but they disagreed on chain identity (${confirmedComp1.receipt.chainId}/${confirmedComp1.receipt.terminalVulnClass} vs ${confirmedComp2.receipt.chainId}/${confirmedComp2.receipt.terminalVulnClass}).`,
        },
        exchanges,
        receipt: null,
        compositeReceipt: chosenComposite,
        vulnClass: null,
        transcriptDigests,
        sealedCapabilities,
        transcriptRecords,
        hostTranscript,
        ...attribution,
      }
    }
    const compositeVerdict: VerifyVerdict = {
      ...verdict,
      confirmed: true,
      reason: 'confirmed',
      rejectedBy: null,
      missingEvidence: [],
      disagreements: [],
      claimTitle: attribution.claimTitle,
      detail: `Both fresh runs confirmed ${chosenComposite.receipt.hops.length}-hop CompositeProofReceipt (${chosenComposite.receipt.chainId}, ${chosenComposite.receipt.terminalVulnClass}, ${chosenComposite.verification.verifiedEdges.length} verified edge(s)).`,
      attempts: verdict.attempts.map(att => ({
        ...att,
        oraclePassed: true,
        failures: [],
        rejectedBy: null,
        missingEvidence: [],
      })),
    }
    return {
      verdict: compositeVerdict,
      exchanges,
      receipt: null,
      compositeReceipt: chosenComposite,
      vulnClass: chosenComposite.receipt.terminalVulnClass,
      transcriptDigests,
      sealedCapabilities,
      transcriptRecords,
      hostTranscript,
      ...attribution,
    }
  }

  const rejectedComposite = a2?.composites.find(c => !c.verification.confirmed)
    ?? a1?.composites.find(c => !c.verification.confirmed)
    ?? null
  if (!verdict.confirmed && rejectedComposite) {
    const capture = a2 ?? a1
    const exchanges = capture ? transcriptToScriptExchanges(capture.transcript, vault) : []
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: 'oracle_failed',
        rejectedBy: 'composite_receipt',
        detail: `CompositeProofReceipt rejected at stage '${rejectedComposite.verification.failedStage ?? 'unknown'}': ${rejectedComposite.verification.reason}`,
      },
      exchanges,
      receipt: null,
      compositeReceipt: rejectedComposite,
      vulnClass: null,
      transcriptDigests,
      sealedCapabilities,
      transcriptRecords,
      hostTranscript,
      claimTitle: capture?.title ?? verdict.claimTitle ?? null,
      severity: capture?.severity ?? null,
      description: capture?.description ?? null,
    }
  }

  // Standard single-hop ProofReceipt path.
  const passing = verdict.confirmed
    ? [...attempts.entries()]
        .sort((a, b) => b[0] - a[0])
        .find(([, captured]) => captured.transcript.size > 0)
    : undefined
  if (!passing) {
    return {
      verdict,
      exchanges: latestCapture ? transcriptToScriptExchanges(latestCapture.transcript, vault) : [],
      receipt: null,
      compositeReceipt: null,
      vulnClass: null,
      transcriptDigests,
      sealedCapabilities,
      transcriptRecords,
      hostTranscript,
      claimTitle: latestCapture?.title ?? verdict.claimTitle ?? null,
      severity: latestCapture?.severity ?? null,
      description: latestCapture?.description ?? null,
    }
  }
  const captured = passing[1]
  const attribution = {
    claimTitle: captured.title ?? verdict.claimTitle ?? null,
    severity: captured.severity,
    description: captured.description,
  }
  const exchanges = transcriptToScriptExchanges(captured.transcript, vault)
  const origin = exchanges.find(exchange => exchange.sessionRole === 'probe')?.origin
    ?? exchanges[0]?.origin
    ?? params.targetOrigins[0]
    ?? ''
  const built = buildAgentScriptReceipt({
    claims: captured.claims,
    exchanges,
    origin,
    title: params.title?.trim() || verdict.claimTitle || 'Agent script proof',
  })
  if (!built) {
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: 'oracle_failed',
        rejectedBy: 'receipt',
        missingEvidence: [...new Set([...(verdict.missingEvidence ?? []), 'verified_proof_receipt'])],
        detail: 'ProofReceipt could not be built from the script claims: mutating boundary claims require persisted before/after readbacks via ctx.prove_persisted_mutation; read-only boundaries require GET/HEAD.',
      },
      exchanges,
      receipt: null,
      compositeReceipt: null,
      vulnClass: null,
      transcriptDigests,
      sealedCapabilities,
      transcriptRecords,
      hostTranscript,
      ...attribution,
    }
  }
  const verification = verifyReceipt(built.receipt, built.transcript)
  if (!verification.confirmed) {
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: 'oracle_failed',
        detail: `ProofReceipt verification rejected the script claim (${verification.rule}): ${verification.reason}`,
        rejectedBy: 'receipt',
      },
      exchanges,
      receipt: null,
      compositeReceipt: null,
      vulnClass: null,
      transcriptDigests,
      sealedCapabilities,
      transcriptRecords,
      hostTranscript,
      ...attribution,
    }
  }
  return {
    verdict,
    exchanges,
    receipt: { receipt: built.receipt, verification },
    compositeReceipt: null,
    vulnClass: built.receipt.vulnClass,
    transcriptDigests,
    sealedCapabilities,
    transcriptRecords,
    hostTranscript,
    ...attribution,
  }
}

export async function retestPersistedAgentScript(
  envelope: AgentScriptProofEnvelope,
  params: VerifyReplaySpecParams & {
    origin?: string
    capabilityVault?: DerivedCapabilityVault
    compositeVerifyOptions?: Omit<CompositeVerifyOptions, 'signingKey'>
  },
): Promise<RetestReplayResult> {
  const origin = params.origin?.trim() ?? ''
  const result = await runAgentScriptProof({
    script: envelope.script,
    runtime: envelope.runtime,
    ...(envelope.vulnClass ? { title: `${envelope.vulnClass} agent proof retest` } : {}),
    broker: params.broker,
    grant: params.grant,
    backend: params.backend,
    runId: params.runId ?? 'retest',
    assignmentId: params.assignmentId ?? 'retest',
    targetOrigins: origin ? [origin] : [],
    signal: params.signal,
    ...(params.canaryBroker ? { canaryBroker: params.canaryBroker } : {}),
    ...(params.capabilityVault ? { capabilityVault: params.capabilityVault } : {}),
    ...(params.compositeVerifyOptions ? { compositeVerifyOptions: params.compositeVerifyOptions } : {}),
  })
  const exchangeIds: string[] = []
  const exchanges: BrokerExchangeResult[] = []
  for (const exchange of result.exchanges) {
    const status = exchange.status ?? 0
    const body = exchange.body ?? ''
    const bodyHash = createHash('sha256').update(body).digest('hex')
    const brokerExchange: BrokerExchangeResult = {
      origin: exchange.origin,
      finalOrigin: exchange.origin,
      redirectOrigins: [],
      method: exchange.method.toUpperCase(),
      pathAndQuery: exchange.pathAndQuery,
      personaHandle: exchange.personaHandle ?? null,
      status,
      mediaType: 'application/octet-stream',
      reqHeaders: exchange.requestHeaders ?? {},
      respHeaders: exchange.responseHeaders ?? {},
      setCookies: [],
      bodyPreview: body.slice(0, 4_096),
      body,
      bodySha256: bodyHash,
      bodyBytes: Buffer.byteLength(body),
      bodyTruncated: false,
      durationMs: exchange.durationMs ?? 0,
      secretMatches: [],
      observation: {
        origin: exchange.origin,
        finalOrigin: exchange.origin,
        status,
        mediaType: 'application/octet-stream',
        transportMaxAge: null,
        includeSubDomains: false,
        source: 'public response' as const,
      },
    }
    exchanges.push(brokerExchange)
    const saved = params.onExchange?.(brokerExchange)
    exchangeIds.push(typeof saved === 'string' && saved ? saved : exchange.exchangeId)
  }
  const hasConfirmedProof = result.receipt?.verification.confirmed === true
    || result.compositeReceipt?.verification.confirmed === true
  const confirmed = result.verdict.confirmed && (!envelope.vulnClass || hasConfirmedProof)
  const replay: ReplayVerificationResult = {
    verdict: confirmed ? 'confirmed' : result.verdict.reason === 'oracle_failed' ? 'dismissed' : 'inconclusive',
    ...(confirmed ? { verificationTier: 'runtime_confirmed' as const } : {}),
    outcome: {
      confirmed,
      controlPassed: result.verdict.attempts.every(attempt => attempt.oraclePassed),
      observed: confirmed
        ? `Agent script ${envelope.runtime} proof reproduced (${result.verdict.attempts.length} fresh runs).`
        : `Agent script proof did not reproduce: ${result.verdict.reason}.`,
      expected: 'the persisted proof script reproduces its confirmation',
      ...(result.verdict.detail ? { reason: result.verdict.detail } : {}),
    },
    exchangeIds,
    exchanges,
    evidencePayload: {
      mode: 'agent_script',
      runtime: envelope.runtime,
      scriptSha256: envelope.scriptSha256,
      transcriptDigests: result.transcriptDigests,
      receipt: result.receipt?.verification ?? result.compositeReceipt?.verification ?? null,
      ...(result.compositeReceipt ? { compositeReceipt: result.compositeReceipt.receipt } : {}),
    },
    evidenceSha256: createHash('sha256').update(JSON.stringify({
      script: envelope.scriptSha256,
      digests: result.transcriptDigests,
      verdict: result.verdict.reason,
    })).digest('hex'),
    ...(result.receipt
      ? { receipt: { mode: 'strict' as const, receipt: result.receipt.receipt, verification: result.receipt.verification } }
      : {}),
  }
  return {
    verdict: replay.verdict === 'confirmed' ? 'reproduced' : replay.verdict === 'dismissed' ? 'fixed' : 'inconclusive',
    replay,
  }
}
