/**
 * Agent-script proof execution and retest (v7 M5).
 *
 * One place that runs a Layer-3 `guardian_verify` script for production: every attempt opens a real
 * worker session with the attempt's RPC directory mounted, so the script runs in the air-gapped
 * sandbox and its HTTP/browser/OOB calls cross the Layer-1 grant. The transcript stays host-side.
 *
 * Extracted from `replay-verifier.ts` (Cut 3f) so the verifier module only owns the legacy
 * declarative VM. `replay-verifier.ts` re-exports every public symbol here, so no caller import
 * changes.
 */
import { createHash } from 'node:crypto'
import { agentScriptProofEnvelopeSchema } from '../replay-spec.ts'
import type { AgentScriptProofEnvelope } from '../replay-spec.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { buildAgentScriptReceipt, verifyReceipt } from './proof-receipt.ts'
import type { ProofReceipt, ReceiptVerification, ScriptProofExchange } from './proof-receipt.ts'
import { TranscriptStore, VerifyRpcServer, verifyScript } from './verify-rpc.ts'
import type { VerifyAttemptSession, VerifyVerdict } from './verify-rpc.ts'
import type { WorkerBackend } from './worker-backend.ts'
import type { ReplayVerificationResult, RetestReplayResult, VerifyReplaySpecParams } from './replay-verifier.ts'

export function persistedAgentScriptOf(spec: unknown): { envelope: AgentScriptProofEnvelope; origin: string } | null {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return null
  const record = spec as Record<string, unknown>
  const parsed = agentScriptProofEnvelopeSchema.safeParse(record.agentScript)
  if (!parsed.success) return null
  return { envelope: parsed.data, origin: typeof record.origin === 'string' ? record.origin : '' }
}

// ---------------------------------------------------------------------------
// Agent script proof runner (v7 M5)
//
// One place that runs a Layer-3 `guardian_verify` script for production: every attempt opens a real
// worker session with the attempt's RPC directory mounted, so the script runs in the air-gapped
// sandbox and its HTTP/browser/OOB calls cross the Layer-1 grant. The transcript stays host-side.
// ---------------------------------------------------------------------------

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
}

export interface AgentScriptProofResult {
  verdict: VerifyVerdict
  /** Host-recorded exchanges of the last passing attempt (empty when no attempt passed). */
  exchanges: ScriptProofExchange[]
  /** Present only when the claims map onto a receipt rule AND `verifyReceipt` confirms it. */
  receipt: { receipt: ProofReceipt; verification: ReceiptVerification } | null
  vulnClass: string | null
  transcriptDigests: string[]
  /** Script-declared attribution (never evidence by itself). */
  claimTitle: string | null
  severity: string | null
  description: string | null
}

export async function runAgentScriptProof(params: AgentScriptProofParams): Promise<AgentScriptProofResult> {
  const code = params.script.trim()
  if (!code) throw new Error('An agent proof script is required.')
  if (Buffer.byteLength(code) > 64 * 1024) throw new Error('The agent proof script exceeds the 64 KiB limit.')
  const attempts = new Map<1 | 2, {
    claims: Record<string, unknown>[]
    transcript: TranscriptStore
    title: string | null
    severity: string | null
    description: string | null
  }>()
  const openAttempt = async (input: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const server = new VerifyRpcServer({
      broker: params.broker,
      grant: params.grant,
      runId: params.runId,
      assignmentId: params.assignmentId,
      nonce: input.nonce,
      targetOrigins: [...params.targetOrigins],
      ...(params.canaryBroker ? { canary: params.canaryBroker } : {}),
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
        const claims = execution.result && typeof execution.result === 'object'
          ? ((execution.result as { claims?: unknown }).claims)
          : undefined
        const declared = execution.result && typeof execution.result === 'object'
          ? execution.result as { title?: unknown; severity?: unknown; description?: unknown }
          : {}
        attempts.set(input.attempt, {
          claims: Array.isArray(claims)
            ? claims.filter((claim): claim is Record<string, unknown> => Boolean(claim) && typeof claim === 'object' && !Array.isArray(claim))
            : [],
          transcript: server.transcript,
          title: typeof declared.title === 'string' && declared.title.trim() ? declared.title.trim() : null,
          severity: typeof declared.severity === 'string' && declared.severity.trim() ? declared.severity.trim() : null,
          description: typeof declared.description === 'string' && declared.description.trim() ? declared.description.trim() : null,
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
  const passing = verdict.confirmed
    ? [...attempts.entries()]
        .sort((a, b) => b[0] - a[0])
        .find(([, captured]) => captured.transcript.size > 0)
    : undefined
  if (!passing) {
    return { verdict, exchanges: [], receipt: null, vulnClass: null, transcriptDigests, claimTitle: null, severity: null, description: null }
  }
  const captured = passing[1]
  const attribution = {
    claimTitle: captured.title ?? verdict.claimTitle ?? null,
    severity: captured.severity,
    description: captured.description,
  }
  const exchanges: ScriptProofExchange[] = captured.transcript.list().flatMap(record => {
    if (record.op === 'oob' || record.op === 'browser') return []
    const request = record.request
    if (!request) return []
    const body = captured.transcript.body(record.exchangeId)
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
    // Fail closed: every agent script confirmation MUST produce a verified ProofReceipt.
    // Never fall back to a receiptless script-only confirmation (e.g. mutating POST boundary claims
    // that lack persisted before/after readbacks).
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
      vulnClass: null,
      transcriptDigests,
      ...attribution,
    }
  }
  const verification = verifyReceipt(built.receipt, built.transcript)
  if (!verification.confirmed) {
    // Fail closed: if a script claim maps onto a ProofReceipt rule and `verifyReceipt()` rejects
    // it (status-only, missing readback, anon-401 control, ...), do not fall back to confirming
    // the script verdict without a receipt.
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
      vulnClass: null,
      transcriptDigests,
      ...attribution,
    }
  }
  return {
    verdict,
    exchanges,
    receipt: { receipt: built.receipt, verification },
    vulnClass: built.receipt.vulnClass,
    transcriptDigests,
    ...attribution,
  }
}

export async function retestPersistedAgentScript(
  envelope: AgentScriptProofEnvelope,
  params: VerifyReplaySpecParams & { origin?: string },
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
  const confirmed = result.verdict.confirmed && (!envelope.vulnClass || result.receipt?.verification.confirmed === true)
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
      receipt: result.receipt?.verification ?? null,
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

