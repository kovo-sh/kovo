/**
 * Unified agent-script proof execution and retest (v7 M5 + v8 CompositeProofReceipt).
 *
 * One place that runs a Layer-3 `kovo_verify` script for both live execution and patch retest:
 * every attempt opens a real worker session with the attempt's RPC directory mounted, shares an
 * optional run-scoped `DerivedCapabilityVault`, and captures both single-hop `ProofReceipt`s and
 * multi-hop `CompositeProofReceipt`s without monkey-patching `VerifyRpcServer`.
 */
import { createHash, randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { join, posix } from 'node:path'
import { agentScriptProofEnvelopeSchema } from '../replay-spec.ts'
import type { AgentScriptProofEnvelope } from '../replay-spec.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import {
  compositeProofReceiptSchema,
  type CompositeProofReceipt,
  type CompositeReceiptVerification,
  type CompositeVerifyOptions,
  type HostSignedTranscript,
} from './composite-receipt.ts'
import { normalizeCompositeTerminalEndpoint, parsePersonaPrivilegeProfile } from './causal-proof-compiler.ts'
import { DerivedCapabilityVault, type DerivedCapabilityMeta } from './derived-custody.ts'
import { createEgressSanitizer, type EgressSanitizer } from './egress-sanitizer.ts'
import { HostFactLog } from './host-fact-log.ts'
import { parseRoleLabel } from './oracle-invariants.ts'
import { buildAgentScriptReceipt } from './proof-receipt.ts'
import type { ProofReceipt, ReceiptVerification, ScriptProofExchange } from './proof-receipt.ts'
import { defaultTerminalOracleRegistry } from './terminal-oracle-registry.ts'
import {
  TranscriptStore,
  VerifyRpcServer,
  verifyScript,
  type VerifyAttemptSession,
  type VerifyReason,
  type VerifyTranscriptRecord,
  type VerifyVerdict,
} from './verify-rpc.ts'
import {
  assessRetestHealth,
  buildAgentScriptRetestInputs,
  isFixedEligibleFailureReason,
  type RetestFailureReason,
  type RetestHealthAssessment,
} from './retest-health.ts'
import {
  prepareSessionScratchDir,
  resolveDoodScratchConfig,
  type WorkerBackend,
} from './worker-backend.ts'
import type { ReplayVerificationResult, RetestReplayResult, VerifyReplaySpecParams } from './replay-verifier.ts'

export function resolveVerifyRpcHostDir(
  assignmentId: string,
  attempt: 1 | 2,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const dood = resolveDoodScratchConfig(env)
  if (dood) {
    const safeAssignment = assignmentId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 48) || 'verify'
    const sid = `${safeAssignment}-verify-${attempt}-${randomUUID().slice(0, 8)}`
    return prepareSessionScratchDir(sid, 'rpc', env)
  }
  const containerRaw = env.KOVO_CONTAINER_SCRATCH_DIR?.trim()
  if (!containerRaw) return undefined
  if (/[\0,\r\n]/.test(containerRaw) || !containerRaw.startsWith('/') || containerRaw.split(/[\\/]+/).includes('..')) {
    throw new Error('Invalid KOVO_CONTAINER_SCRATCH_DIR path.')
  }
  const resolvedBase = posix.resolve(containerRaw)
  if (resolvedBase === '/') {
    throw new Error('KOVO_CONTAINER_SCRATCH_DIR must not be root "/".')
  }
  mkdirSync(resolvedBase, { recursive: true, mode: 0o755 })
  return mkdtempSync(join(resolvedBase, 'kovo-verify-rpc-'))
}

export const PERSISTED_SCRIPT_INTEGRITY_ERROR =
  'Persisted proof script integrity check failed (SHA-256 mismatch; script was redacted or modified after confirmation).'

/**
 * R2-H-16: Verify that a persisted executable proof script's SHA-256 matches its recorded
 * `scriptSha256` (and optional proof-table `expectedSha256`) before re-execution. A mismatch
 * (e.g. from legacy heuristic redaction or tampering) MUST fail closed as `inconclusive` — never
 * `fixed` or `dismissed`.
 */
export function verifyPersistedScriptIntegrity(
  envelope: Pick<AgentScriptProofEnvelope, 'script' | 'scriptSha256'>,
  expectedSha256?: string | null,
): { ok: true; actualSha256: string } | { ok: false; actualSha256: string; reason: string } {
  const actualSha256 = createHash('sha256').update(envelope.script).digest('hex')
  const recorded = typeof envelope.scriptSha256 === 'string' ? envelope.scriptSha256.trim().toLowerCase() : ''
  if (!recorded || actualSha256 !== recorded) {
    return { ok: false, actualSha256, reason: PERSISTED_SCRIPT_INTEGRITY_ERROR }
  }
  if (expectedSha256 && actualSha256 !== expectedSha256.trim().toLowerCase()) {
    return { ok: false, actualSha256, reason: PERSISTED_SCRIPT_INTEGRITY_ERROR }
  }
  return { ok: true, actualSha256 }
}

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

export const LEGACY_PYTHON_PROOF_REASON =
  "Legacy Python agent_script proof is no longer supported; re-verify with TypeScript (runtime='ts')."

export interface AgentScriptProofParams {
  script: string
  runtime: 'ts'
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

export type AgentScriptVerifyReason = VerifyReason | RetestFailureReason

export interface AgentScriptVerifyVerdict extends Omit<VerifyVerdict, 'reason'> {
  reason: AgentScriptVerifyReason
}

export interface AgentScriptProofResult {
  verdict: AgentScriptVerifyVerdict
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

interface CapturedRequestBody {
  method: string
  origin: string
  pathAndQuery: string
  body: string
}

function correlateCapturedRequestBodies(
  transcript: TranscriptStore,
  captured: readonly CapturedRequestBody[],
): Map<string, string> {
  const byId = new Map<string, string>()
  if (captured.length === 0) return byId
  const remaining = [...captured]
  for (const rec of transcript.list()) {
    if (!rec.request || (rec.op !== 'http' && rec.op !== 'http2' && rec.op !== 'race')) continue
    const method = rec.request.method.toUpperCase()
    const origin = rec.request.origin
    const pq = rec.request.pathAndQuery
    const idx = remaining.findIndex(item => item.method === method && item.origin === origin && item.pathAndQuery === pq)
    if (idx >= 0) {
      byId.set(rec.exchangeId, remaining[idx]!.body)
      remaining.splice(idx, 1)
    }
  }
  return byId
}

function factLogToScriptExchanges(factLog: HostFactLog, sanitizer: EgressSanitizer): ScriptProofExchange[] {
  return factLog.orderedExchanges().flatMap(fact => {
    if (fact.op === 'browser') return []
    const workerView = factLog.buildWorkerView(fact.exchangeId, sanitizer, 'worker_rpc')
    const body = workerView?.responseBody ?? undefined
    const requestBody = fact.rawRequestBody
    return [{
      exchangeId: fact.exchangeId,
      ...(fact.op ? { op: fact.op } : {}),
      seq: fact.seq,
      ...(fact.startedAt !== undefined ? { startedAt: fact.startedAt } : {}),
      ...(fact.endedAt !== undefined ? { endedAt: fact.endedAt } : {}),
      method: fact.method,
      pathAndQuery: fact.pathAndQuery,
      origin: fact.origin,
      status: fact.status,
      durationMs: fact.durationMs,
      personaHandle: fact.actor,
      sessionRole: fact.sessionRole ?? null,
      actorRoleLabel: fact.actorRoleLabel ?? null,
      ambientAuth: fact.ambientAuth,
      sessionSameSite: fact.sameSite,
      ...(fact.consumedCapabilityId !== undefined ? { consumedCapabilityId: fact.consumedCapabilityId } : {}),
      ...(fact.consumedCapabilities ? { consumedCapabilities: [...fact.consumedCapabilities] } : {}),
      ...(fact.sessionId !== undefined ? { sessionId: fact.sessionId } : {}),
      ...(fact.artifact !== undefined ? { artifact: fact.artifact } : {}),
      ...(body !== undefined ? { body } : {}),
      ...(requestBody !== null ? { requestBody } : {}),
      requestHeaders: { ...fact.requestHeaders },
      responseHeaders: { ...fact.responseHeaders },
    }]
  })
}

function normalizeCompositeForBundle(
  receipt: CompositeProofReceipt,
  verification: CompositeReceiptVerification,
): CompositeProofReceipt {
  const effSummary = receipt.terminalImpact.summary && receipt.terminalImpact.summary.length > 0
    ? receipt.terminalImpact.summary
    : receipt.terminalImpact.claimedImpact
  const terminalImpact = effSummary
    ? { ...receipt.terminalImpact, summary: effSummary, claimedImpact: receipt.terminalImpact.claimedImpact || effSummary }
    : receipt.terminalImpact
  const termEndpoint = verification.terminalEndpoint?.trim() || ''
  const hops = termEndpoint
    ? receipt.hops.map(h => (h.hopId === terminalImpact.terminalHopId && !h.target.pathAndQuery
        ? { ...h, target: { ...h.target, pathAndQuery: termEndpoint } }
        : h))
    : receipt.hops
  return { ...receipt, hops, terminalImpact }
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
      const normalized = verification.confirmed
        ? normalizeCompositeForBundle(parsed.data, verification)
        : parsed.data
      this.verifiedComposites.push({
        receipt: normalized,
        verification,
        hopActors: extractHopActors(normalized, hostTranscript),
      })
    }
    return verification
  }

  getVerifiedComposites(): readonly V8CompositeProofBundle[] {
    return this.verifiedComposites
  }
}

/**
 * H-11 / R4-H-6: Derive `CompositeVerifyOptions` attacker/forbidden-shortcut persona lists from
 * the run's `Grant` whenever the caller did not supply explicit options. Mixed-role / dual-
 * membership personas (admin in tenant A, low-priv in tenant B) stay in `forbiddenShortcutPersonas`
 * by default (never unconditionally in `attackerPersonas`) and are recorded in
 * `dualTenantAbacPersonas` + `personaRoleLabels` so `verifyAttackerProvenance` permits them ONLY
 * when acting in a host-bound non-admin tenant under an explicit `dual_tenant_abac` oracle.
 */
export function buildCompositeVerifyOptionsFromGrant(
  grant: Pick<Grant, 'personas'>,
): Omit<CompositeVerifyOptions, 'signingKey'> | undefined {
  if (!grant.personas || grant.personas.size === 0) return undefined
  const attackerPersonas: string[] = []
  const forbiddenShortcutPersonas: string[] = []
  const dualTenantAbacPersonas: string[] = []
  const personaRoleLabels: Record<string, string> = {}
  for (const [handle, persona] of grant.personas.entries()) {
    if (persona.roleLabel?.trim()) personaRoleLabels[handle] = persona.roleLabel
    const parsed = parseRoleLabel(persona.roleLabel)
    const profile = parsePersonaPrivilegeProfile(handle, parsed.role, persona.roleLabel)
    if (profile.alwaysForbidden) {
      forbiddenShortcutPersonas.push(handle)
    } else if (profile.isMixedDual) {
      forbiddenShortcutPersonas.push(handle)
      dualTenantAbacPersonas.push(handle)
    } else {
      attackerPersonas.push(handle)
    }
  }
  if (attackerPersonas.length === 0 && forbiddenShortcutPersonas.length === 0) return undefined
  return {
    ...(attackerPersonas.length ? { attackerPersonas } : {}),
    ...(forbiddenShortcutPersonas.length ? { forbiddenShortcutPersonas } : {}),
    ...(dualTenantAbacPersonas.length ? { dualTenantAbacPersonas } : {}),
    ...(Object.keys(personaRoleLabels).length ? { personaRoleLabels } : {}),
  }
}

export async function runAgentScriptProof(params: AgentScriptProofParams): Promise<AgentScriptProofResult> {
  if (params.runtime !== 'ts') {
    throw new Error(`Unsupported kovo_verify runtime: ${String(params.runtime)}. kovo_verify supports TypeScript only (runtime='ts').`)
  }
  const code = params.script.trim()
  if (!code) throw new Error('An agent proof script is required.')
  if (Buffer.byteLength(code) > 64 * 1024) throw new Error('The agent proof script exceeds the 64 KiB limit.')

  const vault = guardVaultAgainstPlaceholderReseal(
    params.capabilityVault ?? params.v8Vault ?? new DerivedCapabilityVault({ runId: safeVaultRunId(params.runId) }),
  )
  const workerSanitizer = createEgressSanitizer({ capabilityVaults: [vault] })
  const handlesBefore = new Set(vault.list().map(meta => meta.handle))

  type AttemptCapture = {
    claims: Record<string, unknown>[]
    transcript: TranscriptStore
    factLog: HostFactLog
    hostTranscript: HostSignedTranscript | null
    composites: V8CompositeProofBundle[]
    title: string | null
    severity: string | null
    description: string | null
  }
  const attempts = new Map<1 | 2, AttemptCapture>()

  const openAttempt = async (input: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const capturedReqBodies: CapturedRequestBody[] = []
    const recordReqBody = (req: BrokerHttpRequest) => {
      if (typeof req.body === 'string' && req.body.length > 0) {
        capturedReqBodies.push({
          method: (req.method || 'GET').toUpperCase(),
          origin: req.origin,
          pathAndQuery: req.pathAndQuery,
          body: req.body,
        })
      }
    }
    const observingBroker = new Proxy(params.broker, {
      get(target, prop) {
        if (prop === 'executeHttp') {
          return (req: BrokerHttpRequest, grant: Grant, signal: AbortSignal) => {
            recordReqBody(req)
            return target.executeHttp(req, grant, signal)
          }
        }
        if (prop === 'executeBatch') {
          return (reqs: readonly BrokerHttpRequest[], grant: Grant, signal: AbortSignal) => {
            for (const req of reqs) recordReqBody(req)
            return target.executeBatch(reqs, grant, signal)
          }
        }
        const value = Reflect.get(target, prop, target)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const rpcHostDir = resolveVerifyRpcHostDir(params.assignmentId, input.attempt)
    const effectiveCompositeVerifyOptions = params.compositeVerifyOptions ?? buildCompositeVerifyOptionsFromGrant(params.grant)
    const server = new CapturingVerifyRpcServer({
      broker: observingBroker,
      grant: params.grant,
      runId: params.runId,
      assignmentId: params.assignmentId,
      nonce: input.nonce,
      targetOrigins: [...params.targetOrigins],
      capabilityVault: vault,
      ...(rpcHostDir ? { hostDir: rpcHostDir } : {}),
      ...(params.canaryBroker ? { canary: params.canaryBroker } : {}),
      ...(effectiveCompositeVerifyOptions ? { compositeVerifyOptions: effectiveCompositeVerifyOptions } : {}),
    })
    try {
      await server.start()
    } catch (error) {
      if (rpcHostDir) {
        try { rmSync(rpcHostDir, { recursive: true, force: true }) } catch { /* ignore */ }
      }
      throw error
    }
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
        const hostTranscript = server.buildHostSignedTranscript()
        const rawRequestBodies = correlateCapturedRequestBodies(server.transcript, capturedReqBodies)
        const factLog = HostFactLog.fromTranscriptStore(server.transcript, {
          rawRequestBodies,
          hostTranscript,
          sanitizer: workerSanitizer,
        })
        attempts.set(input.attempt, {
          claims,
          transcript: server.transcript,
          factLog,
          hostTranscript,
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
    candidate: { name: `agent-proof-${params.runId}.ts`, runtime: 'ts', code },
    openAttempt,
    signal: params.signal,
    fastFailOnAttempt1: true,
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
    const termEntity1 = confirmedComp1.receipt.hops.find(h => h.hopId === confirmedComp1.receipt.terminalImpact.terminalHopId)?.entityId
    const termEntity2 = confirmedComp2.receipt.hops.find(h => h.hopId === confirmedComp2.receipt.terminalImpact.terminalHopId)?.entityId
    const endpoint1 = normalizeCompositeTerminalEndpoint(confirmedComp1.verification.terminalEndpoint, termEntity1)
    const endpoint2 = normalizeCompositeTerminalEndpoint(confirmedComp2.verification.terminalEndpoint, termEntity2)
    const family1 = (confirmedComp1.verification.terminalOracleFamily ?? confirmedComp1.receipt.terminalImpact.oracleFamily ?? '').trim()
    const family2 = (confirmedComp2.verification.terminalOracleFamily ?? confirmedComp2.receipt.terminalImpact.oracleFamily ?? '').trim()
    const agrees = confirmedComp1.receipt.chainId === confirmedComp2.receipt.chainId
      && confirmedComp1.receipt.terminalVulnClass === confirmedComp2.receipt.terminalVulnClass
      && confirmedComp1.receipt.hops.length === confirmedComp2.receipt.hops.length
      && endpoint1 === endpoint2
      && family1 === family2
    const chosenCapture = a2 ?? a1!
    const chosenComposite = confirmedComp2
    const exchanges = factLogToScriptExchanges(chosenCapture.factLog, workerSanitizer)
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

  const hasAuthenticated401 = (list: readonly ScriptProofExchange[]): boolean =>
    list.some(ex => Boolean(ex.personaHandle && ex.personaHandle.trim()) && ex.status === 401)

  const rejectedComposite = a2?.composites.find(c => !c.verification.confirmed)
    ?? a1?.composites.find(c => !c.verification.confirmed)
    ?? null
  if (!verdict.confirmed && rejectedComposite) {
    const capture = a2 ?? a1
    const exchanges = capture ? factLogToScriptExchanges(capture.factLog, workerSanitizer) : []
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: 'composite_stage_rejected',
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
    const exchanges = latestCapture ? factLogToScriptExchanges(latestCapture.factLog, workerSanitizer) : []
    let typedVerdict: AgentScriptVerifyVerdict = verdict
    if (!verdict.confirmed && verdict.reason === 'oracle_failed') {
      const hasCompositeFailure = verdict.attempts.some(att => att.failures.some(f => f.startsWith('composite_receipt:')))
      const drifted = hasAuthenticated401(exchanges)
        || verdict.attempts.some(att => att.nonceMismatch || !att.signaturesValid)
      const fallbackOrigin = exchanges.find(exchange => exchange.sessionRole === 'probe')?.origin
        ?? exchanges[0]?.origin
        ?? params.targetOrigins[0]
        ?? ''
      const receiptUnbuildable = !hasCompositeFailure && !drifted && Boolean(latestCapture) && !buildAgentScriptReceipt({
        claims: latestCapture!.claims,
        exchanges,
        factLog: latestCapture!.factLog,
        origin: fallbackOrigin,
        title: params.title?.trim() || verdict.claimTitle || 'Agent script proof',
      })
      typedVerdict = {
        ...verdict,
        reason: hasCompositeFailure
          ? 'composite_stage_rejected'
          : drifted
            ? 'session_drifted'
            : receiptUnbuildable
              ? 'receipt_unbuildable'
              : 'claim_not_reproduced',
      }
    }
    return {
      verdict: typedVerdict,
      exchanges,
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
  const exchanges = factLogToScriptExchanges(captured.factLog, workerSanitizer)
  const origin = exchanges.find(exchange => exchange.sessionRole === 'probe')?.origin
    ?? exchanges[0]?.origin
    ?? params.targetOrigins[0]
    ?? ''
  const built = buildAgentScriptReceipt({
    claims: captured.claims,
    exchanges,
    factLog: captured.factLog,
    origin,
    title: params.title?.trim() || verdict.claimTitle || 'Agent script proof',
  })
  if (!built) {
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: 'receipt_unbuildable',
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
  const oracleRes = defaultTerminalOracleRegistry.evaluate(
    built.factLog,
    {
      kind: 'single_hop',
      receipt: built.receipt,
      armOverrides: built.armOverrides,
      ...(built.evidenceRoleOverrides ? { evidenceRoleOverrides: built.evidenceRoleOverrides } : {}),
    },
    {
      strictHostDerivation: true,
      ...(built.receipt.oracleEvents?.length ? { trustedOracleEvents: built.receipt.oracleEvents } : {}),
    },
  )
  const verification: ReceiptVerification = oracleRes.singleHop ?? {
    confirmed: oracleRes.confirmed,
    vulnClass: built.receipt.vulnClass,
    rule: 'none',
    reason: oracleRes.reason,
    observed: built.receipt.claimedDelta,
    expected: 'host-custody verified single-hop receipt',
  }
  if (!verification.confirmed) {
    const drifted = hasAuthenticated401(exchanges)
    const structuralFailure = /missing|unbuildable|stub|decoy|echoed|schema|no control|anonymous|unauthenticated/i.test(verification.reason)
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: drifted ? 'session_drifted' : structuralFailure ? 'receipt_unbuildable' : 'claim_not_reproduced',
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
  if (envelope.runtime !== 'ts') {
    const replay: ReplayVerificationResult = {
      verdict: 'inconclusive',
      outcome: {
        confirmed: false,
        controlPassed: false,
        observed: LEGACY_PYTHON_PROOF_REASON,
        expected: 'the persisted proof script reproduces its confirmation',
        reason: LEGACY_PYTHON_PROOF_REASON,
      },
      exchangeIds: [],
      exchanges: [],
      evidencePayload: {
        mode: 'agent_script',
        runtime: envelope.runtime,
        scriptSha256: envelope.scriptSha256,
        transcriptDigests: [],
        receipt: null,
      },
      evidenceSha256: createHash('sha256').update(JSON.stringify({
        script: envelope.scriptSha256,
        digests: [],
        verdict: 'inconclusive',
        reason: 'legacy_python_unsupported',
      })).digest('hex'),
    }
    return { verdict: 'inconclusive', replay }
  }
  const integrity = verifyPersistedScriptIntegrity(envelope)
  if (!integrity.ok) {
    const replay: ReplayVerificationResult = {
      verdict: 'inconclusive',
      outcome: {
        confirmed: false,
        controlPassed: false,
        observed: integrity.reason,
        expected: 'the persisted proof script SHA-256 matches its recorded confirmation digest',
        reason: integrity.reason,
      },
      exchangeIds: [],
      exchanges: [],
      evidencePayload: {
        mode: 'agent_script',
        runtime: envelope.runtime,
        scriptSha256: envelope.scriptSha256,
        actualScriptSha256: integrity.actualSha256,
        integrityMismatch: true,
        transcriptDigests: [],
        receipt: null,
      },
      evidenceSha256: createHash('sha256').update(JSON.stringify({
        script: envelope.scriptSha256,
        actual: integrity.actualSha256,
        digests: [],
        verdict: 'inconclusive',
        reason: 'script_integrity_mismatch',
      })).digest('hex'),
    }
    return { verdict: 'inconclusive', replay }
  }
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
  const confirmed = result.verdict.confirmed && hasConfirmedProof
  const healthInputs = buildAgentScriptRetestInputs({
    confirmed,
    verdictReason: result.verdict.reason,
    verdictDetail: result.verdict.detail,
    attempts: result.verdict.attempts,
    exchanges: result.exchanges,
    compositeRejectedStage: result.compositeReceipt && !result.compositeReceipt.verification.confirmed
      ? (result.compositeReceipt.verification.failedStage ?? 'unknown')
      : null,
    vulnClass: envelope.vulnClass ?? result.vulnClass ?? null,
  })
  const health: RetestHealthAssessment = assessRetestHealth(
    healthInputs.baseline,
    healthInputs.probeArms,
    healthInputs.session,
  )
  const fixedEligible = !confirmed
    && isFixedEligibleFailureReason(result.verdict.reason)
    && health.healthy
    && health.failureReason === 'claim_not_reproduced'
  const replayVerdict = confirmed ? 'confirmed' : fixedEligible ? 'dismissed' : 'inconclusive'
  const outcomeReason = confirmed
    ? result.verdict.detail
    : fixedEligible
      ? result.verdict.detail
      : (health.reason ?? result.verdict.detail)
  const replay: ReplayVerificationResult = {
    verdict: replayVerdict,
    ...(confirmed ? { verificationTier: 'runtime_confirmed' as const } : {}),
    outcome: {
      confirmed,
      controlPassed: confirmed || fixedEligible,
      observed: confirmed
        ? `Agent script ${envelope.runtime} proof reproduced (${result.verdict.attempts.length} fresh runs).`
        : `Agent script proof did not reproduce: ${result.verdict.reason}.`,
      expected: 'the persisted proof script reproduces its confirmation',
      ...(outcomeReason ? { reason: outcomeReason } : {}),
    },
    exchangeIds,
    exchanges,
    evidencePayload: {
      mode: 'agent_script',
      runtime: envelope.runtime,
      scriptSha256: envelope.scriptSha256,
      transcriptDigests: result.transcriptDigests,
      retestHealth: health,
      receipt: result.receipt?.verification ?? result.compositeReceipt?.verification ?? null,
      ...(result.compositeReceipt ? {
        compositeReceipt: result.compositeReceipt.receipt,
        compositeVerification: result.compositeReceipt.verification,
      } : {}),
    },
    evidenceSha256: createHash('sha256').update(JSON.stringify({
      script: envelope.scriptSha256,
      digests: result.transcriptDigests,
      verdict: result.verdict.reason,
      health: health.failureReason,
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
