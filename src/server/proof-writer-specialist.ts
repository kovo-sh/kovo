import { runAgentSession } from './agent-session.ts'
import type { IntentCompletion, KovoVerifyArgs, WorkerToolHandlers } from './agent-prompts.ts'
import { redact } from './redact.ts'

export const DEFAULT_PROOF_WRITER_MAX_TURNS = 6
export const DEFAULT_PROOF_WRITER_WALL_CLOCK_MS = 90_000
export const DEFAULT_PROOF_WRITER_BUDGET_CAP_USD = 0.25
export const MAX_PROOF_WRITER_BODY_PREVIEW_CHARS = 1_500
const MAX_DRAFT_SCRIPT_CHARS = 24_000
const MAX_REPRO_NOTES_CHARS = 2_000
const MAX_HEADER_VALUE_CHARS = 240
const SENSITIVE_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-session-token|x-csrf-token|x-xsrf-token|x-webhook-secret|x-signature)$/i

export interface ProofWriterExchangeSummary {
  exchangeId: string
  origin: string
  method: string
  pathAndQuery: string
  persona?: string
  requestHeaders?: Record<string, string>
  requestBodyPreview?: string
  status: number
  mediaType?: string
  responseHeaders?: Record<string, string>
  responseBodyPreview?: string
}

export interface ProofWriterInput {
  runId: string
  assignmentId: string
  title: string
  vulnClass: string
  oracleFamily?: string
  reproNotes?: string
  targetOrigins: string[]
  personasPub: Array<{ handle: string; role?: string; tenant?: string }>
  exchanges: ProofWriterExchangeSummary[]
  draftScript?: string
  compilerWarnings?: string[]
  compilerFailure?: { rejectedBy?: string; compositeRejectedBy?: string; reason?: string; detail?: string; missingEvidence?: string[] }
  maxTurns?: number
  wallClockMs?: number
  budgetCapUsd?: number
}

export interface ProofWriterResult {
  confirmed: boolean
  findingId?: string
  spendUsd: number
  turns: number
  attempts: number
  compositeRejectedBy?: string
  lastRejection?: { rejectedBy?: string; compositeRejectedBy?: string; reason?: string; detail?: string }
  error?: string
}

export interface ProofWriterVerifyResult {
  confirmed: boolean
  findingId?: string
  rejectedBy?: string
  compositeRejectedBy?: string
  reason?: string
  detail?: string
  missingEvidence?: string[]
  usageHint?: string
}

export interface ProofWriterDeps {
  profiles: Parameters<typeof runAgentSession>[0]['profiles']
  runKovoVerify: (args: { script: string; title?: string; vulnClass?: string }) => Promise<ProofWriterVerifyResult>
  beforeCall?: () => Promise<void> | void
  onUsage?: (u: { costUsd?: number; inputTokens?: number; outputTokens?: number }) => void
  onProfileSuccess?: Parameters<typeof runAgentSession>[0]['onProfileSuccess']
  onProfileFailure?: Parameters<typeof runAgentSession>[0]['onProfileFailure']
  signal?: AbortSignal
  sessionRunner?: typeof runAgentSession
}

class ProofWriterShortCircuitError extends Error {
  constructor() { super('proof_writer_confirmed_short_circuit'); this.name = 'ProofWriterShortCircuitError' }
}

class ProofWriterBudgetError extends Error {
  constructor(spendUsd: number, budgetCapUsd: number) {
    super(`budget_cap_exceeded: spend $${spendUsd.toFixed(4)} reached cap $${budgetCapUsd.toFixed(4)}`)
    this.name = 'ProofWriterBudgetError'
  }
}

const VALID_TERMINAL_CLASSES =
  'dual_tenant_abac, broken_access_control, bola, bfla, privilege_escalation, cross_tenant_read, cross_tenant_write, cross_tenant_export, cross_tenant_exfiltration, signed_url_mint, auth_bypass, jwt_forgery, webhook_forgery, economic_conservation, conserved_balance, ledger_overcredit, forged_settlement, stale_privilege_use, temporal_revocation, cryptographic_scope_replay, parser_cache_differential, cross_surface_pivot, business_logic, mass_assignment, ssrf, xxe, sqli, xss'

export function buildProofWriterSystemPrompt(): string {
  return [
    'Proof-Writer: TS `kovo_verify` Mode-A (`fresh_clean_replay`) `CompositeProofReceipt`.',
    'ChainBuilder v2 (`ctx.chain()`, 2x):',
    '```ts',
    'const ch = ctx.chain({ chainId: "c1", terminalVulnClass: "<class>" })',
    'const ctrl = await ch.control(t, { as: atk }) // OUTSIDE any hop',
    'const h1 = await ch.step(u1, { hopId: "h1", method: "POST", as: atk, body: {}, claimedDelta: "d" })',
    'const cap = await ch.seal(h1, { jsonPath: "$.token", kind: "bearer_token" }) // NEVER cap.handle',
    'const h2 = await ch.hop("h2", () => ctx.http_send(t, { capability: { handle: cap, target: "bearer" }, role: "probe" }))',
    'const urlCap = await ch.seal(h2, { kind: "signed_url", jsonPath: "$.url" }) // NO leading `/`',
    'const h3 = await ch.hop("h3", () => ctx.http_send({ method: "GET", path: urlCap }))',
    'await ch.readback(t, { as: atk })',
    'await ch.prove({ terminalHopId: "h3", claimedImpact: "i" })',
    'return ctx.result({ title: "t" })',
    '```',
    '`ch.seal` returns handle STRING directly, NEVER write `cap.handle` (`ctx.seal_capability`->{handle}; no regex). `jsonPath|header|setCookie|locationQuery`; `kind`: `bearer_token|signed_url|cookie|api_token|header_secret|hmac_key|jwt|generic_secret`. `body`, not `jsonBody`/`textBody`.',
    'Helpers: `ch.race`/`ctx.race_burst`, `ctx.hmac_sign`, `ctx.jwt_sign`, `ctx.await_async`, `ch.stateTransition`, `ch.edge`.',
    `Classes: ${VALID_TERMINAL_CLASSES}. No \`cross_tenant_data_access\`.`,
    'Rules: 1. Link hops to `terminalHopId`; prune orphan `hop_*`. 2. `ch.control` BEFORE mutations, OUTSIDE any hop (strictly for denied controls); MUST hit exact terminal route path + identical non-auth query params (strip ONLY `sig`/`signature`/`hmac`/`token`/`expires`/`ts`/`nonce` — NEVER drop/swap non-auth params -> `query_mismatch`). 3. Call `ctx.hmac_sign(...)` BEFORE/OUTSIDE `ch.step`/`ch.hop`, NEVER inside a hop (else `HMAC_SIGN`, not `POST`). 4. `webhook_forgery`/`forged_settlement`: add `ch.readback(...)` after forged POST proving state changed (or `cross_tenant_write` + control + readback). 5. `economic_conservation`: `await ch.readback(balanceTarget, { as: attacker })` BEFORE hop 1 AND AFTER `ch.race(...)`. 6. Patch `draftScript` for `compilerFailure`; use `ctx.nonce`; stop on `confirmed: true`; `complete_intent` only if unconfirmable.',
  ].join('\n')
}

function clampText(text: string, maxChars: number): string {
  const scrubbed = redact(text).trim()
  if (scrubbed.length <= maxChars) return scrubbed
  const suffix = '…[truncated]'
  return `${scrubbed.slice(0, Math.max(0, maxChars - suffix.length))}${suffix}`
}

function formatSafeHeaders(headers: Record<string, string> | undefined): string | undefined {
  if (!headers) return undefined
  const entries = Object.entries(headers)
  if (entries.length === 0) return undefined
  const safe: Record<string, string> = {}
  for (const [key, val] of entries) {
    safe[key] = SENSITIVE_HEADER_RE.test(key.trim()) ? '[REDACTED]' : clampText(String(val), MAX_HEADER_VALUE_CHARS)
  }
  return JSON.stringify(safe)
}

function formatExchange(ex: ProofWriterExchangeSummary, idx: number): string {
  const lines = [
    `### Exchange ${idx + 1} (${ex.exchangeId})`,
    `- Request: ${ex.method} ${ex.origin}${ex.pathAndQuery}${ex.persona ? ` [persona=${ex.persona}]` : ''}`,
    `- Response: HTTP ${ex.status}${ex.mediaType ? ` (${ex.mediaType})` : ''}`,
  ]
  const reqHeaders = formatSafeHeaders(ex.requestHeaders)
  if (reqHeaders) lines.push(`- Request headers: ${reqHeaders}`)
  if (ex.requestBodyPreview?.trim()) {
    lines.push(`- Request body preview:\n\`\`\`\n${clampText(ex.requestBodyPreview, MAX_PROOF_WRITER_BODY_PREVIEW_CHARS)}\n\`\`\``)
  }
  const resHeaders = formatSafeHeaders(ex.responseHeaders)
  if (resHeaders) lines.push(`- Response headers: ${resHeaders}`)
  if (ex.responseBodyPreview?.trim()) {
    lines.push(`- Response body preview:\n\`\`\`\n${clampText(ex.responseBodyPreview, MAX_PROOF_WRITER_BODY_PREVIEW_CHARS)}\n\`\`\``)
  }
  return lines.join('\n')
}

export function buildProofWriterUserPrompt(input: ProofWriterInput): string {
  const personasLine = input.personasPub.length > 0
    ? input.personasPub.map(p => {
        const meta = [p.role ? `role=${p.role}` : '', p.tenant ? `tenant=${p.tenant}` : ''].filter(Boolean).join(', ')
        return meta ? `${p.handle} (${meta})` : p.handle
      }).join('; ')
    : '(none)'

  const sections: string[] = [
    '# Candidate Proof Task',
    `- Title: ${clampText(input.title, 300)}`,
    `- Vuln class: ${input.vulnClass}`,
    ...(input.oracleFamily ? [`- Oracle family: ${input.oracleFamily}`] : []),
    `- Target origins: ${input.targetOrigins.join(', ') || '(none)'}`,
    `- Personas: ${personasLine}`,
  ]
  if (input.reproNotes?.trim()) sections.push(`\n## Reproduction Notes\n${clampText(input.reproNotes, MAX_REPRO_NOTES_CHARS)}`)
  sections.push(
    `\n## Winning Exchanges (${input.exchanges.length})\n`
    + (input.exchanges.length > 0 ? input.exchanges.map(formatExchange).join('\n\n') : '(no exchanges provided)'),
  )
  if (input.compilerWarnings?.length) {
    sections.push(`\n## Compiler Warnings\n${input.compilerWarnings.map(w => `- ${clampText(w, 400)}`).join('\n')}`)
  }
  if (input.compilerFailure) {
    const cf = input.compilerFailure
    sections.push([
      '\n## Compiler Verification Failure (FIX THIS DIRECTLY)',
      ...(cf.rejectedBy ? [`- rejectedBy: ${cf.rejectedBy}`] : []),
      ...(cf.compositeRejectedBy ? [`- compositeRejectedBy: ${cf.compositeRejectedBy}`] : []),
      ...(cf.reason ? [`- reason: ${clampText(cf.reason, 500)}`] : []),
      ...(cf.detail ? [`- detail: ${clampText(cf.detail, 800)}`] : []),
      ...(cf.missingEvidence?.length ? [`- missingEvidence: ${cf.missingEvidence.join(', ')}`] : []),
    ].join('\n'))
  }
  if (input.draftScript?.trim()) {
    const label = input.compilerFailure ? ' (Edit directly to fix the failure above)' : ''
    sections.push(`\n## Draft Script${label}\n\`\`\`ts\n${clampText(input.draftScript, MAX_DRAFT_SCRIPT_CHARS)}\n\`\`\``)
  }
  sections.push('\n## Action\nCall `kovo_verify` with inline TypeScript (`runtime: "ts"`) using `ChainBuilder` v2 (`ch.control` outside hops, `ch.step`/`ch.hop`, `ch.seal`, `ch.readback`/`ch.race`/`ch.stateTransition`/`ch.edge`). Remember: **`const cap = await ch.seal(h, { jsonPath, kind })` returns the handle STRING directly — pass `cap` directly, NEVER `cap.handle`!** For `signed_url`, pass `path: urlCap` directly (no leading `/`), and use `body` (not `jsonBody`/`textBody`). Prune any unlinked recon/listing hops so every hop connects to `terminalHopId`. Stop immediately when `confirmed: true`.')
  return sections.join('\n')
}

const positiveInt = (v: number | undefined, fb: number): number => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.max(1, Math.floor(v)) : fb)
const positiveFloat = (v: number | undefined, fb: number): number => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : fb)
const formatError = (err: unknown): string => (err instanceof Error ? err.message || err.name : typeof err === 'string' && err.trim() ? err.trim() : String(err))

function makeToolResult(f: { confirmed: boolean; title: string; findingId?: string; rejectedBy: string | null; reason: string; detail: string; missingEvidence?: string[]; usageHint?: string }) {
  return {
    confirmed: f.confirmed,
    ...(f.findingId ? { findingId: f.findingId } : {}),
    rejectedBy: f.rejectedBy,
    reason: f.reason,
    detail: f.detail,
    missingEvidence: f.missingEvidence ?? [],
    ...(f.usageHint ? { usageHint: f.usageHint } : {}),
    title: f.title,
    transcriptDigest: null,
    transcriptDigests: [],
    failures: f.confirmed ? [] : [f.reason],
    disagreements: [],
    attempts: [],
    transcriptSummary: [],
  }
}

export async function runProofWriterSpecialist(deps: ProofWriterDeps, input: ProofWriterInput): Promise<ProofWriterResult> {
  const maxTurns = positiveInt(input.maxTurns, DEFAULT_PROOF_WRITER_MAX_TURNS)
  const wallClockMs = positiveInt(input.wallClockMs, DEFAULT_PROOF_WRITER_WALL_CLOCK_MS)
  const budgetCapUsd = positiveFloat(input.budgetCapUsd, DEFAULT_PROOF_WRITER_BUDGET_CAP_USD)
  const sessionRunner = deps.sessionRunner ?? runAgentSession
  if (deps.signal?.aborted) return { confirmed: false, spendUsd: 0, turns: 0, attempts: 0, error: 'aborted' }

  const localAbort = new AbortController()
  let parentAborted = false
  const onParentAbort = () => { parentAborted = true; localAbort.abort(deps.signal?.reason ?? 'parent_aborted') }
  deps.signal?.addEventListener('abort', onParentAbort, { once: true })

  let confirmed = false
  let findingId: string | undefined
  let spendUsd = 0
  let turns = 0
  let attempts = 0
  let budgetExceeded = false
  let beforeCallError: string | undefined
  let completionSummary: string | undefined
  let lastRejection: { rejectedBy?: string; compositeRejectedBy?: string; reason?: string; detail?: string } | undefined

  const handlers: WorkerToolHandlers = {
    kovo_verify: async (args: KovoVerifyArgs) => {
      const script = (args.script ?? '').trim()
      const verifyTitle = args.title?.trim() || input.title
      if (!script) {
        lastRejection = { rejectedBy: 'validation', reason: 'missing_script', detail: 'kovo_verify requires non-empty inline TypeScript `script`.' }
        return makeToolResult({ confirmed: false, title: verifyTitle, rejectedBy: 'validation', reason: 'missing_script', detail: lastRejection.detail!, missingEvidence: ['script'] })
      }
      attempts += 1
      const res = await deps.runKovoVerify({ script, title: verifyTitle, vulnClass: input.vulnClass })
      if (res.confirmed) {
        confirmed = true
        findingId = res.findingId
        localAbort.abort(new ProofWriterShortCircuitError())
        return makeToolResult({ confirmed: true, title: verifyTitle, findingId: res.findingId, rejectedBy: null, reason: res.reason ?? 'confirmed', detail: res.detail ?? 'Composite proof confirmed.' })
      }
      lastRejection = {
        ...(res.rejectedBy ? { rejectedBy: res.rejectedBy } : {}),
        ...(res.compositeRejectedBy ? { compositeRejectedBy: res.compositeRejectedBy } : {}),
        ...(res.reason ? { reason: res.reason } : {}),
        ...(res.detail ? { detail: res.detail } : {}),
      }
      return makeToolResult({ confirmed: false, title: verifyTitle, rejectedBy: res.rejectedBy ?? null, reason: res.reason ?? 'unconfirmed', detail: res.detail ?? 'Verification did not confirm.', missingEvidence: res.missingEvidence, usageHint: res.usageHint })
    },
    complete_intent: async (completion: IntentCompletion) => {
      completionSummary = completion.summary?.trim() || completion.status
      return { ok: true, status: completion.status }
    },
  }

  const confirmedResult = (): ProofWriterResult => ({ confirmed: true, ...(findingId ? { findingId } : {}), spendUsd, turns: Math.max(turns, attempts > 0 ? 1 : 0), attempts })
  const budgetMsg = () => `budget_cap_exceeded: spend $${spendUsd.toFixed(4)} reached cap $${budgetCapUsd.toFixed(4)}`

  try {
    const sessionResult = await sessionRunner({
      directory: process.cwd(),
      runId: input.runId,
      sessionId: `proof-writer:${input.assignmentId}`,
      requestId: `proof-writer:${input.runId}:${input.assignmentId}`,
      profiles: deps.profiles,
      scenario: 'worker-investigation',
      instructions: buildProofWriterSystemPrompt(),
      prompt: buildProofWriterUserPrompt(input),
      signal: localAbort.signal,
      maxTurns,
      wallClockMs,
      compaction: false,
      enableSettlement: false,
      requireCompleteIntent: false,
      allowLegacyReplaySpec: false,
      handlers,
      beforeCall: () => {
        if (confirmed) { localAbort.abort(new ProofWriterShortCircuitError()); throw new ProofWriterShortCircuitError() }
        if (spendUsd >= budgetCapUsd) { budgetExceeded = true; const err = new ProofWriterBudgetError(spendUsd, budgetCapUsd); localAbort.abort(err); throw err }
        const pending = deps.beforeCall?.()
        if (pending && typeof (pending as Promise<void>).then === 'function') {
          void (pending as Promise<void>).catch(err => { beforeCallError = formatError(err); localAbort.abort(err) })
        }
      },
      onUsage: usage => {
        if (typeof usage.costUsd === 'number' && Number.isFinite(usage.costUsd) && usage.costUsd > 0) spendUsd += usage.costUsd
        deps.onUsage?.({ costUsd: usage.costUsd, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens })
      },
      onTurn: turn => { if (turn > turns) turns = turn },
      ...(deps.onProfileSuccess ? { onProfileSuccess: deps.onProfileSuccess } : {}),
      ...(deps.onProfileFailure ? { onProfileFailure: deps.onProfileFailure } : {}),
    })

    turns = Math.max(turns, sessionResult.turnsUsed ?? 0)
    if (confirmed) return confirmedResult()
    const error = budgetExceeded ? budgetMsg()
      : beforeCallError ?? (parentAborted || deps.signal?.aborted ? 'aborted'
        : sessionResult.status === 'wall_clock_rotated' ? `wall_clock_timeout: exceeded ${wallClockMs}ms`
        : sessionResult.status === 'turn_limit' ? `max_turns_reached: ${turns}/${maxTurns}`
        : completionSummary ? `unconfirmed: ${completionSummary}`
        : !lastRejection ? 'unconfirmed: specialist ended without confirming proof' : undefined)
    return {
      confirmed: false, spendUsd, turns, attempts,
      ...(lastRejection?.compositeRejectedBy ? { compositeRejectedBy: lastRejection.compositeRejectedBy } : {}),
      ...(lastRejection ? { lastRejection } : {}),
      ...(error ? { error } : {}),
    }
  } catch (err) {
    if (confirmed) return confirmedResult()
    const error = budgetExceeded || err instanceof ProofWriterBudgetError ? (err instanceof ProofWriterBudgetError ? err.message : budgetMsg())
      : beforeCallError ?? (parentAborted || deps.signal?.aborted ? 'aborted' : formatError(err))
    return {
      confirmed: false, spendUsd, turns, attempts,
      ...(lastRejection?.compositeRejectedBy ? { compositeRejectedBy: lastRejection.compositeRejectedBy } : {}),
      ...(lastRejection ? { lastRejection } : {}),
      error,
    }
  } finally {
    deps.signal?.removeEventListener('abort', onParentAbort)
  }
}
