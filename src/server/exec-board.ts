import {
  parseBoardMentions,
  specialistHandleByProfile,
  specialistProfileByHandle,
  type BoardAuthorRole,
  type BoardMessageKind,
  type Finding,
  type InlineVerifyFeedback,
  type VerificationTier,
} from '../domain.ts'
import { buildBoardDelta, type WarmSpecialistController } from './agent-session.ts'
import { computeDynamicStepBudget, hardChainStepsCeiling } from './exec-dispatch.ts'
import type { NamedSecret } from './redact.ts'
import type { Assignment, BoardMessageRow, ChainStep, Run, Store } from './store.ts'

export interface ExecBoardHost {
  storage: Store
  warm: WarmSpecialistController
  boardHandleByAssignment: Map<string, string>
  approvedOriginsSet: (run: Run) => Set<string>
  scheduleWake: () => void
}

/**
 * Swarm Board lifecycle & deterministic poster wiring extracted from `Execution`.
 * Owns board cursors, hop resets, sharded handle allocation, and warm-member mirroring.
 */
export class ExecBoardManager {
  private readonly host: ExecBoardHost
  readonly boardAssignmentTokens = new Map<string, number>()
  readonly boardHandleTokens = new Map<string, number>()
  readonly wakeHandleByStepId = new Map<string, string>()
  private readonly routedOperatorBoardSeq = new Map<string, number>()
  private readonly wokenBoardMessageKeys = new Set<string>()
  private readonly postedVerdictKeys = new Set<string>()
  private readonly postedCanaryKeys = new Set<string>()
  private readonly boardScopeSync = new Map<string, string>()
  readonly trackedBoardRuns = new Set<string>()

  constructor(host: ExecBoardHost) {
    this.host = host
  }

  private get storage(): Store { return this.host.storage }
  private get warm(): WarmSpecialistController { return this.host.warm }
  private get boardHandleByAssignment(): Map<string, string> { return this.host.boardHandleByAssignment }

  private boardHost(origin: string): string {
    try { return new URL(origin).hostname } catch { return origin }
  }

  /** Store-level board writes are advisory: a rejected/malformed post must never break the run. */
  postBoard(run: Run, input: {
    authorHandle: string
    authorRole: BoardAuthorRole
    kind: BoardMessageKind
    body: string
    mentions?: readonly string[]
    refFactIds?: readonly string[]
    refExchangeIds?: readonly string[]
    refFindingIds?: readonly string[]
    refStepId?: string | null
    refApprovalId?: string | null
    sourceOrigins?: readonly string[]
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow | null {
    try {
      this.trackedBoardRuns.add(run.id)
      return this.storage.postBoardMessage(run, input, secrets)
    } catch {
      return null
    }
  }

  isPeerBoardHandle(handle: string): boolean {
    return !['all', 'system', 'operator', 'coordinator', 'verifier', 'broker', 'canary'].includes(handle)
  }

  /** Plain text (or @coordinator) goes to the legacy coordinator thread; @specialist routes to that peer. */
  shouldCoordinatorAnswer(content: string): boolean {
    const mentions = parseBoardMentions(content)
    const peers = mentions.filter(handle => this.isPeerBoardHandle(handle))
    return peers.length === 0 || mentions.includes('coordinator')
  }

  private boardBaseHandle(handle: string): string {
    return handle.replace(/-(?:\d+|r\d+)$/, '')
  }

  boardProfileForHandle(handle: string) {
    return specialistProfileByHandle[this.boardBaseHandle(handle)] ?? null
  }

  private boardMemberMentionable(run: Run, handle: string): boolean {
    const member = this.storage.boardMember(run.id, handle)
    if (member) return member.state !== 'retired'
    return Boolean(this.boardProfileForHandle(handle)) ||
      ['coordinator', 'operator', 'verifier', 'broker', 'canary', 'all'].includes(handle)
  }

  /** Resolve the roster handle for an assignment (mapped at step start, else derived from its step profile). */
  boardHandleForAssignmentId(run: Run, assignmentId: string): string {
    const mapped = this.boardHandleByAssignment.get(assignmentId)
    if (mapped) return mapped
    const existing = this.storage.listBoardMembers(run.id).find(member => member.activeAssignmentId === assignmentId)
    if (existing) return existing.handle
    try {
      const worker = this.storage.worker(assignmentId)
      const step = worker.stepId
        ? this.storage.listChainSteps(run.id, run.goalRevision).find(candidate => candidate.id === worker.stepId)
        : undefined
      if (step?.specialistProfile) return specialistHandleByProfile[step.specialistProfile]
    } catch { /* assignment may be gone */ }
    return 'coordinator'
  }

  private boardAuthorForAssignmentId(run: Run, assignmentId: string): { handle: string; role: BoardAuthorRole } {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member) return { handle, role: member.role }
    if (handle === 'coordinator') return { handle, role: 'coordinator' }
    if (handle === 'verifier') return { handle, role: 'verifier' }
    return { handle, role: 'specialist' }
  }

  /** Sharded handle allocation: reuse base while free, then base-2..9, then recycle a waiting shard. */
  allocateBoardHandle(run: Run, profile: NonNullable<ChainStep['specialistProfile']>, step: ChainStep): string {
    const base = specialistHandleByProfile[profile]
    if (step.trialGroupId) return `${base}-${Math.max(1, step.trialIndex + 1)}`
    const members = this.storage.listBoardMembers(run.id)
    if (!members.some(member => member.handle === base)) return base
    for (let shard = 2; shard <= 9; shard += 1) {
      const handle = `${base}-${shard}`
      if (!members.some(member => member.handle === handle)) return handle
    }
    const waiting = members
      .filter(member => member.handle.startsWith(base + '-') && member.state === 'waiting' && !member.activeAssignmentId)
      .sort((a, b) => a.updatedAt - b.updatedAt)[0]
    return waiting?.handle ?? `${base}-r${members.filter(member => member.handle.startsWith(base)).length + 1}`
  }

  /** Deterministic @coordinator brief emitted when a chain step is dispatched. */
  postCoordinatorBrief(run: Run, step: ChainStep, handle: string, origins: readonly string[]): BoardMessageRow | null {
    if (!this.boardMemberMentionable(run, handle)) return null
    const targets = origins.map(origin => this.boardHost(origin)).join(', ')
    const body = `Brief · ${step.title} [${step.category}] on ${targets}. Hypothesis: ${step.hypothesis}`.slice(0, 900)
    return this.postBoard(run, {
      authorHandle: 'coordinator',
      authorRole: 'coordinator',
      kind: 'brief',
      body,
      mentions: [handle],
      refStepId: step.id,
      sourceOrigins: [...origins],
    })
  }

  /** Deterministic @verifier verdict for inline and Phase-3 Zero-LLM verification. */
  postVerificationVerdict(run: Run, opts: {
    replaySpecId: string
    findingId?: string | null
    title: string
    status: Finding['status']
    verificationTier?: VerificationTier | null
    feedback?: InlineVerifyFeedback | null
    assignmentId?: string | null
    refStepId?: string | null
    attempt?: number
    secrets?: readonly NamedSecret[]
  }): BoardMessageRow | null {
    const key = `${run.id}:${opts.replaySpecId}:${opts.status}:${opts.findingId ?? ''}:${opts.attempt ?? ''}`
    if (this.postedVerdictKeys.has(key)) return null
    this.postedVerdictKeys.add(key)
    const confirmed = opts.status === 'confirmed' || opts.status === 'static_verified'
    const authorHandle = opts.assignmentId ? this.boardHandleForAssignmentId(run, opts.assignmentId) : 'coordinator'
    const feedback = opts.feedback
    const body = confirmed
      ? `Verdict · ${opts.title.slice(0, 300)} — ${opts.status}${opts.verificationTier ? ` (${opts.verificationTier})` : ''} [spec: ${opts.replaySpecId}${opts.findingId ? `, finding: ${opts.findingId}` : ''}]`
      : [
          `Verdict · spec ${opts.replaySpecId} ${opts.status}:`,
          feedback?.assertionSummary?.observed ?? 'replay did not confirm',
          feedback?.assertionSummary?.expected ? `(expected ${feedback.assertionSummary.expected})` : '',
          feedback?.failedStepId ? `[step: ${feedback.failedStepId}]` : '',
          feedback?.jqError ? `jq=${feedback.jqError.slice(0, 160)}` : '',
        ].filter(Boolean).join(' ').slice(0, 900)
    const mentions = !confirmed && this.boardMemberMentionable(run, authorHandle) ? [authorHandle] : []
    let authorOrigins: string[] = []
    if (opts.assignmentId) {
      try { authorOrigins = this.storage.worker(opts.assignmentId).sourceOrigins } catch { /* assignment may be gone */ }
    }
    const basePayload = {
      authorHandle: 'verifier' as const,
      authorRole: 'verifier' as const,
      kind: 'verdict' as const,
      body,
      ...(opts.findingId ? { refFindingIds: [opts.findingId] } : {}),
      ...(opts.refStepId ? { refStepId: opts.refStepId } : {}),
    }
    const sent = this.postBoard(run, {
      ...basePayload,
      mentions,
      ...(authorOrigins.length ? { sourceOrigins: authorOrigins } : {}),
    }, opts.secrets)
    if (sent || !mentions.length) return sent
    // A retired/unknown author handle must not lose the verdict: post without the mention.
    return this.postBoard(run, basePayload, opts.secrets)
  }

  /** Deterministic @broker blocker for circuit-open / repeated 429 conditions. */
  postBrokerBlocker(run: Run, origin: string, status?: number): BoardMessageRow | null {
    const reason = status === 429 ? 'HTTP 429 rate limiting' : 'repeated 5xx/429 responses'
    return this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'blocker',
      body: `Blocker · circuit open on ${this.boardHost(origin)} after ${reason}; further traffic to this origin is paused while healthy hosts continue.`,
      mentions: ['all'],
      sourceOrigins: [origin],
    })
  }

  /** Tier-3 gate: pause the warm member and post an approval card linked by refApprovalId. */
  postApprovalCard(run: Run, assignmentId: string, input: {
    approvalId: string
    origin: string
    method: string
    pathAndQuery: string
    rationale: string
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow | null {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member && member.role === 'specialist') {
      try {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'paused', activeAssignmentId: assignmentId })
        this.warm.register(handle, { sessionId: member.sessionId, state: 'working', lastReadSeq: member.lastReadSeq })
        this.warm.pause(handle, assignmentId)
      } catch { /* roster mirror is best-effort */ }
    }
    return this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'approval',
      body: `Approval required · Tier ${run.capabilityTier} ${input.method.toUpperCase()} ${this.boardHost(input.origin)}${input.pathAndQuery} — ${input.rationale.slice(0, 400)}`,
      mentions: [handle],
      refApprovalId: input.approvalId,
      sourceOrigins: [input.origin],
    }, secrets)
  }

  postApprovalResolution(run: Run, assignmentId: string, input: {
    approvalId: string
    decision: string
    origin: string
    method: string
    pathAndQuery: string
  }): void {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member && member.role === 'specialist' && member.state === 'paused') {
      try {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'working', activeAssignmentId: assignmentId })
        this.warm.register(handle, { sessionId: member.sessionId, state: 'paused', lastReadSeq: member.lastReadSeq })
        this.warm.resume(handle, assignmentId)
      } catch { /* roster mirror is best-effort */ }
    }
    this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'status',
      body: `Tier-3 ${input.decision} · ${input.method.toUpperCase()} ${this.boardHost(input.origin)}${input.pathAndQuery}`,
      mentions: this.boardMemberMentionable(run, handle) ? [handle] : [],
      refApprovalId: input.approvalId,
      sourceOrigins: [input.origin],
    })
  }

  /** Deterministic @canary lead on OOB callbacks and second-order surfaces. */
  postCanaryLead(run: Run, input: {
    marker?: string
    origin: string
    endpoint?: string
    persona?: string | null
    exchangeId?: string | null
    mediaType?: string | null
    key?: string
  }): BoardMessageRow | null {
    const key = input.key ?? `${run.id}:${input.marker ?? ''}:${input.origin}:${input.endpoint ?? ''}:${input.exchangeId ?? ''}`
    if (this.postedCanaryKeys.has(key)) return null
    this.postedCanaryKeys.add(key)
    const target = /html|render|page|admin/i.test(`${input.endpoint ?? ''} ${input.mediaType ?? ''}`) ? 'browser' : 'injection'
    const body = [
      'Lead · canary surfaced',
      input.endpoint ? `at ${input.endpoint}` : '',
      input.persona ? `via persona ${input.persona}` : '',
      input.mediaType ? `(${input.mediaType})` : '',
      input.exchangeId ? `[exchange: ${input.exchangeId}]` : '',
      '— second-order/cross-persona evidence; treat as a hypothesis until replay-verified.',
    ].filter(Boolean).join(' ').slice(0, 900)
    return this.postBoard(run, {
      authorHandle: 'canary',
      authorRole: 'system',
      kind: 'lead',
      body,
      mentions: [target],
      ...(input.exchangeId ? { refExchangeIds: [input.exchangeId] } : {}),
      sourceOrigins: [input.origin],
    })
  }

  /** Turn-start delta: sanitized peer posts only, plus the cursor to persist atomically. */
  boardTurnDelta(run: Run, handle: string, lastReadSeq: number): { text: string; cursor: number } {
    const delta = buildBoardDelta({ store: this.storage, run: run.id, handle, lastReadSeq })
    try {
      this.storage.updateBoardMemberState(run.id, handle, { lastReadSeq: delta.cursor })
      this.warm.noteBoardCursor(handle, delta.cursor)
    } catch { /* member may have been retired between turns */ }
    return { text: delta.text, cursor: delta.cursor }
  }

  /** Operator/coordinator intervention resets every member's consecutive peer-hop budget. */
  resetBoardHops(run: Run): void {
    for (const member of this.storage.listBoardMembers(run.id)) {
      if (member.peerHopsUsed === 0) continue
      try { this.storage.updateBoardMemberState(run.id, member.handle, { peerHopsUsed: 0 }) } catch { /* ignore */ }
    }
    this.warm.noteEvidence()
  }

  /** Retire/sleep warm members on stop, scope revoke, and mirror roster rows into the controller. */
  syncBoardRoster(run: Run): void {
    this.trackedBoardRuns.add(run.id)
    const signature = `${run.scopeRevision}:${run.status}:${run.phase}`
    if (this.boardScopeSync.get(run.id) !== signature) {
      this.boardScopeSync.set(run.id, signature)
      if (run.status !== 'running' || run.phase === 'complete') {
        for (const member of this.storage.listBoardMembers(run.id)) {
          if (member.role !== 'specialist' || member.state === 'retired') continue
          try { this.storage.retireBoardMember(run, member.handle, `Run ${run.status}.`) } catch { /* ignore */ }
          this.warm.retire(member.handle, `run_${run.status}`)
        }
        this.trackedBoardRuns.delete(run.id)
        return
      } else {
        try {
          const revoked = this.storage.taintBoardMessagesForRevokedOrigins(run.id, this.host.approvedOriginsSet(run))
          for (const handle of revoked.retiredHandles) this.warm.retire(handle, 'scope_revoked')
        } catch { /* store may be closing */ }
      }
    }
    for (const member of this.storage.listBoardMembers(run.id)) {
      this.warm.register(member.handle, {
        sessionId: member.sessionId,
        state: member.state === 'working' ? 'working' : member.state === 'paused' ? 'paused' : 'waiting',
        turnsUsed: member.turnsUsed,
        postsCount: member.postsCount,
        peerHopsUsed: member.peerHopsUsed,
        lastReadSeq: member.lastReadSeq,
      })
      if (member.state === 'retired') this.warm.retire(member.handle, 'roster_retired')
    }
  }

  /** Operator composer: plain text is handled by the legacy coordinator thread; @handle wakes that peer. */
  routeOperatorBoardMessages(run: Run): void {
    this.trackedBoardRuns.add(run.id)
    const cursor = this.routedOperatorBoardSeq.get(run.id) ?? 0
    const msgs = this.storage.listBoardMessages(run.id, {
      authorHandle: 'operator', sinceSeq: cursor, limit: 100, includeTainted: false,
    })
    if (!msgs.length) return
    this.resetBoardHops(run)
    for (const message of msgs) {
      const targets = message.mentions.filter(handle => handle !== 'all' && this.isPeerBoardHandle(handle))
      for (const target of targets) this.wakeBoardMember(run, target, message)
    }
    this.routedOperatorBoardSeq.set(run.id, msgs[msgs.length - 1].seq)
  }

  /** Queue a chain-scoped follow-up step for a woken member (respects budget + workerConcurrency). */
  wakeBoardMember(run: Run, handle: string, message: BoardMessageRow): ChainStep | null {
    if (run.status !== 'running' || run.phase !== 'investigation') return null
    if (this.storage.checkBudgetExceeded(run.id)) return null
    const profile = this.boardProfileForHandle(handle)
    if (!profile) return null
    const key = `${run.id}:${message.id}:${handle}`
    if (this.wokenBoardMessageKeys.has(key)) return null
    const member = this.storage.boardMember(run.id, handle)
    if (member?.state === 'paused' || member?.state === 'working') return null

    const approved = this.host.approvedOriginsSet(run)
    const origins = [...new Set([
      ...message.sourceOrigins.filter(origin => approved.has(origin)),
      ...(member?.sourceOrigins ?? []).filter(origin => approved.has(origin)),
    ])]
    if (!origins.length) return null
    const assetIds = run.candidates
      .filter(candidate => run.approved.includes(candidate.id) && origins.includes(candidate.origin))
      .map(candidate => candidate.id)
    if (!assetIds.length) return null

    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const pendingWake = steps.some(candidate =>
      this.wakeHandleByStepId.get(candidate.id) === handle &&
      (candidate.status === 'ready' || candidate.status === 'pending'))
    if (pendingWake) return null
    const dynamicBudget = Math.max(1, Math.min(hardChainStepsCeiling, run.dynamicStepBudget ?? computeDynamicStepBudget(this.storage, run.id)))
    if (steps.length >= dynamicBudget) return null

    this.wokenBoardMessageKeys.add(key)
    const step = this.storage.addChainStep(run, {
      title: `Peer handoff · @${handle}`.slice(0, 200),
      hypothesis: `Follow up ${message.kind} from @${message.authorHandle}: ${message.body}`.slice(0, 1200),
      category: 'misconfig-exposure',
      priority: message.kind === 'blocker' ? 92 : 88,
      targetAssetIds: assetIds,
      sourceOrigins: origins,
      dependsOnFactIds: message.refFactIds,
      specialistProfile: profile,
    })
    this.wakeHandleByStepId.set(step.id, handle)
    if (!member) {
      try {
        this.storage.upsertBoardMember(run, {
          handle,
          role: 'specialist',
          specialistProfile: profile,
          state: 'waiting',
          sourceOrigins: origins,
        })
        this.warm.register(handle, { state: 'waiting' })
      } catch { /* roster mirror is best-effort */ }
    }
    this.storage.event(run.id, 'board.wakeup', `@${handle} queued from @${message.authorHandle}'s ${message.kind} (board #${message.seq}).`, {
      handle, messageSeq: message.seq, stepId: step.id,
    })
    this.host.scheduleWake()
    return step
  }

  /** Sleep (waiting, same session) or retire a warm member after its assignment finishes. */
  finishBoardMember(run: Run, assignmentId: string): void {
    const handle = this.boardHandleByAssignment.get(assignmentId)
    if (!handle) return
    const tokens = this.boardHandleTokens.get(handle) ?? this.boardAssignmentTokens.get(assignmentId) ?? 0
    this.boardHandleByAssignment.delete(assignmentId)
    this.boardAssignmentTokens.delete(assignmentId)
    let worker: Assignment | undefined
    try { worker = this.storage.worker(assignmentId) } catch { /* deleted */ }
    const succeeded = worker?.status === 'complete'
    const completion = this.warm.completeTurn(handle, { tokensUsed: tokens })
    try {
      if (!succeeded || completion?.state === 'retired') {
        this.warm.retire(handle, completion?.retiredReason ?? 'step_failed')
        this.storage.updateBoardMemberState(run.id, handle, { state: 'retired', activeAssignmentId: null })
        this.boardHandleTokens.delete(handle)
      } else {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'waiting', activeAssignmentId: null })
      }
    } catch { /* roster mirror is best-effort */ }
    if (completion?.closureRequired) {
      const author = this.boardAuthorForAssignmentId(run, assignmentId)
      this.postBoard(run, {
        authorHandle: author.handle,
        authorRole: author.role,
        kind: 'status',
        body: `Closure · @${author.handle}: ${(worker?.outcome ?? 'step complete').slice(0, 700)}`,
        ...(worker?.stepId ? { refStepId: worker.stepId } : {}),
      })
    }
  }

  noteTokens(assignmentId: string, handle: string, tokens: number): void {
    this.boardAssignmentTokens.set(assignmentId, (this.boardAssignmentTokens.get(assignmentId) ?? 0) + tokens)
    this.boardHandleTokens.set(handle, (this.boardHandleTokens.get(handle) ?? 0) + tokens)
  }

  syncTrackedRuns(): void {
    for (const runId of [...this.trackedBoardRuns]) {
      try { this.syncBoardRoster(this.storage.run(runId)) } catch { this.trackedBoardRuns.delete(runId) }
    }
  }
}
