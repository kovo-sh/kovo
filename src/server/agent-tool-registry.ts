/**
 * Single authoritative metadata registry for every worker/coordinator tool registered
 * via `defineTool` in `src/server/agent-session.ts`.
 *
 * All settlement allowlists/revocation sets, route-evidence sets, proof-submission sets,
 * parallel read-only sets, and settlement banner lists derive directly from this table so
 * new network tools fail closed during settlement by default and runtime <-> prompt
 * contracts cannot drift.
 */

export type SettlementToolPhase =
  /** Disabled as soon as settlement starts (live network / active probing tools). */
  | 'revoked'
  /** Allowed in settlement only when no proof obligation is open; paused while `specPending`. */
  | 'spec_paused'
  /** Allowed in settlement until the final turn (read/query/legacy verify tools). */
  | 'wrapup'
  /** Always allowed through the final settlement turn (`kovo_verify`, closure tools). */
  | 'final_allowed'

export interface AgentToolMetadata {
  /** True for tools that send live network/browser traffic to target origins. */
  readonly network: boolean
  /** True for tools whose calls count as route evidence in `SpecSubmissionTracker`. */
  readonly routeEvidence: boolean
  /** True for proof/spec submission tools tracked by settlement & verify-grace. */
  readonly proofSubmission: boolean
  /** True for read-only tools safe to execute concurrently within a single tool round. */
  readonly parallelReadOnly: boolean
  /**
   * True when the tool is allowlisted during settlement.
   * Settlement gating uses this positive allowlist so any unknown or newly added network
   * tool fails closed during settlement.
   */
  readonly settlementAllowed: boolean
  /** Fine-grained settlement sub-phase gating. */
  readonly settlementPhase: SettlementToolPhase
}

export const AGENT_TOOL_REGISTRY = {
  // Live network / active probing tools (fail closed in settlement)
  request_http: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  request_http_batch: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  request_http_race: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  inspect_dns: {
    network: true,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  inspect_tls: {
    network: true,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  browser_visit: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  browser_session: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  crawl_state_graph: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  probe_surface: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  probe_differential: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  run_safe_templates: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },
  probe_websocket: {
    network: true,
    routeEvidence: true,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: false,
    settlementPhase: 'revoked',
  },

  // Host-executed Q2 read-only repo & evidence tools (parallel, wrapup-allowed)
  read_repo_file: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  search_repo: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  read_evidence_slice: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },

  // Offline / static analysis tools (paused during settlement while a proof obligation is open)
  run_sast_scan: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  run_offline_script: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  derive_evidence: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  analyze_artifact: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },

  // Read/query wrap-up tools (allowed during settlement until the final turn)
  query_cves: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  load_skill: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  search_exchanges: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  get_exchange: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  search_facts: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  read_peer_trace: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  expand_digest: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  board_read: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },

  // Canary tools (checking planted OOB canaries stays available during wrap-up; minting/listing pause while specPending)
  mint_canary: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  check_canary: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },
  mint_second_order_canary: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  list_second_order_canaries: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },

  // Coordinator / graph query tools (paused while proof obligation is open)
  query_endpoints: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  query_program_graph: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  query_facts: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  query_findings: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: true,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  dispatch_investigations: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'final_allowed',
  },

  // Proof submission tools
  kovo_verify: {
    network: false,
    routeEvidence: false,
    proofSubmission: true,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'final_allowed',
  },
  propose_chain_finding: {
    network: false,
    routeEvidence: false,
    proofSubmission: true,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'final_allowed',
  },
  update_proposed_finding: {
    network: false,
    routeEvidence: false,
    proofSubmission: true,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'final_allowed',
  },
  verify_replay_spec: {
    network: false,
    routeEvidence: false,
    proofSubmission: true,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'wrapup',
  },

  // Closure, recording, and coordination tools
  record_fact: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'final_allowed',
  },
  record_coverage: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'final_allowed',
  },
  suggest_candidate_host: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  board_post: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'spec_paused',
  },
  complete_intent: {
    network: false,
    routeEvidence: false,
    proofSubmission: false,
    parallelReadOnly: false,
    settlementAllowed: true,
    settlementPhase: 'final_allowed',
  },
} as const satisfies Record<string, AgentToolMetadata>

export type AgentToolName = keyof typeof AGENT_TOOL_REGISTRY

export const AGENT_TOOL_NAMES = Object.keys(AGENT_TOOL_REGISTRY) as readonly AgentToolName[]

function deriveToolSet(predicate: (meta: AgentToolMetadata) => boolean): ReadonlySet<string> {
  return new Set(
    (Object.entries(AGENT_TOOL_REGISTRY) as Array<[AgentToolName, AgentToolMetadata]>)
      .filter(([, meta]) => predicate(meta))
      .map(([name]) => name),
  )
}

/** Positive allowlist of tools permitted during settlement (unknown / new network tools fail closed). */
export const SETTLEMENT_ALLOWED_TOOLS: ReadonlySet<string> = deriveToolSet(meta => meta.settlementAllowed)

/** Registered tools revoked as soon as settlement begins (`!settlementAllowed`). */
export const SETTLEMENT_REVOKED_TOOLS: ReadonlySet<string> = deriveToolSet(meta => !meta.settlementAllowed)

/** Tools permitted during settlement until the final turn (`settlementPhase === 'wrapup'`). */
export const SETTLEMENT_WRAPUP_TOOLS: ReadonlySet<string> = deriveToolSet(meta => meta.settlementPhase === 'wrapup')

/** Offline/analysis tools paused during settlement while a probed route still owes a proof. */
export const SETTLEMENT_SPEC_PAUSED_TOOLS: ReadonlySet<string> = deriveToolSet(meta => meta.settlementPhase === 'spec_paused')

/** Live network / browser tools. */
export const NETWORK_TOOLS: ReadonlySet<string> = deriveToolSet(meta => meta.network)

/** Tools whose calls count as route evidence in `SpecSubmissionTracker`. */
export const ROUTE_EVIDENCE_TOOLS: ReadonlySet<string> = deriveToolSet(meta => meta.routeEvidence)

/** Proof/spec submission tools tracked by settlement and verify-grace. */
export const SPEC_SUBMISSION_TOOLS: ReadonlySet<string> = deriveToolSet(meta => meta.proofSubmission)

/** Read-only tools safe to execute concurrently within a single tool round. */
export const PARALLEL_READ_ONLY_TOOLS: ReadonlySet<string> = deriveToolSet(meta => meta.parallelReadOnly)

/** Lookup helper for a tool's authoritative metadata entry (undefined for unregistered/extra tools). */
export function getAgentToolMetadata(name: string): AgentToolMetadata | undefined {
  return Object.prototype.hasOwnProperty.call(AGENT_TOOL_REGISTRY, name)
    ? AGENT_TOOL_REGISTRY[name as AgentToolName]
    : undefined
}
