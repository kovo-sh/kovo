// Core types for benchmarks/oss-multihop/ (v8 M2 Dev & M4 Sealed OSS Multi-Hop Anchor Corpus).
// Pure TypeScript, zero npm dependencies, Node 24+ erasable syntax only.

export type AnchorSplit = 'dev' | 'sealed'
export type EvaluationMode = 'black-box' | 'grey-box' | 'white-box'
export type AnchorLanguage = 'go' | 'typescript' | 'javascript' | 'python' | 'java' | 'ruby' | 'php' | 'rust'

export type CausalEdgeBindingKind =
  | 'value_binding'
  | 'derived_crypto_binding'
  | 'state_transition_binding'
  | 'async_pivot_binding'

export type SurfaceKind =
  | 'http'
  | 'graphql'
  | 'ws'
  | 'sse'
  | 'browser'
  | 'webhook'
  | 'async_job'
  | 'idp'
  | 'cdn'
  | 'storage'

export type ComposeServiceRole =
  | 'app'
  | 'db'
  | 'cache'
  | 'worker'
  | 'idp'
  | 'internal_target'
  | 'lab_proxy'

export type OracleKind =
  | 'db_query'
  | 'container_log'
  | 'loopback_oob_collector'
  | 'file_integrity'

export type ReplayMode = 'fresh_clean_replay' | 'one_shot_transcript'

export interface BuildPinSpec {
  repoUrl: string
  /** Explicit release/version tag (never floating tags such as `latest` or `main`). */
  versionTag: string
  /** 40-character lowercase hex Git commit SHA. */
  commitSha: string
  /** Container image reference with explicit version tag (never `:latest`). */
  imageRef: string
  /** Pinned OCI digest (`sha256:<64-hex>`). */
  imageDigest: string
  /** Explicit lock state so placeholder pins are clearly distinguished from verified Docker locks. */
  pinVerification: 'pending_docker_lock' | 'locked'
  advisoryCategory?: string
}

export interface ComposeNetworkSpec {
  driver: 'bridge'
  /** MUST be `true` (`docker network create --internal`) — zero public egress. */
  internal: boolean
  attachable?: boolean
}

export interface ComposeServiceSpec {
  role: ComposeServiceRole
  imageRef: string
  imageDigest: string
  networks: string[]
  /** Allowed only on `app` or `lab_proxy`, and every entry MUST bind `127.0.0.1:<port>:<containerPort>`. */
  ports?: string[]
  /** Must never be `host` or another container's unisolated namespace. */
  networkMode?: string
  privileged?: boolean
  readOnlyRootFs?: boolean
  capDrop?: string[]
  capAdd?: string[]
  environment?: Record<string, string>
}

export interface IsolatedComposeSchema {
  version: '3.9'
  projectNamePrefix: string
  egressPolicy: 'deny_all_internal_only'
  labProxyMode: 'loopback_port_publish' | 'isolated_lab_proxy'
  networks: Record<string, ComposeNetworkSpec>
  services: Record<string, ComposeServiceSpec>
}

export interface AnchorHopSpec {
  hopId: string
  order: number
  serviceRole: ComposeServiceRole
  surface: SurfaceKind
  /** Defensive architectural description of the state/capability transition (zero exploit payloads). */
  summary: string
  incomingEdgeKind?: CausalEdgeBindingKind
  preconditionCapabilityKind?: string
  postconditionCapabilityKind: string
  expectedPatchBreak?: boolean
}

export interface ExternalImpactOracleBase {
  oracleId: string
  kind: OracleKind
  description: string
  targetService: string
  expectedCorrelationField: string
  pollTimeoutMs: number
  runScopedCanaryPrefix: string
}

export interface DbQueryOracleSpec extends ExternalImpactOracleBase {
  kind: 'db_query'
  engine: 'postgres' | 'mysql' | 'sqlite'
  /** Strictly read-only `SELECT` verification query against the isolated lab DB. */
  readOnlyQuery: string
  expectedPredicate: {
    column: string
    matchMode: 'equals' | 'contains' | 'row_count_gt_zero' | 'boolean_true'
    expectedValue?: string | number | boolean
  }
}

export interface ContainerLogOracleSpec extends ExternalImpactOracleBase {
  kind: 'container_log'
  containerRole: ComposeServiceRole
  stream: 'stdout' | 'stderr' | 'both'
  expectedPattern: string
  forbidPattern?: string
}

export interface LoopbackOobCollectorOracleSpec extends ExternalImpactOracleBase {
  kind: 'loopback_oob_collector'
  /** MUST resolve to loopback (`http://127.0.0.1:...` or `http://[::1]:...`). */
  collectorUrl: string
  expectedMethod: 'GET' | 'POST' | 'HEAD' | 'ANY'
  expectedPathPrefix: string
  requireCanaryToken: boolean
}

export interface FileIntegrityOracleSpec extends ExternalImpactOracleBase {
  kind: 'file_integrity'
  containerRole: ComposeServiceRole
  watchPath: string
  checkMode: 'marker_created' | 'checksum_changed' | 'canary_written'
  baselineSha256?: string
}

export type ExternalImpactOracleSpec =
  | DbQueryOracleSpec
  | ContainerLogOracleSpec
  | LoopbackOobCollectorOracleSpec
  | FileIntegrityOracleSpec

export interface SyntheticPersonaSpec {
  personaId: string
  role: 'attacker_low_priv' | 'attacker_member' | 'victim_admin' | 'service_account'
  username: string
  /** Synthetic credential handle (`oss_lab_*`), never real secret material. */
  credentialRef: string
  allowedAsChainOrigin: boolean
}

export interface OssAnchorManifest {
  schemaVersion: '1.0'
  anchorId: string
  name: string
  project: string
  split: AnchorSplit
  language: AnchorLanguage
  domain: string
  terminalVulnClass: string
  hopCount: number
  hops: AnchorHopSpec[]
  vulnerableBuild: BuildPinSpec
  patchedBuild: BuildPinSpec
  expectedPatchBrokeHopIds: string[]
  impactOracle: ExternalImpactOracleSpec
  personas: SyntheticPersonaSpec[]
  composeTemplate: IsolatedComposeSchema
  evaluationModes: EvaluationMode[]
  notes?: string
}

export interface CleanNegativeControlSpec {
  schemaVersion: '1.0'
  controlId: string
  name: string
  project: string
  language: AnchorLanguage
  domain: string
  patchedBuild: BuildPinSpec
  rationale: string
  /** Hard 0-FP requirement: any confirmed or claimed finding fails the gate. */
  maxAllowedFindings: 0
  personas: SyntheticPersonaSpec[]
  composeTemplate: IsolatedComposeSchema
  impactOracles: ExternalImpactOracleSpec[]
}

export interface ManifestBundle {
  schemaVersion: '1.0'
  bundleKind: 'dev_anchors' | 'sealed_anchors' | 'clean_controls'
  description: string
  anchors?: OssAnchorManifest[]
  cleanControls?: CleanNegativeControlSpec[]
}

export interface ValidationIssue {
  path: string
  code: string
  message: string
}

export interface ValidationResult {
  valid: boolean
  issues: ValidationIssue[]
}

// ---------------------------------------------------------------------------
// External Oracle Evaluation & Two-Side Grading Types
// ---------------------------------------------------------------------------

export interface ExternalOracleObservation {
  observationId: string
  targetId: string
  oracleId: string
  kind: OracleKind
  buildTarget: 'vulnerable' | 'patched'
  observed: boolean
  observedAtMs: number
  runId: string
  correlationId?: string
  matchedValue?: string
  matchedRows?: number
  detail: string
}

export type OracleProbeInput =
  | {
      kind: 'db_query'
      rows: Array<Record<string, string | number | boolean | null>>
      observedAtMs: number
      correlationId?: string
    }
  | {
      kind: 'container_log'
      lines: Array<{ stream: 'stdout' | 'stderr'; text: string; timestampMs?: number }>
      observedAtMs: number
      correlationId?: string
    }
  | {
      kind: 'loopback_oob_collector'
      requests: Array<{
        method: string
        path: string
        canaryToken?: string
        correlationId?: string
        receivedAtMs: number
      }>
      observedAtMs: number
      correlationId?: string
    }
  | {
      kind: 'file_integrity'
      exists: boolean
      sha256?: string
      contentPreview?: string
      observedAtMs: number
      correlationId?: string
    }

export interface CompositeReceiptHopSummary {
  hopId: string
  order: number
  surface: SurfaceKind
  actorPersona: string
  observedAtMs: number
  exchangeIds: string[]
}

export interface CompositeReceiptEdgeSummary {
  fromHopId: string
  toHopId: string
  bindingKind: CausalEdgeBindingKind
  verified: boolean
}

export interface GuardianCompositeProofReceipt {
  receiptId: string
  chainId: string
  targetId: string
  terminalVulnClass: string
  verified: boolean
  attackerOriginVerified: boolean
  originPersona: string
  replayMode: ReplayMode
  hops: CompositeReceiptHopSummary[]
  causalEdges: CompositeReceiptEdgeSummary[]
  terminalImpact: {
    observed: boolean
    oracleId?: string
    correlationId?: string
    observedAtMs: number
  }
  runId: string
}

export interface PatchRetestRecord {
  targetId: string
  receiptId: string
  patchedCommitSha: string
  replayedFullDag: boolean
  terminalImpactEliminated: boolean
  /** The exact hop where the paired official patch broke the multi-hop chain. */
  patchBrokeHopId: string | null
  patchedOracleObservation?: ExternalOracleObservation
  detail?: string
}

export interface RunTelemetry {
  runId: string
  split: AnchorSplit
  mode: EvaluationMode
  durationMs: number
  costUsd: number
}

export interface OssGradeInput {
  anchors: OssAnchorManifest[]
  cleanControls: CleanNegativeControlSpec[]
  receipts: GuardianCompositeProofReceipt[]
  oracleObservations: ExternalOracleObservation[]
  patchRetests: PatchRetestRecord[]
  telemetry: RunTelemetry
}

export type AnchorOutcomeStatus =
  | 'tp'
  | 'fn'
  | 'unconfirmed_oracle_only'
  | 'unconfirmed_receipt_only'
  | 'rejected_shortcut'
  | 'rejected_edge_binding'
  | 'rejected_replay_mode'
  | 'rejected_correlation'

export type PatchRetestStatus =
  | 'not_applicable'
  | 'closed'
  | 'open_still_reproduces'
  | 'missing_broke_hop'
  | 'invalid_broke_hop'
  | 'commit_mismatch'
  | 'not_run'

export interface AnchorGradeDetail {
  anchorId: string
  project: string
  split: AnchorSplit
  status: AnchorOutcomeStatus
  oracleConfirmed: boolean
  receiptConfirmed: boolean
  twoSideConfirmed: boolean
  matchedReceiptId?: string
  patchRetestStatus: PatchRetestStatus
  patchBrokeHopId: string | null
  maxObservedHopDepth: number
  reasons: string[]
}

export interface CleanControlGradeDetail {
  controlId: string
  project: string
  passed: boolean
  fpCount: number
  fpReceiptIds: string[]
  unexpectedOracleTriggers: number
  reasons: string[]
}

export interface HopDepthFunnel {
  h1: number
  h2: number
  h3: number
  h4Plus: number
  oracleObserved: number
  twoSideConfirmed: number
}

export interface OssGateEvaluation {
  passed: boolean
  precisionGatePassed: boolean
  cleanControlGatePassed: boolean
  recallGatePassed: boolean
  patchRetestGatePassed: boolean
  failures: string[]
}

export interface OssGradeResult {
  schemaVersion: '1.0'
  runId: string
  split: AnchorSplit
  mode: EvaluationMode
  totalAnchors: number
  tpCount: number
  fnCount: number
  unmatchedFpCount: number
  spuriousAnchorFpCount: number
  cleanControlCount: number
  cleanControlFpCount: number
  totalFpCount: number
  recall: number
  precision: number
  patchRetestAttempted: number
  patchRetestClosed: number
  patchRetestClosureRate: number
  tpPerUsd: number
  tpPer10m: number
  hopDepthFunnel: HopDepthFunnel
  anchorResults: AnchorGradeDetail[]
  cleanControlResults: CleanControlGradeDetail[]
  gates: OssGateEvaluation
}
