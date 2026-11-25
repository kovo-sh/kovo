import type { DeclarativeReplaySpec } from '../replay-spec.ts'

/**
 * Retired legacy JSON-to-`http_chain` proof compiler module (Bucket-3 consolidation).
 *
 * All runtime verification executes through `kovo_verify` (Layer-3 TypeScript SDK + independent
 * transcript oracle + `ProofReceipt` / `CompositeProofReceipt`). This module keeps only the
 * minimal type-only contract required by `agent-prompts.ts` (`CompiledProof`) until the prompt
 * handler type is removed in a follow-up cut.
 */
export const proofToolNames = [] as const

export type ProofToolName = typeof proofToolNames[number]

export interface CompiledProof {
  spec: Extract<DeclarativeReplaySpec, { kind: 'http_chain' }>
  assertionsJq: string
  spaCatchallControl: boolean
  rationale: string
  warnings: string[]
}
