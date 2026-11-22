/**
 * Live benchmark pipeline (placeholder entry point, expanded in follow-up commits).
 * Real engine execution is gated behind GUARDIAN_ALLOW_LOCAL_LAB=1 by the caller.
 */
import type {
  BenchmarkManifest,
  BenchmarkProfileMode,
  BenchmarkSuiteName,
  PatchVerificationSummary,
  TargetTrace,
} from './benchmark-core.ts'
import type { BenchmarkServerLauncher, VerifierBackendChoice } from './benchmark-recall.ts'

export interface LivePipelineArgs {
  suite: BenchmarkSuiteName
  manifest: BenchmarkManifest
  profileMode: BenchmarkProfileMode
  launcher?: BenchmarkServerLauncher
  verifierBackend: VerifierBackendChoice
  repoRootDir: string
}

export interface LivePipelineOutcome {
  traces: TargetTrace[]
  totalCostUsd: number
  verifierBackend: string | null
  notes: string[]
}

export async function runLivePipeline(_args: LivePipelineArgs): Promise<LivePipelineOutcome> {
  throw new Error('Live benchmark pipeline is not implemented yet.')
}

export async function verifyPatchesLive(_args: {
  manifest: BenchmarkManifest
  profileMode?: BenchmarkProfileMode
  launcher?: BenchmarkServerLauncher
  verifierBackend?: VerifierBackendChoice
  repoRootDir?: string
}): Promise<PatchVerificationSummary> {
  throw new Error('Patch verification is not implemented yet.')
}
