// @kovo/core/advisory: OSV/GHSA normalization, severity (GHSA label, CVSS v4.0/v3.x), npm range
// evaluation, matching, SPEC's tier(), the finding lifecycle, target resolution and the P1
// cooldown (BUILD_PLAN item 6). Pure: no I/O; time is always a parameter.

export {
  cooldownAllows,
  evaluateCooldown,
  type CooldownInput,
  type CooldownOutcome,
} from "./cooldown.js";
export {
  cvss3BaseScore,
  cvss4BaseScore,
  cvss4Score,
  parseCvss3,
  parseCvss4,
  roundup30,
  roundup31,
  scoreCvssEntry,
  type Cvss3Parse,
  type Cvss3ParseError,
  type Cvss3Version,
  type Cvss4Nomenclature,
  type Cvss4Parse,
  type Cvss4ParseError,
  type CvssScoring,
  type CvssVersion,
} from "./cvss/index.js";
export {
  dismissalIsCurrent,
  dismissFinding,
  escalatesDismissal,
  reconcileFindings,
  type AdvisoryState,
  type DismissOutcome,
  type FindingChange,
  type FindingChangeKind,
  type FindingState,
  type P0Detection,
  type ReconcileCounts,
  type ReconcileInput,
  type ReconcileResult,
} from "./findings.js";
export {
  introducedSevere,
  isIntroducedSevere,
  isSevere,
  severeBaseline,
  type SevereBaseline,
  type TieredMatch,
} from "./introduced.js";
export {
  indexAdvisories,
  matchAdvisories,
  type AdvisoryIndex,
  type AdvisoryMatch,
  type MatchInput,
  type ResolvedInstance,
} from "./match.js";
export {
  INTRODUCED_ZERO,
  LIMIT_INFINITY,
  advisoryRangeEventSchema,
  advisoryRangeSchema,
  normalizedAdvisorySchema,
  type AdvisoryFacts,
  type AdvisoryRange,
  type AdvisoryRangeEvent,
  type JsonObject,
  type NormalizedAdvisory,
} from "./model.js";
export {
  normalizeOsvRecord,
  type NormalizeDiagnostic,
  type NormalizeDiagnosticCode,
  type NormalizeFailureReason,
  type NormalizeIssue,
  type NormalizeOptions,
  type NormalizeResult,
} from "./normalize.js";
export { OSV_LIMITS } from "./osv-schema.js";
export {
  affectedSet,
  compileAdvisory,
  compiledAdvisoryAffects,
  compiledRangeAffects,
  compileRange,
  intervalContains,
  isAffected,
  rangeAffects,
  rangeIntervals,
  type AffectedSet,
  type CompiledAdvisory,
  type CompiledRange,
  type VersionBound,
  type VersionInterval,
} from "./ranges.js";
export {
  deriveSeverity,
  severityFromScore,
  type SeverityAssessment,
  type SeverityEntry,
  type SeverityInput,
  type VectorAssessment,
} from "./severity.js";
export {
  affectedWithin,
  latestRelease,
  publishedReleases,
  rangeAffectedness,
  releasesWithin,
  type RangeAffectedness,
  type VersionBounds,
} from "./published.js";
export { reviewedRemovalFeasible } from "./removal.js";
export {
  resolveTarget,
  type CandidateCounts,
  type InstanceChange,
  type RegistryVersion,
  type TargetInstance,
  type TargetRequest,
  type TargetResolution,
  type UnchangedInstance,
} from "./target.js";
export {
  tier,
  tierDecision,
  type TierAdvisory,
  type TierDecision,
  type TierFinding,
} from "./tier.js";
export {
  coerceOsvVersion,
  compareNpmVersions,
  compareVersionText,
  isNpmVersion,
  parseNpmVersion,
  parseVersionText,
  type CoercedVersion,
  type NpmVersion,
} from "./version.js";
