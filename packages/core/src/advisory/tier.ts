import {
  TIER_REASON_TIER,
  type Severity,
  type Tier,
  type TierConfigSets,
  type TierReason,
} from "@kovo/contracts";

// SPEC "Inventory, advisories, and tiering", verbatim:
//
//   function tier(f: Finding, a: Advisory, kev: Set<string>, cfg: TierConfig): Tier {
//     if (a.isMalicious) return 'P0';
//     if (f.isDev) return 'digest';
//     if (a.aliases.some(id => kev.has(id))) return 'P0';
//     if (!['HIGH', 'CRITICAL'].includes(a.severity)) return 'digest';
//     if (cfg.p0Packages.has(f.package) && a.cweIds.some(c => cfg.p0Cwes.has(c))) return 'P0';
//     return 'P1';
//   }
//
// `tierDecision` is that function with the branch that decided recorded (contracts
// `TIER_REASONS`, one per branch in order) together with the config version ("evidence records
// the tiering config version"); `tier` returns only the tier.

/** The finding facts `tier()` reads. */
export interface TierFinding {
  readonly package: string;
  readonly isDev: boolean;
}

/** The advisory facts `tier()` reads. */
export interface TierAdvisory {
  readonly isMalicious: boolean;
  readonly aliases: readonly string[];
  readonly severity: Severity;
  readonly cweIds: readonly number[];
}

export interface TierDecision {
  readonly tier: Tier;
  readonly reason: TierReason;
  /** The `TierConfig.version` the decision used. */
  readonly configVersion: string;
}

function decide(reason: TierReason, cfg: TierConfigSets): TierDecision {
  return { tier: TIER_REASON_TIER[reason], reason, configVersion: cfg.version };
}

/** SPEC's `tier()` with the deciding branch and the config version. */
export function tierDecision(
  f: TierFinding,
  a: TierAdvisory,
  kev: ReadonlySet<string>,
  cfg: TierConfigSets,
): TierDecision {
  if (a.isMalicious) return decide("malicious", cfg);
  if (f.isDev) return decide("dev_dependency", cfg);
  if (a.aliases.some((id) => kev.has(id))) return decide("kev", cfg);
  if (!["HIGH", "CRITICAL"].includes(a.severity)) return decide("not_high_or_critical", cfg);
  if (cfg.p0Packages.has(f.package) && a.cweIds.some((c) => cfg.p0Cwes.has(c))) {
    return decide("curated_package_and_cwe", cfg);
  }
  return decide("high_or_critical", cfg);
}

/** SPEC's `tier()`. */
export function tier(
  f: TierFinding,
  a: TierAdvisory,
  kev: ReadonlySet<string>,
  cfg: TierConfigSets,
): Tier {
  return tierDecision(f, a, kev, cfg).tier;
}
