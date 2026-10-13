// CVSS v3.0 / v3.1 base scores (FIRST CVSS v3.1 specification §7.1 and Appendix A; v3.0
// specification §8.1). Only the Base score is computed: SPEC derives severity "from the highest
// supported CVSS v4/v3 vector", and GHSA/NVD publish v3 vectors to be read by their Base score.
// Temporal and environmental metrics are validated when present but do not change the result.

export type Cvss3Version = "3.0" | "3.1";

const BASE_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const;
type BaseMetric = (typeof BASE_METRICS)[number];

/** Every metric a v3.x vector may carry, with its allowed values (v3.1 Table 15; same for v3.0). */
const ALLOWED_VALUES: Readonly<Record<string, readonly string[]>> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  PR: ["N", "L", "H"],
  UI: ["N", "R"],
  S: ["U", "C"],
  C: ["H", "L", "N"],
  I: ["H", "L", "N"],
  A: ["H", "L", "N"],
  E: ["X", "H", "F", "P", "U"],
  RL: ["X", "U", "W", "T", "O"],
  RC: ["X", "C", "R", "U"],
  CR: ["X", "H", "M", "L"],
  IR: ["X", "H", "M", "L"],
  AR: ["X", "H", "M", "L"],
  MAV: ["X", "N", "A", "L", "P"],
  MAC: ["X", "L", "H"],
  MPR: ["X", "N", "L", "H"],
  MUI: ["X", "N", "R"],
  MS: ["X", "U", "C"],
  MC: ["X", "H", "L", "N"],
  MI: ["X", "H", "L", "N"],
  MA: ["X", "H", "L", "N"],
};

const ATTACK_VECTOR: Readonly<Record<string, number>> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const ATTACK_COMPLEXITY: Readonly<Record<string, number>> = { L: 0.77, H: 0.44 };
const USER_INTERACTION: Readonly<Record<string, number>> = { N: 0.85, R: 0.62 };
const IMPACT: Readonly<Record<string, number>> = { H: 0.56, L: 0.22, N: 0 };
/** Privileges Required depends on Scope: L is 0.68 and H is 0.50 when Scope is Changed. */
const PRIVILEGES_UNCHANGED: Readonly<Record<string, number>> = { N: 0.85, L: 0.62, H: 0.27 };
const PRIVILEGES_CHANGED: Readonly<Record<string, number>> = { N: 0.85, L: 0.68, H: 0.5 };

export type Cvss3ParseError =
  | "bad_prefix"
  | "malformed_metric"
  | "unknown_metric"
  | "invalid_value"
  | "duplicate_metric"
  | "missing_base_metric";

export type Cvss3Parse =
  | {
      readonly ok: true;
      readonly version: Cvss3Version;
      readonly metrics: Readonly<Record<string, string>>;
    }
  | { readonly ok: false; readonly error: Cvss3ParseError };

/**
 * Parses a v3.x vector strictly: the `CVSS:3.0/` or `CVSS:3.1/` prefix, `KEY:VALUE` parts separated
 * by single slashes (no empty part, so no trailing slash), known keys and values only, no
 * duplicates, all eight Base metrics present. Metric order is free, as in FIRST's reference
 * calculator.
 */
export function parseCvss3(vector: string): Cvss3Parse {
  const parts = vector.split("/");
  const prefix = parts.shift();
  const version = prefix === "CVSS:3.1" ? "3.1" : prefix === "CVSS:3.0" ? "3.0" : null;
  if (version === null) return { ok: false, error: "bad_prefix" };
  const metrics: Record<string, string> = {};
  for (const part of parts) {
    const pieces = part.split(":");
    if (pieces.length !== 2) return { ok: false, error: "malformed_metric" };
    const [key = "", value = ""] = pieces;
    const allowed = Object.hasOwn(ALLOWED_VALUES, key) ? ALLOWED_VALUES[key] : undefined;
    if (allowed === undefined) return { ok: false, error: "unknown_metric" };
    if (!allowed.includes(value)) return { ok: false, error: "invalid_value" };
    if (Object.hasOwn(metrics, key)) return { ok: false, error: "duplicate_metric" };
    metrics[key] = value;
  }
  for (const key of BASE_METRICS) {
    if (!Object.hasOwn(metrics, key)) return { ok: false, error: "missing_base_metric" };
  }
  return { ok: true, version, metrics };
}

/**
 * CVSS v3.1 Roundup (Appendix A): the smallest one-decimal number ≥ the input, computed on
 * integers so floating-point noise (e.g. 1 − 0.58 = 0.42000000000000004) cannot round up a tenth.
 */
export function roundup31(value: number): number {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
}

/** CVSS v3.0 Round up (§8.1): "the smallest number, specified to one decimal place, that is equal to or higher than its input", as FIRST's v3.0 calculator computes it. */
export function roundup30(value: number): number {
  return Math.ceil(value * 10) / 10;
}

function weight(
  table: Readonly<Record<string, number>>,
  metrics: Readonly<Record<string, string>>,
  key: BaseMetric,
): number {
  const value = metrics[key];
  const result = value === undefined ? undefined : table[value];
  if (result === undefined) throw new RangeError(`CVSS v3 metric ${key} has no weight`);
  return result;
}

/** The Base score of a parsed vector (v3.1 §7.1; identical formulas in v3.0 except Roundup). */
export function cvss3BaseScore(
  version: Cvss3Version,
  metrics: Readonly<Record<string, string>>,
): number {
  const roundup = version === "3.1" ? roundup31 : roundup30;
  const scopeChanged = metrics["S"] === "C";
  const iss =
    1 -
    (1 - weight(IMPACT, metrics, "C")) *
      (1 - weight(IMPACT, metrics, "I")) *
      (1 - weight(IMPACT, metrics, "A"));
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploitability =
    8.22 *
    weight(ATTACK_VECTOR, metrics, "AV") *
    weight(ATTACK_COMPLEXITY, metrics, "AC") *
    weight(scopeChanged ? PRIVILEGES_CHANGED : PRIVILEGES_UNCHANGED, metrics, "PR") *
    weight(USER_INTERACTION, metrics, "UI");
  if (impact <= 0) return 0;
  return scopeChanged
    ? roundup(Math.min(1.08 * (impact + exploitability), 10))
    : roundup(Math.min(impact + exploitability, 10));
}
