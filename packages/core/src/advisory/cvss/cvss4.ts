// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// CVSS v4.0 scoring: a TypeScript port of `Vector` and `CVSS40.calculateScore` from `cvss40.js` of
// RedHatProductSecurity/cvss-v4-calculator@b0930b7646be5892492df16ba81cd8d8423eb49a (the macrovector
// interpolation of the FIRST CVSS v4.0 specification §8). Changes from the original: a strict
// order-independent parser replaces `validateStringVector` (which required canonical metric order
// and crashed on duplicates), the `console.error` calls and the browser/CommonJS export tail are
// gone, and max vectors are parsed into maps instead of searched with `indexOf` (equivalent for the
// fixed composed vectors). License and provenance: ./NOTICE.md.

import { LOOKUP_TABLE, MAX_COMPOSED, MAX_SEVERITY, METRIC_LEVELS } from "./cvss4-tables.js";

/** CVSS v4.0 metrics in canonical order, each with its allowed values (default first). */
const METRICS = {
  // Base
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  AT: ["N", "P"],
  PR: ["N", "L", "H"],
  UI: ["N", "P", "A"],
  VC: ["N", "L", "H"],
  VI: ["N", "L", "H"],
  VA: ["N", "L", "H"],
  SC: ["N", "L", "H"],
  SI: ["N", "L", "H"],
  SA: ["N", "L", "H"],
  // Threat
  E: ["X", "A", "P", "U"],
  // Environmental
  CR: ["X", "H", "M", "L"],
  IR: ["X", "H", "M", "L"],
  AR: ["X", "H", "M", "L"],
  MAV: ["X", "N", "A", "L", "P"],
  MAC: ["X", "L", "H"],
  MAT: ["X", "N", "P"],
  MPR: ["X", "N", "L", "H"],
  MUI: ["X", "N", "P", "A"],
  MVC: ["X", "H", "L", "N"],
  MVI: ["X", "H", "L", "N"],
  MVA: ["X", "H", "L", "N"],
  MSC: ["X", "H", "L", "N"],
  MSI: ["X", "S", "H", "L", "N"],
  MSA: ["X", "S", "H", "L", "N"],
  // Supplemental
  S: ["X", "N", "P"],
  AU: ["X", "N", "Y"],
  R: ["X", "A", "U", "I"],
  V: ["X", "D", "C"],
  RE: ["X", "L", "M", "H"],
  U: ["X", "Clear", "Green", "Amber", "Red"],
} as const satisfies Readonly<Record<string, readonly string[]>>;

type Metric = keyof typeof METRICS;
type Metrics = Readonly<Record<string, string>>;

const BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"] as const;
const THREAT_METRICS = ["E"] as const;
const ENVIRONMENTAL_METRICS = [
  "CR",
  "IR",
  "AR",
  "MAV",
  "MAC",
  "MAT",
  "MPR",
  "MUI",
  "MVC",
  "MVI",
  "MVA",
  "MSC",
  "MSI",
  "MSA",
] as const;

function isMetric(key: string): key is Metric {
  return Object.hasOwn(METRICS, key);
}

export type Cvss4ParseError =
  | "bad_prefix"
  | "malformed_metric"
  | "unknown_metric"
  | "invalid_value"
  | "duplicate_metric"
  | "missing_base_metric";

/** `CVSS-B`, `CVSS-BT`, `CVSS-BE` or `CVSS-BTE`: which metric groups the score reflects. */
export type Cvss4Nomenclature = "CVSS-B" | "CVSS-BT" | "CVSS-BE" | "CVSS-BTE";

export type Cvss4Parse =
  | { readonly ok: true; readonly metrics: Metrics; readonly nomenclature: Cvss4Nomenclature }
  | { readonly ok: false; readonly error: Cvss4ParseError };

/**
 * Parses a v4.0 vector strictly: the `CVSS:4.0/` prefix, `KEY:VALUE` parts separated by single
 * slashes (no empty part, so no trailing slash), known keys and values only, no duplicates, all
 * eleven Base metrics present. Metric order is free; undefined optional metrics default to `X`.
 */
export function parseCvss4(vector: string): Cvss4Parse {
  const parts = vector.split("/");
  if (parts.shift() !== "CVSS:4.0") return { ok: false, error: "bad_prefix" };
  const given: Record<string, string> = {};
  for (const part of parts) {
    const pieces = part.split(":");
    if (pieces.length !== 2) return { ok: false, error: "malformed_metric" };
    const [key = "", value = ""] = pieces;
    if (!isMetric(key)) return { ok: false, error: "unknown_metric" };
    if (!(METRICS[key] as readonly string[]).includes(value)) {
      return { ok: false, error: "invalid_value" };
    }
    if (Object.hasOwn(given, key)) return { ok: false, error: "duplicate_metric" };
    given[key] = value;
  }
  for (const key of BASE_METRICS) {
    if (!Object.hasOwn(given, key)) return { ok: false, error: "missing_base_metric" };
  }
  const metrics: Record<string, string> = {};
  for (const [key, values] of Object.entries(METRICS)) metrics[key] = given[key] ?? values[0];
  const threat = THREAT_METRICS.some((key) => metrics[key] !== "X");
  const environmental = ENVIRONMENTAL_METRICS.some((key) => metrics[key] !== "X");
  const nomenclature: Cvss4Nomenclature = `CVSS-B${threat ? "T" : ""}${environmental ? "E" : ""}`;
  return { ok: true, metrics, nomenclature };
}

/** `Vector.getEffectiveMetricValue`: worst-case defaults for X, then environmental overrides. */
function effective(metrics: Metrics, metric: string): string {
  const worstCase: Readonly<Record<string, string>> = { E: "A", CR: "H", IR: "H", AR: "H" };
  const value = metrics[metric];
  if (value === "X" && Object.hasOwn(worstCase, metric)) return worstCase[metric] ?? value;
  const modified = metrics[`M${metric}`];
  if (modified !== undefined && modified !== "X") return modified;
  if (value === undefined) throw new RangeError(`CVSS v4 metric ${metric} is not set`);
  return value;
}

/** `Vector.equivalentClasses`: the macrovector EQ1..EQ6. */
function macrovector(metrics: Metrics): string {
  const m = (metric: string) => effective(metrics, metric);
  const av = m("AV");
  const pr = m("PR");
  const ui = m("UI");
  const eq1 =
    av === "N" && pr === "N" && ui === "N"
      ? 0
      : (av === "N" || pr === "N" || ui === "N") && av !== "P"
        ? 1
        : 2;
  const eq2 = m("AC") === "L" && m("AT") === "N" ? 0 : 1;
  const vc = m("VC");
  const vi = m("VI");
  const va = m("VA");
  const eq3 = vc === "H" && vi === "H" ? 0 : vc === "H" || vi === "H" || va === "H" ? 1 : 2;
  const eq4 =
    m("MSI") === "S" || m("MSA") === "S"
      ? 0
      : m("SC") === "H" || m("SI") === "H" || m("SA") === "H"
        ? 1
        : 2;
  const exploit = m("E");
  const eq5 = exploit === "A" ? 0 : exploit === "P" ? 1 : 2;
  const eq6 =
    (m("CR") === "H" && vc === "H") ||
    (m("IR") === "H" && vi === "H") ||
    (m("AR") === "H" && va === "H")
      ? 0
      : 1;
  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
}

/** `roundToDecimalPlaces`: half-up to one decimal with the Oct-2024 epsilon fix. */
function roundToOneDecimal(value: number): number {
  const EPSILON = 10 ** -6;
  return Math.round((value + EPSILON) * 10) / 10;
}

/** A lookup-table score, or NaN when the macrovector does not exist (as `cvss40.js` does). */
function lookup(macro: string): number {
  return LOOKUP_TABLE[macro] ?? Number.NaN;
}

/** Composed max vectors come from a fixed table, so each is parsed once. */
const composedCache = new Map<string, ReadonlyMap<string, string>>();

function parseComposed(vector: string): ReadonlyMap<string, string> {
  const cached = composedCache.get(vector);
  if (cached !== undefined) return cached;
  const parsed = new Map<string, string>();
  for (const part of vector.split("/")) {
    if (part === "") continue;
    const [key = "", value = ""] = part.split(":");
    parsed.set(key, value);
  }
  composedCache.set(vector, parsed);
  return parsed;
}

function level(metric: string, value: string | undefined): number {
  const levels = METRIC_LEVELS[metric];
  const result = value === undefined || levels === undefined ? undefined : levels[value];
  return result ?? Number.NaN;
}

/** `CVSS40.calculateSeverityDistances`: effective level minus the max vector's level. */
function severityDistances(metrics: Metrics, maxVector: string): Readonly<Record<string, number>> {
  const max = parseComposed(maxVector);
  const distances: Record<string, number> = {};
  for (const metric of Object.keys(METRIC_LEVELS)) {
    distances[metric] = level(metric, effective(metrics, metric)) - level(metric, max.get(metric));
  }
  return distances;
}

function listAt(
  table: Readonly<Record<number, readonly string[]>>,
  key: number,
): readonly string[] {
  const list = table[key];
  if (list === undefined) throw new RangeError(`CVSS v4 has no max vector for level ${key}`);
  return list;
}

function numberAt(table: Readonly<Record<number, number>>, key: number): number {
  const value = table[key];
  if (value === undefined) throw new RangeError(`CVSS v4 has no max severity for level ${key}`);
  return value;
}

/** `CVSS40.calculateScore` for parsed metrics. */
export function cvss4Score(metrics: Metrics): number {
  const STEP = 0.1;
  const noImpact = ["VC", "VI", "VA", "SC", "SI", "SA"].every(
    (metric) => effective(metrics, metric) === "N",
  );
  if (noImpact) return 0;

  const macro = macrovector(metrics);
  const value = lookup(macro);
  const [eq1 = 0, eq2 = 0, eq3 = 0, eq4 = 0, eq5 = 0, eq6 = 0] = macro.split("").map(Number);

  // The next lower macrovector per EQ; EQ3 and EQ6 are joint. A missing one scores NaN.
  const eq1Lower = lookup(`${eq1 + 1}${eq2}${eq3}${eq4}${eq5}${eq6}`);
  const eq2Lower = lookup(`${eq1}${eq2 + 1}${eq3}${eq4}${eq5}${eq6}`);
  let eq3eq6Lower: number;
  if (eq3 === 1 && eq6 === 1) {
    eq3eq6Lower = lookup(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`);
  } else if (eq3 === 0 && eq6 === 1) {
    eq3eq6Lower = lookup(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`);
  } else if (eq3 === 1 && eq6 === 0) {
    eq3eq6Lower = lookup(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`);
  } else if (eq3 === 0 && eq6 === 0) {
    eq3eq6Lower = Math.max(
      lookup(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`),
      lookup(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`),
    );
  } else {
    eq3eq6Lower = lookup(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6 + 1}`);
  }
  const eq4Lower = lookup(`${eq1}${eq2}${eq3}${eq4 + 1}${eq5}${eq6}`);
  const eq5Lower = lookup(`${eq1}${eq2}${eq3}${eq4}${eq5 + 1}${eq6}`);

  // The first composed max vector whose severity distances are all non-negative.
  const eq3Max = MAX_COMPOSED.eq3[eq3]?.[eq6];
  if (eq3Max === undefined) throw new RangeError(`CVSS v4 has no max vector for EQ3/EQ6 ${macro}`);
  const maxVectors: string[] = [];
  for (const a of listAt(MAX_COMPOSED.eq1, eq1)) {
    for (const b of listAt(MAX_COMPOSED.eq2, eq2)) {
      for (const c of eq3Max) {
        for (const d of listAt(MAX_COMPOSED.eq4, eq4)) {
          for (const e of listAt(MAX_COMPOSED.eq5, eq5)) maxVectors.push(a + b + c + d + e);
        }
      }
    }
  }
  let distances: Readonly<Record<string, number>> = {};
  for (const vector of maxVectors) {
    distances = severityDistances(metrics, vector);
    if (Object.values(distances).every((distance) => distance >= 0)) break;
  }
  const d = (metric: string) => distances[metric] ?? Number.NaN;
  const currentEq1 = d("AV") + d("PR") + d("UI");
  const currentEq2 = d("AC") + d("AT");
  const currentEq3eq6 = d("VC") + d("VI") + d("VA") + d("CR") + d("IR") + d("AR");
  const currentEq4 = d("SC") + d("SI") + d("SA");

  const maxSeverityEq1 = numberAt(MAX_SEVERITY.eq1, eq1) * STEP;
  const maxSeverityEq2 = numberAt(MAX_SEVERITY.eq2, eq2) * STEP;
  const eq3eq6Severity = MAX_SEVERITY.eq3eq6[eq3]?.[eq6];
  if (eq3eq6Severity === undefined) {
    throw new RangeError(`CVSS v4 has no max severity for EQ3/EQ6 ${macro}`);
  }
  const maxSeverityEq3eq6 = eq3eq6Severity * STEP;
  const maxSeverityEq4 = numberAt(MAX_SEVERITY.eq4, eq4) * STEP;

  // Proportional distances for every EQ that has a lower macrovector; EQ5 always contributes 0.
  let existingLower = 0;
  let total = 0;
  const parts: readonly (readonly [number, number, number])[] = [
    [value - eq1Lower, currentEq1, maxSeverityEq1],
    [value - eq2Lower, currentEq2, maxSeverityEq2],
    [value - eq3eq6Lower, currentEq3eq6, maxSeverityEq3eq6],
    [value - eq4Lower, currentEq4, maxSeverityEq4],
  ];
  for (const [available, current, maxSeverity] of parts) {
    if (Number.isNaN(available)) continue;
    existingLower += 1;
    total += available * (current / maxSeverity);
  }
  if (!Number.isNaN(value - eq5Lower)) existingLower += 1;
  const meanDistance = existingLower === 0 ? 0 : total / existingLower;
  return roundToOneDecimal(Math.max(0, Math.min(10, value - meanDistance)));
}

/**
 * The CVSS-B score: the vector's Base metrics with every threat, environmental and supplemental
 * metric reset to `X` (so `E` counts as Attacked and `CR`/`IR`/`AR` as High, as in a published
 * Base-only vector). Kovo derives severity from it, as it does from a v3.x Base score
 * (docs/decisions/advisory.md "Severity").
 */
export function cvss4BaseScore(metrics: Metrics): number {
  const base: Record<string, string> = {};
  for (const [key, values] of Object.entries(METRICS)) base[key] = values[0];
  for (const key of BASE_METRICS) {
    const value = metrics[key];
    if (value === undefined) throw new RangeError(`CVSS v4 Base metric ${key} is not set`);
    base[key] = value;
  }
  return cvss4Score(base);
}
