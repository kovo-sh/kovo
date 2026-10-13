import { cvss3BaseScore, parseCvss3, type Cvss3ParseError, type Cvss3Version } from "./cvss3.js";
import {
  cvss4BaseScore,
  parseCvss4,
  type Cvss4Nomenclature,
  type Cvss4ParseError,
} from "./cvss4.js";

// Scoring of OSV `severity[]` entries. OSV types: CVSS_V2, CVSS_V3, CVSS_V4, Ubuntu (schema 1.9).
// SPEC: "derive severity from the highest supported CVSS v4/v3 vector"; v2 and Ubuntu are not
// supported. Both versions are scored by their Base metrics (v3.x Base score, v4.0 CVSS-B), so a
// publisher's threat or environmental metrics cannot lower a severity that tiering depends on.

export { cvss3BaseScore, parseCvss3, roundup30, roundup31 } from "./cvss3.js";
export type { Cvss3Parse, Cvss3ParseError, Cvss3Version } from "./cvss3.js";
export { cvss4BaseScore, cvss4Score, parseCvss4 } from "./cvss4.js";
export type { Cvss4Nomenclature, Cvss4Parse, Cvss4ParseError } from "./cvss4.js";

/** The CVSS versions Kovo scores. */
export type CvssVersion = Cvss3Version | "4.0";

export type CvssScoring =
  | {
      readonly outcome: "scored";
      readonly version: CvssVersion;
      /** The Base score: v3.x Base, v4.0 CVSS-B (threat/environmental metrics reset to `X`). */
      readonly score: number;
      readonly vector: string;
      /** v4.0 only: which metric groups the vector as published carries. */
      readonly nomenclature: Cvss4Nomenclature | null;
    }
  | { readonly outcome: "unsupported"; readonly type: string }
  | {
      readonly outcome: "invalid";
      readonly type: string;
      readonly error: Cvss3ParseError | Cvss4ParseError | "type_mismatch";
    };

/**
 * Scores one OSV severity entry by its Base metrics. The vector must match its declared type
 * (`CVSS_V3` carries a `CVSS:3.0/` or `CVSS:3.1/` vector, `CVSS_V4` a `CVSS:4.0/` vector); anything
 * else is invalid. Vectors are taken as published: no trimming, case folding or trailing-slash
 * repair.
 */
export function scoreCvssEntry(type: string, vector: string): CvssScoring {
  if (type === "CVSS_V3") {
    if (!vector.startsWith("CVSS:3.")) return { outcome: "invalid", type, error: "type_mismatch" };
    const parsed = parseCvss3(vector);
    if (!parsed.ok) return { outcome: "invalid", type, error: parsed.error };
    return {
      outcome: "scored",
      version: parsed.version,
      score: cvss3BaseScore(parsed.version, parsed.metrics),
      vector,
      nomenclature: null,
    };
  }
  if (type === "CVSS_V4") {
    if (!vector.startsWith("CVSS:4.")) return { outcome: "invalid", type, error: "type_mismatch" };
    const parsed = parseCvss4(vector);
    if (!parsed.ok) return { outcome: "invalid", type, error: parsed.error };
    return {
      outcome: "scored",
      version: "4.0",
      score: cvss4BaseScore(parsed.metrics),
      vector,
      nomenclature: parsed.nomenclature,
    };
  }
  return { outcome: "unsupported", type };
}
