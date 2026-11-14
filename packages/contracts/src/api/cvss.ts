import { z } from "zod";

import { whenValid } from "../primitives.js";

// The CVSS score shape on its own, so a consumer that needs only it (the CLI bundle,
// `@kovo/contracts/api/cli`) does not load the findings endpoint module. Re-exported by
// ./findings.js under the same name.

/** A CVSS base score, 0.0–10.0 in tenths. */
export const cvssScoreSchema = z
  .number()
  .min(0)
  .max(10)
  .refine((score) => Math.round(score * 10) / 10 === score, {
    ...whenValid,
    error: "a CVSS score has one decimal place",
  });
