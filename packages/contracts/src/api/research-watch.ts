import { z } from "zod";
import { defineEndpoint } from "./endpoint.js";
import { packageNameSchema, exactVersionSchema } from "../npm.js";

const timestamp = z.number().int().min(0).max(8_640_000_000_000_000);
export const researchWindowSchema = z.strictObject({
  urls: z.array(z.url().max(2048)).min(1).max(10),
  since: timestamp,
  until: timestamp,
  cursor: timestamp.optional(),
});
export const researchExtractionSchema = z.strictObject({
  ecosystem: z.literal("npm"),
  package: packageNameSchema.refine((name) =>
    /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(name),
  ),
  version: exactVersionSchema.max(128),
  source: z.enum(["socket", "stepsecurity", "wiz", "datadog", "ghsa"]),
  publishedAt: timestamp,
  reportHash: z.string().regex(/^[a-f0-9]{64}$/),
});
export const researchMetadataResultSchema = z.strictObject({
  since: timestamp,
  until: timestamp,
  pageSince: timestamp,
  pageUntil: timestamp,
  nextCursor: timestamp.nullable(),
  extractions: z.array(researchExtractionSchema).max(1280),
  reasons: z.record(z.string().regex(/^[a-z_]+$/), z.int().nonnegative()),
  calls: z.int().min(0).max(200),
  reservedMicroUsd: z.string().regex(/^\d+$/),
});

export const researchWatchResultSchema = z.strictObject({
  observations: z
    .array(
      z.strictObject({
        name: z.string().max(214),
        version: z.string().max(128),
        url: z.url().max(2048),
        observedAt: z.number().finite(),
      }),
    )
    .max(1280),
  audits: z
    .array(
      z.strictObject({
        url: z.url().max(2048),
        candidate: z.strictObject({
          ecosystem: z.string().max(32),
          name: z.string().max(214),
          version: z.string().max(128),
          quote: z.string().max(400),
        }),
      }),
    )
    .max(1280),
  reasons: z.record(z.string().regex(/^[a-z_]+$/), z.int().nonnegative()),
  calls: z.int().min(0).max(200),
  reservedMicroUsd: z.string().regex(/^\d+$/),
  score: z.strictObject({
    candidates: z.int().nonnegative(),
    confirmed: z.int().nonnegative(),
    unconfirmed: z.int().nonnegative(),
    pending: z.int().nonnegative(),
    matured: z.int().nonnegative(),
    confirmedWithinSevenDays: z.int().nonnegative(),
    precisionLowerBound: z.number().min(0).max(1).nullable(),
    sevenDayPrecisionLowerBound: z.number().min(0).max(1).nullable(),
    recall: z.number().min(0).max(1).nullable(),
    leadP50Ms: z.number().finite().nullable(),
    leadP90Ms: z.number().finite().nullable(),
    go: z.boolean(),
  }),
});

export const runOperatorResearchBacktest = defineEndpoint({
  operationId: "runOperatorResearchBacktest",
  area: "operator",
  method: "POST",
  path: "/v1/operator/research-watch/backtest",
  summary: "Shadow extraction of bounded public research reports; no holds or customer data.",
  source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
  auditStorage: "admin_audit",
  params: null,
  query: null,
  // Legacy callers receive exactly the legacy response. Only window callers use the new
  // metadata contract; no previous strict response reader consumes that response variant.
  body: z.union([
    z.strictObject({ urls: z.array(z.url().max(2048)).min(1).max(10), days: z.literal(90) }),
    researchWindowSchema,
  ]),
  responses: { 200: z.union([researchWatchResultSchema, researchMetadataResultSchema]) },
  authorization: {
    spec: "Operator pause uses service identity plus explicit operator authorization, not a shared customer API key; log actor/reason and alert until cleared. Operator routes are not publicly usable through ordinary account sessions.",
    actors: ["operator"],
    tenant: "none",
  },
});
