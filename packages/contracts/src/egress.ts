import { z } from "zod";
import { isPublicDnsName } from "./primitives.js";
import { jobIdSchema, recipeVersionIdSchema } from "./ids.js";

/** Legacy provider domain catalog; the replacement fetch writer must not use this catalog. */
export const INSTALL_BINARY_CATALOG_VERSION = 1 as const;
export const INSTALL_BINARY_HOSTS = ["binaries.prisma.sh", "nodejs.org"] as const;
/** Advisory fetch identities; kept separate from the legacy provider domain catalog. */
export const INSTALL_BINARY_DISCLOSURE_HOSTS = [
  ...INSTALL_BINARY_HOSTS,
  "download.cypress.io",
  "cdn.cypress.io",
] as const;

export const EGRESS_MODES = ["strict", "trust_kovo", "review_new_hosts", "open"] as const;
export const egressModeSchema = z.enum(EGRESS_MODES);
export type EgressMode = z.output<typeof egressModeSchema>;

/** S2 reader: new or unrecognized modes have only Strict authority until enabled. */
export function readEgressMode(value: unknown): "strict" | "trust_kovo" | "open" {
  return value === "trust_kovo" || value === "open" ? value : "strict";
}
export const writableEgressModeSchema = z.enum(["strict", "trust_kovo", "open"]);
export const EGRESS_DECISION_BASES = [
  "vetted",
  "llm",
  "plan_restriction",
  "blocklist",
  "strict",
  "baseline",
  "fix_scoped",
  "post_merge",
  "admin_whole_host",
] as const;
export const egressDecisionBasisSchema = z.enum(EGRESS_DECISION_BASES);
const decisionBasisLabels: Readonly<Record<z.output<typeof egressDecisionBasisSchema>, string>> = {
  vetted: "vetted",
  llm: "llm",
  plan_restriction: "plan_restriction",
  blocklist: "blocklist",
  strict: "strict",
  baseline: "learned baseline",
  fix_scoped: "this run and package version only",
  post_merge: "first observed after merge",
  admin_whole_host: "admin whole-host approval",
};
/** Fixed labels only; unknown bases disclose refusal, never untrusted basis text. */
export function egressDecisionBasisLabel(value: unknown): string {
  const parsed = egressDecisionBasisSchema.safeParse(value);
  return parsed.success ? decisionBasisLabels[parsed.data] : "unrecognized basis; no authority";
}

export const egressModeReaderSchema = z.codec(
  z.string().catch("strict"),
  writableEgressModeSchema,
  {
    decode: readEgressMode,
    encode: (mode) => mode,
  },
);
const basisReader = z.codec(
  z.string().catch("unknown"),
  z.enum([...EGRESS_DECISION_BASES, "unknown"]),
  {
    decode: (value) => egressDecisionBasisSchema.safeParse(value).data ?? "unknown",
    encode: (basis) => basis,
  },
);

/** Advisory metadata only. Resolution and destination enforcement remain the sandbox's job. */
export const deniedEgressHostnameSchema = z
  .string()
  .max(253)
  .refine(
    (hostname) =>
      isPublicDnsName(hostname) &&
      !["example.com", "example.net", "example.org"].some(
        (name) => hostname.toLowerCase() === name || hostname.toLowerCase().endsWith(`.${name}`),
      ),
    {
      error: "must be a public DNS hostname without a port, wildcard or IP address",
    },
  )
  .toLowerCase();

const disclosureShape = z.strictObject({
  recipe_version_id: recipeVersionIdSchema,
  version: z.int().positive(),
  mode: egressModeReaderSchema,
  desired_mode: egressModeReaderSchema,
  full_internet: z.boolean(),
  requires_human_approval: z.boolean(),
  acknowledged: z.boolean(),
  desired_full_internet: z.boolean(),
  /** Reader first: writers add this only after tolerant readers are promoted. */
  install_binary_hosts: z.array(deniedEgressHostnameSchema).max(100).exactOptional(),
  proposals: z
    .array(z.strictObject({ hostname: deniedEgressHostnameSchema, curated: z.boolean() }))
    .max(100),
  issue_notice: z.enum(["permission_missing", "delivery_failed"]).nullable(),
  allowed_hosts: z.array(deniedEgressHostnameSchema).max(100),
  decisions: z
    .array(
      z.strictObject({
        hostname: deniedEgressHostnameSchema,
        decision: z.enum(["allow", "deny"]),
        basis: basisReader,
        job_id: jobIdSchema,
        summary: z.string().min(1).max(300),
        mode: egressModeReaderSchema,
      }),
    )
    .max(100),
  observation: z.literal("best_effort"),
});

// Future disclosure fields are advisory to this release: discard them on read, including
// nested proposal/decision metadata. Encoding still requires the exact known shape.
const disclosureInput = disclosureShape.strip().extend({
  // Reader-first: future catalog hosts are advisory, never runtime authority. Keep this
  // release's runtime authority unchanged while accepting later reviewed identities.
  install_binary_hosts: z.array(deniedEgressHostnameSchema).max(100).exactOptional(),
  proposals: z.array(disclosureShape.shape.proposals.element.strip()).max(100),
  decisions: z.array(disclosureShape.shape.decisions.element.strip()).max(100),
});

/** Normalize coupled authority fields too: a future mode cannot retain Open flags. */
export const recipeEgressDisclosureSchema = z.codec(disclosureInput, disclosureShape, {
  decode: (wire) => {
    const data = disclosureShape.parse(wire);
    if (data.mode === "strict") delete data.install_binary_hosts;
    data.full_internet = data.mode === "open" && data.full_internet;
    data.desired_full_internet = data.desired_mode === "open" && data.desired_full_internet;
    for (const item of data.decisions) {
      if (item.basis === "unknown") {
        item.decision = "deny";
        item.summary = "Unrecognized decision basis; no authority.";
      }
    }
    return data;
  },
  encode: (data, ctx) => {
    if (
      data.install_binary_hosts?.some(
        (host) => !(INSTALL_BINARY_DISCLOSURE_HOSTS as readonly string[]).includes(host),
      )
    )
      ctx.issues.push({
        code: "custom",
        message: "unknown install binary writer identity",
        path: ["install_binary_hosts"],
        input: data.install_binary_hosts,
      });
    return disclosureShape.parse(data);
  },
});
