import { z } from "zod";

import { deniedEgressHostnameSchema } from "./egress.js";
import { SUPPORTED_NODE_MAJORS } from "./enums/recipes.js";
import { customerAskIdSchema, jobIdSchema } from "./ids.js";
import { utcDateTimeSchema } from "./time.js";

// "Kovo needs X" asks (#8256 V6, plans/js-coverage-phase2.md section 2.9; docs/decisions/
// recipes.md "Customer asks"): when only the customer can fix what stops Kovo's checks, Kovo asks
// once, plainly, with one button. An ask holds a closed kind and one closed subject: a Node major
// from the image's list, a public build host name the sandbox refused (already shown to the same
// customer in the egress decisions), or a framework from the closed list below. Never source,
// output, a command, a step name or a URL.

/** What an ask offers. None of them touches CI workflows (D-707 is phase 3). */
export const CUSTOMER_ASK_KINDS = [
  /** A PR that adds `engines.node` to the root `package.json`. */
  "set_node_engine",
  /** The existing human approval of one refused build host, from the dashboard. */
  "allow_build_host",
  /** A PR that adds the framework's default `build` script to the root `package.json`. */
  "add_build_script",
] as const;
export const customerAskKindSchema = z.enum(CUSTOMER_ASK_KINDS);
export type CustomerAskKind = z.infer<typeof customerAskKindSchema>;

/** Why a failure category carries no ask: closed reason codes (D-267), never text. */
export const NO_ASK_REASONS = [
  /** Kovo fixes it on its side (the playbook, the image or the recipe), so asking would be noise. */
  "kovo_handles",
  /** A real failure of the code itself: the customer's own CI and Kovo's PR already say so. */
  "code_failure",
  /** No single change in the repository is known to fix it, so a button could only guess. */
  "no_single_change",
] as const;
export const noAskReasonSchema = z.enum(NO_ASK_REASONS);
export type NoAskReason = z.infer<typeof noAskReasonSchema>;

/** Frameworks with a known default `build` script. */
export const BUILD_SCRIPT_FRAMEWORKS = [
  "next",
  "nuxt",
  "@sveltejs/kit",
  "astro",
  "react-router",
  "@angular/core",
  "vite",
] as const;
export const buildScriptFrameworkSchema = z.enum(BUILD_SCRIPT_FRAMEWORKS);
export type BuildScriptFramework = z.infer<typeof buildScriptFrameworkSchema>;

/** Each framework's default `build` script (the framework's own docs). */
export const BUILD_SCRIPT_DEFAULTS: Readonly<Record<BuildScriptFramework, string>> = {
  next: "next build",
  nuxt: "nuxt build",
  "@sveltejs/kit": "vite build",
  astro: "astro build",
  "react-router": "react-router build",
  "@angular/core": "ng build",
  vite: "vite build",
};

export const askNodeMajorSchema = z
  .int()
  .refine((major) => (SUPPORTED_NODE_MAJORS as readonly number[]).includes(major), {
    error: "a Node major the image provides",
  });

/** One ask: its kind and its one closed subject. */
export const customerAskSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("set_node_engine"), node_major: askNodeMajorSchema }),
  z.strictObject({ kind: z.literal("allow_build_host"), hostname: deniedEgressHostnameSchema }),
  z.strictObject({ kind: z.literal("add_build_script"), framework: buildScriptFrameworkSchema }),
]);
export type CustomerAsk = z.infer<typeof customerAskSchema>;

/** The de-duplication key of an ask on one repository: its kind and subject. */
export function customerAskKey(ask: CustomerAsk): string {
  if (ask.kind === "set_node_engine") return `set_node_engine:${ask.node_major}`;
  if (ask.kind === "allow_build_host") return `allow_build_host:${ask.hostname}`;
  return `add_build_script:${ask.framework}`;
}

export const CUSTOMER_ASK_STATUSES = [
  /** Raised by a run and not yet answered. */
  "open",
  /** A person pressed a PR ask's button; the worker is opening the PR. */
  "requested",
  /** The PR is open or the host is approved. */
  "done",
  /** A person said no; a later run never reopens it. */
  "dismissed",
  /** A later run no longer raised it. */
  "resolved",
] as const;
export const customerAskStatusSchema = z.enum(CUSTOMER_ASK_STATUSES);
export type CustomerAskStatus = z.infer<typeof customerAskStatusSchema>;

/** The public docs section behind every ask's "Learn more" (apps/web `DOCS.customerAsks`). */
export const CUSTOMER_ASKS_DOCS_PATH = "/docs/autopilot#when-kovo-needs-something-from-you";

/** What a person sees for one ask: a question, one sentence of why, and the button's label. */
export interface CustomerAskText {
  readonly question: string;
  readonly why: string;
  readonly button: string;
}

/** Plain user-facing text (AGENTS.md; engineering.md "Plain user-facing text"). */
export function customerAskText(ask: CustomerAsk): CustomerAskText {
  if (ask.kind === "set_node_engine")
    return {
      question: `Your build needs Node ${ask.node_major}. Add it to engines?`,
      why: "Kovo checks your fixes on the Node version your package.json asks for.",
      button: "Open a PR",
    };
  if (ask.kind === "allow_build_host")
    return {
      question: `Allow ${ask.hostname} for builds?`,
      why: "Your build tried to download from this site and Kovo blocked it.",
      button: "Allow",
    };
  return {
    question: "Add a build script?",
    why: `Kovo found no build script. It would add "${BUILD_SCRIPT_DEFAULTS[ask.framework]}".`,
    button: "Open a PR",
  };
}

/** The title of the one App-owned ask issue per repository. */
export const CUSTOMER_ASKS_ISSUE_TITLE = "Kovo needs a few things from you";

/**
 * Why Kovo opened no PR for a pressed button (stable reason codes, D-267). The ask goes back to
 * open with the code, so a person can fix it and press again.
 */
export const CUSTOMER_ASK_REFUSALS = [
  "manifest_missing",
  "manifest_not_object",
  "manifest_format_unsupported",
  "field_not_object",
  "branch_taken",
  "pull_request_closed",
  "access_revoked",
] as const;
export const customerAskRefusalSchema = z.enum(CUSTOMER_ASK_REFUSALS);
export type CustomerAskRefusal = z.infer<typeof customerAskRefusalSchema>;

/** What a person sees for a refusal (plain user-facing text). */
export const CUSTOMER_ASK_REFUSAL_TEXT: Readonly<Record<CustomerAskRefusal, string>> = {
  manifest_missing: "Kovo found no package.json at the root of your repository.",
  manifest_not_object: "Your package.json isn't a JSON object, so Kovo left it alone.",
  manifest_format_unsupported:
    "Kovo can't change your package.json without changing its formatting. Make this change yourself.",
  field_not_object: "That part of your package.json isn't an object, so Kovo left it alone.",
  branch_taken: "Someone else pushed to Kovo's branch for this change, so Kovo left it alone.",
  pull_request_closed: "Kovo's PR for this change was merged or closed.",
  access_revoked: "Kovo no longer has access to this repository.",
};

/** One ask as the dashboard reads it. */
export const customerAskViewSchema = z.strictObject({
  id: customerAskIdSchema,
  ask: customerAskSchema,
  status: customerAskStatusSchema,
  /** How many runs raised it. */
  runs: z.int().min(1),
  first_job_id: jobIdSchema,
  last_job_id: jobIdSchema,
  first_seen_at: utcDateTimeSchema,
  last_seen_at: utcDateTimeSchema,
  /** The PR the button opened, for a PR ask a person clicked. */
  pull_number: z.int().positive().nullable(),
  /** Why the last press opened no PR; null otherwise. */
  refusal: customerAskRefusalSchema.nullable(),
});
export type CustomerAskView = z.infer<typeof customerAskViewSchema>;

/** Why the ask issue could not be written (shown on the dashboard), or null. */
export const CUSTOMER_ASK_ISSUE_NOTICES = ["permission_missing", "delivery_failed"] as const;

export const customerAsksResponseSchema = z.strictObject({
  asks: z.array(customerAskViewSchema).max(100),
  issue_number: z.int().positive().nullable(),
  issue_notice: z.enum(CUSTOMER_ASK_ISSUE_NOTICES).nullable(),
});
export type CustomerAsksResponse = z.infer<typeof customerAsksResponseSchema>;

/** What a button did. */
export const customerAskActionResultSchema = z.strictObject({
  ask: customerAskViewSchema,
  outcome: z.enum([
    /** Kovo's worker opens the PR now; the ask shows it once open. */
    "pull_request_requested",
    /** The host is approved through the existing human egress approval. */
    "host_allowed",
    "dismissed",
  ]),
});

export type CustomerAskActionResult = z.infer<typeof customerAskActionResultSchema>;
