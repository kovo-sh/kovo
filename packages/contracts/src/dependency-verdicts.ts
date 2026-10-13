import { z } from "zod";

import { exactVersionSchema, packageNameSchema } from "./npm.js";
import { sriSha512Schema, whenValid } from "./primitives.js";
import { utcDateTimeSchema } from "./time.js";

// The dependency verdict engine's stable vocabulary (plans/dependency-firewall.md Part 1; SPEC
// "Recipes and verification" → "Dependency verdict engine"). One engine answers the same question
// for every enforcement point: is this `(ecosystem, name, version, integrity)` change safe to admit?
// Reason codes are stable API, so customers can map them to their own policy. They never name an
// evidence source: a verdict that rests on a third-party scanner's evidence shows only as a Kovo
// hold (`malware_confirmed` or `malware_suspected`).

export const DEPENDENCY_ECOSYSTEMS = ["npm"] as const;
export const dependencyEcosystemSchema = z.enum(DEPENDENCY_ECOSYSTEMS);
export type DependencyEcosystem = z.infer<typeof dependencyEcosystemSchema>;

/** Least to most severe; a change's verdict is the most severe its reasons call for. */
export const DEPENDENCY_VERDICTS = ["allow", "warn", "wait", "block"] as const;
export const dependencyVerdictKindSchema = z.enum(DEPENDENCY_VERDICTS);
export type DependencyVerdictKind = z.infer<typeof dependencyVerdictKindSchema>;

/**
 * Stable reason codes, in the order a verdict lists them (most severe first).
 *
 * - `malware_confirmed`: an active confirmed Kovo hold or malware advisory names the version.
 * - `integrity_mismatch`: the change's integrity is not the registry's integrity for the version.
 * - `non_registry_source`: resolved from git, a tarball URL, plain `http:` or a local path.
 * - `malware_suspected`: an active suspected Kovo hold names the version.
 * - `evidence_unknown`: evidence the verdict needs is missing (the version is not on the public
 *   registry, has no publication time, or a hold is still being investigated).
 * - `min_age`: published less than the minimum age ago.
 * - `private_registry_source`: resolved from a registry the account explicitly configured, where
 *   Kovo has no public evidence.
 * - `vulnerability_introduced`: a known advisory affects the new version but not the previous one.
 * - `install_script_added`: the new version runs install lifecycle scripts the previous one did not.
 * - `trust_downgrade`: the previous version had a registry provenance attestation and the new one
 *   does not, or the publishing path changed away from a verified history.
 * - `maintainer_changed`: the publishing identity differs from the previous version's.
 * - `possible_typosquat`: a new direct dependency's name is close to a popular package's name.
 */
export const DEPENDENCY_VERDICT_REASONS = [
  "malware_confirmed",
  "integrity_mismatch",
  "non_registry_source",
  "malware_suspected",
  "evidence_unknown",
  "min_age",
  "private_registry_source",
  "vulnerability_introduced",
  "install_script_added",
  "trust_downgrade",
  "maintainer_changed",
  "possible_typosquat",
] as const;
export const dependencyVerdictReasonSchema = z.enum(DEPENDENCY_VERDICT_REASONS);
export type DependencyVerdictReason = z.infer<typeof dependencyVerdictReasonSchema>;

/** Whether the change adds a package new to the graph or replaces another version of it. */
export const DEPENDENCY_VERDICT_CHANGE_KINDS = ["new", "changed"] as const;
export const dependencyVerdictChangeKindSchema = z.enum(DEPENDENCY_VERDICT_CHANGE_KINDS);
export type DependencyVerdictChangeKind = z.infer<typeof dependencyVerdictChangeKindSchema>;

/**
 * Where the lockfile resolves the version from: the public registry (canonical public tarball URL,
 * or no recorded URL), a registry the account explicitly configured (none can be configured yet),
 * or an exotic source (git, a tarball URL on any other host, plain `http:`, a local path, or a
 * public-registry URL naming another package or version).
 */
export const DEPENDENCY_SOURCES = ["registry", "private_registry", "exotic"] as const;
export const dependencySourceSchema = z.enum(DEPENDENCY_SOURCES);
export type DependencySource = z.infer<typeof dependencySourceSchema>;

/** At most this many changes are judged in one request. */
export const MAX_DEPENDENCY_VERDICT_CHANGES = 500;

/** One changed or new version, as callers derive it from a lockfile diff: identifiers only. */
export const dependencyVerdictChangeSchema = z
  .strictObject({
    ecosystem: dependencyEcosystemSchema,
    name: packageNameSchema,
    version: exactVersionSchema,
    /** The lockfile's sha512 integrity; null when it records none (legacy sha1-only or bundled). */
    integrity: sriSha512Schema.nullable(),
    kind: dependencyVerdictChangeKindSchema,
    direct: z.boolean(),
    /** The version this one replaces; null exactly for a new package. */
    previous_version: exactVersionSchema.nullable(),
    source: dependencySourceSchema,
  })
  .refine((change) => (change.kind === "new") === (change.previous_version === null), {
    ...whenValid,
    error: "exactly a changed version names the version it replaces",
    path: ["previous_version"],
  })
  .refine((change) => change.previous_version !== change.version, {
    ...whenValid,
    error: "a changed version differs from the version it replaces",
    path: ["previous_version"],
  });
export type DependencyVerdictChangeWire = z.infer<typeof dependencyVerdictChangeSchema>;

/**
 * Signals a request may report as unavailable: disclosed for the request, never a verdict by
 * themselves. The same list as `@kovo/core/dependency-verdicts` `DEPENDENCY_VERDICT_SIGNALS`; the
 * public route's types refuse to compile if the engine reports one this list lacks.
 */
export const dependencyVerdictSignalSchema = z.enum(["possible_typosquat"]);
export type DependencyVerdictSignalWire = z.infer<typeof dependencyVerdictSignalSchema>;

/**
 * Signals an enforcement point did not evaluate at all, stated on every verdict it returns so a
 * caller never reads a signal's absence as clean ("unknown is not a pass"). `publishing_path`: the
 * public endpoint does not verify attestation signatures, so a publishing-path change
 * (`trust_downgrade` from it) is never raised there.
 */
export const DEPENDENCY_UNEVALUATED_SIGNALS = ["publishing_path"] as const;
export const dependencyUnevaluatedSignalSchema = z.enum(DEPENDENCY_UNEVALUATED_SIGNALS);
export type DependencyUnevaluatedSignal = z.infer<typeof dependencyUnevaluatedSignalSchema>;

const REASON_ORDER: ReadonlyMap<string, number> = new Map(
  DEPENDENCY_VERDICT_REASONS.map((reason, index) => [reason, index]),
);

/**
 * One change's verdict as `POST /v1/dependency-verdicts` returns it: the change's identifiers, the
 * verdict, its stable reasons (in {@link DEPENDENCY_VERDICT_REASONS} order, empty exactly for
 * `allow`) and when a wait ends by itself. It never names an evidence source, a hold, a scanner or
 * an advisory: a verdict resting on third-party evidence reads exactly like any other Kovo hold.
 */
export const dependencyVerdictWireSchema = z
  .strictObject({
    ecosystem: dependencyEcosystemSchema,
    name: packageNameSchema,
    version: exactVersionSchema,
    verdict: dependencyVerdictKindSchema,
    reasons: z.array(dependencyVerdictReasonSchema).max(DEPENDENCY_VERDICT_REASONS.length),
    /** When the wait ends by itself (every waiting reason is `min_age`); null otherwise. */
    wait_until: utcDateTimeSchema.nullable(),
    /** Signals not evaluated for this verdict at all (never a clean result for them). */
    not_evaluated: z
      .array(dependencyUnevaluatedSignalSchema)
      .max(DEPENDENCY_UNEVALUATED_SIGNALS.length)
      .refine((signals) => new Set(signals).size === signals.length, {
        ...whenValid,
        error: "signals are unique",
      }),
  })
  .refine(
    (verdict) =>
      verdict.reasons.every(
        (reason, index) =>
          index === 0 ||
          (REASON_ORDER.get(reason) ?? -1) > (REASON_ORDER.get(verdict.reasons[index - 1]!) ?? -1),
      ),
    { ...whenValid, error: "reasons are unique and in their stable order", path: ["reasons"] },
  )
  .refine((verdict) => (verdict.verdict === "allow") === (verdict.reasons.length === 0), {
    ...whenValid,
    error: "exactly an allowed change has no reasons",
    path: ["reasons"],
  })
  .refine((verdict) => verdict.wait_until === null || verdict.verdict === "wait", {
    ...whenValid,
    error: "only a waiting change has a time its wait ends",
    path: ["wait_until"],
  });
export type DependencyVerdictWire = z.output<typeof dependencyVerdictWireSchema>;
