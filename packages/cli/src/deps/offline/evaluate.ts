import {
  packageNameSchema,
  type DependencyVerdictChangeWire,
  type DependencyVerdictWire,
} from "@kovo/contracts";
import {
  evaluateDependencyChanges,
  PLATFORM_DEPENDENCY_POLICY,
  type DependencyEvidence,
  type DependencyVerdictInput,
} from "@kovo/core/dependency-verdicts";

import { unavailableError } from "../../errors.js";
import { advisoriesFor, osvEvidence } from "./osv-index.js";
import { osvSnapshot, type OsvSnapshot, type OsvSnapshotOptions } from "./osv-snapshot.js";
import {
  readPackuments,
  versionFacts,
  type PackumentRead,
  type RegistryOptions,
} from "./registry.js";

// `kovo deps check --offline` (plans/dependency-firewall.md Part 4 items 3-4): the same change list
// judged by the same pure engine (`evaluateDependencyChanges`, `PLATFORM_DEPENDENCY_POLICY`) from
// evidence the CLI reads itself: OSV's public npm export and the public npm registry. Kovo's own
// holds are not consulted, and neither is the popular-package list (the typosquat signal is then
// reported unavailable, as the engine does).

export interface OfflineOptions {
  readonly osv: Omit<OsvSnapshotOptions, "fetch">;
  readonly registry: Omit<RegistryOptions, "fetch">;
  readonly fetch: typeof fetch;
  readonly now: Date;
}

export interface OfflineAnswer {
  readonly verdicts: readonly DependencyVerdictWire[];
  readonly unavailableSignals: readonly string[];
  readonly snapshot: OsvSnapshot;
}

function input(change: DependencyVerdictChangeWire): DependencyVerdictInput {
  return {
    ecosystem: change.ecosystem,
    name: change.name,
    version: change.version,
    integrity: change.integrity,
    kind: change.kind,
    direct: change.direct,
    previousVersion: change.previous_version,
    source: change.source,
  };
}

function registryEvidence(
  change: DependencyVerdictChangeWire,
  read: PackumentRead | undefined,
): DependencyEvidence["registry"] {
  if (read === undefined || read.status === "unavailable") return { status: "unavailable" };
  if (read.status === "not_found") return { status: "read", current: null, previous: null };
  return {
    status: "read",
    current: versionFacts(read.packument, change.version),
    previous:
      change.previous_version === null
        ? null
        : versionFacts(read.packument, change.previous_version),
  };
}

/**
 * Judges `changes` offline. Errors (exit 3): the OSV snapshot cannot be had or read, or the
 * registry answered none of the packages it was asked about.
 */
export async function offlineVerdicts(
  changes: readonly DependencyVerdictChangeWire[],
  options: OfflineOptions,
): Promise<OfflineAnswer> {
  const snapshot = await osvSnapshot({ ...options.osv, fetch: options.fetch });
  const names = new Set(changes.map((change) => change.name));
  const advisories = await advisoriesFor(snapshot, names);
  const osv = osvEvidence(
    changes.map((change) => ({
      name: change.name,
      version: change.version,
      previousVersion: change.previous_version,
    })),
    advisories,
  );
  // Registry evidence describes only versions the public registry serves (the engine ignores it
  // for exotic sources), so only those packages are read.
  const registryNames = [
    ...new Set(changes.filter((c) => c.source === "registry").map((c) => c.name)),
  ].map((name) => packageNameSchema.parse(name));
  const packuments = await readPackuments(registryNames, {
    ...options.registry,
    fetch: options.fetch,
  });
  if (
    registryNames.length > 0 &&
    registryNames.every((name) => packuments.get(name)?.status === "unavailable")
  )
    throw unavailableError(
      "registry_unreachable",
      "The npm registry could not be read for any changed package.",
    );
  const result = evaluateDependencyChanges({
    changes: changes.map(input),
    evidence: changes.map((change, index) => ({
      holds: osv[index]!.holds,
      introducedAdvisories: osv[index]!.introducedAdvisories,
      registry: registryEvidence(change, packuments.get(change.name)),
    })),
    popular: null,
    now: options.now,
    policy: PLATFORM_DEPENDENCY_POLICY,
  });
  return {
    // Aligned with `changes` (the engine's contract), so identifiers come from the change list.
    verdicts: result.verdicts.map((verdict, index) => ({
      ecosystem: changes[index]!.ecosystem,
      name: changes[index]!.name,
      version: changes[index]!.version,
      verdict: verdict.verdict,
      reasons: [...verdict.reasons],
      wait_until: verdict.waitUntil,
      // Attestations are not verified offline, so neither publishing-path signal runs.
      not_evaluated: ["publishing_path"],
    })),
    unavailableSignals: result.unavailableSignals,
    snapshot,
  };
}
