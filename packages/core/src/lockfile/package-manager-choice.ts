import {
  PACKAGE_MANAGER_CHOICE_LOCKFILES,
  PACKAGE_MANAGER_CHOICE_OPTIONS,
  type PackageManagerChoiceOption,
  type PackageManagerPreselectionBasis,
  type StoredPackageManagerChoice,
} from "@kovo/contracts";

import { isJsonObject, parseBoundedJson, type JsonObject } from "../manifest/bounded-json.js";
import { PACKAGE_JSON_LIMITS } from "../manifest/package-json.js";
import {
  NO_RUNTIME_DECLARATIONS,
  resolveRuntimeReleases,
  type PmSource,
  type RuntimeCatalog,
  type RuntimeDeclarations,
  type RuntimeRejectionReason,
} from "./compat.js";
import { FOREIGN_LOCKFILES, detectPackageManager } from "./detect.js";
import { LOCKFILE_NAMES } from "./parse.js";

// Repositories whose root commits both `package-lock.json` and `pnpm-lock.yaml` (owner choice A,
// 2026-10-27; SPEC "Web application and onboarding UI" → "Two root lockfiles"): detection
// refuses them (`multiple_lockfiles`) until a repository admin records which manager they use.
// Pure: names, versions and timestamps come in, decisions come out; nothing is read or logged.

/** The other option: the manager whose lockfile a choice ignores. */
export function otherPackageManager(
  chosen: PackageManagerChoiceOption,
): PackageManagerChoiceOption {
  return chosen === "npm" ? "pnpm" : "npm";
}

/** The root lockfiles a choice keeps and ignores. */
export function choiceLockfiles(chosen: PackageManagerChoiceOption): {
  readonly kept: (typeof PACKAGE_MANAGER_CHOICE_LOCKFILES)[PackageManagerChoiceOption];
  readonly ignored: (typeof PACKAGE_MANAGER_CHOICE_LOCKFILES)[PackageManagerChoiceOption];
} {
  return {
    kept: PACKAGE_MANAGER_CHOICE_LOCKFILES[chosen],
    ignored: PACKAGE_MANAGER_CHOICE_LOCKFILES[otherPackageManager(chosen)],
  };
}

/**
 * Whether a root's file names are the two-lockfile case a choice resolves: `package.json` with
 * both `package-lock.json` and `pnpm-lock.yaml`, and no Yarn, bun or shrinkwrap lockfile (those
 * keep their own refusals).
 */
export function isTwoLockfileRoot(rootFiles: readonly string[]): boolean {
  const detection = detectPackageManager(rootFiles);
  if (detection.ok || detection.reason !== "multiple_lockfiles") return false;
  const present = new Set(rootFiles);
  return (
    PACKAGE_MANAGER_CHOICE_OPTIONS.every((pm) => present.has(LOCKFILE_NAMES[pm])) &&
    !present.has(LOCKFILE_NAMES.yarn) &&
    !Object.keys(FOREIGN_LOCKFILES).some((name) => present.has(name))
  );
}

/** Why admission did not apply a stored choice (reason codes; metadata only). */
export const CHOICE_ADMISSION_REASONS = [
  "package_manager_choice_absent", // no choice is recorded: `multiple_lockfiles` stays
  "package_manager_choice_unreadable", // a stored value no known shape reads: fail closed
  "package_manager_choice_not_applicable", // the root does not commit exactly both lockfiles (N2)
] as const;
export type ChoiceAdmissionReason = (typeof CHOICE_ADMISSION_REASONS)[number];

export type ChoiceAdmission =
  | {
      readonly honoured: true;
      readonly packageManager: PackageManagerChoiceOption;
      /** The root lockfile admission keeps. */
      readonly keptLockfile: (typeof PACKAGE_MANAGER_CHOICE_LOCKFILES)[PackageManagerChoiceOption];
      /** The root lockfile admission ignores for detection and install. */
      readonly ignoredLockfile: (typeof PACKAGE_MANAGER_CHOICE_LOCKFILES)[PackageManagerChoiceOption];
      /** `<pm>@<version>`: the `packageManager` declaration the cleanup PR writes. */
      readonly declaration: string;
    }
  | { readonly honoured: false; readonly reason: ChoiceAdmissionReason };

/**
 * Whether admission applies a stored choice to a root, from the root's file names: only when the
 * root really commits both `package-lock.json` and `pnpm-lock.yaml` ({@link isTwoLockfileRoot}).
 * Any other root ignores a recorded choice and keeps its own detection outcome, and an unreadable
 * choice is never applied, so the root keeps its `multiple_lockfiles` refusal.
 */
export function admitPackageManagerChoice(
  rootFiles: readonly string[],
  stored: StoredPackageManagerChoice,
): ChoiceAdmission {
  if (stored.kind === "absent") return { honoured: false, reason: "package_manager_choice_absent" };
  if (stored.kind === "unreadable")
    return { honoured: false, reason: "package_manager_choice_unreadable" };
  if (!isTwoLockfileRoot(rootFiles))
    return { honoured: false, reason: "package_manager_choice_not_applicable" };
  const { kept, ignored } = choiceLockfiles(stored.choice.package_manager);
  return {
    honoured: true,
    packageManager: stored.choice.package_manager,
    keptLockfile: kept,
    ignoredLockfile: ignored,
    declaration: `${stored.choice.package_manager}@${stored.choice.version}`,
  };
}

/** The root's file names with an honoured choice's ignored lockfile removed. */
export function rootFilesUnderChoice(
  rootFiles: readonly string[],
  admission: ChoiceAdmission,
): readonly string[] {
  return admission.honoured
    ? rootFiles.filter((name) => name !== admission.ignoredLockfile)
    : rootFiles;
}

/**
 * The runtime declarations admission resolves under an honoured choice: the repository as the
 * cleanup PR leaves it. Without a root `packageManager` field the choice is the declaration, so
 * Kovo runs the baked release of the chosen major against the kept lockfile; a field the
 * repository already commits still governs (a field naming the other manager refuses as
 * `package_manager_mismatch`). Engines, Volta and Node files are checked as always.
 */
export function withChosenPackageManager(
  declarations: RuntimeDeclarations,
  chosen: string | undefined,
): RuntimeDeclarations {
  if (chosen === undefined || declarations.packageManager !== null) return declarations;
  return { ...declarations, packageManager: chosen };
}

export type ChosenVersionValidation =
  | {
      readonly ok: true;
      /** The exact release Kovo runs: the image's baked release of the chosen major. */
      readonly runningVersion: string;
    }
  | { readonly ok: false; readonly reason: RuntimeRejectionReason };

/**
 * Validates an admin's exact version for the chosen manager with the one runtime resolver, as if
 * the root declared `"packageManager": "<pm>@<version>"`: the major must be in the compatibility
 * matrix (`pm_major_unsupported`) and baked into the image (`pm_version_unavailable`); a
 * malformed version is `invalid_package_manager_field`. The repository's other declarations
 * (engines, Volta, Node files) are checked again by admission against the kept lockfile.
 */
export function validateChosenVersion(input: {
  readonly packageManager: PackageManagerChoiceOption;
  readonly version: string;
  readonly catalog: RuntimeCatalog;
}): ChosenVersionValidation {
  const resolution = resolveRuntimeReleases({
    declarations: {
      ...NO_RUNTIME_DECLARATIONS,
      packageManager: `${input.packageManager}@${input.version}`,
    },
    packageManager: input.packageManager,
    catalog: input.catalog,
  });
  if (!resolution.ok) return { ok: false, reason: resolution.reason };
  return { ok: true, runningVersion: resolution.runtime.pmVersion };
}

/** Evidence for preselecting a manager, reduced to names and commit timestamps. */
export interface PreselectionEvidence {
  /** The root `package.json` `packageManager` value (read in memory), or null. */
  readonly packageManagerField: string | null;
  /** The managers CI installs dependencies with (`ciInstallManagers`), in order of appearance. */
  readonly ciInstallManagers: readonly PackageManagerChoiceOption[];
  /**
   * When each root lockfile last changed on the default branch, from commit metadata only; null
   * when unknown.
   */
  readonly lockfileLastChanged: {
    readonly npm: Date | null;
    readonly pnpm: Date | null;
  };
}

export interface Preselection {
  readonly packageManager: PackageManagerChoiceOption | null;
  readonly basis: PackageManagerPreselectionBasis;
}

/** The manager a `packageManager` value names, when it is npm or pnpm. */
function fieldManager(field: string | null): PackageManagerChoiceOption | null {
  if (field === null) return null;
  const name = field.trim().split("@", 1)[0];
  return name === "npm" || name === "pnpm" ? name : null;
}

/**
 * The picker's preselection, in precedence order: a `packageManager` field naming npm or pnpm;
 * CI installing with exactly one of them; the lockfile that changed most recently. With none of
 * these (or a tie), nothing is preselected and the admin chooses.
 */
export function preselectPackageManager(evidence: PreselectionEvidence): Preselection {
  const declared = fieldManager(evidence.packageManagerField);
  if (declared !== null) return { packageManager: declared, basis: "package_manager_field" };
  const ci = [...new Set(evidence.ciInstallManagers)];
  const [onlyCi] = ci;
  if (ci.length === 1 && onlyCi !== undefined) {
    return { packageManager: onlyCi, basis: "ci_install" };
  }
  const { npm, pnpm } = evidence.lockfileLastChanged;
  if (npm !== null && pnpm !== null && npm.getTime() !== pnpm.getTime()) {
    return {
      packageManager: npm.getTime() > pnpm.getTime() ? "npm" : "pnpm",
      basis: "lockfile_recency",
    };
  }
  return { packageManager: null, basis: "none" };
}

/** A string member of a JSON object, or null. */
function stringMember(object: JsonObject, key: string): string | null {
  const value = Object.hasOwn(object, key) ? object[key] : undefined;
  return typeof value === "string" ? value : null;
}

/**
 * The runtime declarations of a root `package.json` and its version files, read leniently for the
 * picker: only the string `packageManager`, `engines` and `volta` members are taken, and a
 * document that does not parse declares nothing. Admission still parses the manifest strictly.
 * The text stays in memory; only the declarations come out.
 */
export function pickerRuntimeDeclarations(files: {
  readonly packageJson: string | null;
  readonly nvmrc: string | null;
  readonly nodeVersionFile: string | null;
  readonly toolVersions: string | null;
}): RuntimeDeclarations {
  const parsed =
    files.packageJson === null ? null : parseBoundedJson(files.packageJson, PACKAGE_JSON_LIMITS);
  const document: JsonObject =
    parsed !== null && parsed.ok && isJsonObject(parsed.value) ? parsed.value : {};
  const member = stringMember;
  const section = (key: string): JsonObject => {
    const value = Object.hasOwn(document, key) ? document[key] : undefined;
    return isJsonObject(value) ? value : {};
  };
  const engines = section("engines");
  const volta = section("volta");
  return {
    nvmrc: files.nvmrc,
    nodeVersionFile: files.nodeVersionFile,
    toolVersions: files.toolVersions,
    volta: { node: member(volta, "node"), npm: member(volta, "npm"), pnpm: member(volta, "pnpm") },
    engines: {
      node: member(engines, "node"),
      npm: member(engines, "npm"),
      pnpm: member(engines, "pnpm"),
    },
    packageManager: member(document, "packageManager"),
  };
}

/** The version the picker suggests for one manager, or why it has none. */
export type SuggestedPackageManagerVersion =
  | {
      readonly packageManager: PackageManagerChoiceOption;
      readonly ok: true;
      /** The exact release Kovo would run: the image's baked release of the resolved major. */
      readonly version: string;
      /** Where the major came from (the resolver's package-manager source). */
      readonly source: PmSource;
    }
  | {
      readonly packageManager: PackageManagerChoiceOption;
      readonly ok: false;
      /** The resolver's rejection: the admin must enter a version the matrix accepts. */
      readonly reason: RuntimeRejectionReason;
    };

export interface PackageManagerSuggestion {
  /** Whether the root commits exactly the npm and pnpm lockfiles ({@link isTwoLockfileRoot}). */
  readonly twoLockfileRoot: boolean;
  readonly preselection: Preselection;
  /** One entry per option, npm first; empty when the root needs no choice. */
  readonly options: readonly SuggestedPackageManagerVersion[];
}

/** What CI says about the managers: which ones install, and the Node and pnpm majors it runs. */
export interface PackageManagerCiEvidence {
  readonly installManagers: readonly PackageManagerChoiceOption[];
  readonly nodeMajors: readonly number[];
  readonly pnpmMajors: readonly number[];
}

/**
 * What the picker shows for a repository root (SPEC "Two root lockfiles"): whether the root needs
 * a choice, the preselected manager and, for each option, the exact version the one runtime
 * resolver picks from the repository's declarations and CI, with its source. Each option is
 * resolved as the repository's declarations stand, so a `packageManager` field naming the other
 * manager leaves that option without a version (`package_manager_mismatch`).
 */
export function suggestPackageManagerChoice(input: {
  readonly rootFiles: readonly string[];
  readonly declarations: RuntimeDeclarations;
  readonly ci: PackageManagerCiEvidence;
  readonly lockfileLastChanged: PreselectionEvidence["lockfileLastChanged"];
  readonly catalog: RuntimeCatalog;
}): PackageManagerSuggestion {
  if (!isTwoLockfileRoot(input.rootFiles)) {
    return {
      twoLockfileRoot: false,
      preselection: { packageManager: null, basis: "none" },
      options: [],
    };
  }
  const preselection = preselectPackageManager({
    packageManagerField: input.declarations.packageManager,
    ciInstallManagers: input.ci.installManagers,
    lockfileLastChanged: input.lockfileLastChanged,
  });
  const options = PACKAGE_MANAGER_CHOICE_OPTIONS.map(
    (packageManager): SuggestedPackageManagerVersion => {
      const resolution = resolveRuntimeReleases({
        declarations: input.declarations,
        packageManager,
        catalog: input.catalog,
        preferences: {
          nodeMajors: input.ci.nodeMajors,
          pmMajors: packageManager === "pnpm" ? input.ci.pnpmMajors : [],
        },
      });
      return resolution.ok
        ? {
            packageManager,
            ok: true,
            version: resolution.runtime.pmVersion,
            source: resolution.runtime.pmSource,
          }
        : { packageManager, ok: false, reason: resolution.reason };
    },
  );
  return { twoLockfileRoot: true, preselection, options };
}
