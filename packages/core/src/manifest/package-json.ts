import {
  isSettingsOnlyPnpmYaml,
  type PnpmFixRefusalReason,
  pnpmSettingJsonValueAccepted,
  pnpmSettingsOverrides,
} from "./pnpm-settings.js";
import { packageNameSchema, type PackageName, type UnsupportedRepoReason } from "@kovo/contracts";
import { z } from "zod";

import {
  isJsonObject,
  parseBoundedJson,
  type JsonLimits,
  type JsonObject,
  type JsonValue,
} from "./bounded-json.js";
import {
  classifyDependencySpec,
  MAX_SPEC_LENGTH,
  type DependencySpec,
  type RegistrySpec,
} from "./dependency-spec.js";
import { pointerOf } from "./json-pointer.js";
import {
  manifestRejection,
  primaryUnsupportedReason,
  type ManifestRejection,
  type ManifestRejectionReason,
} from "./reasons.js";
import { reportedPointer } from "./safe-pointer.js";
import { parsePnpmSelector, parseSelectorStep, parseYarnSelector } from "./selectors.js";

// package.json parsing (BUILD_PLAN item 7; SPEC inventoryWorkflow step 1 "Reject customer
// workspaces …"; "single-package customer repos (no workspaces)"). The file is hostile input: it is
// parsed with the bounded JSON parser, validated with Zod, and every dependency spec is classified.
// The parsed manifest lives in memory only; package.json content is never persisted or logged
// (SPEC: "Never persist or log source, diffs, manifests …").

/** Bounds for package.json: generous for real projects, small enough to parse safely. */
export const PACKAGE_JSON_LIMITS: JsonLimits = {
  maxLength: 1024 * 1024,
  maxDepth: 32,
  maxNodes: 100_000,
  maxStringLength: 64 * 1024,
};

/** At most this many entries in one dependency map or override map. */
export const MAX_DEPENDENCIES_PER_SECTION = 10_000;

export const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;
export type DependencySection = (typeof DEPENDENCY_SECTIONS)[number];

type RegistryDependencySpec = Extract<DependencySpec, { kind: "range" | "tag" | "alias" }>;

export interface ManifestDependency {
  readonly section: DependencySection;
  /** The dependency key: the install folder name, which is an alias for `npm:` specs. */
  readonly alias: PackageName;
  /** The registry package installed under `alias` (the alias target, or `alias` itself). */
  readonly name: PackageName;
  /** The declared spec, kept in memory for edit planning only. */
  readonly spec: string;
  /** The spec as the registry resolves it (`range`/`tag` for the target of an alias). */
  readonly registrySpec: RegistrySpec;
  readonly aliased: boolean;
}

/** One override rule, flattened to its selector path. */
export interface OverrideRule {
  readonly manager: "npm" | "pnpm" | "yarn";
  /** Where the rule lives, e.g. `/overrides/debug@4.3.4/ms` or `/pnpm/overrides/debug@4.3.4>ms`. */
  readonly pointer: string;
  /** Selector steps from the outermost key to the overridden package (`["debug@4.3.4", "ms"]`). */
  readonly selector: readonly string[];
  /** The package the rule overrides (the last selector step, without its range). */
  readonly target: PackageName;
  readonly spec: string;
}

export interface PackageManifest {
  readonly name: string | null;
  readonly version: string | null;
  readonly dependencies: readonly ManifestDependency[];
  readonly overrides: readonly OverrideRule[];
  readonly engines: {
    readonly node: string | null;
    readonly npm: string | null;
    readonly pnpm: string | null;
    readonly yarn?: string | null;
  };
  readonly packageManager: string | null;
  /**
   * Volta pins (`volta.node`, `volta.npm`, `volta.pnpm`), a runtime declaration; string members
   * only (anything else is not a pin Volta would use).
   */
  readonly volta: {
    readonly node: string | null;
    readonly npm: string | null;
    readonly pnpm: string | null;
    readonly yarn?: string | null;
  };
  /** Script names to commands, in memory only (recipe discovery reads them). */
  readonly scripts: Readonly<Record<string, string>>;
  /** `pnpm.patchedDependencies` selectors: packages patched from repository files. */
  readonly pnpmPatchedDependencies: readonly string[];
  /** The parsed document, for JSON-pointer checks and edits. */
  readonly document: JsonObject;
}

export interface PackageJsonInput {
  /** The raw package.json text at the inventoried commit. */
  readonly text: string;
  /** Lockfile manager; absent preserves legacy npm/pnpm resolutions interpretation. */
  readonly packageManager?: "npm" | "pnpm" | "yarn";
  /** Whether `pnpm-workspace.yaml` exists at the repository root (a pnpm workspace). */
  readonly pnpmWorkspaceYamlPresent: boolean;
  /** Complete root configuration text; omitted/unreadable present files still refuse. */
  readonly pnpmWorkspaceYaml?: string;
}

export type PackageJsonResult =
  | { readonly ok: true; readonly manifest: PackageManifest }
  | {
      readonly ok: false;
      /** The coarse reason to record on the repository. */
      readonly unsupported: UnsupportedRepoReason;
      /** Every problem found, in document order (bounded). */
      readonly rejections: readonly ManifestRejection[];
    };

/** At most this many rejections are reported; one is enough to reject. */
export const MAX_REPORTED_REJECTIONS = 50;

const stringMap = (maxValue: number) =>
  z
    .record(z.string().max(256), z.string().max(maxValue))
    .refine((map) => Object.keys(map).length <= MAX_DEPENDENCIES_PER_SECTION, {
      error: "too many entries",
    });

/** The fields Kovo reads, with their shapes; every other field is left alone. */
const packageJsonShapeSchema = z.looseObject({
  name: z.string().max(214).optional(),
  version: z.string().max(256).optional(),
  dependencies: stringMap(MAX_SPEC_LENGTH).optional(),
  devDependencies: stringMap(MAX_SPEC_LENGTH).optional(),
  optionalDependencies: stringMap(MAX_SPEC_LENGTH).optional(),
  peerDependencies: stringMap(MAX_SPEC_LENGTH).optional(),
  engines: stringMap(1024).optional(),
  packageManager: z.string().max(512).optional(),
  scripts: stringMap(64 * 1024).optional(),
  overrides: z.record(z.string(), z.unknown()).optional(),
  resolutions: stringMap(MAX_SPEC_LENGTH).optional(),
  pnpm: z
    .looseObject({
      overrides: stringMap(MAX_SPEC_LENGTH).optional(),
      patchedDependencies: stringMap(4096).optional(),
      packageExtensions: z.record(z.string(), z.unknown()).optional(),
    })
    .optional(),
});

/** `pnpm` keys validated on their own below: overrides, patches and package extensions. */
const PNPM_FIELDS_VALIDATED = new Set(["overrides", "patchedDependencies", "packageExtensions"]);

/**
 * Keys a JavaScript reader may resolve through the prototype chain rather than as data (#1828):
 * refused anywhere inside the `pnpm` field of a pnpm repository.
 */
const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function hasWorkspaces(value: JsonValue | undefined): boolean {
  if (value === undefined || value === null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (isJsonObject(value)) {
    const packages = value["packages"];
    return !(Array.isArray(packages) && packages.length === 0 && Object.keys(value).length === 1);
  }
  return true;
}

const JSON_ERROR_REASON = {
  too_large: "json_too_large",
  too_deep: "json_too_deep",
  too_many_nodes: "json_too_large",
  string_too_long: "json_too_large",
  duplicate_key: "json_duplicate_key",
  syntax: "json_syntax",
} as const satisfies Record<string, ManifestRejectionReason>;

/** A registry spec or the reason it is not one. */
function registrySpecOrReason(
  spec: string,
): { readonly spec: RegistryDependencySpec } | { readonly reason: ManifestRejectionReason } {
  const classified = classifyDependencySpec(spec);
  if (classified.kind === "rejected") return { reason: classified.reason };
  if (classified.kind === "invalid") return { reason: "invalid_dependency_spec" };
  return { spec: classified };
}

/** An override value: a registry spec, a `$name` reference to a direct dependency, or pnpm's `-`. */
function checkOverrideValue(
  value: string,
  manager: "npm" | "pnpm" | "yarn",
): ManifestRejectionReason | null {
  if (manager !== "yarn" && /^\$[^\s]+$/.test(value)) {
    return packageNameSchema.safeParse(value.slice(1)).success ? null : "invalid_override";
  }
  if (manager === "pnpm" && value === "-") return null;
  const result = registrySpecOrReason(value);
  return "reason" in result
    ? result.reason === "invalid_dependency_spec"
      ? "invalid_override"
      : result.reason
    : null;
}

class ManifestReader {
  readonly rejections: ManifestRejection[] = [];
  /** The parsed document, once there is one (positions of unshowable keys come from it). */
  document: JsonObject | null = null;

  reject(reason: ManifestRejectionReason, segments: readonly string[]): void {
    if (this.rejections.length < MAX_REPORTED_REJECTIONS) {
      this.rejections.push(manifestRejection(reason, reportedPointer(this.document, segments)));
    }
  }

  dependencies(document: z.infer<typeof packageJsonShapeSchema>): ManifestDependency[] {
    const result: ManifestDependency[] = [];
    for (const section of DEPENDENCY_SECTIONS) {
      const map = document[section];
      if (map === undefined) continue;
      for (const [key, spec] of Object.entries(map)) {
        const segments = [section, key];
        const alias = packageNameSchema.safeParse(key);
        if (!alias.success) {
          this.reject("invalid_dependency_name", segments);
          continue;
        }
        const classified = registrySpecOrReason(spec);
        if ("reason" in classified) {
          this.reject(classified.reason, segments);
          continue;
        }
        const aliased = classified.spec.kind === "alias";
        result.push({
          section,
          alias: alias.data,
          name: classified.spec.kind === "alias" ? classified.spec.name : alias.data,
          spec,
          registrySpec: classified.spec.kind === "alias" ? classified.spec.target : classified.spec,
          aliased,
        });
      }
    }
    return result;
  }

  /** npm `overrides`: nested objects keyed by selectors, with `.` meaning the enclosing package. */
  npmOverrides(overrides: JsonValue | undefined): OverrideRule[] {
    const rules: OverrideRule[] = [];
    const walk = (node: JsonObject, path: readonly string[]): void => {
      for (const [key, value] of Object.entries(node)) {
        const selector = [...path, key];
        const segments = ["overrides", ...selector];
        const stepName = key === "." ? null : parseSelectorStep(key);
        if (key !== "." && stepName === null) {
          this.reject("invalid_override", segments);
          continue;
        }
        if (typeof value === "string") {
          const problem = checkOverrideValue(value, "npm");
          if (problem !== null) {
            this.reject(problem, segments);
            continue;
          }
          const targetStep = key === "." ? path[path.length - 1] : key;
          const target = targetStep === undefined ? null : parseSelectorStep(targetStep);
          if (target === null) {
            this.reject("invalid_override", segments);
            continue;
          }
          rules.push({
            manager: "npm",
            pointer: pointerOf(segments),
            selector,
            target,
            spec: value,
          });
        } else if (isJsonObject(value)) {
          walk(value, selector);
        } else {
          this.reject("invalid_override", segments);
        }
      }
    };
    if (isJsonObject(overrides)) walk(overrides, []);
    return rules;
  }

  /** pnpm `pnpm.overrides` (and `resolutions`, which pnpm also honours): flat `a>b` selectors. */
  pnpmOverrides(
    overrides: Record<string, string> | undefined,
    base: readonly string[],
  ): OverrideRule[] {
    const rules: OverrideRule[] = [];
    for (const [key, value] of Object.entries(overrides ?? {})) {
      const segments = [...base, key];
      const selector = parsePnpmSelector(key);
      if (selector === null) {
        this.reject("invalid_override", segments);
        continue;
      }
      const problem = checkOverrideValue(value, "pnpm");
      if (problem !== null) {
        this.reject(problem, segments);
        continue;
      }
      rules.push({
        manager: "pnpm",
        pointer: pointerOf(segments),
        selector: selector.steps,
        target: selector.target,
        spec: value,
      });
    }
    return rules;
  }

  yarnResolutions(resolutions: Record<string, string> | undefined): OverrideRule[] {
    const rules: OverrideRule[] = [];
    for (const [key, value] of Object.entries(resolutions ?? {})) {
      const segments = ["resolutions", key];
      const selector = parseYarnSelector(key);
      const problem = checkOverrideValue(value, "yarn");
      if (selector === null || problem !== null) {
        this.reject(problem ?? "invalid_override", segments);
        continue;
      }
      rules.push({
        manager: "yarn",
        pointer: pointerOf(segments),
        selector: selector.steps,
        target: selector.target,
        spec: value,
      });
    }
    return rules;
  }

  /**
   * The other `pnpm` keys of a pnpm repository's package.json. pnpm 9 and 10 read settings from
   * this field (#1879; pnpm 11 and 12 ignore it), so it may set only what `pnpm-workspace.yaml` may:
   * a key the shared allowlist admits, with a value it accepts (`pnpmSettingJsonValueAccepted`).
   * Anything else, and a reserved key at any depth, is refused as `unsupported_workspace_setting`,
   * the reason the YAML and `.npmrc` settings get. The pnpm major is not always known here, so the
   * rule applies to every pnpm repository.
   */
  pnpmSettings(pnpmField: JsonValue | undefined): void {
    if (!isJsonObject(pnpmField)) return;
    const reserved = (node: JsonValue, segments: readonly string[]): void => {
      const entries = Array.isArray(node)
        ? node.map((item, index) => [String(index), item] as const)
        : isJsonObject(node)
          ? Object.entries(node)
          : [];
      for (const [key, value] of entries) {
        const next = [...segments, key];
        if (!Array.isArray(node) && RESERVED_KEYS.has(key)) {
          this.reject("unsupported_workspace_setting", next);
        } else {
          reserved(value, next);
        }
      }
    };
    // A reserved key at the top is no admitted setting, so the allowlist refuses it.
    for (const [key, value] of Object.entries(pnpmField)) {
      const segments = ["pnpm", key];
      if (!PNPM_FIELDS_VALIDATED.has(key) && !pnpmSettingJsonValueAccepted(key, value)) {
        this.reject("unsupported_workspace_setting", segments);
      } else {
        reserved(value, segments);
      }
    }
  }

  /** `pnpm.packageExtensions` add dependencies to other packages; their specs must be registry specs. */
  packageExtensions(extensions: JsonValue | undefined): void {
    if (!isJsonObject(extensions)) return;
    for (const [selector, extension] of Object.entries(extensions)) {
      const segments = ["pnpm", "packageExtensions", selector];
      if (parseSelectorStep(selector) === null || !isJsonObject(extension)) {
        this.reject("invalid_field", segments);
        continue;
      }
      for (const section of DEPENDENCY_SECTIONS) {
        const map = Object.hasOwn(extension, section) ? extension[section] : undefined;
        if (map === undefined) continue;
        if (!isJsonObject(map)) {
          this.reject("invalid_field", [...segments, section]);
          continue;
        }
        for (const [key, spec] of Object.entries(map)) {
          const entrySegments = [...segments, section, key];
          if (!packageNameSchema.safeParse(key).success) {
            this.reject("invalid_dependency_name", entrySegments);
          } else if (typeof spec !== "string") {
            this.reject("invalid_dependency_spec", entrySegments);
          } else {
            const classified = registrySpecOrReason(spec);
            if ("reason" in classified) this.reject(classified.reason, entrySegments);
          }
        }
      }
    }
  }
}

/**
 * Parses and validates package.json. Rejects workspaces (npm `workspaces`, or a pnpm-workspace.yaml
 * next to it), malformed or oversized documents, and every dependency, override or package
 * extension whose source is not the public npm registry, each with an explicit reason.
 */
export function parsePackageJson(input: PackageJsonInput): PackageJsonResult {
  const reader = new ManifestReader();
  const fail = (): PackageJsonResult => ({
    ok: false,
    unsupported: primaryUnsupportedReason(reader.rejections.map((r) => r.unsupported)),
    rejections: reader.rejections,
  });

  if (
    input.pnpmWorkspaceYamlPresent &&
    (input.pnpmWorkspaceYaml === undefined || !isSettingsOnlyPnpmYaml(input.pnpmWorkspaceYaml))
  )
    reader.reject("pnpm_workspace_file", []);
  const parsed = parseBoundedJson(input.text, PACKAGE_JSON_LIMITS);
  if (!parsed.ok) {
    reader.reject(JSON_ERROR_REASON[parsed.error], []);
    return fail();
  }
  if (!isJsonObject(parsed.value)) {
    reader.reject("not_an_object", []);
    return fail();
  }
  const document = parsed.value;
  reader.document = document;
  if (
    input.packageManager === "yarn" ||
    (typeof document["packageManager"] === "string" &&
      document["packageManager"].startsWith("yarn@"))
  ) {
    const installConfig = document["installConfig"];
    if (
      isJsonObject(installConfig) &&
      Object.hasOwn(installConfig, "pnp") &&
      installConfig["pnp"] !== false
    )
      reader.reject("invalid_field", ["installConfig", "pnp"]);
  }
  if (hasWorkspaces(document["workspaces"])) reader.reject("npm_workspaces", ["workspaces"]);

  const shape = packageJsonShapeSchema.safeParse(document);
  if (!shape.success) {
    for (const issue of shape.error.issues) {
      reader.reject(
        "invalid_field",
        issue.path.map((segment) => String(segment)),
      );
    }
    return fail();
  }
  const fields = shape.data;
  const dependencies = reader.dependencies(fields);
  const pnpmField = document["pnpm"];
  const overrides = [
    ...reader.npmOverrides(document["overrides"]),
    ...reader.pnpmOverrides(fields.pnpm?.overrides, ["pnpm", "overrides"]),
    ...reader.pnpmOverrides(pnpmSettingsOverrides(input.pnpmWorkspaceYaml), ["pnpm", "overrides"]),
    ...(input.packageManager === "yarn" || fields.packageManager?.startsWith("yarn@")
      ? reader.yarnResolutions(fields.resolutions)
      : reader.pnpmOverrides(fields.resolutions, ["resolutions"])),
  ];
  reader.packageExtensions(isJsonObject(pnpmField) ? pnpmField["packageExtensions"] : undefined);
  if (input.packageManager === "pnpm") reader.pnpmSettings(pnpmField);
  if (reader.rejections.length > 0) return fail();

  const engines = fields.engines ?? {};
  const voltaField = document["volta"];
  const volta = isJsonObject(voltaField) ? voltaField : {};
  const pin = (tool: string): string | null => {
    const value = volta[tool];
    return typeof value === "string" ? value : null;
  };
  return {
    ok: true,
    manifest: {
      name: fields.name ?? null,
      version: fields.version ?? null,
      dependencies,
      overrides,
      engines: {
        node: engines["node"] ?? null,
        npm: engines["npm"] ?? null,
        pnpm: engines["pnpm"] ?? null,
        ...(engines["yarn"] === undefined ? {} : { yarn: engines["yarn"] }),
      },
      packageManager: fields.packageManager ?? null,
      volta: {
        node: pin("node"),
        npm: pin("npm"),
        pnpm: pin("pnpm"),
        ...(pin("yarn") === null ? {} : { yarn: pin("yarn") }),
      },
      scripts: fields.scripts ?? {},
      pnpmPatchedDependencies: Object.keys(fields.pnpm?.patchedDependencies ?? {}),
      document,
    },
  };
}

/**
 * Why fixes are refused for a pnpm repository's root package.json, or null. Dependency checks
 * still accept the file; only fix generation and verification refuse it.
 *
 * pnpm 9 and 10 read settings from the `pnpm` field (#1879), and Kovo's verification install
 * cannot enforce `trustPolicy: no-downgrade` (see `pnpmFixRefusal`). A `pnpm.trustPolicy` other
 * than exactly `"off"` refuses as `trust_policy_unenforced`. Text `parsePackageJson` refuses yields
 * null: callers refuse it already.
 */
export function packageJsonFixRefusal(text: string): PnpmFixRefusalReason | null {
  const parsed = parseBoundedJson(text, PACKAGE_JSON_LIMITS);
  if (!parsed.ok || !isJsonObject(parsed.value)) return null;
  const pnpm = Object.hasOwn(parsed.value, "pnpm") ? parsed.value["pnpm"] : undefined;
  return isJsonObject(pnpm) && Object.hasOwn(pnpm, "trustPolicy") && pnpm["trustPolicy"] !== "off"
    ? "trust_policy_unenforced"
    : null;
}

/** The dependencies declared under `alias` (normally one; npm tolerates duplicates across sections). */
export function dependenciesNamed(
  manifest: PackageManifest,
  alias: string,
): readonly ManifestDependency[] {
  return manifest.dependencies.filter((dependency) => dependency.alias === alias);
}
