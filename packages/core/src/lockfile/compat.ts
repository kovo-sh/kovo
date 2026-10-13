import {
  LOCKFILE_FORMATS_BY_PM,
  SUPPORTED_NODE_MAJORS,
  SUPPORTED_PM_MAJORS,
  exactVersionSchema,
  runtimeSupport,
  whenValid,
  type LockfileFormat,
  type PackageManager,
  type UnsupportedRepoReason,
} from "@kovo/contracts";
import semver from "semver";
import { z } from "zod";

import type { PackageManifest } from "../manifest/package-json.js";
import {
  parseNodeDeclaration,
  toolVersionsNode,
  type NodeDeclaration,
} from "./node-declaration.js";

// The compatibility matrix and runtime resolution (SPEC "Version and sandbox compatibility"):
// "supported Node 22/24 runtimes, npm 10/11 and pnpm 9/10/11/12; npm lockfile v2/v3 and pnpm lockfile v9
// are the initial accepted formats. Unsupported majors/formats produce an explicit unsupported
// reason; never substitute the nearest runtime. Resolve an exact compatible runtime/PM version into
// each recipe. Runtime/bootstrap packages are baked into the image or fetched only through the
// proxy."
//
// The one resolver: inventory judges a repository's support with it, and recipe discovery resolves
// the exact runtime of each recipe with it, so the two never disagree (docs/decisions/lockfile.md
// "Runtime resolution"). Support is judged by major: a version declaration (`.nvmrc`,
// `.node-version`, `.tool-versions`, Volta, `packageManager`) fixes the major, which must be in the
// matrix and baked into the image; the exact version resolved is the image's baked release of that
// major. `engines` ranges must be satisfied exactly by the baked release. A major outside the
// matrix, or one the image does not bake, is an explicit unsupported reason, never another major.

const catalogNodeSchema = z.strictObject({
  version: exactVersionSchema,
  /** The npm release this Node release bundles. */
  npm: exactVersionSchema,
});

/**
 * The exact runtimes and package managers the pinned sandbox image provides: the shape of the
 * catalog the image build writes to `/opt/kovo/toolchain.json` from
 * `infra/sandbox-image/toolchain.json`.
 */
export const runtimeCatalogSchema = z
  .strictObject({
    node: z.array(catalogNodeSchema).min(1).max(20),
    /** npm releases baked in addition to the ones Node bundles. */
    npm: z.array(exactVersionSchema).max(20),
    pnpm: z.array(exactVersionSchema).min(1).max(20),
    yarn: z.array(exactVersionSchema).max(20).exactOptional(),
    defaultNodeMajor: z.int(),
    defaultPnpm: exactVersionSchema,
    /** What `lts/*` means for this catalog version (the active LTS major), or null. */
    ltsNodeMajor: z.int().nullable(),
  })
  .superRefine((catalog, ctx) => {
    const nodeMajors: readonly number[] = SUPPORTED_NODE_MAJORS;
    for (const node of catalog.node) {
      if (!nodeMajors.includes(semver.major(node.version))) {
        ctx.addIssue({ code: "custom", path: ["node"], message: "Node outside the matrix" });
      }
    }
    const npmMajors: readonly number[] = SUPPORTED_PM_MAJORS.npm;
    for (const version of [...catalog.npm, ...catalog.node.map((node) => node.npm)]) {
      if (!npmMajors.includes(semver.major(version))) {
        ctx.addIssue({ code: "custom", path: ["npm"], message: "npm outside the matrix" });
      }
    }
    const pnpmMajors: readonly number[] = SUPPORTED_PM_MAJORS.pnpm;
    for (const version of catalog.pnpm) {
      if (!pnpmMajors.includes(semver.major(version))) {
        ctx.addIssue({ code: "custom", path: ["pnpm"], message: "pnpm outside the matrix" });
      }
    }
    for (const version of catalog.yarn ?? []) {
      if (semver.major(version) !== 1) {
        ctx.addIssue({ code: "custom", path: ["yarn"], message: "Yarn outside the matrix" });
      }
    }
    if (!catalog.node.some((node) => semver.major(node.version) === catalog.defaultNodeMajor)) {
      ctx.addIssue({ code: "custom", path: ["defaultNodeMajor"], message: "not in the catalog" });
    }
    if (!catalog.pnpm.includes(catalog.defaultPnpm)) {
      ctx.addIssue({ code: "custom", path: ["defaultPnpm"], message: "not in the catalog" });
    }
  }, whenValid);
export type RuntimeCatalog = z.infer<typeof runtimeCatalogSchema>;

/** The exact Node releases the catalog bakes. */
export function catalogNodeVersions(catalog: RuntimeCatalog): string[] {
  return catalog.node.map((node) => node.version);
}

/** The exact releases of `pm` the catalog bakes (npm: every bundled release and the extra ones). */
export function catalogPmVersions(catalog: RuntimeCatalog, pm: PackageManager): string[] {
  if (pm === "yarn") return [...(catalog.yarn ?? [])];
  return pm === "pnpm"
    ? [...catalog.pnpm]
    : [...new Set([...catalog.node.map((node) => node.npm), ...catalog.npm])];
}

export const RUNTIME_REJECTION_REASONS = [
  "unrecognized_node_declaration", // a version file no version manager accepts (or over its bound)
  "node_alias_unresolvable", // `node`, `latest`, `lts/*` without a pinned LTS major, …
  "node_major_unsupported", // the declaration excludes every supported major (e.g. Node 20)
  "node_version_unavailable", // a supported major or range the image bakes no release for
  "conflicting_node_declarations", // each satisfiable alone, never together
  "invalid_package_manager_field", // `packageManager` is not `<name>@<exact version>[+<hash>]`
  "package_manager_unsupported", // `packageManager` names yarn, bun, …
  "package_manager_mismatch", // `packageManager` names the other supported manager than the lockfile
  "pm_major_unsupported", // e.g. pnpm@8, npm@9
  "pm_version_unavailable", // a supported major or engines range the image bakes no release for
  "pm_engines_mismatch", // packageManager's exact version violates engines
  "pnpm_settings_requires_v10", // pnpm 9 requires workspace membership in its YAML
  "lockfile_format_mismatch", // e.g. a pnpm lockfile for npm
] as const;
export type RuntimeRejectionReason = (typeof RUNTIME_REJECTION_REASONS)[number];

export const RUNTIME_REJECTION_UNSUPPORTED = {
  unrecognized_node_declaration: "unsupported_node_version",
  node_alias_unresolvable: "unsupported_node_version",
  node_major_unsupported: "unsupported_node_version",
  node_version_unavailable: "unsupported_node_version",
  conflicting_node_declarations: "unsupported_node_version",
  invalid_package_manager_field: "invalid_package_json",
  package_manager_unsupported: "unsupported_package_manager",
  package_manager_mismatch: "ambiguous_package_manager",
  pm_major_unsupported: "unsupported_pm_version",
  pm_version_unavailable: "unsupported_pm_version",
  pm_engines_mismatch: "unsupported_pm_version",
  pnpm_settings_requires_v10: "unsupported_pm_version",
  lockfile_format_mismatch: "unsupported_lockfile_format",
} as const satisfies Record<RuntimeRejectionReason, UnsupportedRepoReason>;

export const NODE_SOURCES = [
  "nvmrc",
  "node_version_file",
  "tool_versions",
  "volta",
  "engines",
  "ci",
  "default",
] as const;
export type NodeSource = (typeof NODE_SOURCES)[number];
export const PM_SOURCES = [
  "package_manager_field",
  "volta",
  "engines",
  "ci",
  "bundled_with_node",
  "default",
] as const;
export type PmSource = (typeof PM_SOURCES)[number];

/** Declarations that did not change the outcome, reported rather than failing (value-free). */
export const IGNORED_DECLARATIONS = ["invalid_engines_node", "invalid_engines_pm"] as const;
export type IgnoredDeclaration = (typeof IGNORED_DECLARATIONS)[number];

/** A repository's runtime declarations, read from its files (hostile text, bounded). */
export interface RuntimeDeclarations {
  /** `.nvmrc` content, or null when the file does not exist. */
  readonly nvmrc: string | null;
  /** `.node-version` content, or null when the file does not exist. */
  readonly nodeVersionFile: string | null;
  /** `.tool-versions` content (asdf, mise), or null when the file does not exist. */
  readonly toolVersions: string | null;
  /** package.json `volta` pins (string members only). */
  readonly volta: {
    readonly node: string | null;
    readonly npm: string | null;
    readonly pnpm: string | null;
    readonly yarn?: string | null;
  };
  /** package.json `engines` ranges (string members only). */
  readonly engines: {
    readonly node: string | null;
    readonly npm: string | null;
    readonly pnpm: string | null;
    readonly yarn?: string | null;
  };
  /** package.json `packageManager`, when it is a string. */
  readonly packageManager: string | null;
}

/** No declaration at all. */
export const NO_RUNTIME_DECLARATIONS: RuntimeDeclarations = {
  nvmrc: null,
  nodeVersionFile: null,
  toolVersions: null,
  volta: { node: null, npm: null, pnpm: null },
  engines: { node: null, npm: null, pnpm: null },
  packageManager: null,
};

/** The runtime declarations of a parsed package.json and the root's version files. */
export function runtimeDeclarationsOf(
  manifest: Pick<PackageManifest, "engines" | "packageManager" | "volta">,
  files: {
    readonly nvmrc: string | null;
    readonly nodeVersionFile: string | null;
    readonly toolVersions: string | null;
  },
): RuntimeDeclarations {
  return {
    nvmrc: files.nvmrc,
    nodeVersionFile: files.nodeVersionFile,
    toolVersions: files.toolVersions,
    volta: manifest.volta,
    engines: manifest.engines,
    packageManager: manifest.packageManager,
  };
}

/**
 * What CI runs (recipe discovery's `setup-node` and `pnpm/action-setup` majors): a preference
 * among the releases the declarations admit, never a constraint, so it never changes whether a
 * repository is supported.
 */
export interface RuntimePreferences {
  readonly nodeMajors: readonly number[];
  readonly pmMajors: readonly number[];
}

export interface RuntimeInput {
  readonly declarations: RuntimeDeclarations;
  /** The package manager the lockfile belongs to. */
  readonly packageManager: PackageManager;
  readonly lockfileFormat: LockfileFormat;
  readonly catalog: RuntimeCatalog;
  readonly preferences?: RuntimePreferences;
  /** Validated root YAML without workspace membership; pnpm 9 cannot execute this layout. */
  readonly pnpmSettingsOnly?: boolean;
}

export interface ResolvedRuntime {
  /** The exact baked Node release. */
  readonly node: string;
  readonly nodeSource: NodeSource;
  /** The declaration text that decided the Node major or range, when one did. */
  readonly nodeDeclared: string | null;
  readonly packageManager: PackageManager;
  /** The exact baked package-manager release. */
  readonly pmVersion: string;
  readonly pmSource: PmSource;
  readonly pmDeclared: string | null;
  readonly lockfileFormat: LockfileFormat;
  readonly ignored: readonly IgnoredDeclaration[];
}

export type RuntimeResolution =
  | { readonly ok: true; readonly runtime: ResolvedRuntime }
  | {
      readonly ok: false;
      readonly reason: RuntimeRejectionReason;
      readonly unsupported: UnsupportedRepoReason;
    };

type Step<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: RuntimeRejectionReason };

/** `22.x || 24.x`: the semver range of the matrix's majors. */
function supportedRange(majors: readonly number[]): string {
  return majors.map((major) => `${major}.x`).join(" || ");
}

const SUPPORTED_NODE_RANGE = supportedRange(SUPPORTED_NODE_MAJORS);

/** A valid engines range, or null (absent; invalid ones are reported in `ignored`). */
function enginesRange(
  value: string | null,
  note: IgnoredDeclaration,
  ignored: IgnoredDeclaration[],
): string | null {
  if (value === null) return null;
  const range = semver.validRange(value);
  if (range === null) ignored.push(note);
  return range;
}

interface NodeDeclared {
  readonly source: Extract<NodeSource, "nvmrc" | "node_version_file" | "tool_versions" | "volta">;
  readonly declaration: NodeDeclaration;
}

/** The Node declarations present, in precedence order. */
function nodeDeclarations(
  declarations: RuntimeDeclarations,
  ltsMajor: number | null,
): Step<NodeDeclared[]> {
  const found: NodeDeclared[] = [];
  const add = (source: NodeDeclared["source"], content: string | null) => {
    if (content === null) return;
    const declaration = parseNodeDeclaration(content, ltsMajor);
    if (declaration.kind !== "empty") found.push({ source, declaration });
  };
  add("nvmrc", declarations.nvmrc);
  add("node_version_file", declarations.nodeVersionFile);
  if (declarations.toolVersions !== null) {
    const line = toolVersionsNode(declarations.toolVersions);
    if (line.kind === "unreadable") return { ok: false, reason: "unrecognized_node_declaration" };
    if (line.kind === "version") add("tool_versions", line.text);
  }
  add("volta", declarations.volta.node);
  for (const { declaration } of found) {
    if (declaration.kind === "alias") return { ok: false, reason: "node_alias_unresolvable" };
    if (declaration.kind === "unrecognized") {
      return { ok: false, reason: "unrecognized_node_declaration" };
    }
  }
  return { ok: true, value: found };
}

function highest(versions: readonly string[]): string | undefined {
  return versions.toSorted(semver.rcompare)[0];
}

interface NodeChoice {
  readonly version: string;
  readonly npm: string;
  readonly source: NodeSource;
  readonly declared: string | null;
}

function resolveNode(input: RuntimeInput, ignored: IgnoredDeclaration[]): Step<NodeChoice> {
  const { catalog } = input;
  const found = nodeDeclarations(input.declarations, catalog.ltsNodeMajor);
  if (!found.ok) return found;
  const supported: readonly number[] = SUPPORTED_NODE_MAJORS;
  const pins: { readonly source: NodeSource; readonly major: number; readonly text: string }[] = [];
  const ranges: { readonly source: NodeSource; readonly range: string; readonly text: string }[] =
    [];
  for (const { source, declaration } of found.value) {
    if (declaration.kind === "major") {
      pins.push({ source, major: declaration.major, text: declaration.text });
    }
    if (declaration.kind === "range") {
      ranges.push({ source, range: declaration.range, text: declaration.text });
    }
  }
  const majors = new Set(pins.map((pin) => pin.major));
  if (majors.size > 1) return { ok: false, reason: "conflicting_node_declarations" };
  const [declaredMajor] = majors;
  if (declaredMajor !== undefined && !supported.includes(declaredMajor)) {
    return { ok: false, reason: "node_major_unsupported" };
  }
  const engines = enginesRange(input.declarations.engines.node, "invalid_engines_node", ignored);
  if (engines !== null) {
    ranges.push({ source: "engines", range: engines, text: input.declarations.engines.node ?? "" });
  }

  const baked = catalog.node.filter((node) => supported.includes(semver.major(node.version)));
  const candidates = baked.filter(
    (node) =>
      (declaredMajor === undefined || semver.major(node.version) === declaredMajor) &&
      ranges.every(({ range }) => semver.satisfies(node.version, range)),
  );
  if (candidates.length === 0) {
    // Explain precisely why nothing fits: never fall back to the nearest runtime.
    const wanted = [
      ...(declaredMajor === undefined ? [] : [`${declaredMajor}.x`]),
      ...ranges.map(({ range }) => range),
    ];
    const outside = wanted.some((range) => !semver.intersects(range, SUPPORTED_NODE_RANGE));
    if (outside) return { ok: false, reason: "node_major_unsupported" };
    const eachAlone = wanted.every((range) =>
      baked.some((node) => semver.satisfies(node.version, range)),
    );
    return {
      ok: false,
      reason: eachAlone ? "conflicting_node_declarations" : "node_version_unavailable",
    };
  }
  const inMajor = (major: number) =>
    candidates.filter((node) => semver.major(node.version) === major);
  const pick = (nodes: readonly (typeof candidates)[number][]) => {
    const version = highest(nodes.map((node) => node.version));
    return nodes.find((node) => node.version === version);
  };
  const [pin] = pins;
  if (pin !== undefined) {
    // A declared major: the image's release of it (every candidate is of that major).
    const chosen = pick(candidates);
    if (chosen === undefined) return { ok: false, reason: "node_version_unavailable" };
    return {
      ok: true,
      value: { version: chosen.version, npm: chosen.npm, source: pin.source, declared: pin.text },
    };
  }
  // Only ranges (or nothing) constrain the choice: what CI runs, then the catalog's default major,
  // then the oldest supported major the image bakes.
  for (const major of input.preferences?.nodeMajors ?? []) {
    const chosen = pick(inMajor(major));
    if (chosen !== undefined) {
      return {
        ok: true,
        value: { version: chosen.version, npm: chosen.npm, source: "ci", declared: null },
      };
    }
  }
  const [constraint] = ranges;
  for (const major of [catalog.defaultNodeMajor, ...supported]) {
    const chosen = pick(inMajor(major));
    if (chosen !== undefined) {
      return {
        ok: true,
        value: {
          version: chosen.version,
          npm: chosen.npm,
          source: constraint?.source ?? "default",
          declared: constraint?.text ?? null,
        },
      };
    }
  }
  return { ok: false, reason: "node_version_unavailable" };
}

const PACKAGE_MANAGER_FIELD =
  /^([a-z][a-z0-9-]*)@([^+\s]+)(?:\+([A-Za-z0-9]+\.[A-Za-z0-9+/=_-]+))?$/;

interface PmChoice {
  readonly version: string;
  readonly source: PmSource;
  readonly declared: string | null;
}

function resolvePackageManager(
  input: RuntimeInput,
  bundledNpm: string,
  ignored: IgnoredDeclaration[],
): Step<PmChoice> {
  const pm = input.packageManager;
  const supported: readonly number[] = SUPPORTED_PM_MAJORS[pm];
  const engines = enginesRange(
    input.declarations.engines[pm] ?? null,
    "invalid_engines_pm",
    ignored,
  );

  // A declaration fixes the major: `packageManager`, else a Volta pin of the lockfile's manager.
  let declaredMajor: number | null = null;
  let source: PmSource = "default";
  let declared: string | null = null;
  const field = input.declarations.packageManager;
  if (field !== null) {
    const match = PACKAGE_MANAGER_FIELD.exec(field.trim());
    const name = match?.[1];
    const version = match?.[2];
    if (name === undefined || version === undefined) {
      return { ok: false, reason: "invalid_package_manager_field" };
    }
    if (name !== "npm" && name !== "pnpm" && name !== "yarn") {
      return { ok: false, reason: "package_manager_unsupported" };
    }
    if (name === "yarn" && semver.valid(version) !== null && semver.major(version) !== 1) {
      return { ok: false, reason: "package_manager_unsupported" };
    }
    if (name !== pm) return { ok: false, reason: "package_manager_mismatch" };
    if (!exactVersionSchema.safeParse(version).success) {
      return { ok: false, reason: "invalid_package_manager_field" };
    }
    if (!supported.includes(semver.major(version))) {
      return { ok: false, reason: "pm_major_unsupported" };
    }
    if (engines !== null && !semver.satisfies(version, engines)) {
      return { ok: false, reason: "pm_engines_mismatch" };
    }
    declaredMajor = semver.major(version);
    source = "package_manager_field";
    declared = field;
  } else {
    const pin = input.declarations.volta[pm] ?? null;
    const coerced = pin === null ? null : semver.coerce(pin);
    if (pin !== null && coerced !== null) {
      if (!supported.includes(coerced.major)) {
        return { ok: false, reason: "pm_major_unsupported" };
      }
      declaredMajor = coerced.major;
      source = "volta";
      declared = pin;
    }
  }

  const baked = catalogPmVersions(input.catalog, pm).filter((version) =>
    supported.includes(semver.major(version)),
  );
  const candidates = baked.filter(
    (version) =>
      (declaredMajor === null || semver.major(version) === declaredMajor) &&
      (engines === null || semver.satisfies(version, engines)),
  );
  if (candidates.length === 0) {
    const wanted = [
      ...(declaredMajor === null ? [] : [`${declaredMajor}.x`]),
      ...(engines === null ? [] : [engines]),
    ];
    return {
      ok: false,
      reason: wanted.every((range) => semver.intersects(range, supportedRange(supported)))
        ? "pm_version_unavailable"
        : "pm_major_unsupported",
    };
  }
  if (declaredMajor === null && engines !== null) {
    source = "engines";
    declared = input.declarations.engines[pm] ?? null;
  }
  // The manager's natural release when the declarations admit it: npm bundled with the resolved
  // Node, the catalog's default pnpm; otherwise what CI installs, then the newest admitted release.
  const natural =
    pm === "npm"
      ? bundledNpm
      : pm === "pnpm"
        ? input.catalog.defaultPnpm
        : (highest(input.catalog.yarn ?? []) ?? "");
  if (declaredMajor === null) {
    for (const major of input.preferences?.pmMajors ?? []) {
      const inMajor = candidates.filter((version) => semver.major(version) === major);
      const version = inMajor.includes(natural) ? natural : highest(inMajor);
      if (version !== undefined)
        return { ok: true, value: { version, source: "ci", declared: null } };
    }
  }
  if (candidates.includes(natural)) {
    const naturalSource: PmSource =
      source === "default" ? (pm === "npm" ? "bundled_with_node" : "default") : source;
    return { ok: true, value: { version: natural, source: naturalSource, declared } };
  }
  const version = highest(candidates);
  if (version === undefined) return { ok: false, reason: "pm_version_unavailable" };
  return { ok: true, value: { version, source, declared } };
}

function rejected(reason: RuntimeRejectionReason): RuntimeResolution {
  return { ok: false, reason, unsupported: RUNTIME_REJECTION_UNSUPPORTED[reason] };
}

/**
 * Resolves the exact Node and package-manager releases a repository runs with in the pinned image,
 * or the explicit reason it is outside the matrix (docs/decisions/lockfile.md "Runtime
 * resolution"). Declarations are constraints that must all hold; CI preferences only choose among
 * what they admit; with none, the catalog's default Node major is used.
 */
export function resolveRuntime(input: RuntimeInput): RuntimeResolution {
  const formats: readonly LockfileFormat[] = LOCKFILE_FORMATS_BY_PM[input.packageManager];
  if (!formats.includes(input.lockfileFormat)) return rejected("lockfile_format_mismatch");
  const ignored: IgnoredDeclaration[] = [];
  const node = resolveNode(input, ignored);
  if (!node.ok) return rejected(node.reason);
  const pm = resolvePackageManager(input, node.value.npm, ignored);
  if (!pm.ok) return rejected(pm.reason);
  if (
    input.pnpmSettingsOnly &&
    input.packageManager === "pnpm" &&
    pm.value.version.split(".")[0] === "9"
  )
    return rejected("pnpm_settings_requires_v10");
  const runtime: ResolvedRuntime = {
    node: node.value.version,
    nodeSource: node.value.source,
    nodeDeclared: node.value.declared,
    packageManager: input.packageManager,
    pmVersion: pm.value.version,
    pmSource: pm.value.source,
    pmDeclared: pm.value.declared,
    lockfileFormat: input.lockfileFormat,
    ignored: [...new Set(ignored)],
  };
  // The catalog schema and the checks above keep every result inside the matrix; re-check with the
  // contracts rule the recipe runtime is validated against.
  const support = runtimeSupport({
    node: runtime.node,
    packageManager: runtime.packageManager,
    pmVersion: runtime.pmVersion,
  });
  if (support !== null) {
    return rejected(
      support === "unsupported_node_version" ? "node_major_unsupported" : "pm_major_unsupported",
    );
  }
  return { ok: true, runtime };
}
