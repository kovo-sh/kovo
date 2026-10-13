import { z } from "zod";

import { lockfileFormatSchema, packageManagerSchema } from "./enums/recipes.js";
import { exactVersionSchema } from "./npm.js";
import { whenValid } from "./primitives.js";
import { stepNameSchema } from "./step-result.js";
import { wellKnownPackageSchema } from "./well-known-packages.js";

// A repository's toolchain fingerprint (docs/decisions/recipes.md "Toolchain fingerprints and
// failure categories"): the facts about how a repository builds that trusted code already holds in
// memory when it verifies one (the manifest, the lockfile, the GitHub tree), recorded so a failed
// calibration or verification can be diagnosed without reading the repository. Enums, versions and
// counts only: no file contents, no private package names (only `WELL_KNOWN_PACKAGES`), no paths
// (configuration files by a fixed name and their directory depth only), and no command text: the
// programs each recipe step's scripts run are named from a fixed list, with a fixed subcommand and
// an argument count. It travels in durable workflow outputs, which hold only identifiers and
// sanitized metadata (SPEC Workflows), so nothing here is free text.

export const TOOLCHAIN_LIMITS = {
  maxVersionsPerTool: 4,
  maxConfigFiles: 200,
  /** Directory depth is recorded up to this; deeper files count at this depth. */
  maxDepth: 32,
  /** Package manifests counted in the tree; more are recorded as this many, capped. */
  maxPackages: 10_000,
  maxCommands: 20,
  /** Program invocations one recipe step records. */
  maxInvocations: 16,
  /** Arguments and other programs are counted up to this. */
  maxArguments: 1000,
} as const;

const SCRIPT_EXTENSIONS = ["js", "cjs", "mjs", "ts", "cts", "mts"] as const;

/**
 * The configuration file names a fingerprint can record: an explicit finite list, so a file name
 * never carries repository text. `tsconfig.*.json` stands for every other `tsconfig.<x>.json`.
 */
export const TOOLCHAIN_CONFIG_FILES: readonly string[] = [
  ...SCRIPT_EXTENSIONS.map((ext) => `eslint.config.${ext}` as const),
  ".eslintrc",
  ...(["js", "cjs", "json", "yaml", "yml"] as const).map((ext) => `.eslintrc.${ext}` as const),
  "tsconfig.json",
  ...(["base", "build", "app", "node", "lib", "test", "spec", "eslint", "check"] as const).map(
    (name) => `tsconfig.${name}.json` as const,
  ),
  "tsconfig.*.json",
  "jsconfig.json",
  ...SCRIPT_EXTENSIONS.map((ext) => `vite.config.${ext}` as const),
  ...SCRIPT_EXTENSIONS.map((ext) => `vitest.config.${ext}` as const),
  ...SCRIPT_EXTENSIONS.map((ext) => `vitest.workspace.${ext}` as const),
  ...SCRIPT_EXTENSIONS.map((ext) => `next.config.${ext}` as const),
  ...[...SCRIPT_EXTENSIONS, "json"].map((ext) => `jest.config.${ext}`),
  ...SCRIPT_EXTENSIONS.map((ext) => `playwright.config.${ext}` as const),
  ...SCRIPT_EXTENSIONS.map((ext) => `cypress.config.${ext}` as const),
  ".prettierrc",
  ...(["json", "js", "cjs", "mjs", "yaml", "yml"] as const).map(
    (ext) => `.prettierrc.${ext}` as const,
  ),
  ...(["js", "cjs", "mjs"] as const).map((ext) => `prettier.config.${ext}` as const),
  ...(["js", "cjs", "mjs", "json"] as const).map((ext) => `babel.config.${ext}` as const),
  ".babelrc",
  ...(["js", "cjs", "json", "yaml", "yml"] as const).map((ext) => `.mocharc.${ext}` as const),
  "biome.json",
  "biome.jsonc",
  ".swcrc",
  ...(["js", "cjs", "mjs", "ts"] as const).map((ext) => `webpack.config.${ext}` as const),
  ...(["js", "cjs", "mjs", "ts"] as const).map((ext) => `rollup.config.${ext}` as const),
  ...(["js", "cjs", "mjs", "ts"] as const).map((ext) => `tailwind.config.${ext}` as const),
  ...(["js", "cjs", "mjs"] as const).map((ext) => `postcss.config.${ext}` as const),
  "turbo.json",
  "nx.json",
  "lerna.json",
  "pnpm-workspace.yaml",
  ".npmrc",
  ".nvmrc",
  ".node-version",
  ".tool-versions",
];

const CONFIG_FILES: ReadonlySet<string> = new Set(TOOLCHAIN_CONFIG_FILES);

export const toolchainConfigFileSchema = z
  .string()
  .refine((name) => CONFIG_FILES.has(name), { error: "must be a known configuration file name" });

/** The recorded name of a tree path's file, or null when it is not a known configuration file. */
export function toolchainConfigFileOf(path: string): string | null {
  const name = path.slice(path.lastIndexOf("/") + 1);
  if (CONFIG_FILES.has(name)) return name;
  return /^tsconfig\.[^/]+\.json$/.test(name) ? "tsconfig.*.json" : null;
}

/**
 * Programs a recipe step's scripts may be recorded as running (by name only). Any other program is
 * counted, never named.
 */
export const TOOLCHAIN_PROGRAMS = [
  "next",
  "tsc",
  "vue-tsc",
  "svelte-check",
  "eslint",
  "oxlint",
  "biome",
  "prettier",
  "stylelint",
  "vite",
  "vitest",
  "jest",
  "mocha",
  "ava",
  "playwright",
  "cypress",
  "c8",
  "nyc",
  "tsx",
  "ts-node",
  "node",
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "turbo",
  "nx",
  "lerna",
  "astro",
  "nuxt",
  "nuxi",
  "svelte-kit",
  "ng",
  "nest",
  "remix",
  "react-router",
  "react-scripts",
  "storybook",
  "webpack",
  "rollup",
  "esbuild",
  "tsup",
  "tailwindcss",
  "prisma",
  "drizzle-kit",
  "concurrently",
  "run-s",
  "run-p",
  "npm-run-all",
  "rimraf",
] as const;
export const toolchainProgramSchema = z.enum(TOOLCHAIN_PROGRAMS);
export type ToolchainProgram = z.infer<typeof toolchainProgramSchema>;

/** Subcommands recorded when a program's first argument is one of them. */
export const TOOLCHAIN_SUBCOMMANDS = [
  "lint",
  "build",
  "dev",
  "start",
  "test",
  "run",
  "exec",
  "check",
  "typecheck",
  "generate",
  "preview",
  "export",
  "format",
  "migrate",
  "deploy",
  "watch",
  "serve",
  "install",
  "ci",
  "e2e",
  "sync",
  "prepare",
  "codegen",
] as const;
export const toolchainSubcommandSchema = z.enum(TOOLCHAIN_SUBCOMMANDS);

/** `engines.node` as declared: a version range of digits, wildcards and comparators only. */
export const nodeEngineRangeSchema = z
  .string()
  .regex(/^[0-9xX*.^~<>=| -]{1,64}$/, { error: "must be a plain version range" });

/**
 * A recorded tool or package-manager version: exact SemVer without build metadata. Build metadata
 * never orders versions and can carry arbitrary identifiers (corepack's `+sha512.…` digest), so
 * writers drop it (`withoutBuildMetadata`) and readers refuse it.
 */
export const toolchainVersionSchema = exactVersionSchema.refine(
  (version) => !version.includes("+"),
  { error: "a recorded version carries no build metadata" },
);

/** `1.2.3+build.5` → `1.2.3`; anything else unchanged. */
export function withoutBuildMetadata(version: string): string {
  const plus = version.indexOf("+");
  return plus === -1 ? version : version.slice(0, plus);
}

export const WORKSPACE_LAYOUTS = [
  "single",
  "pnpm_workspace",
  "npm_workspaces",
  "yarn_workspaces",
] as const;
export const DECLARED_PACKAGE_MANAGERS = ["npm", "pnpm", "yarn", "bun"] as const;

function sortedUnique(values: readonly string[]): boolean {
  return values.every((value, index) => index === 0 || values[index - 1]! < value);
}

export const toolchainSchema = z.strictObject({
  schema: z.literal("kovo.toolchain/1"),
  package_manager: z.strictObject({
    /** The package manager the recipe runs (the lockfile's). */
    name: packageManagerSchema,
    /** `packageManager` in the manifest, when it names a known one (version when exact). */
    declared: z
      .strictObject({
        name: z.enum(DECLARED_PACKAGE_MANAGERS),
        version: toolchainVersionSchema.nullable(),
      })
      .nullable(),
    /** Null when the lockfile was missing or did not parse. */
    lock_format: lockfileFormatSchema.nullable(),
  }),
  workspace: z.strictObject({
    layout: z.enum(WORKSPACE_LAYOUTS),
    /** Package manifests in the tree (the root included), up to the cap. */
    packages: z.int().min(0).max(TOOLCHAIN_LIMITS.maxPackages),
  }),
  /** `engines.node`: null when undeclared, `unrecognized` when not a plain range. */
  node_engine: z.union([nodeEngineRangeSchema, z.literal("unrecognized")]).nullable(),
  /** The manifest's `eslintConfig` key; null when the manifest was unreadable. */
  eslint_config_declared: z.boolean().nullable(),
  /** Well-known tools the lockfile resolves, by name; empty when it did not parse. */
  tools: z
    .array(
      z.strictObject({
        name: wellKnownPackageSchema,
        /** Resolved versions, newest first. */
        versions: z.array(toolchainVersionSchema).min(1).max(TOOLCHAIN_LIMITS.maxVersionsPerTool),
        /** Declared by the root manifest (not only reached through another package). */
        direct: z.boolean(),
      }),
    )
    .max(wellKnownPackageSchema.options.length)
    .refine((tools) => sortedUnique(tools.map((tool) => tool.name)), {
      ...whenValid,
      error: "tools are unique and sorted by name",
    }),
  /** Known configuration files by name and directory depth (0: the repository root). */
  config_files: z
    .array(
      z.strictObject({
        name: toolchainConfigFileSchema,
        depth: z.int().min(0).max(TOOLCHAIN_LIMITS.maxDepth),
        count: z.int().min(1).max(TOOLCHAIN_LIMITS.maxPackages),
      }),
    )
    .max(TOOLCHAIN_LIMITS.maxConfigFiles)
    .refine(
      (files) =>
        sortedUnique(
          files.map((file) => `${file.name}\u0000${String(file.depth).padStart(2, "0")}`),
        ),
      { ...whenValid, error: "config files are unique and sorted by name, then depth" },
    ),
  /** The programs each recipe step runs, as the tree's manifest expands its scripts. */
  commands: z
    .array(
      z.strictObject({
        step: stepNameSchema,
        invocations: z
          .array(
            z.strictObject({
              program: toolchainProgramSchema,
              subcommand: toolchainSubcommandSchema.nullable(),
              /** Arguments after the subcommand, counted (never recorded). */
              arguments: z.int().min(0).max(TOOLCHAIN_LIMITS.maxArguments),
            }),
          )
          .max(TOOLCHAIN_LIMITS.maxInvocations),
        /** Commands of programs not on the list: counted, never named. */
        other_programs: z.int().min(0).max(TOOLCHAIN_LIMITS.maxArguments),
        /** False when the expansion or its parse was cut short, or ran more than is recorded. */
        complete: z.boolean(),
      }),
    )
    .max(TOOLCHAIN_LIMITS.maxCommands)
    .refine(
      (commands) => new Set(commands.map((command) => command.step)).size === commands.length,
      { ...whenValid, error: "one command per step" },
    ),
});
export type Toolchain = z.infer<typeof toolchainSchema>;
