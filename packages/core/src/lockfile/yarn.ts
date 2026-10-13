import semver from "semver";

import {
  hasControlCharacter,
  npmTarballUrl,
  packageNameSchema,
  packageVersionSchema,
} from "@kovo/contracts";

import { classifyDependencySpec } from "../manifest/dependency-spec.js";
import type { PackageManifest } from "../manifest/package-json.js";
import type { Instance, InstanceEdge, InstanceSet, RootDependency } from "./instances.js";
import { RejectionCollector } from "./reasons.js";
import { checkIntegrity, checkTarballSource } from "./registry-source.js";
import { GRAPH_LIMITS, SECTION_KIND, type LockfileLimits } from "./types.js";
import { localInstance, type WorkspaceParserContext } from "./workspace/parser-context.js";

/** Yarn's non-YAML v1 format is parsed by a bounded line scanner, without evaluation. */
export const YARN_LOCKFILE_LIMITS = {
  maxLength: 8 * 1024 * 1024,
  maxLineLength: 64 * 1024,
} as const;
type Entry = {
  selectors: string[];
  fields: Map<string, string>;
  dependencies: Map<string, string>;
  optionalDependencies: Map<string, string>;
};
function tokens(text: string, separator: "comma" | "space"): string[] | null {
  const out: string[] = [];
  let position = 0;
  while (position < text.length) {
    while (text[position] === " ") position += 1;
    if (position >= text.length) return null;
    let value: string;
    if (text[position] === '"') {
      const start = position++;
      let escaped = false;
      while (position < text.length) {
        const char = text[position++];
        if (!escaped && char === '"') break;
        if (!escaped && char === "\\") escaped = true;
        else escaped = false;
      }
      try {
        const parsed: unknown = JSON.parse(text.slice(start, position));
        if (typeof parsed !== "string") return null;
        value = parsed;
      } catch {
        return null;
      }
    } else {
      const start = position;
      while (position < text.length) {
        const char = text[position];
        if (char === " " || (separator === "comma" && char === ",")) break;
        position += 1;
      }
      value = text.slice(start, position);
    }
    if (!value || hasControlCharacter(value)) return null;
    out.push(value);
    if (position === text.length) break;
    if (separator === "comma") {
      while (text[position] === " ") position += 1;
      if (position === text.length) break;
      if (text[position++] !== ",") return null;
      if (position === text.length) return null;
    } else if (text[position] !== " ") return null;
  }
  return out;
}
function selector(value: string): { alias: string; spec: string; name: string } | null {
  const at = value.indexOf("@", value.startsWith("@") ? 1 : 0);
  if (at < 1) return null;
  const alias = value.slice(0, at),
    spec = value.slice(at + 1);
  if (!packageNameSchema.safeParse(alias).success) return null;
  const classified = classifyDependencySpec(spec);
  if (classified.kind === "invalid" || classified.kind === "rejected") return null;
  return { alias, spec, name: classified.kind === "alias" ? classified.name : alias };
}
function entryId(entry: Entry): string {
  // Entry order is formatting, not installation identity.
  return `yarn:${entry.selectors.toSorted()[0] ?? ""}`;
}
function legacyIntegrity(hex: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const bytes = Array.from({ length: 20 }, (_, i) =>
    Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16),
  );
  let encoded = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0,
      b = bytes[i + 1] ?? 0,
      c = bytes[i + 2] ?? 0;
    encoded += alphabet[a >> 2] ?? "";
    encoded += alphabet[((a & 3) << 4) | (b >> 4)] ?? "";
    encoded += i + 1 < bytes.length ? alphabet[((b & 15) << 2) | (c >> 6)] : "=";
    encoded += i + 2 < bytes.length ? alphabet[c & 63] : "=";
  }
  return `sha1-${encoded}`;
}
export type YarnParseResult =
  | { readonly ok: true; readonly instances: InstanceSet }
  | { readonly ok: false; readonly rejections: RejectionCollector };
/** The root manifest is mandatory: v1 records selectors but no importer declarations. */
export function parseYarnLockfile(
  text: string,
  limits: LockfileLimits = GRAPH_LIMITS,
  manifest?: PackageManifest,
  context?: WorkspaceParserContext,
): YarnParseResult {
  const rejections = new RejectionCollector();
  const fail = (): YarnParseResult => ({ ok: false, rejections });
  if (text.length > YARN_LOCKFILE_LIMITS.maxLength) {
    rejections.add("lockfile_too_large");
    return fail();
  }
  if (!/^# yarn lockfile v1\r?$/mu.test(text) || /^__metadata\s*:/mu.test(text)) {
    rejections.add("unsupported_lockfile_version");
    return fail();
  }
  if (manifest === undefined && context === undefined) {
    rejections.add("missing_root");
    return fail();
  }
  const entries: Entry[] = [];
  let current: Entry | undefined;
  let section: "dependencies" | "optionalDependencies" | undefined;
  let edgeCount = 0;
  let selectorCount = 0;
  for (const raw of text.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.length > YARN_LOCKFILE_LIMITS.maxLineLength) {
      rejections.add("lockfile_too_large");
      return fail();
    }
    if (!line || line.startsWith("#")) continue;
    if (line.includes("\t")) {
      rejections.add("lockfile_syntax");
      return fail();
    }
    if (!line.startsWith(" ")) {
      const keys = line.endsWith(":") ? tokens(line.slice(0, -1), "comma") : null;
      if (keys === null || keys.length === 0) {
        rejections.add("lockfile_syntax");
        return fail();
      }
      selectorCount += keys.length;
      if (selectorCount > limits.maxDependencyEdges) {
        rejections.add("too_many_dependencies");
        return fail();
      }
      if (entries.length >= limits.maxPackages) {
        rejections.add("too_many_packages");
        return fail();
      }
      current = {
        selectors: keys,
        fields: new Map(),
        dependencies: new Map(),
        optionalDependencies: new Map(),
      };
      entries.push(current);
      section = undefined;
    } else if (current !== undefined && line.startsWith("  ") && !line.startsWith("   ")) {
      const body = line.slice(2);
      if (body === "dependencies:" || body === "optionalDependencies:") {
        if (current.fields.has(body)) {
          rejections.add("lockfile_duplicate_key");
          return fail();
        }
        current.fields.set(body, "");
        section = body === "dependencies:" ? "dependencies" : "optionalDependencies";
      } else {
        const pair = tokens(body, "space");
        if (pair?.length !== 2 || !["version", "resolved", "integrity"].includes(pair[0] ?? "")) {
          rejections.add("lockfile_invalid");
          return fail();
        }
        const key = pair[0] ?? "";
        if (current.fields.has(key)) {
          rejections.add("lockfile_duplicate_key");
          return fail();
        }
        current.fields.set(key, pair[1] ?? "");
        section = undefined;
      }
    } else if (
      current !== undefined &&
      section !== undefined &&
      line.startsWith("    ") &&
      !line.startsWith("     ")
    ) {
      const pair = tokens(line.slice(4), "space");
      if (pair?.length !== 2) {
        rejections.add("lockfile_syntax");
        return fail();
      }
      const alias = pair[0] ?? "";
      if (current[section].has(alias)) {
        rejections.add("lockfile_duplicate_key");
        return fail();
      }
      if (++edgeCount > limits.maxDependencyEdges) {
        rejections.add("too_many_dependencies");
        return fail();
      }
      current[section].set(alias, pair[1] ?? "");
    } else {
      rejections.add("lockfile_syntax");
      return fail();
    }
  }
  const resolutions =
    (
      context?.layout.members.find((member) => member.path === ".")?.manifest ?? manifest
    )?.overrides.filter((rule) => rule.manager === "yarn") ?? [];
  const instances = new Map<string, Instance>();
  const selectors = new Map<string, string>();
  const mismatches = new Map<
    string,
    { readonly id: string; readonly alias: string; readonly spec: string }
  >();
  for (const entry of entries) {
    const names = entry.selectors.map(selector);
    const first = names[0];
    if (
      first === null ||
      first === undefined ||
      names.some((name) => name === null || name.name !== first.name)
    ) {
      rejections.add("lockfile_invalid");
      continue;
    }
    const name = packageNameSchema.parse(first.name);
    const version = packageVersionSchema.safeParse(entry.fields.get("version"));
    if (!version.success) {
      rejections.add("invalid_package_version", name);
      continue;
    }
    const rawResolved = entry.fields.get("resolved");
    if (rawResolved === undefined) {
      rejections.add("lockfile_invalid", name);
      continue;
    }
    const hashIndex = rawResolved.indexOf("#");
    const fragment = hashIndex < 0 ? undefined : rawResolved.slice(hashIndex + 1);
    if (fragment !== undefined && !/^[a-f0-9]{40}$/u.test(fragment)) {
      rejections.add("invalid_integrity", name);
      continue;
    }
    const source = (hashIndex < 0 ? rawResolved : rawResolved.slice(0, hashIndex)).replace(
      /^https:\/\/registry\.yarnpkg\.com\//u,
      "https://registry.npmjs.org/",
    );
    const sourceProblem = checkTarballSource(source, name, version.data);
    if (sourceProblem !== null) {
      rejections.add(sourceProblem, name);
      continue;
    }
    const integrity = checkIntegrity(
      entry.fields.get("integrity") ??
        (fragment === undefined ? undefined : legacyIntegrity(fragment)),
    );
    if (!integrity.ok) {
      rejections.add(integrity.reason, name);
      continue;
    }
    const id = entryId(entry);
    for (const item of names) {
      if (item === null) continue;
      const classified = classifyDependencySpec(item.spec);
      const range = classified.kind === "alias" ? classified.target : classified;
      if (range.kind === "range" && !semver.satisfies(version.data, range.range))
        mismatches.set(`${id}\u0000${item.alias}\u0000${item.spec}`, {
          id,
          alias: item.alias,
          spec: item.spec,
        });
    }
    instances.set(id, {
      id,
      name,
      version: version.data,
      integrity: integrity.integrity,
      integrityAlgorithm: integrity.algorithm,
      resolved: npmTarballUrl(name, version.data),
      bundled: false,
      bundles: [],
      hasInstallScript: null,
      patched: false,
      edges: [],
    });
    for (const key of entry.selectors) {
      if (selectors.has(key)) rejections.add("lockfile_duplicate_key", name);
      selectors.set(key, id);
    }
  }
  if (!rejections.empty) return fail();
  const edge = (
    alias: string,
    spec: string,
    kind: InstanceEdge["kind"],
    optional: boolean,
  ): InstanceEdge | null => {
    const name = packageNameSchema.safeParse(alias);
    const classified = classifyDependencySpec(spec);
    if (!name.success) {
      rejections.add("invalid_package_name");
      return null;
    }
    if (classified.kind === "rejected") {
      rejections.add(classified.reason, name.data);
      return null;
    }
    if (classified.kind === "invalid") {
      rejections.add("lockfile_invalid", name.data);
      return null;
    }
    const target = selectors.get(`${alias}@${spec}`) ?? null;
    if (target === null && !optional && kind !== "peer")
      rejections.add("dangling_reference", name.data);
    return { alias: name.data, range: spec, kind, optional, target };
  };
  for (const entry of entries) {
    const id = entryId(entry),
      instance = instances.get(id);
    if (instance === undefined) continue;
    const edges: InstanceEdge[] = [];
    for (const sectionName of ["dependencies", "optionalDependencies"] as const)
      for (const [alias, spec] of entry[sectionName]) {
        const resolvedEdge = edge(
          alias,
          spec,
          SECTION_KIND[sectionName],
          sectionName === "optionalDependencies",
        );
        if (resolvedEdge !== null) edges.push(resolvedEdge);
      }
    instances.set(id, { ...instance, edges });
  }
  const root: RootDependency[] = [];
  const members =
    context?.layout.members ?? (manifest === undefined ? [] : [{ path: ".", manifest, local: [] }]);
  for (const member of members) {
    const direct: RootDependency[] = [];
    for (const dep of member.manifest.dependencies) {
      if (++edgeCount > limits.maxDependencyEdges) {
        rejections.add("too_many_dependencies");
        return fail();
      }
      const resolvedEdge = edge(
        dep.alias,
        dep.spec,
        SECTION_KIND[dep.section],
        dep.section === "optionalDependencies",
      );
      if (resolvedEdge !== null)
        direct.push({
          importer: member.path,
          alias: dep.alias,
          section: dep.section,
          spec: dep.spec,
          edge: resolvedEdge,
        });
    }
    for (const dep of member.local) {
      if (++edgeCount > limits.maxDependencyEdges) {
        rejections.add("too_many_dependencies");
        return fail();
      }
      direct.push({
        importer: member.path,
        alias: dep.alias,
        section: dep.section,
        spec: dep.spec,
        edge: {
          alias: dep.alias,
          range: dep.spec,
          kind: SECTION_KIND[dep.section],
          optional: dep.section === "optionalDependencies",
          target: `workspace:${dep.target}`,
        },
      });
    }
    root.push(...direct);
    if (context !== undefined) {
      const localMember = context.layout.members.find((item) => item.path === member.path);
      if (localMember !== undefined)
        instances.set(`workspace:${member.path}`, {
          ...localInstance(localMember),
          edges: direct.map((dep) => dep.edge),
        });
    }
  }
  if (!rejections.empty) return fail();
  if (mismatches.size > 0) {
    const proved = new Set<string>();
    const budget = { remaining: limits.maxPathWork };
    const matchesPath = (steps: readonly string[], path: readonly string[]): boolean => {
      const pattern = steps.length === 1 ? ["**", ...steps] : steps;
      let states = new Set([0]);
      const closure = (input: Set<number>): Set<number> => {
        const out = new Set(input);
        for (let i = 0; i < pattern.length; i += 1) {
          if (--budget.remaining < 0) return new Set();
          if (out.has(i) && pattern[i] === "**") out.add(i + 1);
        }
        return out;
      };
      states = closure(states);
      for (const alias of path) {
        const next = new Set<number>();
        for (const state of states) {
          if (--budget.remaining < 0) return false;
          if (pattern[state] === "**") next.add(state);
          else if (pattern[state] === "*" || pattern[state] === alias) next.add(state + 1);
        }
        states = closure(next);
      }
      return states.has(pattern.length);
    };
    for (const direct of root) {
      // Each importer is a separate Yarn request root; scoped names remain single path steps.
      const stack: { edge: InstanceEdge; exit: boolean }[] = [{ edge: direct.edge, exit: false }];
      const path: string[] = [];
      const active = new Set<string>();
      while (stack.length > 0) {
        if (--budget.remaining < 0) {
          rejections.add("too_many_dependencies");
          return fail();
        }
        const frame = stack.pop();
        if (frame === undefined || frame.edge.target === null) continue;
        const target = instances.get(frame.edge.target);
        if (target === undefined) continue;
        if (frame.exit) {
          active.delete(target.id);
          path.pop();
          continue;
        }
        path.push(frame.edge.alias);
        const key = `${target.id}\u0000${frame.edge.alias}\u0000${frame.edge.range ?? ""}`;
        if (mismatches.has(key)) {
          const applied = resolutions.some((rule) => {
            if (--budget.remaining < 0) return false;
            if (rule.target !== frame.edge.alias || !matchesPath(rule.selector, path)) return false;
            const value = classifyDependencySpec(rule.spec);
            const resolvedName = value.kind === "alias" ? value.name : frame.edge.alias;
            const range = value.kind === "alias" ? value.target : value;
            return (
              resolvedName === target.name &&
              range.kind === "range" &&
              semver.satisfies(target.version, range.range)
            );
          });
          if (!applied || budget.remaining < 0) {
            rejections.add("lockfile_invalid", target.name);
            return fail();
          }
          proved.add(key);
        }
        if (active.has(target.id) || path.length > limits.maxPathDepth) {
          rejections.add("lockfile_too_deep");
          return fail();
        }
        active.add(target.id);
        stack.push({ edge: frame.edge, exit: true });
        for (const child of target.edges) stack.push({ edge: child, exit: false });
      }
    }
    if ([...mismatches.keys()].some((key) => !proved.has(key))) {
      rejections.add("lockfile_invalid");
      return fail();
    }
  }
  return {
    ok: true,
    instances: {
      packageManager: "yarn",
      format: "yarn-v1",
      root,
      instances,
      lockfileOverrides: [],
    },
  };
}
