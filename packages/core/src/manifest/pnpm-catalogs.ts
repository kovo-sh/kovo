import { packageNameSchema } from "@kovo/contracts";
import { z } from "zod";

import { classifyDependencySpec, isRegistrySpec } from "./dependency-spec.js";

const entries = z.record(z.string(), z.string().max(4096));
const schema = z.object({
  catalog: entries.optional(),
  catalogs: z.record(z.string(), entries).optional(),
  catalogMode: z.enum(["strict", "prefer", "manual"]).optional(),
});

/** Transient version sources. `default` is pnpm's canonical name for `catalog:`. */
export interface PnpmCatalogs {
  readonly mode: "strict" | "prefer" | "manual";
  readonly entries: Readonly<Record<string, Readonly<Record<string, string>>>>;
}

export function parsePnpmCatalogs(value: unknown): PnpmCatalogs | null {
  const parsed = schema.safeParse(value);
  if (!parsed.success) return null;
  const data = parsed.data;
  // pnpm merges catalog and catalogs.default; conflicting sources are ambiguous to edit.
  if (data.catalog !== undefined && data.catalogs?.["default"] !== undefined) return null;
  const maps = {
    ...data.catalogs,
    ...(data.catalog === undefined ? {} : { default: data.catalog }),
  };
  for (const [name, map] of Object.entries(maps)) {
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(name)) return null;
    for (const [alias, spec] of Object.entries(map)) {
      const source = classifyDependencySpec(spec);
      if (
        !packageNameSchema.safeParse(alias).success ||
        spec.trim().startsWith(".") ||
        !isRegistrySpec(source) ||
        (source.kind === "alias" &&
          source.target.kind === "tag" &&
          source.target.tag.startsWith("."))
      )
        return null;
    }
  }
  return { mode: data.catalogMode ?? "manual", entries: maps };
}

export function catalogName(spec: string): string | null {
  if (spec === "catalog:") return "default";
  return /^catalog:[A-Za-z0-9_-]{1,256}$/u.test(spec) ? spec.slice(8) : null;
}

export function catalogEntry(
  catalogs: PnpmCatalogs,
  name: string,
  alias: string,
): string | undefined {
  const map = Object.hasOwn(catalogs.entries, name) ? catalogs.entries[name] : undefined;
  return map !== undefined && Object.hasOwn(map, alias) ? map[alias] : undefined;
}
