import { z } from "zod";

import { packageManagerSchema, lockfileFormatSchema } from "./enums/index.js";
import { gitShaSchema, sha256HexSchema } from "./primitives.js";
import { packageNameSchema, packageVersionSchema } from "./npm.js";

/** One bounded, unpaginated metadata projection, measured as serialized UTF-8 JSON. */
export const WORKSPACE_INVENTORY_MAX_BYTES = 8 * 1024 * 1024;
/** Enabled after the 8 MiB tolerant reader release is promoted; rollback retains that reader. */
export const WORKSPACE_INVENTORY_WRITE_MAX_BYTES = 8 * 1024 * 1024;
export function workspaceInventoryWithinByteLimit(
  value: unknown,
  maxBytes: number = WORKSPACE_INVENTORY_MAX_BYTES,
): boolean {
  // Count JSON tokens with an early stop; never allocate a potentially enormous graph string.
  const encoder = new TextEncoder();
  let remaining = maxBytes;
  const charge = (bytes: number): boolean => (remaining -= bytes) >= 0;
  const visit = (item: unknown): boolean => {
    if (Array.isArray(item)) {
      if (!charge(2 + Math.max(0, item.length - 1))) return false;
      return item.every((entry) => visit(entry === undefined ? null : entry));
    }
    if (item !== null && typeof item === "object") {
      const entries = Object.entries(item).filter(([, entry]) => entry !== undefined);
      if (!charge(2 + Math.max(0, entries.length - 1))) return false;
      return entries.every(
        ([key, entry]) =>
          charge(encoder.encode(JSON.stringify(key)).byteLength + 1) && visit(entry),
      );
    }
    const encoded = JSON.stringify(item);
    return encoded !== undefined && charge(encoder.encode(encoded).byteLength);
  };
  return visit(value);
}

/** Metadata only. Raw manifests, registry URLs and config text never enter durable state. */
export const workspacePathSchema = z
  .string()
  .min(1)
  .max(1024)
  .refine(
    (path) =>
      path === "." ||
      (!/[\\:%]/u.test(path) &&
        !Array.from(path).some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127) &&
        !path.startsWith("/") &&
        path
          .split("/")
          .every(
            (part) =>
              part !== "" &&
              part !== "." &&
              part !== ".." &&
              part.toLowerCase() !== "node_modules" &&
              part.toLowerCase() !== ".git",
          )),
  );
const identity = z.string().min(1).max(2048);
const section = z.enum([
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
]);
const pkg = z.strictObject({
  name: packageNameSchema,
  version: packageVersionSchema,
  isDirect: z.boolean(),
  isDev: z.boolean(),
  depPaths: z.array(z.array(packageNameSchema).min(1).max(64)).min(1).max(32),
});
export const workspaceInventorySchema = z
  .strictObject({
    packageManager: packageManagerSchema,
    format: lockfileFormatSchema,
    lockfileSha256: sha256HexSchema,
    graphHash: sha256HexSchema,
    treeSha: gitShaSchema,
    workspaceConfigOid: gitShaSchema.nullable(),
    members: z
      .array(
        z.strictObject({
          path: workspacePathSchema,
          name: packageNameSchema.nullable(),
          version: packageVersionSchema.nullable(),
          manifestId: gitShaSchema,
        }),
      )
      .min(1)
      .max(101),
    importers: z
      .array(
        z.strictObject({
          path: workspacePathSchema,
          direct: z
            .array(
              z.strictObject({
                alias: packageNameSchema,
                section,
                spec: z
                  .string()
                  .max(1024)
                  .regex(/^[A-Za-z0-9@._~^*<>=| +:/-]*$/u),
                target: identity.nullable(),
              }),
            )
            .max(10000),
          packages: z.array(pkg).max(20000),
        }),
      )
      .min(1)
      .max(101),
    instances: z
      .array(
        z.strictObject({
          id: identity,
          name: packageNameSchema,
          version: packageVersionSchema.nullable(),
          localMember: workspacePathSchema.nullable(),
          integrity: z.string().max(1024).nullable(),
          edges: z
            .array(
              z.strictObject({
                alias: packageNameSchema,
                target: identity.nullable(),
                kind: z.enum(["prod", "dev", "optional", "peer"]),
                optional: z.boolean(),
              }),
            )
            .max(10000),
        }),
      )
      .max(20000),
  })
  .refine((value) => workspaceInventoryWithinByteLimit(value), "workspace inventory size limit");

export const workspaceInventoryWriteSchema = workspaceInventorySchema.refine(
  (value) => workspaceInventoryWithinByteLimit(value, WORKSPACE_INVENTORY_WRITE_MAX_BYTES),
  "workspace inventory writer size limit",
);
export type WorkspaceInventory = z.infer<typeof workspaceInventorySchema>;
