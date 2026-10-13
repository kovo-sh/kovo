import {
  exactVersionSchema,
  packageNameSchema,
  packageVersionSchema,
  type PackageName,
  type PackageVersion,
} from "@kovo/contracts";

import { IntegrityError } from "../ports/errors.js";
import {
  INSTALL_LIFECYCLE_SCRIPTS,
  distTagSchema,
  npmPublisherSchema,
  packumentSchema,
  partitionPackumentVersions,
  registryIntegrity,
  type NpmPublisher,
  type Packument,
  type PackumentKind,
} from "../ports/npm-upstream.js";

// Registry packument JSON → the port's typed view, shared by the real adapter and the fake
// registry so both apply exactly the same per-version rules (docs/decisions/adapters.md
// "Packuments are typed version by version"). Registry content is hostile: nothing here repairs a
// value; a malformed version fails `npmVersionSchema` and is omitted and counted.

/** The media type of the abbreviated ("corgi") packument. */
export const ABBREVIATED_PACKUMENT_MEDIA_TYPE = "application/vnd.npm.install-v1+json";

type Json = Readonly<Record<string, unknown>>;

function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

/** A registry timestamp (`2025-02-08T03:03:08.256Z`) as a Date; null when malformed. */
export function parseRegistryTime(value: unknown): Date | null {
  if (typeof value !== "string" || !ISO_INSTANT.test(value)) return null;
  const at = Date.parse(value);
  return Number.isNaN(at) ? null : new Date(at);
}

/** `_npmUser` → publisher. Names only (emails are never read); null when absent or unusable. */
function publisherOf(value: unknown): NpmPublisher | null {
  if (!isRecord(value)) return null;
  const trusted = value["trustedPublisher"];
  // A malformed publishing mode cannot establish that the previous release was human-published.
  if (trusted != null && (!isRecord(trusted) || typeof trusted["id"] !== "string")) return null;
  const parsed = npmPublisherSchema.safeParse({
    name: value["name"],
    trustedPublisher: isRecord(trusted) && typeof trusted["id"] === "string" ? trusted["id"] : null,
  });
  return parsed.success ? parsed.data : null;
}

/** Maintainer names from `[{ name, email }]` (or legacy `"name <email>"` strings); null when absent. */
function maintainerNamesOf(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > 1000) return null;
  const names: string[] = [];
  for (const maintainer of value) {
    const name = isRecord(maintainer)
      ? maintainer["name"]
      : typeof maintainer === "string"
        ? maintainer.replace(/\s*<[^>]*>\s*$/, "").trim()
        : undefined;
    if (typeof name !== "string" || name.length === 0 || name.length > 214) return null;
    names.push(name);
  }
  return names;
}

function declaredInstallScripts(scripts: unknown): (typeof INSTALL_LIFECYCLE_SCRIPTS)[number][] {
  if (!isRecord(scripts)) return [];
  return INSTALL_LIFECYCLE_SCRIPTS.filter((name) => {
    const command = scripts[name];
    return typeof command === "string" && command.trim().length > 0;
  });
}

function signaturesOf(value: unknown): unknown {
  return Array.isArray(value)
    ? value.map((signature) =>
        isRecord(signature) ? { keyid: signature["keyid"], sig: signature["sig"] } : signature,
      )
    : [];
}

/**
 * The candidate object for `npmVersionSchema` built from one registry version entry. Values are
 * passed through unrepaired, so anything malformed fails the schema and the version is omitted.
 */
function versionCandidate(entry: unknown, kind: PackumentKind): unknown {
  if (!isRecord(entry) || !isRecord(entry["dist"])) return undefined;
  const dist = entry["dist"];
  const full = kind === "full";
  const installScripts = full ? declaredInstallScripts(entry["scripts"]) : null;
  const hasInstallScript =
    entry["hasInstallScript"] === true ||
    (installScripts !== null && installScripts.length > 0) ||
    // npm runs `node-gyp rebuild` for a package with binding.gyp and no install script.
    (full && entry["gypfile"] === true);
  const unpackedSize = dist["unpackedSize"];
  const deprecated = entry["deprecated"];
  return {
    version: entry["version"],
    dist: {
      tarball: dist["tarball"],
      integrity: registryIntegrity(dist["integrity"]),
      shasum: dist["shasum"] ?? null,
      signatures: signaturesOf(dist["signatures"]),
      hasAttestations: isRecord(dist["attestations"]),
      unpackedSize:
        typeof unpackedSize === "number" && Number.isSafeInteger(unpackedSize) && unpackedSize >= 0
          ? unpackedSize
          : null,
    },
    dependencies: entry["dependencies"] ?? {},
    optionalDependencies: entry["optionalDependencies"] ?? {},
    peerDependencies: entry["peerDependencies"] ?? {},
    ...(entry["os"] === undefined ? {} : { os: entry["os"] }),
    ...(entry["cpu"] === undefined ? {} : { cpu: entry["cpu"] }),
    ...(typeof entry["libc"] === "string" && entry["libc"].length > 0 && entry["libc"].length <= 64
      ? { libc: [entry["libc"]] }
      : Array.isArray(entry["libc"]) &&
          entry["libc"].length <= 64 &&
          entry["libc"].every(
            (value) => typeof value === "string" && value.length > 0 && value.length <= 64,
          )
        ? { libc: entry["libc"] }
        : {}),
    hasInstallScript,
    installScripts,
    deprecated: typeof deprecated === "string" ? deprecated.length > 0 : deprecated === true,
    publisher: full ? publisherOf(entry["_npmUser"]) : null,
    maintainers: full ? maintainerNamesOf(entry["maintainers"]) : null,
    repository: full ? repositoryOf(entry["repository"]) : null,
  };
}

function repositoryOf(value: unknown): string | null {
  const url = isRecord(value) ? value["url"] : value;
  return typeof url === "string" && url.length <= 2048 ? url : null;
}

function malformed(code: string): IntegrityError {
  return new IntegrityError({ service: "npm", operation: "getPackument", code });
}

/**
 * The typed packument for a registry document of the given kind. IntegrityError when the document
 * is not a packument object or names another package than `expectedName`.
 */
export function packumentFromDocument(
  document: unknown,
  kind: PackumentKind,
  expectedName: PackageName,
): Packument {
  if (!isRecord(document)) throw malformed("malformed_packument");
  const name = packageNameSchema.safeParse(document["name"]);
  if (!name.success) throw malformed("malformed_packument");
  if (name.data !== expectedName) throw malformed("packument_name_mismatch");

  const rawVersions = isRecord(document["versions"]) ? document["versions"] : {};
  const candidates: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(rawVersions)) {
    candidates[key] = versionCandidate(entry, kind);
  }
  const { versions, omittedVersions } = partitionPackumentVersions(candidates);
  const omittedVersionNames =
    omittedVersions === 0
      ? []
      : Object.keys(rawVersions).filter(
          (version) =>
            exactVersionSchema.safeParse(version).success && !Object.hasOwn(versions, version),
        );

  const distTags: Record<string, PackageVersion> = {};
  const rawTags = isRecord(document["dist-tags"]) ? document["dist-tags"] : {};
  for (const [tag, version] of Object.entries(rawTags)) {
    const parsed = packageVersionSchema.safeParse(version);
    if (distTagSchema.safeParse(tag).success && parsed.success) distTags[tag] = parsed.data;
  }

  let publishedAt: Record<string, Date> | null = null;
  let modifiedAt: Date | null;
  if (kind === "full") {
    publishedAt = {};
    const time = isRecord(document["time"]) ? document["time"] : {};
    for (const [key, value] of Object.entries(time)) {
      const at = parseRegistryTime(value);
      if (at !== null && exactVersionSchema.safeParse(key).success) publishedAt[key] = at;
    }
    modifiedAt = parseRegistryTime(time["modified"]);
  } else {
    modifiedAt = parseRegistryTime(document["modified"]);
  }

  // Every version has already passed npmVersionSchema; the other fields were validated above.
  // Re-parsing the whole view would validate and clone all dependency maps a second time.
  return {
    name: name.data,
    kind: packumentSchema.shape.kind.parse(kind),
    distTags,
    versions,
    omittedVersions,
    ...(omittedVersions === 0 || omittedVersionNames.length > 100_000
      ? {}
      : { omittedVersionNames }),
    publishedAt,
    modifiedAt,
  };
}
