import { NPM_PUBLIC_REGISTRY_ORIGIN, packageNameSchema, type PackageName } from "@kovo/contracts";
import semver from "semver";

import type { SourceRejectionReason } from "./reasons.js";

// Classifies a dependency spec from package.json (or an override value) the way npm/pnpm would
// interpret it, and decides whether it stays inside Kovo's supported model: a semver range or a
// dist-tag resolved against the public npm registry, optionally through an `npm:` alias to a public
// package (SPEC: "npm and pnpm, public npm registry only"; "Reject private registries and external
// git/file/HTTP dependency sources outside the supported public-registry model").

/** A spec resolved against the registry: a semver range (`^1.2.3`, `*`, `""`) or a dist-tag. */
export type RegistrySpec =
  | { readonly kind: "range"; readonly range: string }
  | { readonly kind: "tag"; readonly tag: string };

export type DependencySpec =
  | RegistrySpec
  /** `npm:<name>@<range|tag>`: the dependency key is an alias for another public package. */
  | { readonly kind: "alias"; readonly name: PackageName; readonly target: RegistrySpec }
  | { readonly kind: "rejected"; readonly reason: SourceRejectionReason }
  /** Syntactically not a spec npm or pnpm accepts. */
  | { readonly kind: "invalid" };

/** The longest spec Kovo reads (npm itself has no limit; real specs are short). */
export const MAX_SPEC_LENGTH = 1024;

const GIT_PREFIXES = ["git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:"];
const LOCAL_PREFIXES = ["file:", "link:", "portal:"];
const SCHEME = /^[a-z][a-z0-9+.-]*:/i;
// A dist-tag: URL-safe, as npm requires (`encodeURIComponent(tag) === tag`), and not a range.
const TAG = /^[A-Za-z0-9._~-]+$/;
// `user/repo` or `user/repo#ref`: npm's GitHub shorthand.
const GITHUB_SHORTHAND = /^[^@/\s:#][^/\s:#]*\/[^/\s:#]+(?:#.*)?$/;

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function isPathLike(spec: string): boolean {
  return (
    spec === "." ||
    spec === ".." ||
    spec.startsWith("./") ||
    spec.startsWith("../") ||
    spec.startsWith("/") ||
    spec.startsWith("~/") ||
    /^[a-zA-Z]:[\\/]/.test(spec) ||
    spec.includes("\\") ||
    /\.(?:tgz|tar|tar\.gz)$/i.test(spec)
  );
}

/**
 * An http(s) URL is a private registry when its path has the registry tarball shape
 * (`/<name>/-/<file>.tgz`) on any origin other than the public registry; any other URL is a remote
 * tarball. Both are rejected; the distinction only makes the reason explicit.
 */
function classifyUrl(spec: string): SourceRejectionReason {
  let url: URL;
  try {
    url = new URL(spec);
  } catch {
    return "remote_tarball_dependency";
  }
  const registryShaped = /^\/(?:[^/]+\/)*(?:@[^/]+\/)?[^/]+\/-\/[^/]+\.tgz$/.test(url.pathname);
  if (registryShaped && url.origin !== NPM_PUBLIC_REGISTRY_ORIGIN) {
    return "private_registry_dependency";
  }
  return "remote_tarball_dependency";
}

function classifyRegistrySpec(spec: string): RegistrySpec | null {
  if (semver.validRange(spec) !== null) return { kind: "range", range: spec };
  if (TAG.test(spec)) return { kind: "tag", tag: spec };
  return null;
}

/** Splits `name@spec` (the part after `npm:`); a bare name means the `latest` tag. */
function splitAlias(rest: string): { readonly name: string; readonly spec: string } {
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  if (at === -1) return { name: rest, spec: "latest" };
  return { name: rest.slice(0, at), spec: rest.slice(at + 1) };
}

/** Classifies one dependency spec. Pure and total: never throws. */
export function classifyDependencySpec(spec: string): DependencySpec {
  if (spec.length > MAX_SPEC_LENGTH || hasControlCharacter(spec)) return { kind: "invalid" };
  const lower = spec.toLowerCase();

  if (lower.startsWith("npm:")) {
    const { name, spec: inner } = splitAlias(spec.slice(4));
    const parsedName = packageNameSchema.safeParse(name);
    if (!parsedName.success) return { kind: "invalid" };
    const target = classifyDependencySpec(inner);
    if (target.kind === "range" || target.kind === "tag") {
      return { kind: "alias", name: parsedName.data, target };
    }
    // An alias to anything but a registry spec (`npm:foo@git+…`, a nested alias) is rejected
    // for the inner reason, or invalid.
    return target.kind === "rejected" ? target : { kind: "invalid" };
  }
  if (lower.startsWith("workspace:")) return { kind: "rejected", reason: "workspace_protocol" };
  if (lower.startsWith("catalog:")) return { kind: "rejected", reason: "catalog_protocol" };
  if (LOCAL_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
    return { kind: "rejected", reason: "local_path_dependency" };
  }
  if (GIT_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
    return { kind: "rejected", reason: "git_dependency" };
  }
  if (lower.startsWith("http://") || lower.startsWith("https://")) {
    return { kind: "rejected", reason: classifyUrl(spec) };
  }
  // Before the scheme check: `C:\lib` is a Windows path, not a `c:` protocol.
  if (isPathLike(spec)) return { kind: "rejected", reason: "local_path_dependency" };
  if (SCHEME.test(spec)) return { kind: "rejected", reason: "unsupported_protocol" };
  if (GITHUB_SHORTHAND.test(spec)) return { kind: "rejected", reason: "git_dependency" };

  return classifyRegistrySpec(spec) ?? { kind: "invalid" };
}

/** Whether a classified spec resolves against the public registry. */
export function isRegistrySpec(
  spec: DependencySpec,
): spec is Extract<DependencySpec, { kind: "range" | "tag" | "alias" }> {
  return spec.kind === "range" || spec.kind === "tag" || spec.kind === "alias";
}
