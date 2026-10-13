import { z } from "zod";

// Small validated building blocks shared by the domain contracts. Every schema here is strict about
// its wire form because values cross trust boundaries (API bodies, JSONB columns, sandbox output).

/**
 * Whether `value` contains an ASCII control character (U+0000–U+001F or U+007F). Tab and line feed
 * are tolerated only when `allowTabAndNewline` is set.
 */
export function hasControlCharacter(value: string, allowTabAndNewline = false): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x7f) return true;
    if (code >= 0x20) continue;
    if (allowTabAndNewline && (code === 0x09 || code === 0x0a)) continue;
    return true;
  }
  return false;
}

/**
 * Refinement params for cross-field rules. Zod 4 still runs a refinement after non-aborting issues
 * (a failed regex or range check) and hands it the raw value; with this guard a refinement only
 * sees data every field schema accepted, so it can never crash on or mis-judge invalid input.
 */
export const whenValid = {
  when: (payload: { readonly issues: readonly unknown[] }): boolean => payload.issues.length === 0,
};

/** Git object ID (SHA-1, 40 hex digits). Accepts either case and normalizes to lower case. */
export const gitShaSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{40}$/, { error: "must be a 40-hex-digit Git object ID" })
  .toLowerCase()
  .brand<"GitSha">();
export type GitSha = z.infer<typeof gitShaSchema>;

/** A SHA-256 digest as 64 lower-case hex digits (lockfile, report and step-output hashes). */
export const sha256HexSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, { error: "must be 64 lower-case hex digits" })
  .brand<"Sha256Hex">();
export type Sha256Hex = z.infer<typeof sha256HexSchema>;

/** npm tarball integrity in Subresource Integrity form, `sha512-<base64>`. */
export const sriSha512Schema = z
  .string()
  .regex(/^sha512-[A-Za-z0-9+/]{86}==$/, { error: "must be an sha512 SRI integrity string" })
  .brand<"SriSha512">();
export type SriSha512 = z.infer<typeof sriSha512Schema>;

/**
 * A container image digest, `sha256:<64 hex>` (SPEC: sandbox image "pinned by digest"). Unbranded
 * because SPEC's `Recipe.runtime.imageDigest` is a plain `string`.
 */
export const imageDigestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, { error: "must be an image digest sha256:<64 hex>" });

/**
 * Structural safety of a repository-relative POSIX path: no leading or trailing slash, no empty,
 * `.` or `..` segments, no backslashes or control characters.
 */
function isSafeRelativePath(value: string): boolean {
  if (value.length === 0 || value.startsWith("/") || value.endsWith("/")) return false;
  if (value.includes("\\") || hasControlCharacter(value)) return false;
  return value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

/**
 * A repository-relative POSIX file path (changed files, sabotage targets and runs, recipe source
 * references): structure only. `[`, `]`, `{`, `}`, `(`, `)`, `*` and `?` are ordinary file-name
 * characters here, because Next.js route files are named `app/[slug]/page.tsx`,
 * `pages/[...all].tsx` or `app/(group)/page.tsx` (SPEC's target customer ships "Next.js apps").
 * Paths are never matched as patterns; unbranded because SPEC's `Recipe.sabotageTargets[].path` is
 * a plain `string`.
 */
export const repoFilePathSchema = z
  .string()
  .max(1024)
  .refine(isSafeRelativePath, { error: "must be a normalized repository-relative path" });

/** Opaque Git listing name only; never use this schema to authorize a filesystem operation. */
export const repoTreePathSchema = z
  .string()
  .max(1024)
  .refine(
    (value) =>
      value.length > 0 &&
      !value.startsWith("/") &&
      !value.endsWith("/") &&
      !hasControlCharacter(value) &&
      value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== ".."),
  );

/**
 * A repository-relative glob pattern (repository policy `protected_paths`). The same structural
 * rules as {@link repoFilePathSchema}; negation (`!`) is rejected so a pattern can only add
 * protection.
 */
export const pathGlobSchema = z
  .string()
  .max(256)
  .refine((value) => !value.startsWith("!") && isSafeRelativePath(value), {
    error: "must be a normalized repository-relative glob without negation",
  });

/** An RFC 6901 JSON Pointer (`""` is the whole document, otherwise `/segment/...`). */
export const jsonPointerSchema = z
  .string()
  .max(512)
  .regex(/^(?:\/(?:[^~/]|~[01])*)*$/, { error: "must be an RFC 6901 JSON Pointer" });

/** Shared bounded DNS syntax check, also embedded in the credential-free gateway. */
export function dnsNameSyntax(value: string): boolean {
  if (value.length > 253) return false;
  const labels = value.split(".");
  return (
    labels.length >= 2 &&
    labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
    !/^\d+$/.test(labels.at(-1) ?? "")
  );
}

/**
 * A DNS hostname for the Sandbox B build egress allowlist. Lower-cased; at least two labels; no IP
 * literals, ports, wildcards, schemes or trailing dot (SPEC: "Explicit approved build-host
 * allowlist; no implicit general internet").
 */
export const egressHostSchema = z.string().max(253).toLowerCase().refine(dnsNameSyntax, {
  error: "must be a DNS hostname (no IP literal, port, wildcard or scheme)",
});

/**
 * Top-level labels that never name a public host: names that only resolve inside private networks
 * (`metadata.google.internal`, `printer.local`, `kubernetes.default.svc`, reverse-DNS `arpa`) and
 * the special-use TLDs of RFC 2606, RFC 6761 and RFC 7686 (`test`, `example`, `invalid`,
 * `localhost`, `onion`). One list for every outbound destination Kovo validates (webhook
 * receivers, release documentation).
 */
export const NON_PUBLIC_TLDS: ReadonlySet<string> = new Set([
  "localhost",
  "local",
  "localdomain",
  "internal",
  "intranet",
  "lan",
  "home",
  "corp",
  "svc",
  "arpa",
  "test",
  "example",
  "invalid",
  "onion",
]);

const OCTET = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/**
 * Whether a host name embeds an IPv4 address: a dotted quad split across labels
 * (`169.254.169.254.nip.io`) or one dashed label (`10-0-0-1.sslip.io`). Wildcard-DNS services
 * resolve such names to the embedded address.
 */
export function hostNameEmbedsIpv4(hostname: string): boolean {
  const labels = hostname.toLowerCase().split(".");
  const dashed = labels.some((label) => {
    const parts = label.split("-");
    return parts.length === 4 && parts.every((part) => OCTET.test(part));
  });
  const dotted = labels.some((_, start) => {
    const quad = labels.slice(start, start + 4);
    return quad.length === 4 && quad.every((label) => OCTET.test(label));
  });
  return dashed || dotted;
}

/**
 * Whether `hostname` can name a public host: a DNS name ({@link egressHostSchema}: at least two
 * labels, no IP literal) whose top-level label is not in {@link NON_PUBLIC_TLDS} and that does not
 * embed an IPv4 address. A syntactic judgment only: whoever connects must still resolve the name
 * and refuse private, loopback and link-local addresses.
 */
export function isPublicDnsName(hostname: string): boolean {
  if (typeof hostname !== "string") return false;
  const normalized = hostname.toLowerCase();
  if (!dnsNameSyntax(normalized)) return false;
  const labels = normalized.split(".");
  return !NON_PUBLIC_TLDS.has(labels.at(-1) ?? "") && !hostNameEmbedsIpv4(normalized);
}

/** A POSIX environment variable name. */
export const envVarNameSchema = z
  .string()
  .max(128)
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, { error: "must be an environment variable name" });

/**
 * A shell command string retained as approved recipe configuration. Multi-line scripts are allowed
 * (CI `run:` blocks); NUL and other control characters are not.
 */
export const shellCommandSchema = z
  .string()
  .min(1)
  .max(8192)
  .refine((value) => value.trim().length > 0 && !hasControlCharacter(value, true), {
    error: "must be a non-blank command without control characters",
  });

/** An absolute URL path such as `/healthz` (smoke routes). No scheme, host, query or fragment. */
export const urlPathSchema = z
  .string()
  .max(2048)
  .regex(/^\/[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*$/, {
    error: "must be an absolute URL path without query or fragment",
  });

/** A CVE identifier as used by CISA KEV (`CVE-2025-55182`). */
export const cveIdSchema = z
  .string()
  .regex(/^CVE-\d{4}-\d{4,19}$/, { error: "must be a CVE identifier" })
  .brand<"CveId">();
export type CveId = z.infer<typeof cveIdSchema>;

/** A CWE number (`CWE-502` is `502`), matching SPEC's numeric CWE set. */
export const cweIdSchema = z.int().positive().max(1_000_000);
export type CweId = z.infer<typeof cweIdSchema>;

/** A final HTTP response status code. */
export const httpStatusSchema = z.int().min(100).max(599);

/** A bounded human-readable label (names, titles). Trimmed, single line, non-empty. */
export function labelSchema(max: number) {
  return z
    .string()
    .trim()
    .min(1)
    .max(max)
    .refine((value) => !hasControlCharacter(value), {
      error: "must be a single line without control characters",
    });
}

/** A non-negative safe integer (counts, byte sizes, durations in milliseconds). */
export const countSchema = z.int().nonnegative();
