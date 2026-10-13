// Member names that must never carry a value in an API response or an audit projection (SPEC: "All
// mutations write a sanitized audit event; exclude secrets and source-bearing before/after values";
// "Never persist or log source, diffs, manifests, CI files, prompts, model/tool output,
// stdout/stderr, secrets, tokens or capability URLs"). Used by the response-shape tests over every
// registered endpoint and by the audit value schema, whose keys are dynamic. A one-time secret an
// endpoint deliberately reveals is declared in that endpoint's `oneTimeFields` instead.
//
// Names are matched by token (split on `_`, `-`, `.` and camelCase), not by exact spelling, so
// `signing_key`, `unified_diff` or `privateKeyPem` are caught like `key`, `diff` or `private_key`.

/** Tokens that denote a secret or source-bearing content wherever they appear in a name. */
const SENSITIVE_TOKENS: ReadonlySet<string> = new Set([
  // Credentials and key material.
  "secret",
  "secrets",
  "token",
  "tokens",
  "password",
  "passwords",
  "passphrase",
  "credential",
  "credentials",
  "key",
  "keys",
  "jwt",
  "bearer",
  "cookie",
  "cookies",
  "session",
  "pem",
  "plaintext",
  "ciphertext",
  "dsn",
  "capability",
  "capabilities",
  "proxy",
  // Source, changes and configuration files.
  "diff",
  "diffs",
  "patch",
  "patches",
  "manifest",
  "manifests",
  "lockfile",
  "lockfiles",
  "npmrc",
  "dotenv",
  "yaml",
  "yml",
  "content",
  "contents",
  "tarball",
  // Model and tool traffic.
  "prompt",
  "prompts",
  "completion",
  "completions",
  "transcript",
  "transcripts",
  "response",
  "responses",
  // Raw execution output.
  "stdout",
  "stderr",
  "log",
  "logs",
  "output",
  "outputs",
  "raw",
  "trace",
  "stacktrace",
  "traceback",
]);

/** Tokens that stay sensitive even as a qualified reference: staged patches never surface. */
const ALWAYS_SENSITIVE_TOKENS: ReadonlySet<string> = new Set(["blob", "blobs"]);

/** Adjacent token pairs whose combination denotes content although each token alone does not. */
const SENSITIVE_PAIRS: readonly (readonly [string, string])[] = [
  ["agent", "summary"],
  ["agent", "message"],
  ["model", "summary"],
  ["model", "message"],
  ["tool", "result"],
  ["tool", "results"],
  ["tool", "call"],
  ["tool", "calls"],
  ["source", "code"],
  ["source", "archive"],
  ["source", "text"],
  ["source", "files"],
  ["package", "json"],
  ["ci", "files"],
  ["workflow", "files"],
];

/**
 * A last token that makes the name metadata about something rather than the thing itself:
 * identifiers, versions, counts, digests, locations and times (`api_key_id`, `key_version`,
 * `output_sha256`, `manifest_pointers`, `previous_key_valid_until`).
 */
const METADATA_SUFFIXES: ReadonlySet<string> = new Set([
  "id",
  "ids",
  "version",
  "versions",
  "count",
  "sha256",
  "sha512",
  "pointer",
  "pointers",
  "path",
  "paths",
  "at",
  "until",
]);

/** Exact names that are always sensitive: a bare hash says nothing about what it hashes. */
const SENSITIVE_NAMES: ReadonlySet<string> = new Set(["hash", "authorization", "set_cookie"]);

/** Exact names that are safe although a token matches (each with its reason). */
const ALLOWED_NAMES: ReadonlySet<string> = new Set([
  // A count of model tokens consumed (usage), not an authentication token.
  "model_tokens",
  // Run-record metadata: a nonnegative integer byte count, never the raw content.
  "raw_bytes",
  // Existing inventory publication metadata: a validated SHA-256, never lockfile content.
  "lockfile_hash",
  // step-diagnostics installIssueSchema: integer HTTP status (100–599), byte count
  // (nonnegative safe integer), and a fixed proxy outcome reason enum. These three exact
  // names never carry a URL, capability, response body or arbitrary proxy output.
  "proxy_status",
  "proxy_size_bytes",
  "proxy_reason",
]);

/**
 * Names whose value is a metadata object (never a scalar) that the response-shape test checks
 * member by member: `{ api_key: { id, name, scope, … } }` in the API key routes.
 */
export const SENSITIVE_NAME_CONTAINERS: ReadonlySet<string> = new Set(["api_key"]);

/** Splits a member name into lower-case tokens (`privateKeyPem` → `private`, `key`, `pem`). */
export function nameTokens(name: string): string[] {
  return name
    .replaceAll(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[_\-.]+/)
    .filter((token) => token !== "");
}

/** Whether a JSON member name denotes a secret or a source-bearing value. */
export function isSensitiveFieldName(name: string): boolean {
  const lower = name.toLowerCase();
  if (SENSITIVE_NAMES.has(lower)) return true;
  if (ALLOWED_NAMES.has(lower)) return false;
  const tokens = nameTokens(name);
  if (tokens.some((token) => ALWAYS_SENSITIVE_TOKENS.has(token))) return true;
  const last = tokens.at(-1) ?? "";
  // `*_file` names a file's content (`workflow_file`, `ci_file`); `changed_files` lists paths.
  if (last === "file") return true;
  if (tokens.length > 1 && METADATA_SUFFIXES.has(last)) return false;
  if (tokens.some((token) => SENSITIVE_TOKENS.has(token))) return true;
  return SENSITIVE_PAIRS.some(([first, second]) =>
    tokens.some((token, index) => token === first && tokens[index + 1] === second),
  );
}
