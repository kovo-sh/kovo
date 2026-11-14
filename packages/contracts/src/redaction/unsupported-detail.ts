// The closed detail behind a repository's coarse `unsupported_reason` (D-267, Refs #8256): the
// inventory step that refused (`INVENTORY_REFUSAL_CODES`) and, when it has one, the finer gate it
// names from a closed vocabulary: the lockfile parser's reason, the runtime resolver's gate, a
// refused setting's key, the workspace reason or the fix-only refusal. Stored beside the reason on
// `repos.unsupported_detail` and logged on `inventory_unsupported_detail`. Never a version string,
// URL, package spec, setting value or file content: every part is a member of a closed list.

import {
  INVENTORY_REFUSAL_CODES,
  LOG_FIX_ONLY_REASONS,
  LOG_LOCKFILE_REASONS,
  LOG_RUNTIME_REASONS,
  LOG_SETTING_KEYS,
  LOG_WORKSPACE_REASONS,
} from "./log-vocabulary.js";

/** The stored shape: `<refusal code>` or `<refusal code>/<closed gate>`. The corpus reader checks it. */
export const UNSUPPORTED_DETAIL_PATTERN = "^[a-z0-9_]{1,64}(/[A-Za-z0-9_:-]{1,64})?$";

const SHAPE = new RegExp(UNSUPPORTED_DETAIL_PATTERN);

/** The finer gates, in the order a detail names them when (unusually) more than one is set. */
const GATES: readonly (readonly string[])[] = [
  LOG_LOCKFILE_REASONS,
  LOG_RUNTIME_REASONS,
  LOG_SETTING_KEYS,
  LOG_WORKSPACE_REASONS,
  LOG_FIX_ONLY_REASONS,
];

/** A refusal's closed parts, as inventory's `RefusalDetail` carries them. */
export interface UnsupportedDetailParts {
  readonly code: (typeof INVENTORY_REFUSAL_CODES)[number];
  readonly lockfileReason?: (typeof LOG_LOCKFILE_REASONS)[number];
  readonly runtimeReason?: (typeof LOG_RUNTIME_REASONS)[number];
  readonly settingKey?: (typeof LOG_SETTING_KEYS)[number];
  readonly workspaceReason?: (typeof LOG_WORKSPACE_REASONS)[number];
  readonly fixOnlyReason?: (typeof LOG_FIX_ONLY_REASONS)[number];
}

/**
 * A detail code as `unsupportedDetailOf` or `parseUnsupportedDetail` returns it. Writers take it
 * only from those two.
 */
export type UnsupportedDetail = string;

/**
 * The one detail code of a refusal: its step code, then `/` and the finest closed gate it names
 * (lockfile, runtime, setting, workspace, then fix-only). Null when a part is outside its list.
 */
export function unsupportedDetailOf(parts: UnsupportedDetailParts): UnsupportedDetail | null {
  const gate =
    parts.lockfileReason ??
    parts.runtimeReason ??
    parts.settingKey ??
    parts.workspaceReason ??
    parts.fixOnlyReason;
  return parseUnsupportedDetail(gate === undefined ? parts.code : `${parts.code}/${gate}`);
}

/** The value as a detail code when it is one (closed parts, stored shape), else null. */
export function parseUnsupportedDetail(value: unknown): UnsupportedDetail | null {
  if (typeof value !== "string" || !SHAPE.test(value)) return null;
  const slash = value.indexOf("/");
  const code = slash === -1 ? value : value.slice(0, slash);
  if (!INVENTORY_REFUSAL_CODES.some((known) => known === code)) return null;
  if (slash === -1) return value;
  const gate = value.slice(slash + 1);
  return GATES.some((list) => list.includes(gate)) ? value : null;
}
