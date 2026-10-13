import { parse } from "semver";

/** Verified, artifact-bound facts only. Unknowns cannot establish repository continuity. */
export interface PublishingPathIdentity {
  readonly package: string;
  readonly version: string;
  readonly integrity: string;
  readonly publishedAt: number;
  readonly mode: "trusted" | "token" | "unknown";
  /** Successful evidence assessment only; omitted means unavailable, never absence. */
  readonly verifiedAttestation?: boolean;
  /** Hash of the authenticated immutable repository identifier, never the workflow path. */
  readonly repositoryIdHash: string | null;
  /** Verified normalized source URL hash; absence of an immutable ID remains unknown. */
  readonly repositoryUrlHash?: string | null;
}

export type PublishingPathSignal =
  | "token_after_trusted"
  | "source_repository_changed"
  | "publishing_path_attestation_missing";

export const PUBLISHING_PATH_RUN_LENGTH = 4;
export const PUBLISHING_PATH_HISTORY_LIMIT = 100;
/** No authoritative npm field currently proves token authentication (coordinator Q-002). */
export const PUBLISHING_PATH_TOKEN_UNAVAILABLE = "publishing_mode_unproven";

/** Stable releases compare only with stable releases in their own major, in publish order. */
function line(version: string): number | null {
  const parsed = parse(version);
  return parsed === null || parsed.prerelease.length !== 0 ? null : parsed.major;
}

/**
 * Additive suspicion only: this detector has no clearance, expiry or recovery output.
 * Only authenticated immutable repository IDs establish a repository change.
 */
export function detectPublishingPath(
  current: PublishingPathIdentity,
  history: readonly PublishingPathIdentity[],
): readonly PublishingPathSignal[] {
  const currentLine = line(current.version);
  if (currentLine === null || !Number.isFinite(current.publishedAt)) return [];
  // Unknowns interrupt the token run, but cannot hide an established verified repository.
  if (history.length > PUBLISHING_PATH_HISTORY_LIMIT) return [];
  if (
    history.some(
      (item) =>
        item.package === current.package &&
        line(item.version) === currentLine &&
        (!Number.isFinite(item.publishedAt) || item.publishedAt === current.publishedAt),
    )
  )
    return [];
  const previous = history
    .filter(
      (item) =>
        item.package === current.package &&
        item.version !== current.version &&
        line(item.version) === currentLine &&
        Number.isFinite(item.publishedAt) &&
        item.publishedAt < current.publishedAt,
    )
    .toSorted((a, b) => b.publishedAt - a.publishedAt);
  // Tied publication timestamps cannot establish an unambiguous consecutive ordering.
  if (new Set(previous.map((item) => item.publishedAt)).size !== previous.length) return [];
  const signals: PublishingPathSignal[] = [];
  if (
    current.verifiedAttestation === false &&
    previous.length >= PUBLISHING_PATH_RUN_LENGTH &&
    previous
      .slice(0, PUBLISHING_PATH_RUN_LENGTH)
      .every((item) => item.mode === "trusted" && item.verifiedAttestation === true)
  )
    signals.push("publishing_path_attestation_missing");
  if (
    current.mode === "token" &&
    previous.length >= PUBLISHING_PATH_RUN_LENGTH &&
    previous.slice(0, PUBLISHING_PATH_RUN_LENGTH).every((item) => item.mode === "trusted")
  )
    signals.push("token_after_trusted");
  let baseline: string | null = null;
  let run = 0;
  for (const item of previous) {
    if (item.repositoryIdHash === null) continue;
    run = item.repositoryIdHash === baseline ? run + 1 : 1;
    baseline = item.repositoryIdHash;
    if (run < PUBLISHING_PATH_RUN_LENGTH) continue;
    if (current.repositoryIdHash !== null && current.repositoryIdHash !== baseline)
      signals.push("source_repository_changed");
    break;
  }
  return signals;
}
