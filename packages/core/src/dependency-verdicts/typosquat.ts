// Typosquat candidates by name distance against a mirrored list of popular package names (plans/
// dependency-firewall.md Part 1, "Likely typosquat of a popular package (new direct dependency
// only)"). The signal only warns, and has false positives by design: a name one edit away from a
// popular name, or equal to one once case and the separators `-`, `_` and `.` are ignored.
//
// Distance is the optimal-string-alignment edit distance (insertion, deletion, substitution and
// adjacent transposition each cost 1), found through a deletion-neighbourhood index: two names
// within one edit share the name itself or one of its single-character deletions. Lookups then cost
// O(length) map probes instead of a scan of the whole list.

/** The largest popular-name list the index accepts. */
export const MAX_POPULAR_PACKAGES = 20_000;
/** Names shorter than this are compared only by their normalized form: one edit is too common. */
export const TYPOSQUAT_MIN_EDIT_LENGTH = 5;

export interface PopularPackageIndex {
  /** The list's revision, for disclosure and caching. */
  readonly revision: string;
  readonly names: ReadonlySet<string>;
  /** Normalized name → the most popular name with that normalized form. */
  readonly normalized: ReadonlyMap<string, string>;
  /** A name or one of its single deletions → popular names in list order. */
  readonly neighbourhood: ReadonlyMap<string, readonly string[]>;
  /** List position of each name: earlier is more popular. */
  readonly rank: ReadonlyMap<string, number>;
}

function normalize(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, "");
}

function deletions(name: string): string[] {
  const out = new Set<string>();
  for (let index = 0; index < name.length; index += 1)
    out.add(name.slice(0, index) + name.slice(index + 1));
  return [...out];
}

/** Optimal-string-alignment distance, stopping once it exceeds `limit` (returns limit + 1). */
export function editDistance(a: string, b: string, limit: number): number {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let previous2: number[] = [];
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    let best = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1])
        value = Math.min(value, previous2[j - 2]! + 1);
      current.push(value);
      best = Math.min(best, value);
    }
    if (best > limit) return limit + 1;
    previous2 = previous;
    previous = current;
  }
  return Math.min(previous[b.length]!, limit + 1);
}

/**
 * Indexes a popularity list, most popular first. Errors: RangeError for a list over
 * {@link MAX_POPULAR_PACKAGES} or with an empty revision.
 */
export function indexPopularPackages(
  revision: string,
  names: readonly string[],
): PopularPackageIndex {
  if (names.length > MAX_POPULAR_PACKAGES) throw new RangeError("popularity list too large");
  if (revision.length === 0) throw new RangeError("popularity list revision required");
  const rank = new Map<string, number>();
  const normalized = new Map<string, string>();
  const neighbourhood = new Map<string, string[]>();
  for (const name of names) {
    if (rank.has(name)) continue;
    rank.set(name, rank.size);
    const key = normalize(name);
    if (!normalized.has(key)) normalized.set(key, name);
    for (const probe of [name, ...deletions(name)]) {
      const list = neighbourhood.get(probe);
      if (list === undefined) neighbourhood.set(probe, [name]);
      else if (list.at(-1) !== name) list.push(name);
    }
  }
  return { revision, names: new Set(rank.keys()), normalized, neighbourhood, rank };
}

/**
 * The popular package `name` most likely imitates, or null. A popular name itself is never a
 * candidate; nor is a name whose distance to every popular name is above one edit.
 */
export function typosquatTarget(name: string, index: PopularPackageIndex): string | null {
  if (index.names.has(name)) return null;
  const sameForm = index.normalized.get(normalize(name));
  if (sameForm !== undefined && sameForm !== name) return sameForm;
  if (name.length < TYPOSQUAT_MIN_EDIT_LENGTH) return null;
  let best: string | null = null;
  for (const probe of [name, ...deletions(name)]) {
    for (const candidate of index.neighbourhood.get(probe) ?? []) {
      if (candidate.length < TYPOSQUAT_MIN_EDIT_LENGTH) continue;
      if (best !== null && index.rank.get(candidate)! >= index.rank.get(best)!) continue;
      if (editDistance(name, candidate, 1) <= 1) best = candidate;
    }
  }
  return best;
}
