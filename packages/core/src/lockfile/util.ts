// Small helpers shared by the lockfile modules.

/** The entry for `key`, which the caller has established exists (a broken invariant throws). */
export function required<K, V>(map: ReadonlyMap<K, V>, key: K): V {
  const value = map.get(key);
  if (value === undefined) throw new RangeError("lockfile graph invariant: missing entry");
  return value;
}

/** Code-unit string order (stable across locales, unlike `localeCompare`). */
export function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
