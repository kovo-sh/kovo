/**
 * Canonical JSON: object members sorted by key at every depth, no whitespace. Two requests with the
 * same content in a different member order fingerprint identically.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value))
    return `[${value.map((item: unknown) => canonicalJson(item)).join(",")}]`;
  const entries = Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
}

/** Fingerprint input is the raw HTTP request before codec defaults or decoding. */
export function canonicalHttpRequest(request: {
  readonly method: string;
  readonly route: string;
  readonly params: unknown;
  readonly query: unknown;
  readonly body: unknown;
}): string {
  return canonicalJson({
    method: request.method,
    route: request.route,
    params: request.params,
    query: request.query,
    body: request.body,
  });
}
