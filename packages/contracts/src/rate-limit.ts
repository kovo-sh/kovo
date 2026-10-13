// Per-instance, in-memory token buckets keyed by client address: the rate limits that replace the
// edge's Cloud Armor throttles (docs/decisions/cost-reduction.md "Cloud Armor replaced in the
// application"; the directive: "Keep basic per-instance rate limits. No shared Redis limiter"). One
// implementation for the API, the npm proxy and the web server, which may not import the control
// plane: pure, no clock of its own (the caller passes the time, from its Clock port), no I/O.
//
// A bucket holds `burst` tokens and refills at `perMinute`; a request (or, for a failure limiter, a
// failure) takes one. At most `maxTrackedClients` buckets are kept: when a new client arrives at the
// bound, full buckets are forgotten first (a full bucket is a fresh one), then the least recently
// used, until a tenth of the table is free, so address-rotating traffic pays one scan per tenth of
// the bound rather than per request. Forgetting a spent bucket forgives at most one burst, and an
// address still sending is the most recently used, not the next forgotten. With N instances a
// client's ceiling is at most N times the rate.

/** One limiter's settings (`api.rateLimits.clientIp`, `web.rateLimit`, …). */
export interface TokenBucketLimit {
  readonly burst: number;
  readonly perMinute: number;
  readonly maxTrackedClients: number;
}

interface Bucket {
  tokens: number;
  updatedAtMs: number;
}

export class KeyedTokenBuckets {
  readonly #limit: TokenBucketLimit;
  readonly #perMs: number;
  readonly #buckets = new Map<string, Bucket>();

  constructor(limit: TokenBucketLimit) {
    if (!Number.isSafeInteger(limit.burst) || limit.burst < 1) {
      throw new RangeError("burst must be a positive integer");
    }
    if (!Number.isFinite(limit.perMinute) || limit.perMinute <= 0) {
      throw new RangeError("perMinute must be positive");
    }
    if (!Number.isSafeInteger(limit.maxTrackedClients) || limit.maxTrackedClients < 1) {
      throw new RangeError("maxTrackedClients must be a positive integer");
    }
    this.#limit = limit;
    this.#perMs = limit.perMinute / 60_000;
  }

  /**
   * Takes one token of `key`'s bucket: null when admitted, or the whole seconds until a token is
   * back when the bucket is empty (nothing taken).
   */
  take(key: string, nowMs: number): number | null {
    const wait = this.check(key, nowMs);
    if (wait !== null) return wait;
    const bucket = this.#bucket(key, nowMs);
    bucket.tokens -= 1;
    return null;
  }

  /**
   * Whether `key`'s bucket has a token, taking none: null when it has, or the whole seconds until it
   * has one again. A failure limiter checks before any work and charges only a failure.
   */
  check(key: string, nowMs: number): number | null {
    const bucket = this.#peek(key, nowMs);
    if (bucket === undefined || bucket.tokens >= 1) return null;
    return Math.max(1, Math.ceil((1 - bucket.tokens) / this.#perMs / 1000));
  }

  /** Takes one token of `key`'s bucket whatever it holds (a failure; never below empty). */
  charge(key: string, nowMs: number): void {
    const bucket = this.#bucket(key, nowMs);
    bucket.tokens = Math.max(0, bucket.tokens - 1);
  }

  /** Clients currently tracked (tests and gauges). */
  get trackedClients(): number {
    return this.#buckets.size;
  }

  /** `key`'s bucket refilled to `nowMs`, if tracked, moved to the most recently used end. */
  #peek(key: string, nowMs: number): Bucket | undefined {
    const bucket = this.#buckets.get(key);
    if (bucket === undefined) return undefined;
    this.#refill(bucket, nowMs);
    // A Map iterates in insertion order: re-inserting keeps the least recently used first.
    this.#buckets.delete(key);
    this.#buckets.set(key, bucket);
    return bucket;
  }

  #refill(bucket: Bucket, nowMs: number): void {
    const elapsed = Math.max(0, nowMs - bucket.updatedAtMs);
    bucket.tokens = Math.min(this.#limit.burst, bucket.tokens + elapsed * this.#perMs);
    bucket.updatedAtMs = Math.max(bucket.updatedAtMs, nowMs);
  }

  /** `key`'s bucket, created full (making room) when new. */
  #bucket(key: string, nowMs: number): Bucket {
    const existing = this.#peek(key, nowMs);
    if (existing !== undefined) return existing;
    this.#makeRoom(nowMs);
    const bucket = { tokens: this.#limit.burst, updatedAtMs: nowMs };
    this.#buckets.set(key, bucket);
    return bucket;
  }

  /**
   * Once the table is at its bound, forgets full buckets, then the least recently used ones, until a
   * tenth of the bound (at least one) is free.
   */
  #makeRoom(nowMs: number): void {
    const max = this.#limit.maxTrackedClients;
    if (this.#buckets.size < max) return;
    const keep = max - Math.max(1, Math.floor(max / 10));
    for (const [key, bucket] of this.#buckets) {
      this.#refill(bucket, nowMs);
      if (bucket.tokens >= this.#limit.burst) this.#buckets.delete(key);
    }
    while (this.#buckets.size > keep) {
      const leastRecent = this.#buckets.keys().next().value;
      if (leastRecent === undefined) break;
      this.#buckets.delete(leastRecent);
    }
  }
}
