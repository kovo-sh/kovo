import { createHash, type Hash } from "node:crypto";

// Hashes a byte stream while it is consumed, so integrity can be checked without buffering.

export type DigestAlgorithm = "md5" | "sha1" | "sha256" | "sha512";

export interface DigestTap<A extends DigestAlgorithm> {
  /** The source bytes, unchanged. Consume this stream instead of the source. */
  readonly stream: ReadableStream<Uint8Array>;
  /** Bytes that have flowed through so far. */
  bytes(): number;
  /** The digest of everything that flowed through; call once the stream has closed. */
  digest(algorithm: A): Buffer;
}

export function digestTap<A extends DigestAlgorithm>(
  source: ReadableStream<Uint8Array>,
  algorithms: readonly A[],
): DigestTap<A> {
  const hashes = new Map<A, Hash>(
    algorithms.map((algorithm) => [algorithm, createHash(algorithm)]),
  );
  const results = new Map<A, Buffer>();
  let total = 0;
  const stream = source.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        total += chunk.byteLength;
        for (const hash of hashes.values()) hash.update(chunk);
        controller.enqueue(chunk);
      },
    }),
  );
  return {
    stream,
    bytes: () => total,
    digest: (algorithm) => {
      const done = results.get(algorithm);
      if (done !== undefined) return done;
      const hash = hashes.get(algorithm);
      if (hash === undefined) throw new RangeError(`digest ${algorithm} was not requested`);
      const value = hash.digest();
      results.set(algorithm, value);
      return value;
    },
  };
}
