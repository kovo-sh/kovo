import { sha256HexSchema } from "@kovo/contracts/primitives";
import type { Sha256Hex } from "@kovo/contracts";

// FIPS 180-4 SHA-256, synchronous and dependency-free. `@kovo/core` may not import `node:crypto`
// (it must stay pure and browser-safe), and WebCrypto's `crypto.subtle.digest` is asynchronous,
// which would make every fingerprint and report hash async (docs/decisions/recipe.md "Purity, hashing and the seed").

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const INITIAL = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
] as const;

const HEX = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, "0"));
const encoder = new TextEncoder();

function compress(state: Uint32Array, w: Uint32Array, view: DataView, offset: number): void {
  for (let i = 0; i < 16; i += 1) w[i] = view.getUint32(offset + i * 4, false);
  for (let i = 16; i < 64; i += 1) {
    const w15 = w[i - 15] ?? 0;
    const w2 = w[i - 2] ?? 0;
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    w[i] = ((w[i - 16] ?? 0) + s0 + (w[i - 7] ?? 0) + s1) >>> 0;
  }
  let a = state[0] ?? 0;
  let b = state[1] ?? 0;
  let c = state[2] ?? 0;
  let d = state[3] ?? 0;
  let e = state[4] ?? 0;
  let f = state[5] ?? 0;
  let g = state[6] ?? 0;
  let h = state[7] ?? 0;
  for (let i = 0; i < 64; i += 1) {
    const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + s1 + ch + (K[i] ?? 0) + (w[i] ?? 0)) >>> 0;
    const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (s0 + maj) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) >>> 0;
  }
  state[0] = ((state[0] ?? 0) + a) >>> 0;
  state[1] = ((state[1] ?? 0) + b) >>> 0;
  state[2] = ((state[2] ?? 0) + c) >>> 0;
  state[3] = ((state[3] ?? 0) + d) >>> 0;
  state[4] = ((state[4] ?? 0) + e) >>> 0;
  state[5] = ((state[5] ?? 0) + f) >>> 0;
  state[6] = ((state[6] ?? 0) + g) >>> 0;
  state[7] = ((state[7] ?? 0) + h) >>> 0;
}

/** The SHA-256 digest of `data` (a string is hashed as its UTF-8 encoding). */
export function sha256(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const state = new Uint32Array(INITIAL);
  const w = new Uint32Array(64);
  const fullBlocks = Math.floor(bytes.byteLength / 64);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let block = 0; block < fullBlocks; block += 1) compress(state, w, view, block * 64);

  // Padding: the remaining bytes, 0x80, zeros, then the message length in bits (big-endian u64).
  const rest = bytes.byteLength - fullBlocks * 64;
  const tail = new Uint8Array(rest + 9 > 64 ? 128 : 64);
  tail.set(bytes.subarray(fullBlocks * 64));
  tail[rest] = 0x80;
  const tailView = new DataView(tail.buffer);
  const bitLength = bytes.byteLength * 8;
  tailView.setUint32(tail.byteLength - 8, Math.floor(bitLength / 0x1_0000_0000), false);
  tailView.setUint32(tail.byteLength - 4, bitLength >>> 0, false);
  for (let offset = 0; offset < tail.byteLength; offset += 64) {
    compress(state, w, tailView, offset);
  }

  const digest = new Uint8Array(32);
  const out = new DataView(digest.buffer);
  for (let i = 0; i < 8; i += 1) out.setUint32(i * 4, state[i] ?? 0, false);
  return digest;
}

/** Lower-case hex of `bytes`. */
export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += HEX[byte] ?? "";
  return hex;
}

/** The SHA-256 of `data` as the contracts' 64 lower-case hex digits. */
export function sha256Hex(data: Uint8Array | string): Sha256Hex {
  return sha256HexSchema.parse(toHex(sha256(data)));
}
