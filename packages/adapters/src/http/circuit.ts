import type { Clock } from "../ports/clock.js";
import { PortError, type PortErrorInit } from "../ports/errors.js";

export class UpstreamCircuitOpenError extends PortError {
  readonly kind = "unavailable" as const;
  readonly retryable = false;
  constructor(init: PortErrorInit) {
    super("unavailable", { ...init, code: "upstream_circuit_open" });
  }
}

/** Shared across runs in one worker. No request paths, credentials or payloads are retained. */
export class UpstreamCircuit {
  #failures = 0;
  #openUntil = 0;
  #probe = false;
  #generation = 0;

  readonly threshold: number;
  readonly coolOffMs: number;

  constructor(threshold = 3, coolOffMs = 30_000) {
    this.threshold = threshold;
    this.coolOffMs = coolOffMs;
  }

  enter(clock: Clock, context: PortErrorInit): number {
    if (this.#failures >= this.threshold) {
      if (clock.now().getTime() < this.#openUntil || this.#probe)
        throw new UpstreamCircuitOpenError(context);
      this.#probe = true;
    }
    return this.#generation;
  }

  success(generation: number): void {
    if (generation !== this.#generation) return;
    const recovered = this.#failures >= this.threshold;
    this.#failures = 0;
    this.#probe = false;
    this.#openUntil = 0;
    if (recovered) this.#generation += 1;
  }

  failure(generation: number, clock: Clock): void {
    if (generation !== this.#generation) return;
    this.#failures += 1;
    this.#probe = false;
    if (this.#failures >= this.threshold) {
      this.#openUntil = clock.now().getTime() + this.coolOffMs;
      // Late completions from requests admitted before opening cannot close the circuit.
      this.#generation += 1;
    }
  }

  cancel(generation: number): void {
    if (generation === this.#generation) this.#probe = false;
  }
}

// Transport identity isolates fixture servers and production clients. Production transports are
// long-lived singletons. Only public origins and credential-scope IDs (such as `inst:<id>`) are
// keys, never paths or tokens. Each transport keeps at most MAX_CIRCUITS_PER_TRANSPORT scopes and
// evicts the least recently used one, so per-installation scopes cannot grow without limit.
export const MAX_CIRCUITS_PER_TRANSPORT = 1024;
const circuits = new WeakMap<object, Map<string, UpstreamCircuit>>();
export function upstreamCircuit(
  transport: object,
  origin: string,
  scope = "",
  limit = MAX_CIRCUITS_PER_TRANSPORT,
): UpstreamCircuit {
  const key = JSON.stringify([origin, scope]);
  let entries = circuits.get(transport);
  if (entries === undefined) {
    entries = new Map();
    circuits.set(transport, entries);
  }
  let circuit = entries.get(key);
  if (circuit === undefined) {
    circuit = new UpstreamCircuit();
  } else {
    // Map iteration follows insertion order; re-inserting marks the scope most recently used.
    entries.delete(key);
  }
  entries.set(key, circuit);
  while (entries.size > Math.max(1, limit)) {
    const oldest = entries.keys().next();
    if (oldest.done === true) break;
    entries.delete(oldest.value);
  }
  return circuit;
}
