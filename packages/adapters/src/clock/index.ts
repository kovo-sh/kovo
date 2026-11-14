import type { Clock } from "../ports/clock.js";
import type { Timers } from "../ports/timers.js";

// @kovo/adapters/clock: the real Clock and Timers. The only place outside tests that reads the
// system time or schedules on the system timers (ARCHITECTURE §3 "Time"; the Kovo Sim purity lint
// allowlists this file).

/** Reads the host's wall clock. Cloud Run hosts are NTP-synchronized; the value is UTC. */
export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}

/** The shared real Clock, for runtime code that has no injected one. */
export const systemClock: Clock = new SystemClock();

/**
 * The real Timers. Each call reads the global at call time, so production timings are the globals'
 * own and a Kovo Sim kernel or Vitest's fake timers, once installed, still control them.
 */
export const systemTimers: Timers = {
  setTimeout: (callback, ms) => globalThis.setTimeout(callback, ms),
  setInterval: (callback, ms) => globalThis.setInterval(callback, ms),
  monotonicNow: () => globalThis.performance.now(),
};
