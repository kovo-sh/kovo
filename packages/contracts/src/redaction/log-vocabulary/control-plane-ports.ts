// Closed log vocabulary: apps/control-plane/src/ports.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_ENUM_CODES = [
  "read_invariant_broken",
  "route_invariant_broken",
  "route_wiring_invalid",
] as const;
