// Closed log vocabulary: apps/control-plane/src/relay.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "relay_could_not_book_a_completion",
  "relay_could_not_hold_an_unreported_cost",
  "relay_refused_a_completion_served_outside_its_routing",
  "relay_upstream_failure",
] as const;
