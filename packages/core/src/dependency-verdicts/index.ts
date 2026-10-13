// @kovo/core/dependency-verdicts: the pure dependency verdict engine (plans/dependency-firewall.md
// Part 1). Evidence lookups live in the control plane behind ports; nothing here does I/O.

export * from "./policy.js";
export * from "./source.js";
export * from "./typosquat.js";
