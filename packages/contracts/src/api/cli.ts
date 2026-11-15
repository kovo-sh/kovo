// @kovo/contracts/api/cli: the `/v1` wire shapes the public `kovo` CLI bundle may load: the
// dependency-verdict endpoint and the CVSS score shape @kovo/core's advisory model uses. The CLI
// bundle build resolves `@kovo/contracts/api` here (see ../cli.ts), so no other endpoint module
// is a bundle input.

export * from "./cvss.js";
export * from "./dependency-verdicts.js";
