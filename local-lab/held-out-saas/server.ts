// TypeScript entrypoint for in-process consumers (scripts/benchmark-recall.ts). The runtime lives in server.mjs
// so the Docker image can start with plain `node server.mjs` and zero build step.
export { startHeldOutSaasServer, loadHeldOutSaasManifest, heldOutSaasPatchIds } from './server.mjs'
export type { HeldOutSaasOptions, HeldOutSaasServer, HeldOutSaasPersona, HeldOutSaasChallenge } from './server.d.mts'
