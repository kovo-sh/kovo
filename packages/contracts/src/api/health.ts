import { z } from "zod";

import { whenValid } from "../primitives.js";
import { defineEndpoint } from "./endpoint.js";

// Liveness and readiness probes for the API, worker and proxy entrypoints (BUILD_PLAN item 4
// "`/healthz` and `/readyz`"; SPEC rollout "at least five minutes of health/synthetic checks at each
// stage"). They are unauthenticated, outside `/v1`, and reveal only check names and pass/fail:
// never versions, hosts, connection strings or error text.

export const healthResponseSchema = z.strictObject({ status: z.literal("ok") });

export const readinessCheckSchema = z.strictObject({
  name: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/, { error: "must be a check name" }),
  ok: z.boolean(),
});

function readinessSchema<const Status extends "ready" | "not_ready">(status: Status) {
  return z
    .strictObject({
      status: z.literal(status),
      checks: z.array(readinessCheckSchema).min(1).max(20),
    })
    .refine((body) => body.checks.every((check) => check.ok) === (status === "ready"), {
      ...whenValid,
      error: "ready exactly when every check passes",
      path: ["checks"],
    })
    .refine((body) => new Set(body.checks.map((check) => check.name)).size === body.checks.length, {
      ...whenValid,
      error: "check names are unique",
      path: ["checks"],
    });
}

export const readyResponseSchema = readinessSchema("ready");
export const notReadyResponseSchema = readinessSchema("not_ready");

const HEALTH_SPEC =
  "promote web/API/proxy revisions through 5%, 25%, then 100% traffic with at least five minutes of health/synthetic checks at each stage.";

export const HEALTH_ENDPOINTS = {
  getHealth: defineEndpoint({
    operationId: "getHealth",
    area: "health",
    method: "GET",
    path: "/healthz",
    summary: "Liveness: the process is serving requests.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: { 200: healthResponseSchema },
    authorization: { spec: HEALTH_SPEC, actors: ["anonymous"], tenant: "none" },
  }),
  getReadiness: defineEndpoint({
    operationId: "getReadiness",
    area: "health",
    method: "GET",
    path: "/readyz",
    summary: "Readiness: every dependency the entrypoint needs is reachable.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: { 200: readyResponseSchema, 503: notReadyResponseSchema },
    authorization: { spec: HEALTH_SPEC, actors: ["anonymous"], tenant: "none" },
  }),
} as const;
