import { z } from "zod";

// Operational metadata only (plans/incident-management.md §6). Raw Monitoring messages never
// become state, task bodies, diagnostics or paging metrics.
export const incidentIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
export const incidentSeveritySchema = z.enum(["CRITICAL", "ERROR", "WARNING"]);
export const incidentCauseSchema = z.enum([
  "owner_decision_required",
  "mitigation_failed",
  "outside_runbook",
  "customer_impact",
]);
export const incidentPageReasonSchema = z.enum([
  "always_page",
  "unacked",
  "unresolved",
  "coordinator_escalated",
]);
const timestamp = z.int().min(0).max(8_640_000_000_000_000);
export const incidentPolicySchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{0,99}$/),
  title: z.string().min(1).max(200),
  runbookAnchor: z.string().regex(/^[a-z0-9][a-z0-9-]{0,99}$/),
  severity: incidentSeveritySchema,
  source: z.enum(["metric", "log"]),
  page: z
    .strictObject({
      acknowledgementMs: z.int().min(1_000).max(86_400_000).exactOptional(),
      unresolvedMs: z.int().min(1_000).max(86_400_000).exactOptional(),
    })
    .exactOptional(),
});
export type IncidentPolicy = z.infer<typeof incidentPolicySchema>;
export const incidentEventSchema = z.strictObject({
  environment: z.string().regex(/^[a-z][a-z0-9-]{0,31}$/),
  incidentId: incidentIdSchema,
  policyId: incidentPolicySchema.shape.id,
  title: incidentPolicySchema.shape.title,
  runbookAnchor: incidentPolicySchema.shape.runbookAnchor,
  severity: incidentSeveritySchema,
  state: z.enum(["open", "closed"]),
  startedAt: timestamp,
  closedAt: timestamp.nullable(),
  resourceType: z.string().regex(/^[a-z][a-z0-9_]{0,79}$/),
});
export type IncidentEvent = z.infer<typeof incidentEventSchema>;
export const incidentStateSchema = incidentEventSchema.extend({
  acknowledgedAt: timestamp.nullable(),
  issueNumber: z.int().positive().nullable(),
  cause: incidentCauseSchema.nullable(),
  reason: incidentPageReasonSchema.nullable(),
  lastPageAt: timestamp.nullable(),
  pageActive: z.boolean(),
  // Durable outbox markers: failed side effects stay retryable, including resolve-to-zero.
  metricDirty: z.boolean(),
  lastMetricAt: timestamp.nullable(),
  scheduledWakeAt: timestamp.nullable(),
  timersInitialized: z.boolean(),
});
export type IncidentState = z.infer<typeof incidentStateSchema>;
export const incidentLeaseSchema = z.strictObject({
  owner: z.string().uuid(),
  expiresAt: timestamp,
});
export const incidentDocumentSchema = z.strictObject({
  kind: z.literal("incident"),
  state: incidentStateSchema.nullable(),
  lease: incidentLeaseSchema.nullable(),
});
export const incidentCursorSchema = z.strictObject({
  kind: z.literal("cursor"),
  after: incidentIdSchema.nullable(),
});
export const incidentHeartbeatSchema = z.strictObject({
  kind: z.literal("heartbeat"),
  lease: incidentLeaseSchema.nullable(),
  cycle: z.string().regex(/^\d{4}-\d{2}-\d{2}(?:T(?:00|06|12|18))?$/),
  closeAt: timestamp,
  active: z.boolean(),
  dirty: z.boolean(),
  lastMetricAt: timestamp.nullable(),
});
export const bridgeDocumentSchema = z.discriminatedUnion("kind", [
  incidentDocumentSchema,
  incidentCursorSchema,
  incidentHeartbeatSchema,
]);
export type BridgeDocument = z.infer<typeof bridgeDocumentSchema>;
export type IncidentDocument = z.infer<typeof incidentDocumentSchema>;
export const bridgeTimerSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("incident"), incidentId: incidentIdSchema }),
  z.strictObject({ kind: z.literal("sweep") }),
  z.strictObject({ kind: z.literal("heartbeat_open") }),
  z.strictObject({
    kind: z.literal("heartbeat_close"),
    cycle: incidentHeartbeatSchema.shape.cycle,
  }),
]);
export type BridgeTimer = z.infer<typeof bridgeTimerSchema>;
export const bridgeAckSchema = z.strictObject({
  incidentId: incidentIdSchema,
  issueNumber: z.int().positive(),
});
export const bridgeEscalateSchema = z.strictObject({
  incidentId: incidentIdSchema,
  cause: incidentCauseSchema,
});
export const bridgeResolveSchema = z.strictObject({
  incidentId: incidentIdSchema,
  issueNumber: z.int().positive(),
  reason: z.enum(["source_condition_cleared", "mitigation_verified"]),
  // Audited coordinator attestation after checking Monitoring; only for uncatalogued sources.
  source: z.literal("log").exactOptional(),
});
