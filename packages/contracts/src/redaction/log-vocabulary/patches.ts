// Closed log vocabulary: apps/control-plane/src/services/patches.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "patch_blob_deleted",
  "patch_blob_deleted_for_scope",
  "patch_blob_expired_swept",
  "patch_blob_opened",
  "patch_blob_stage_canceled",
  "patch_blob_staged",
] as const;
