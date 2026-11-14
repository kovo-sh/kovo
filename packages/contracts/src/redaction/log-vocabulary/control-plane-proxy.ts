// Closed log vocabulary: apps/control-plane/src/proxy.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "install_binary_response",
  "npm_proxy_artifact_response",
  "npm_proxy_busy_mark_failed",
  "npm_proxy_packument_failed",
  "npm_proxy_packument_response",
  "npm_proxy_refusal",
] as const;
export const LOG_FIELD_KEYS = ["packument_format", "redirect_target", "response_type"] as const;
export const LOG_ENUM_CODES = [
  "artifact_client_aborted",
  "artifact_redirected",
  "artifact_response_failed",
  "artifact_served",
  "artifact_stream_failed",
  "capability_exhausted",
  "capability_invalid",
  "capability_revoked",
  "cdn_cached",
  "install_canary_canary_endpoint",
  "install_canary_npm_proxy",
  "kovo_cdn",
  "npm_cdn_key_absent",
  "npm_cdn_public_url_unusable",
  "npm_cdn_redirect_on",
  "npm_proxy_busy_mark_failed",
  "package_not_allowed",
  "packument_client_aborted",
  "packument_redirected",
  "packument_response_failed",
  "packument_served",
  "packument_stream_failed",
  "redirected",
  "registry_npmjs_org",
  "unsupported_request",
] as const;
