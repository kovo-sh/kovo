// Closed log vocabulary: packages/adapters/src/sandbox.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "sandbox_egress_gateway_bypassed",
  "sandbox_egress_provider_allowlist_refused",
  "sandbox_egress_provider_allowlist_verified",
  "sandbox_egress_ready_wait_passed",
  "sandbox_egress_ready_wait_timed_out",
  "sandbox_egress_relay_not_running",
  "sandbox_open_install_seal_refused",
] as const;
export const LOG_ENUM_CODES = [
  "ci_like_open_runtime_unproven",
  "ci_like_open_unconfigured",
  "daytona_provider_allowlist_d520",
  "egress_job_binding_invalid",
  "egress_network_unavailable",
  "egress_probe_failed_external_dns_blocked",
  "egress_ready_proxy_denied_egress_unavailable_upstream_tls",
  "egress_ready_proxy_denied_host_not_allowed",
  "egress_ready_proxy_refused",
  "egress_ready_timeout",
  "egress_relay_check_failed",
  "egress_relay_not_running",
  "gateway_not_ready",
  "isolation_setup_failed",
  "open_install_seal_block",
  "open_install_seal_labels",
  "open_install_seal_open_sockets",
  "open_install_seal_sockets_unread",
  "open_install_seal_start",
  "open_install_seal_stop",
  "relay_bootstrap_failed",
  "relay_ca_bundle_unavailable",
  "snapshot_source_lifetime",
] as const;
