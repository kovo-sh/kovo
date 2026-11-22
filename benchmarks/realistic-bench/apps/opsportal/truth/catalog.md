# opsportal site catalog

Internal operations/admin portal for a SaaS company. 24 planted sites (approx. 16-18 vulnerable + 6-8 hardened decoys per seed). Four exemplars are fully implemented (vulnerable + hardened + solver + spec); the remaining 20 are spec-only.

| # | id | class | CWE | severity | entry routes | trigger routes | oracle kinds | lure / decoy realism | status |
|---|----|-------|-----|----------|--------------|----------------|--------------|----------------------|--------|
| 1 | og.graphql-account-bola | graphql_bola | CWE-639 | critical | graphql | graphql | cross_tenant_read | top-level account query is tenant-scoped, but the nested resolver reuses a raw id lookup | twin+solver |
| 2 | og.report-ssti | ssti | CWE-1336 | critical | reportRender | reportRender | template_code_exec | preview accepts a layout string that looks sandboxed to literal substitution only | twin+solver |
| 3 | og.ticket-note-xss | xss_stored | CWE-79 | high | ticketNoteCreate | ticketView | stored_xss_rendered | notes are sanitised for angle brackets on write but the viewer re-expands entities | twin+solver |
| 4 | og.diag-cmdi | command_injection | CWE-78 | critical | diagRun | diagRun | command_injection_simulated | host is length-checked and looks validated, but never character-restricted | twin+solver |
| 5 | og.webhook-ssrf | ssrf | CWE-918 | high | webhookCreate | webhookTest | ssrf_internal_fetch | create blocks obvious internal hosts; the test path re-parses the stored URL loosely | spec-only |
| 6 | og.dashboard-cache-poison | cache_poisoning | CWE-525 | high | dashboard | dashboard | cache_poisoned | cache key includes a team query param that is not bound to the session tenant | spec-only |
| 7 | og.log-path-traversal | path_traversal | CWE-22 | high | logView | logView | path_escape | name is checked for a .log suffix which traversal sequences still satisfy | spec-only |
| 8 | og.saml-xxe | xxe | CWE-611 | high | samlImport | samlImport | xxe_entity_resolved | parser enables entities to support signed metadata includes | spec-only |
| 9 | og.ticket-bola-read | bola | CWE-639 | high | ticketGet | ticketGet | cross_tenant_read | query filters by status but the row is loaded by id before the filter applies | spec-only |
| 10 | og.account-bola-write | idor | CWE-639 | high | accountUpdate | accountUpdate | cross_tenant_write | ownership is asserted from a request field rather than the loaded row | spec-only |
| 11 | og.viewer-bfla | bfla | CWE-285 | high | roleChange | roleChange | privilege_escalation | endpoint checks authentication and a feature flag, but not the actor role | spec-only |
| 12 | og.user-mass-assignment | mass_assignment | CWE-915 | high | userUpdate | userUpdate | mass_assignment | profile patch spreads the whole body over the record including privileged columns | spec-only |
| 13 | og.search-sqli | sqli | CWE-89 | high | searchRun | searchRun | sql_structure_change | input is quote-doubled, but the predicate is concatenated outside the quotes | spec-only |
| 14 | og.api-jwt-forgery | jwt | CWE-347 | high | apiWhoami | apiWhoami | token_forgery | verifier keeps a none fallback for backwards compatibility with old agents | spec-only |
| 15 | og.sso-open-redirect | open_redirect | CWE-601 | medium | ssoCallback | ssoCallback | open_redirect | next is checked to start with a slash, which protocol-relative urls satisfy | spec-only |
| 16 | og.job-csrf | csrf | CWE-352 | medium | jobTrigger | jobTrigger | csrf_state_change | relies on a custom header that browsers attach inconsistently | spec-only |
| 17 | og.integration-secret-disclosure | info_disclosure | CWE-200 | high | integrationList | integrationList | secret_disclosed | secrets are masked in the UI but present in the JSON payload | spec-only |
| 18 | og.log-filter-sqli | sqli | CWE-89 | high | logFilter | logFilter | sql_structure_change | filter grammar looks structured but is spliced verbatim into the query | spec-only |
| 19 | og.account-search-xss | xss_reflected | CWE-79 | medium | accountSearch | accountSearch | reflected_xss_rendered | the echoed term is escaped for attributes but emitted raw in the results banner | spec-only |
| 20 | og.flag-bola | bola | CWE-639 | medium | flagGet | flagGet | cross_tenant_read | flag lookup keys by name only, ignoring the team scope column | spec-only |
| 21 | og.job-workflow-skip | workflow_bypass | CWE-840 | medium | jobComplete | jobComplete | workflow_skip | status is set directly instead of transitioning from the prior state | spec-only |
| 22 | og.backup-webhook-forgery | webhook_forgery | CWE-345 | medium | backupCallback | backupCallback | webhook_forgery | signature compare tolerates an out-of-band computed digest | spec-only |
| 23 | og.ticket-assign-cross-write | idor | CWE-639 | high | ticketAssign | ticketAssign | cross_tenant_write | assignee team is validated but the target ticket team is not | spec-only |
| 24 | og.integration-ssrf-direct | ssrf | CWE-918 | high | integrationFetch | integrationFetch | ssrf_internal_fetch | url is restricted to http scheme but not to an external host allowlist | spec-only |

Chain `escal` (shared mode, critical): og.integration-secret-disclosure (step 1, internal account id) -> og.graphql-account-bola (step 2, nested object access) -> og.viewer-bfla (step 3, role escalation).
