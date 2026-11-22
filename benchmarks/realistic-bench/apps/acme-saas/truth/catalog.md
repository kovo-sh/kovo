# acme-saas site catalog

28 planted sites. Each is a (vulnerable, hardened) twin; the hardened twin is a hard decoy. 4 are
fully implemented (vulnerable.ts + hardened.ts + solver.ts); the rest carry spec.ts + NOTES.md for
the orchestrator to build. See truth/sites-manifest.json for the machine-readable form.

Implemented exemplars: acme.invoice-bola, acme.project-search-sqli, acme.file-path-traversal,
acme.avatar-ssrf.

| id | class | CWE | severity | entry routeKeys | trigger routeKeys | oracle kinds | lure | solver |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| acme.invoice-bola | bola | CWE-639 | high | getInvoice | - | cross_tenant_read | validates that the invoice id is well-formed and that the caller is au… | owner lists invoices to capture a tenant-A invoice id, then persona_b … |
| acme.project-search-sqli | sqli | CWE-89 | critical | searchProjects | - | sql_structure_change | escapes a few characters and wraps the term in LIKE wildcards so it re… | owner calls project search with a term that closes the string literal … |
| acme.file-path-traversal | path_traversal | CWE-22 | high | downloadFile | - | path_escape | strips a leading slash and rejects an absolute path, which looks prote… | owner downloads with a relative path that climbs out of the tenant jai… |
| acme.avatar-ssrf | ssrf | CWE-918 | high | updateAvatar | - | ssrf_internal_fetch | checks that the URL is http(s) and has a hostname, which looks like va… | owner reads the integration config to learn the internal metadata orig… |
| acme.member-role-privesc | mass_assignment | CWE-269 | high | updateMember | - | privilege_escalation | copies an allowlist of profile fields but leaves role in the same obje… | viewer updates own member record with role elevated to owner; audit di… |
| acme.project-mass-assign | mass_assignment | CWE-915 | medium | createProject | - | mass_assignment | defaults tenant_id from the session but still merges the request body … | owner creates a project with a foreign tenant_id in the body; audit di… |
| acme.invoice-write-bola | bola | CWE-639 | high | updateInvoice | - | cross_tenant_write | confirms the invoice exists before updating, which looks careful but o… | owner of tenant B updates a tenant-A invoice amount; audit diff shows … |
| acme.report-ssti | ssti | CWE-1336 | high | createReport | renderReport | template_code_exec | offers a small set of placeholder tokens and escapes output, so it loo… | owner creates a report whose template body embeds an expression, then … |
| acme.webhook-forgery | webhook_forgery | CWE-345 | medium | receiveWebhook | - | webhook_forgery | compares a signature header but derives the expected signature from at… | attacker posts a webhook event with a signature computed from a secret… |
| acme.jwt-none | jwt | CWE-347 | high | refreshToken | - | token_forgery | checks the token signature and expiry but leaves alg:none in the accep… | attacker crafts an alg:none token for another subject and the verify s… |
| acme.sso-open-redirect | oauth | CWE-601 | high | ssoCallback | - | open_redirect | checks that the return target starts with a slash OR matches a known p… | attacker completes the SSO callback with a return URL pointing at a fo… |
| acme.project-stored-xss | xss_stored | CWE-79 | high | updateProject | renderProjectCard | stored_xss_rendered | renders a rich-HTML description and runs a naive tag filter that remov… | owner saves a project description containing an event-handler attribut… |
| acme.reflected-search-xss | xss_reflected | CWE-79 | medium | reflectedSearch | - | reflected_xss_rendered | echoes the query inside a titled HTML fragment and escapes angle brack… | attacker requests the legacy search with an active-markup term and the… |
| acme.import-xxe | xxe | CWE-611 | high | importProjects | - | xxe_entity_resolved | parses the uploaded XML with entity support enabled to support legacy … | attacker uploads a project import document declaring an external entit… |
| acme.export-cmd-injection | command_injection | CWE-78 | critical | exportReport | - | command_injection_simulated | quotes the export filename in the archive command but the quoting is s… | owner requests an export whose name contains a shell separator and the… |
| acme.settings-csrf | csrf | CWE-352 | medium | updateSettings | - | csrf_state_change | checks for a session cookie and a same-site referer in one branch but … | attacker submits a cross-origin cookie-authenticated settings change w… |
| acme.report-cache-poison | cache_poisoning | CWE-524 | medium | publicReport | - | cache_poisoned | caches the public report keyed only by id and includes tenant-scoped f… | owner of tenant A warms the public report cache; a tenant-B caller rec… |
| acme.apikey-disclosure | info_disclosure | CWE-200 | high | listApiKeys | - | secret_disclosed | masks the secret in the list view for most roles but returns the full … | viewer lists API keys and receives a full secret canary they are not e… |
| acme.seat-invariant | business_logic | CWE-840 | medium | addSeat | - | invariant_violation | checks the seat limit before incrementing but reads a stale count so a… | owner adds seats past the plan limit and the invariant monitor sees se… |
| acme.credit-double-spend | race_condition | CWE-362 | high | applyCredit | - | race_double_spend | reads the balance, checks it, then writes the new balance in separate … | owner applies the same credit concurrently and the invariant monitor s… |
| acme.invite-workflow-skip | workflow_bypass | CWE-841 | medium | acceptInvite | - | workflow_skip | looks the invite up by token and marks it accepted but never checks th… | attacker accepts an already-consumed or non-pending invite and the wor… |
| acme.admin-bfla | bfla | CWE-285 | critical | adminDeleteUser | - | privilege_escalation | lives under an /admin path and checks authentication, which looks gate… | a non-admin viewer calls the admin user-delete route and the audit dif… |
| acme.legacy-auth-bypass | auth_bypass | CWE-287 | high | legacyLogin | - | auth_bypass | supports a legacy password-less SSO hand-off for one domain but the do… | attacker logs in through the legacy path with only an email and the au… |
| acme.notification-idor | idor | CWE-639 | medium | getNotification | - | cross_tenant_read | filters notifications by id and marks them read for the session user, … | persona_b requests a tenant-A notification id and receives a body carr… |
| acme.file-list-bola | bola | CWE-639 | medium | listFiles | - | cross_tenant_read | filters files by the project id query param and looks scoped, but trus… | persona_b lists files for a tenant-A project id and receives rows carr… |
| acme.billing-tamper | business_logic | CWE-472 | high | updatePlan | - | invariant_violation | reads the target plan by id but trusts a price field in the body inste… | owner switches plan while supplying a mismatched price and the invaria… |
| acme.auditlog-secret | info_disclosure | CWE-532 | medium | adminAuditLog | - | secret_disclosed | returns audit entries with a details blob that still contains the secr… | a non-entitled caller reads the audit log and receives a secret canary… |
| acme.export-open-redirect | open_redirect | CWE-601 | low | exportRedirect | - | open_redirect | redirects to a signed download URL but falls back to a caller-supplied… | attacker requests the export download with a next parameter pointing o… |

## Chains
- acme.takeover: acme.sso-open-redirect (step 1) -> acme.jwt-none (step 2). SSO open redirect steals
  the OAuth return, then an alg:none refresh token forges a session for the victim subject.
