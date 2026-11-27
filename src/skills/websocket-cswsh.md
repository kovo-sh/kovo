# WebSocket Security & Cross-Site WebSocket Hijacking (CSWSH)
Tags: websocket, cswsh, origin, csrf, realtime, authz, socket, streaming
Summary: Audit WebSocket handshakes, Origin header validation, session/token authentication, and per-message channel authorization using Kovo’s brokered probe_websocket tool and kovo_verify checks.

## 1. High-Risk WebSocket Attack Surfaces
Map WebSocket servers and gateways in `/repos` (`ws`, `socket.io`, NestJS `@WebSocketGateway`, FastAPI `@app.websocket`, Django Channels, Rails ActionCable, Go `gorilla/websocket`) via `run_sast_scan` and `derive_evidence`:
1. **Cross-Site WebSocket Hijacking (CSWSH):**
   - Browsers do NOT enforce Same-Origin Policy on WebSocket upgrade handshakes and automatically attach cookies (`SameSite=None` or lax-downgraded) to `Upgrade: websocket` requests.
   - Check whether the server strictly validates the HTTP `Origin` header against an exact allowlist (rejecting missing/untrusted origins and avoiding weak `.includes()` or `origin.startsWith()` checks) or requires an unguessable per-session CSRF/ticket token outside cookies.
   - Watch for `gorilla/websocket` `CheckOrigin: func(r *http.Request) bool { return true }`, `socket.io` `cors: { origin: '*' }`, or Rails `disable_request_forgery_protection = true`.
2. **Missing Handshake Authentication:** Verify unauthenticated clients cannot upgrade to private channels or receive broadcast events.
3. **Missing Per-Message & Channel-Subscription Authorization (WS BOLA):**
   - Even when the initial handshake validates a session, verify every `subscribe`, `join_room`, or RPC message validates that the authenticated user is authorized for the requested `roomId`, `tenantId`, or `channelId`!
4. **Session Revocation & Frame Input Validation:** Verify token expiry/logout invalidates active socket privileges and message payloads are schema-validated before DB/DOM sinks.

## 2. Safe Brokered Testing (`probe_websocket`)
Kovo’s `probe_websocket` routes 100% through `RequestBroker` with strict scope checks, DNS/IP validation, direct-IP TLS, secret redaction, and hard limits (max 10 frames / 64 KiB / 10s lifetime):
1. **Control 1 (Same-Origin Authenticated):** Connect with `persona: "user_a"` and approved same-origin header; observe normal upgrade and authorized event/response.
2. **Control 2 (Unauthenticated):** Connect without a persona; verify private endpoints reject (`401`/`403` or close frame).
3. **Probe A (CSWSH Origin Check):** Connect with `persona: "user_a"` and `spoofOrigin: "https://evil.invalid"`. If upgrade succeeds (`101`) AND returns authenticated data or accepts privileged commands identically to Control 1, CSWSH is demonstrated.
4. **Probe B (Cross-Tenant Subscription):** Connect with `persona: "user_b"` and send a benign read-only subscribe/query message referencing `user_a`'s room/resource ID.

## 3. Closure & `kovo_verify` Discipline
- Confirm HTTP-layer handshake/upgrade origin-validation or WebSocket token-minting boundary flaws via `kovo_verify` (`ctx.prove_access_boundary` or `ctx.http` with clean same-origin control vs spoofed `Origin` probe + `ctx.expect.status` / `ctx.expect.header`, or `ctx.seal_capability` + `ctx.prove_composite` for token->channel chains), finishing with `return ctx.result({ title })`; capture socket frame evidence with `probe_websocket`.
- Close protected endpoints via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line of Origin/authz check or exchangeId>"`).
