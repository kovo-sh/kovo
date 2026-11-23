# acme-saas authorization & impact policy

Machine-readable truth lives in `blueprint.ts` (sites), `monitors.ts` (impact events) and
`sites-manifest.json`. This note records the **authorization model** the app deliberately implements,
so a claim that sits outside the planted sites can be triaged without guessing, and so the impact
oracle is not extended to cover in-policy behaviour.

## Object boundary: the tenant

Every content table (`projects`, `invoices`, `files`, `reports`, `notifications`) is scoped by
`tenant_id`. Route handlers resolve the caller's tenant from the session (or a bearer identity) and
match it against the row before any read or write; a foreign-tenant id answers `404`. There is no
per-row ownership model: `projects.owner_id` is empty for seeded rows and `projects.visibility`
(`private`/`internal`) is presentation metadata that no handler consults for authorization. A
same-tenant member acting on another member's space is therefore **in policy**, not BOLA.

Two API-hygiene quirks are intentional and are not vulnerabilities:

- `DELETE /api/{projects}/:id` for a foreign-tenant id answers `200` but deletes nothing (the
  statement is confined by `tenant_id`). The row stays readable; the status is idempotent, not an
  authorization bypass.
- `PATCH /api/{plans}/current` with no plan code defaults to the `free` tier. The caller switches
  only its own tenant; nothing else is affected.

## Role gates

Roles rank `viewer < member < admin < owner`. The app gates **function-level** actions, not content:

| action | required role |
| --- | --- |
| invite a member | owner / admin |
| remove a member, create/revoke API keys, create a webhook, change the tenant plan, add seats, impersonate | owner |
| admin surface (`/api/admin/**`) | admin / owner |
| update a member profile (`updateMember`, `updateAvatar`), delete a webhook | any authenticated member; `role` is silently ignored for non-owners |
| read/list/write tenant content, apply credit to the own tenant, read own profile, list keys | any authenticated member |

Content writes by a `viewer` are therefore in policy (the UI advertises `updateProject`,
`createInvoice`, … to every signed-in user). The planted vertical-BFLA target is
`acme.admin-bfla` (an admin route with no role check), and the planted role-escalation target is
`acme.member-role-privesc` (a viewer writing `role`); neither is "a viewer edited content".

## Plan price is catalog-authoritative

`acme.billing-tamper` owns `updatePlan`. The hardened twin always writes the catalog price and
ignores `price`/`amount`/`seat_limit`/`credits` from the body; the vulnerable twin persists the
caller price (`invariant_violation`, `kind: plan_price`). Consequences for triage:

- An owner switching plans (including to `free`, whose catalog price is `0`) is a self-service plan
  change. The response `price` is the **catalog** price of the chosen tier; it is not evidence that a
  body field was persisted.
- A plan downgrade can leave `seats_used` above the new tier's limit. That is the owner's own
  downgrade, not the seat invariant: `monitors.ts` only raises the seats `invariant_violation` when
  `seats_used` itself is mutated, so a plan change can never borrow `acme.billing-tamper`'s
  `(invariant_violation, updatePlan)` attribution pair.

## Triage record (acme seed 1 agentic cell)

Seed 1 mounts `acme.billing-tamper` as a **hardened decoy**; `acme.seat-invariant` and
`acme.admin-bfla` are vulnerable targets.

1. *"Vertical BFLA: read-only viewer can PATCH/DELETE another user's private space"* (CWE-285,
   `/api/{projects}/:id`) — **agentic over-claim**. Same-tenant content write is in policy; the
   chain's target id is a seeded workspace whose `owner_id` is empty (no owner to violate), and the
   engine's own first chain carried a cross-tenant control that was correctly denied (`404`) before it
   re-submitted a chain without it. No privilege gain, no ownership violation, no oracle event.
   Verifier gaps: vertical-BFLA impact is satisfied by any 2xx mutation without a role or ownership
   reference, and a denied control (`404`) is treated as a spec error (`requireControlNonError`)
   rather than as disproof, which pushes the agent to drop the strongest control.
2. *"Mass assignment on PATCH /api/{plans}/current: org owner can rewrite privileged price/plan"*
   (CWE-915) — **agentic over-claim**. The probe switched the tenant to `free` and sent `price=0`;
   `free`'s catalog price is `0`, the plans row was untouched, and the chain's own assertion required
   only `control 403 + probe 200 + "ok":true`. `owner` outranks `admin` in this app, so the
   `admin`-reads-the-result step is not a privilege differential at all.
   Verifier gaps: no protected-field persistence proof, no oracle requirement for plan-price claims,
   and no role hierarchy (it cannot tell that `owner` is the highest role).

3. *"CSRF: state-changing API accepts cross-origin text/plain requests"* (CWE-352, observed on
   `POST /api/{projects}` in a later sample) — **agentic over-claim**. The session cookie is issued
   `SameSite=Lax`, so a cross-site form POST does not carry `acme_sid`; the replay broker attached the
   cookie regardless of the foreign `Origin`, which is not a browser-reachable request. The modelled
   CSRF target is `acme.settings-csrf` (`updateSettings`): it is the only route with a
   `csrf_state_change` oracle, and the only one carrying a form token in its hardened twin. A
   token-less write on any other route has no impact event and lies outside the planted site.
   Verifier gap: a CSRF claim is confirmed from "anonymous control denied + cookie-authenticated
   cross-origin probe accepted" without consulting the cookie's SameSite policy (or bearer auth) and
   without requiring the endpoint's `csrf_state_change` impact event.

None of these claims adds truth: the app does not implement the behaviour, so a target would inflate
recall. Each one is a verifier-side gap (see the bullets above), owned by `src/server/replay-verifier.ts`.

## Second triage round (post v6-verifier-harden)

4. *"Two-factor (OTP) verification accepts any/absent code — 2FA bypass"* (CWE-287,
   `POST /api/auth/2fa`) — **agentic over-claim (non-impactful evidence)**, with a genuine latent
   weakness behind it. `twofaVerify` does not check the code, but **no session is ever in a
   2FA-pending state**: `doLogin` always calls `identityForUser(u, false)`, so a password login is
   already fully authorised and the verify call changes nothing (`twofaPending` is `false` before and
   after; no session, role or data delta; no oracle event). The real deficiency is that
   `users.twofa_enabled` (set for `persona_a`) is never enforced — a password-only login is enough —
   but that is **not modelled as a target**: enforcing it at `login` would put every `persona_a`
   solver and every engine cell into a pending state (login is shared by the whole lab and the harness
   has no second-factor step), and an oracle event keyed to `login` would be triggered by any
   ordinary login, i.e. truth inflation. Deterministic probe: password login → `GET /api/me` 200 and
   an owner-only read 200 *before* any challenge; `POST /api/auth/2fa` with a wrong code or an empty
   body → `{ok:true}` with the same 200 afterwards; anonymous → 401; zero oracle events.
   Verifier gap: `auth_protocol_proof` (`src/server/replay-verifier.ts`) and its schema
   (`src/replay-spec.ts:594`) have no second-factor state gate (enrolled account, verifier session
   pending before the probe, access denied before verification and granted after it) and no `mfa`
   protocol; it confirms on `anon 401 / authed 200 {ok:true}` alone.

5. *"Missing vertical role check on `/api/admin/activity` exposes rotated org secret to read-only
   viewer"* (CWE-863, `open_proof_gap`) — **real endpoint, wrong label, unproven claim: charged as an
   FP**. The endpoint is the `adminAuditLog` route owned by the vulnerable `acme.auditlog-secret`
   target (seed 1 mounts it vulnerable): a viewer reads the admin activity log and the response
   carries the tenant secret canary, while `/admin/orgs`, `/admin/orgs/:id` and `PATCH
   /billing/current` are `403` for the same viewer. The claim is labelled `bfla`/CWE-863 (authz
   family) against the entry's `info_disclosure`/CWE-532 (disclosure family) and the verifier declined
   to confirm the BFLA framing. Under the reviewer-approved grader policy an **unverified** claim is a
   contract leak and stays an FP, even on a documented sibling pair; it is also counted in
   `incompatibleClassCount`, which must be `0` for Phase-1. The engine-side fix is to confirm the
   disclosure class (the oracle fires on that request) or drop the unproven note — not to widen truth.

### Grader policy for incompatible classes (reviewer-steered)

`incompatibleClassCount` counts every active finding that hits a planted vulnerable entry's endpoint
without a class-compatible match (any status, any label). An incompatible claim is left *uncharged*
only when it is runtime-confirmed **and** the labels are a documented close-sibling pair
(`bola ↔ idor ↔ bfla ↔ graphql_bola`, `mass_assignment ↔ bfla`, `mass_assignment ↔ business_logic`,
`business_logic ↔ race_condition`, `info_disclosure ↔ bfla`). It never earns recall, it still enters
`strictPrecision = TP / (TP + FP + misclassified)`, and Phase-1 requires `incompatibleClassCount === 0`.
Non-sibling labels and every `static_verified`/`proposed`/`open_proof_gap` claim stay FPs.
