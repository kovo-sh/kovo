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
| invite a member, delete a member, update a member's role | owner / admin (owner for role + delete) |
| revoke/create API keys, manage webhooks | owner |
| change the tenant plan (`updatePlan`), add seats, impersonate | owner |
| admin surface (`/api/admin/**`) | admin / owner |
| read/list/write tenant content, read own profile, list keys | any authenticated member |

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
