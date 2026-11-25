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

## Third triage round (Phase-B, K=6 in-run workers)

The K=6 cell produced three runtime-confirmed findings that matched no target. All three were
confirmed by the **kovo_verify** transcript path, and all three shared one root cause: the host
classified the claimed impact from the **title string only**, and anything outside the four gated
classes fell to `other`, which skips the impact gate entirely.

| finding | recorded evidence | verdict |
| --- | --- | --- |
| *Invoice workflow step-skip: client PATCH sets status draft->paid without payment* (CWE-841) | owner GET `status=draft` → owner PATCH `{status:paid}` 200 → owner GET `paid` | over-claim: an entitled actor's self-service write of a non-protected field; `status` is editable by design in both twins, and the same endpoint's real bug (cross-tenant write) is already `acme.invoice-write-bola` |
| *Unauthenticated report disclosure via `/api/reports/:id/public`* (CWE-200) | anonymous 404 on a bogus id, anonymous 200 on a real id with `workspace`/`ref` | over-claim: the route is a public share link; every actor (including anonymous) is served the same body, and the planted bug there is cross-tenant cache poisoning (`acme.report-cache-poison`) |
| *Stored HTML injection via unescaped report name in GET /api/reports/:id/render* (CWE-79) | viewer GET of a benign report, viewer GET of a report named `<b>gnmarker</b>` rendered raw | over-claim: inert presentation markup, no executable content and no in-proof planted marker; the hardened SSTI twin renders the name the same way, so this is not a planted behaviour |

Follow-on samples produced two more fingerprints, both fixed by the same principle:

- *Cross-tenant BOLA on `/api/reports/:id/public`* — "another tenant also read the same link" is not
  a boundary: a declared-public route (`/public`, `/share`, `/embed`, …) needs owner-scoped private
  data before a cross-tenant read can confirm.
- *Cross-actor resource read* / *Unauthorized state mutation* on `/api/spaces/:id` — a viewer
  reading or editing a peer's space in its **own tenant** is in policy (tenant is the object
  boundary), and a **cross-tenant** 404 from `persona_b` is tenant isolation working, not a denial
  of the viewer. Denials only count for a peer of the probe (or the mirrored cross-tenant direction).

Verifier changes (product side, `src/server/oracle-invariants.ts`, `verify-rpc.ts`,
`replay-verifier.ts`):

- `classifyImpactDescriptor` now maps business-logic/workflow (CWE-840/841/472), markup
  (CWE-79/80/83) and disclosure (CWE-200/359/522/532) instead of `other`, and `verify-rpc` classifies
  from title **and** description.
- `assessBusinessLogicImpact`: boundary differential, repeated terminal transition, persisted
  protected-field change, or a declared invariant event; the delta must reflect a value *this* probe
  sent (K=6 cross-talk), and a same-tenant self-service change is in policy.
- `assessMarkupImpact`: executable markup or a nonce marker planted inside the same proof.
- Disclosure uses the authorization read path (pre-redaction credential fingerprints count);
  same-tenant, same-role reads need private/secret data, not just an owner field.
- `expectControlDenied: false` no longer disables the access boundary gate; the transcript records a
  host-signed persona role label and impact steps ignore script-supplied role/tenant labels; a
  declared oracle event is a requirement, never a substitute for a missing differential.

No truth changes: none of the behaviours is a planted target, and the real bugs on those endpoints
(cross-tenant invoice write, cross-tenant report cache) are already covered.

## Fourth triage round (K=6 run 2): tenant_id overpost reported as BOLA

`9cebbab5…` — *"Mass assignment of tenant_id on POST /api/spaces plants attacker-controlled objects
inside another tenant"* — CWE-639 / broken-access-control, runtime-confirmed, charged as unmatched.

**The app is genuinely vulnerable**: `POST /api/{projects}` merges the request body after defaulting
`tenant_id` from the session, so an attacker-created space lands in the victim tenant (victim list
gains the record and can read it; the attacker then gets `404` on its own object). The impact oracle
confirms it (`mass_assignment` events) and the behaviour is exactly `acme.project-mass-assign`
(`mass_assignment`, CWE-915) — the run's *other* finding on that endpoint was already the TP.

So this is a **mislabeled class of a planted target**, not a grader gap and not a new bug. The
canonical label is mass assignment (a protected identity field persisted from the request body), not
BOLA/CWE-639; `bola ↔ mass_assignment` is deliberately **not** on the sibling allowlist, and widening
it would excuse genuinely wrong labels. The fix is evidence-first labelling in the engine:

- `replay-verifier` computes the impact class *evidence-first*: a create-time overpost that persists
  a protected body field is mass assignment regardless of the model's title/CWE, and the gate runs on
  that class; the evidence payload records `evidenceClass` when the gate is satisfied.
- on confirmation, `execution` aligns the persisted finding's CWE/category with the verified
  evidence class (mass assignment → CWE-915; csrf/markup/disclosure/business-logic likewise;
  authorization/BFLA never relabel; an already in-family label is left untouched).

No truth change; the target already existed. After the fix the finding matches
`acme.project-mass-assign` as a duplicate of the confirmed TP.

## Fifth triage round (K=6 rerun): report-name and SPA-sink XSS claims

Two further runtime-confirmed XSS claims carried no target endpoint:

- *Stored XSS via report name in `GET /api/reports/:id/render`* (CWE-79) — the vulnerable and hardened
  **SSTI twins both** interpolated `row.name` into `<h2>` without escaping. Unlike the safe default
  (`htmlEscape(row.name)`), that made unescaped markup a uniform twin defect rather than a planted
  site, and the impact oracle only models stored XSS on `renderProjectCard` (no event here).
- *Stored HTML injection into an innerHTML sink* (CWE-79) — `ui/views.js` assigned
  `p.description` to `innerHTML`, so the SPA sink stayed live even on a seed where the server-rendered
  project card is the hardened twin. The planted target is the server-side card, not the SPA.

Both are **fixture defects, not missing targets**: adding truth would either make the hardened twin
unsound (report name) or duplicate the planted card target through a UI path the oracle does not
model. Hardened the fixture instead:

- `sites/acme.report-ssti/{vulnerable,hardened}.ts`: escape the report name in `<h2>` (matching the
  safe default). The planted SSTI vector (the stored *template* body evaluated at render) is
  unchanged.
- `ui/views.js`: project descriptions are assigned with `textContent`; the SPA no longer interprets
  tenant-authored data as HTML. The server-rendered card target (`acme.project-stored-xss`) is
  unchanged and still fires on its vulnerable twin.

No truth changes.

## Sixth triage round (45-min K=6): negative invoice amount

`fda9fd1f…` — *"Invoice amount accepts negative values (price-invariant violation)"* — CWE-915 /
mass assignment, runtime-confirmed, charged as unmatched. The replay spec creates one invoice as the
owner with `amount=777` (control) and another with `amount=-777` (probe), then reads both back in the
same tenant: the negative value persists (`-777`), the creator gets `404` on nothing (it is its own
invoice) and there is **no oracle event** (the lab's `invariant_violation` monitor covers tenant
seats/credits and plan price, not invoice amounts).

The app really does store the value — but "invoice amount must be non-negative" is an *invented*
business rule: `createInvoice`/`updateInvoice` accept any amount in both twins (the safe default and
the BOLA twin), so it is in policy, not a planted invariant. It is also not the cross-tenant invoice
target (`acme.invoice-write-bola`, confirmed separately with oracle events on the same endpoint) and
must not be attributed to it by class or scope. **Over-claim; no truth change.**

Verifier fix (shared oracle invariants): a create-shaped probe that persists a caller-chosen
**price/amount-only** value is not an invariant violation or a mass-assigned entitlement. Both the
business-logic and mass-assignment gates now require the endpoint's declared invariant event
(`invariant_violation`/`workflow_skip`/`race_double_spend`) for that shape; a same-resource control
mutation still proves the planted plan-price/credits/seats cases (billing-tamper stays confirmed).
A declared invariant event still confirms the negative-amount shape, so a future planted invoice
invariant would be detectable.

## Seventh triage round (45-min rerun): cross-tenant framing and legacy search

Two further 45-min findings were charged unmatched:

- *"Cross-tenant write BOLA: persona_b tampers tenant f6e944 invoice amount"* (CWE-840) — the planted
  `acme.invoice-write-bola` behaviour, framed as business logic because the mutated field is an
  amount. Cross-tenant evidence is object-level authorization: the verifier now labels a
  business-logic/authorization proof whose *probe* actor sits outside the tenant that read the same
  route as `bola` (CWE-639), and `execution` aligns the persisted finding. In-tenant amount edits
  (billing price, duplicate charges) keep their business-logic label.
- *"Legacy /api/v1/search serves tenant data to unauthenticated users"* (CWE-306) — both
  `reflected-search-xss` twins queried **all tenants' projects** without auth scoping, a uniform twin
  defect (the planted bug is the reflected XSS in the empty-state). Hardened the twins: anonymous
  callers get the empty state and matches are scoped to the caller's tenant, while the vulnerable
  twin still reflects the term unescaped (the solver is anonymous and only needs the empty state).

No truth changes.

