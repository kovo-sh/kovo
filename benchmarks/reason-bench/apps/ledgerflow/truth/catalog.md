# ledgerflow shell contract

## Auth model
- Session cookie `lf_sid`, issued by `POST login`; identity is `{ persona, tenant, role, userExtId, email }`.
- Every mutating area route resolves the caller's **current** role from `memberships` (falling back to
  `users.role`) inside the request tenant. Role ranks: viewer 0, member 1, admin 2, owner 3.
- All reads/writes are tenant-scoped with `tenant_id = <session tenant>`.
- Bearer tokens are hashed into `user_tokens`; `revoked_tokens` is external policy state.
- Webhooks carry no session; they are authenticated by the delivery HMAC over
  `${ts}.${tenantId}.${eventType}.${payload}`.

## Route keys (site modules register these)
| Area | Route keys |
| --- | --- |
| auth | `login`, `logout`, `me`, `ssoStart`, `ssoCallback`, `requestPasswordReset`, `changeEmail`, `updateRole` |
| invoices | `listInvoices`, `getInvoice`, `createInvoice`, `updateInvoice`, `deleteInvoice`, `previewInvoice`, `exportInvoicePdf` |
| orders/cart | `listOrders`, `getOrder`, `updateOrder`, `refundOrderItem`, `listCarts`, `getCart`, `addCartItem`, `patchCartItem`, `deleteCartItem`, `applyCoupon`, `checkoutCart`, `listCoupons` |
| wallets | `listWallets`, `convertWallet`, `listTransfers`, `transferFunds`, `createPayout`, `listPayouts`, `updatePayout`, `approvePayout`, `listApprovals`, `delegateApproval` |
| plans | `getSubscription`, `upgradePlan`, `downgradePlan` |
| team | `listMembers`, `updateRole`, `removeMember`, `listInvites`, `inviteMember`, `downgradeInvite`, `acceptInvite`, `activityFeed` |
| ops | `listExports`, `queueExport`, `downloadExport`, `signedDownload`, `listFiles`, `downloadFile`, `uploadFile`, `receiveWebhook` |
| payments | `createPaymentIntent`, `getPaymentIntent`, `capturePaymentIntent` |

A mounted site module is a single file default-exporting `register(app)`; it owns its entry route keys
and is mounted before the common area modules, so it overrides the safe default. `rootCause.file` must
be `<subdir>/<name>.ts` and materializes to `src/<subdir>/<name>.ts`.

## Schema (all monetary integers)
`tenants`, `plans`, `subscriptions(granted_credits,used_credits)`, `users`, `memberships`,
`user_tokens`, `revoked_tokens`, `invoices`, `carts`, `cart_items`, `coupons`,
`orders`, `order_items`, `refunds`, `wallets(balance_micros,rate_to_base_micros)`, `wallet_entries`,
`transfers(fee_micros,rebate_micros)`, `payouts`, `payout_audit` (shadow maker identity),
`invites`, `exports(creator_id,creator_role)`, `payment_intents`, `webhook_endpoints`,
`webhook_events`, `sso_accounts(pending_email,verified)`, `files` (VFS metadata), `activity`,
`approvals`, `auth_events`.

Canaries: tenant records carry `rbc_<tag>_<hex>`; internal files carry `rbs_<tag>_<hex>`; all secrets
are synthetic `rb_fake_*`.

## Monitor set (`truth/monitors.ts`)
| Check | Event kind |
| --- | --- |
| refunds > paid, underpaid fulfilment, coupon below minimum, wallet value increase/negative/unbalanced, promotion > fee, unearned plan refund | `economic_invariant_violation` |
| payout approved by the shadow-table original maker | `self_approval_bypass` |
| 2xx request carrying a token hash in `revoked_tokens` | `revoked_token_used` |
| export download / delegation / invite redemption below the actor's current role | `stale_privilege_use` |
| SSO session issued from `pending_email` or a foreign `tid` | `sso_tenant_confusion` |
| same signature accepted under two tenant/event scopes | `hmac_scope_replay` |
| signed VFS path outside `/exports/<tenant>/` | `signed_url_prefix_escape` |
| duplicate-key role escalation (`admin` + low role in one request) | `parser_differential_bypass` |
| other-tenant canary on a repeated route/actor path | `cache_tenant_bleed` |
| audit row written outside the caller tenant / two foreign tenants in one request | `cross_tenant_write`, `batch_partial_authz_bypass` |
| transfer between tenants without admin on the source | `cross_org_transfer` |

The payout shadow trigger and all audit triggers are installed from `truth/`, never from `src/`.
Monitors opportunistically consume `lib/policy-oracle.ts` (`install`, `evaluate`) and
`lib/hmac.ts` (`verifyScoped`) when those exports exist; built-in checks are authoritative.
