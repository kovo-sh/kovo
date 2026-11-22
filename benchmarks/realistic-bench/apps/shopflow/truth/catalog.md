# shopflow site catalog

Multi-tenant e-commerce / payments platform. 26 planted sites; 6-8 hardened decoys per seed
(`decoyCount {min:6,max:8}`). Keystones `canBeDecoy:false`: payment-webhook-forgery,
checkout-workflow-skip, admin-impersonate-privesc. Chain `promo-chain`: coupon-after-lock (1),
over-refund-chain (2). Implemented exemplars marked ✓.

| ✓ | id | class | CWE | sev | entry routes | trigger routes | oracle (kind@routeKey) | lure |
|---|----|-------|-----|-----|--------------|----------------|------------------------|------|
|  | order-bola-read | bola | CWE-639 | high | getOrder | getOrder | cross_tenant_read@getOrder | scopes the query by a store header that looks authoritative but is caller-supplied |
|  | shipment-bola-write | bola | CWE-639 | high | updateShipment | updateShipment | cross_tenant_write@updateShipment | checks that the shipment exists before writing but never rechecks ownership |
|  | product-search-sqli | sqli | CWE-89 | high | searchProducts | searchProducts | sql_structure_change@searchProducts | escapes single quotes by doubling but still concatenates the LIKE clause |
|  | invoice-path-traversal | path_traversal | CWE-22 | high | getInvoice | getInvoice | path_escape@getInvoice | strips a leading slash from the filename, which does not stop ../ sequences |
|  | product-image-ssrf | ssrf | CWE-918 | high | importProductImage | importProductImage | ssrf_internal_fetch@importProductImage | blocks obvious metadata hostnames but follows the fetched redirect |
|  | checkout-open-redirect | open_redirect | CWE-601 | medium | checkoutReturn | checkoutReturn | open_redirect@checkoutReturn | allowlists a prefix match that a foreign host can spoof as a subdomain |
|  | review-stored-xss | xss_stored | CWE-79 | high | submitReview | moderationQueue | stored_xss_rendered@moderationQueue | sanitizes on submit yet renders stored rich HTML verbatim in moderation |
|  | order-mass-assignment | mass_assignment | CWE-915 | high | updateOrder | updateOrder | mass_assignment@updateOrder | whitelists note and tags but spreads the rest of the body into the row |
|  | api-jwt-alg-none | jwt | CWE-347 | high | salesReport | salesReport | token_forgery@salesReport | verifies the signature but leaves the alg list open to unsigned tokens |
|  | refund-csrf | csrf | CWE-352 | medium | createRefund | createRefund | csrf_state_change@createRefund | accepts a token field but never compares it to the session token |
|  | negative-qty-logic | business_logic | CWE-840 | medium | addCartItem | addCartItem | invariant_violation@addCartItem | rejects zero quantity but lets negatives through to offset the total |
|  | storefront-cache-poison | cache_poisoning | CWE-525 | medium | storeProductPage | storeProductPage | cache_poisoned@storeProductPage | caches by path only while echoing a per-viewer store header into the body |
| ✓ | giftcard-race | race_condition | CWE-362 | high | redeemGiftCard | redeemGiftCard | race_double_spend@redeemGiftCard | reads the balance and writes it back with a check-then-act gap under load |
| ✓ | payment-webhook-forgery | webhook_forgery | CWE-345 | critical | paymentWebhook | paymentWebhook | webhook_forgery@paymentWebhook | verifies an HMAC but against a shared test-mode secret anyone can compute |
| ✓ | product-feed-xxe | xxe | CWE-611 | high | importProductFeed | importProductFeed | xxe_entity_resolved@importProductFeed | parses the feed with entity expansion left enabled for legacy suppliers |
| ✓ | checkout-workflow-skip | workflow_bypass | CWE-840 | critical | confirmOrder | confirmOrder | workflow_skip@confirmOrder | confirms the order and only then kicks off an async capture that may never run |
|  | coupon-reuse | business_logic | CWE-840 | medium | applyCoupon | applyCoupon | invariant_violation@applyCoupon | marks the coupon used after applying, so a retry slips in a second use |
|  | inventory-oversell | race_condition | CWE-362 | high | checkout | checkout | race_double_spend@checkout | reserves stock with a read then write that interleaves under concurrency |
|  | refund-exceeds-payment | business_logic | CWE-840 | high | approveRefund | approveRefund | invariant_violation@approveRefund | caps each refund at the order total but ignores prior partial refunds |
|  | token-secret-disclosure | info_disclosure | CWE-200 | high | listTokens | listTokens | secret_disclosed@listTokens | returns a masked preview that still includes the full secret in a sibling field |
|  | customer-bola-read | bola | CWE-639 | medium | getCustomer | getCustomer | cross_tenant_read@getCustomer | filters the list endpoint by store but not the single-record endpoint |
|  | admin-impersonate-privesc | bfla | CWE-269 | critical | adminImpersonate | adminImpersonate | privilege_escalation@adminImpersonate | guards the route by login but not by the staff role it assumes |
|  | settings-secret-disclosure | info_disclosure | CWE-200 | medium | getSettings | getSettings | secret_disclosed@getSettings | returns provider keys to any signed-in role rather than owners only |
|  | shipping-label-ssrf | ssrf | CWE-918 | medium | importShippingLabel | importShippingLabel | ssrf_internal_fetch@importShippingLabel | fetches a label template URL from the manifest without host checks |
|  | coupon-after-lock | workflow_bypass | CWE-840 | high | applyCoupon | applyCoupon | workflow_skip@applyCoupon | lets a coupon apply even once the cart has moved past the pricing lock |
|  | over-refund-chain | business_logic | CWE-840 | high | createRefund | createRefund | invariant_violation@createRefund | refunds against the discounted total, turning the stacked promo into cash |

## Solver approach (per site)

- **order-bola-read** (billing/order-access.ts :: loadOrder): drive getOrder; impact proven by cross_tenant_read @ getOrder.
- **shipment-bola-write** (fulfillment/shipment-update.ts :: updateShipment): drive updateShipment; impact proven by cross_tenant_write @ updateShipment.
- **product-search-sqli** (catalog/product-search.ts :: searchProducts): drive searchProducts; impact proven by sql_structure_change @ searchProducts.
- **invoice-path-traversal** (billing/invoice-export.ts :: exportInvoice): drive getInvoice; impact proven by path_escape @ getInvoice.
- **product-image-ssrf** (catalog/image-fetch.ts :: fetchImage): drive importProductImage; impact proven by ssrf_internal_fetch @ importProductImage.
- **checkout-open-redirect** (checkout/return-handler.ts :: handleReturn): drive checkoutReturn; impact proven by open_redirect @ checkoutReturn.
- **review-stored-xss** (reviews/review-render.ts :: renderReview): drive submitReview; impact proven by stored_xss_rendered @ moderationQueue.
- **order-mass-assignment** (billing/order-update.ts :: updateOrder): drive updateOrder; impact proven by mass_assignment @ updateOrder.
- **api-jwt-alg-none** (identity/api-auth.ts :: authorizeReport): drive salesReport; impact proven by token_forgery @ salesReport.
- **refund-csrf** (billing/refund-create.ts :: createRefund): drive createRefund; impact proven by csrf_state_change @ createRefund.
- **negative-qty-logic** (checkout/cart-items.ts :: addItem): drive addCartItem; impact proven by invariant_violation @ addCartItem.
- **storefront-cache-poison** (catalog/store-page.ts :: renderStorePage): drive storeProductPage; impact proven by cache_poisoned @ storeProductPage.
- **giftcard-race** (billing/giftcards.ts :: redeemGiftCard) — IMPLEMENTED: drive redeemGiftCard; impact proven by race_double_spend @ redeemGiftCard.
- **payment-webhook-forgery** (billing/webhooks.ts :: handlePaymentWebhook) — IMPLEMENTED: drive paymentWebhook; impact proven by webhook_forgery @ paymentWebhook.
- **product-feed-xxe** (catalog/feed-import.ts :: importFeed) — IMPLEMENTED: drive importProductFeed; impact proven by xxe_entity_resolved @ importProductFeed.
- **checkout-workflow-skip** (checkout/confirm.ts :: confirmOrder) — IMPLEMENTED: drive confirmOrder; impact proven by workflow_skip @ confirmOrder.
- **coupon-reuse** (checkout/coupon-apply.ts :: applyCoupon): drive applyCoupon; impact proven by invariant_violation @ applyCoupon.
- **inventory-oversell** (checkout/inventory.ts :: reserveInventory): drive checkout; impact proven by race_double_spend @ checkout.
- **refund-exceeds-payment** (billing/refund-approve.ts :: approveRefund): drive approveRefund; impact proven by invariant_violation @ approveRefund.
- **token-secret-disclosure** (identity/token-list.ts :: listTokens): drive listTokens; impact proven by secret_disclosed @ listTokens.
- **customer-bola-read** (crm/customer-access.ts :: loadCustomer): drive getCustomer; impact proven by cross_tenant_read @ getCustomer.
- **admin-impersonate-privesc** (identity/impersonation.ts :: impersonate): drive adminImpersonate; impact proven by privilege_escalation @ adminImpersonate.
- **settings-secret-disclosure** (identity/settings-read.ts :: readSettings): drive getSettings; impact proven by secret_disclosed @ getSettings.
- **shipping-label-ssrf** (fulfillment/label-import.ts :: importLabel): drive importShippingLabel; impact proven by ssrf_internal_fetch @ importShippingLabel.
- **coupon-after-lock** (checkout/coupon-lock.ts :: applyLockedCoupon): drive applyCoupon; impact proven by workflow_skip @ applyCoupon.
- **over-refund-chain** (billing/refund-overage.ts :: refundOverage): drive createRefund; impact proven by invariant_violation @ createRefund.
