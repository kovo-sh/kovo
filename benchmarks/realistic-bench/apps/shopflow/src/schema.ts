// Full relational schema for the storefront + merchant back-office. Tenant-scoped tables carry a
// store_id. External ids are stored verbatim so handlers resolve records by their presented id.
import type { Db } from '../../../lib/db.ts'

export const SCHEMA = `
CREATE TABLE stores (
  id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL
);
CREATE TABLE customers (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  name TEXT NOT NULL, email TEXT NOT NULL, note TEXT
);
CREATE TABLE products (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  title TEXT NOT NULL, price INTEGER NOT NULL, stock INTEGER NOT NULL, body_html TEXT
);
CREATE TABLE carts (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  owner TEXT, status TEXT NOT NULL DEFAULT 'open', subtotal INTEGER NOT NULL DEFAULT 0,
  discount INTEGER NOT NULL DEFAULT 0, locked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE cart_items (
  id INTEGER PRIMARY KEY, cart_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
  qty INTEGER NOT NULL, unit_price INTEGER NOT NULL
);
CREATE TABLE orders (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  customer_id INTEGER, status TEXT NOT NULL, payment_state TEXT NOT NULL DEFAULT 'uncaptured',
  total INTEGER NOT NULL DEFAULT 0, return_url TEXT, created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE order_items (
  id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
  qty INTEGER NOT NULL, unit_price INTEGER NOT NULL
);
CREATE TABLE payments (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  order_id INTEGER, amount INTEGER NOT NULL, status TEXT NOT NULL, captured INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE refunds (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  order_id INTEGER, payment_id INTEGER, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE gift_cards (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  code TEXT NOT NULL, balance INTEGER NOT NULL, initial INTEGER NOT NULL
);
CREATE TABLE coupons (
  id INTEGER PRIMARY KEY, store_id TEXT NOT NULL, code TEXT NOT NULL,
  kind TEXT NOT NULL, value INTEGER NOT NULL, single_use INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE coupon_uses (
  id INTEGER PRIMARY KEY, store_id TEXT NOT NULL, coupon_code TEXT NOT NULL,
  cart_id INTEGER, order_id INTEGER
);
CREATE TABLE shipments (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  order_id INTEGER, status TEXT NOT NULL DEFAULT 'pending', label_url TEXT
);
CREATE TABLE reviews (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  product_id INTEGER NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL, approved INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE invoices (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  order_id INTEGER NOT NULL, path TEXT NOT NULL
);
CREATE TABLE api_tokens (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  label TEXT NOT NULL, token TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'read'
);
CREATE TABLE store_config (
  store_id TEXT PRIMARY KEY, webhook_secret TEXT NOT NULL, provider_key TEXT NOT NULL,
  settings_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE webhook_events (
  id INTEGER PRIMARY KEY, store_id TEXT NOT NULL, event_type TEXT NOT NULL,
  order_id INTEGER, received_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE payouts (
  id INTEGER PRIMARY KEY, external_id TEXT NOT NULL, store_id TEXT NOT NULL,
  amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
);
`

export function applySchema(db: Db): void {
  db.exec(SCHEMA)
}
