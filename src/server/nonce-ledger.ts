/**
 * Per-Run HMAC-Bound Nonce Ledger (`R3-16`).
 *
 * Backs `HostMintedOracle` with cryptographically bound per-run HMAC-SHA256 stamps:
 *   - One fresh 32-byte secret key per `runId` (generated via `crypto.randomBytes(32)`,
 *     NEVER exposed to workers or serialized into worker-facing metadata).
 *   - Every stamp is HMAC-bound to `{ runId, oracleId, armRole, origin, method, route,
 *     param, exchangeId, payloadDigest, mintedAtMs }` so cross-run, cross-oracle,
 *     cross-exchange, cross-arm, or cross-origin citations fail closed.
 *   - Hot-path probes stay strictly in memory (zero DB writes per probe); only **cited**
 *     stamps are persisted to SQLite so post-restart retests re-verify cleanly without DB bloat.
 *   - Per-run in-memory state is registered with `registerRunDisposer` (R2-08 compliant).
 *   - Preserves non-nonce binding kinds (`persona_tenant`, `canary`, `state_ledger`,
 *     `crypto_signature`, etc.) for authz/economic/OOB oracles.
 */
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import type { DatabaseSync } from 'node:sqlite'
import { asHostMinted, type HostMinted } from './evidence-provenance.ts'
import type { OracleBindingKind } from './oracle-spec.ts'
import { registerRunDisposer } from './run-disposers.ts'

export type NonceOracleId = 'timing' | 'redirect' | 'boolean' | 'expression' | 'canary'

export const DEFAULT_NONCE_RUN_ID = 'default_host_run'

/** Authoritative mapping of non-nonce binding kinds preserved alongside nonce-bound oracles. */
export const NON_NONCE_ORACLE_BINDING_KINDS: ReadonlySet<OracleBindingKind> = new Set([
  'persona_tenant',
  'canary',
  'state_ledger',
  'crypto_signature',
  'none_ticketed',
])

export interface NonceBinding {
  readonly runId: string
  readonly oracleId: NonceOracleId
  readonly armRole?: string | null
  readonly origin?: string | null
  readonly method?: string | null
  readonly route?: string | null
  readonly param?: string | null
  readonly exchangeId?: string | null
}

export interface NonceStamp {
  readonly stampId: string
  readonly runId: string
  readonly oracleId: NonceOracleId
  readonly armRole: string | null
  readonly origin: string | null
  readonly method: string | null
  readonly route: string | null
  readonly param: string | null
  readonly exchangeId: string | null
  readonly payloadDigest: string
  readonly mac: string
  readonly mintedAtMs: number
}

export interface NonceVerifyExpected {
  readonly runId?: string | null
  readonly oracleId: NonceOracleId
  readonly armRole?: string | null
  readonly origin?: string | null
  readonly method?: string | null
  readonly route?: string | null
  readonly param?: string | null
  readonly exchangeId?: string | null
  readonly payloadDigest?: string | null
}

export interface PersistedNonceStampRecord {
  readonly stamp: NonceStamp
  readonly payloadJson: string | null
  readonly citedAtMs: number
}

export interface NonceLedgerPersistence {
  saveRunKeyIfAbsent(runId: string, keyHex: string, createdAtMs: number): void
  loadRunKey(runId: string): string | null
  saveCitedStamp(record: PersistedNonceStampRecord): void
  loadCitedStamp(stampId: string): PersistedNonceStampRecord | null
  listCitedStampsForRun(runId: string): readonly PersistedNonceStampRecord[]
  deleteRun(runId: string): void
}

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i
const MAX_IN_MEMORY_STAMPS_PER_RUN = 4096

function normNullable(v: string | null | undefined): string | null {
  if (typeof v !== 'string') return null
  const t = v.trim()
  return t.length > 0 ? t : null
}

function normOrigin(v: string | null | undefined): string | null {
  const s = normNullable(v)
  return s ? s.replace(/\/+$/, '').toLowerCase() : null
}

function normMethod(v: string | null | undefined): string | null {
  const s = normNullable(v)
  return s ? s.toUpperCase() : null
}

function normRoute(v: string | null | undefined): string | null {
  const s = normNullable(v)
  if (!s) return null
  const noQuery = s.split('?')[0]!.split('#')[0]!
  return (noQuery.replace(/\/+$/, '') || '/').toLowerCase()
}

function normArmRole(v: string | null | undefined): string | null {
  const s = normNullable(v)
  return s ? s.toLowerCase() : null
}

export function hashNoncePayload(payload: unknown): string {
  const serialized = typeof payload === 'string' ? payload : JSON.stringify(payload ?? null)
  return createHash('sha256').update(serialized, 'utf8').digest('hex')
}

function canonicalStampInput(stamp: Omit<NonceStamp, 'mac'>): string {
  return JSON.stringify({
    v: 1,
    stampId: stamp.stampId,
    runId: stamp.runId,
    oracleId: stamp.oracleId,
    armRole: stamp.armRole,
    origin: stamp.origin,
    method: stamp.method,
    route: stamp.route,
    param: stamp.param,
    exchangeId: stamp.exchangeId,
    payloadDigest: stamp.payloadDigest,
    mintedAtMs: stamp.mintedAtMs,
  })
}

function computeStampMac(key: Buffer, stamp: Omit<NonceStamp, 'mac'>): string {
  return createHmac('sha256', key).update(canonicalStampInput(stamp), 'utf8').digest('hex')
}

function constantTimeHexEqual(aHex: string, bHex: string): boolean {
  if (!SHA256_HEX_RE.test(aHex) || !SHA256_HEX_RE.test(bHex)) return false
  const a = Buffer.from(aHex.toLowerCase(), 'hex')
  const b = Buffer.from(bHex.toLowerCase(), 'hex')
  return a.length === b.length && timingSafeEqual(a, b)
}

/** Initialize SQLite tables for persisted *cited* nonce stamps and per-run HMAC keys. */
export function initNonceLedgerSchema(client: DatabaseSync): void {
  client.exec(`
    CREATE TABLE IF NOT EXISTS nonce_ledger_run_keys (
      run_id TEXT PRIMARY KEY NOT NULL,
      key_hex TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS nonce_ledger_stamps (
      stamp_id TEXT PRIMARY KEY NOT NULL,
      run_id TEXT NOT NULL,
      oracle_id TEXT NOT NULL,
      arm_role TEXT,
      origin TEXT,
      method TEXT,
      route TEXT,
      param TEXT,
      exchange_id TEXT,
      payload_digest TEXT NOT NULL,
      mac TEXT NOT NULL,
      payload_json TEXT,
      minted_at_ms INTEGER NOT NULL,
      cited_at_ms INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS nonce_ledger_stamps_run
      ON nonce_ledger_stamps (run_id, oracle_id);
  `)
  const hasRuns = client.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'").get()
  if (hasRuns) {
    client.exec('CREATE TRIGGER IF NOT EXISTS runs_after_delete_nonce_ledger AFTER DELETE ON runs BEGIN DELETE FROM nonce_ledger_stamps WHERE run_id = OLD.id; DELETE FROM nonce_ledger_run_keys WHERE run_id = OLD.id; END;')
  }
}

/** SQLite-backed persistence storing ONLY cited nonce stamps (lazy DDL; zero hot-path DB writes). */
export class SqliteNonceLedgerPersistence implements NonceLedgerPersistence {
  private readonly client: DatabaseSync
  private schemaReady = false

  constructor(client: DatabaseSync) {
    this.client = client
  }

  private ensureSchema(): void {
    if (this.schemaReady) return
    initNonceLedgerSchema(this.client)
    this.schemaReady = true
  }

  private hasTables(): boolean {
    if (this.schemaReady) return true
    const row = this.client.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'nonce_ledger_stamps'").get()
    if (row) this.schemaReady = true
    return Boolean(row)
  }

  saveRunKeyIfAbsent(runId: string, keyHex: string, createdAtMs: number): void {
    this.ensureSchema()
    this.client.prepare(
      'INSERT OR IGNORE INTO nonce_ledger_run_keys (run_id, key_hex, created_at) VALUES (?, ?, ?)',
    ).run(runId, keyHex, createdAtMs)
  }

  loadRunKey(runId: string): string | null {
    if (!this.hasTables()) return null
    const row = this.client.prepare(
      'SELECT key_hex FROM nonce_ledger_run_keys WHERE run_id = ?',
    ).get(runId) as { key_hex?: unknown } | undefined
    return typeof row?.key_hex === 'string' && SHA256_HEX_RE.test(row.key_hex) ? row.key_hex : null
  }

  saveCitedStamp(record: PersistedNonceStampRecord): void {
    this.ensureSchema()
    const { stamp } = record
    this.client.prepare(`
      INSERT OR REPLACE INTO nonce_ledger_stamps (
        stamp_id, run_id, oracle_id, arm_role, origin, method, route, param,
        exchange_id, payload_digest, mac, payload_json, minted_at_ms, cited_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      stamp.stampId,
      stamp.runId,
      stamp.oracleId,
      stamp.armRole,
      stamp.origin,
      stamp.method,
      stamp.route,
      stamp.param,
      stamp.exchangeId,
      stamp.payloadDigest,
      stamp.mac,
      record.payloadJson,
      stamp.mintedAtMs,
      record.citedAtMs,
    )
  }

  loadCitedStamp(stampId: string): PersistedNonceStampRecord | null {
    if (!this.hasTables()) return null
    const row = this.client.prepare(`
      SELECT stamp_id, run_id, oracle_id, arm_role, origin, method, route, param,
             exchange_id, payload_digest, mac, payload_json, minted_at_ms, cited_at_ms
      FROM nonce_ledger_stamps WHERE stamp_id = ?
    `).get(stampId) as Record<string, unknown> | undefined
    return row ? this.rowToRecord(row) : null
  }

  listCitedStampsForRun(runId: string): readonly PersistedNonceStampRecord[] {
    if (!this.hasTables()) return []
    const rows = this.client.prepare(`
      SELECT stamp_id, run_id, oracle_id, arm_role, origin, method, route, param,
             exchange_id, payload_digest, mac, payload_json, minted_at_ms, cited_at_ms
      FROM nonce_ledger_stamps WHERE run_id = ? ORDER BY cited_at_ms ASC
    `).all(runId) as Record<string, unknown>[]
    return rows.map(r => this.rowToRecord(r))
  }

  deleteRun(runId: string): void {
    if (!this.hasTables()) return
    this.client.prepare('DELETE FROM nonce_ledger_stamps WHERE run_id = ?').run(runId)
    this.client.prepare('DELETE FROM nonce_ledger_run_keys WHERE run_id = ?').run(runId)
  }

  private rowToRecord(row: Record<string, unknown>): PersistedNonceStampRecord {
    const stamp: NonceStamp = Object.freeze({
      stampId: String(row.stamp_id),
      runId: String(row.run_id),
      oracleId: String(row.oracle_id) as NonceOracleId,
      armRole: typeof row.arm_role === 'string' ? row.arm_role : null,
      origin: typeof row.origin === 'string' ? row.origin : null,
      method: typeof row.method === 'string' ? row.method : null,
      route: typeof row.route === 'string' ? row.route : null,
      param: typeof row.param === 'string' ? row.param : null,
      exchangeId: typeof row.exchange_id === 'string' ? row.exchange_id : null,
      payloadDigest: String(row.payload_digest),
      mac: String(row.mac),
      mintedAtMs: Number(row.minted_at_ms),
    })
    return Object.freeze({
      stamp,
      payloadJson: typeof row.payload_json === 'string' ? row.payload_json : null,
      citedAtMs: Number(row.cited_at_ms),
    })
  }
}

interface InMemoryStampEntry {
  readonly stamp: HostMinted<NonceStamp>
  readonly payloadJson: string | null
  cited: boolean
}

const activeNonceLedgers = new Set<WeakRef<NonceLedger>>()

registerRunDisposer('nonce-ledger:run-states', runId => {
  for (const ref of [...activeNonceLedgers]) {
    const ledger = ref.deref()
    if (!ledger) activeNonceLedgers.delete(ref)
    else ledger.disposeRun(runId)
  }
})

export interface NonceLedgerOptions {
  readonly persistence?: NonceLedgerPersistence
}

/**
 * Per-run HMAC-SHA256 nonce ledger.
 *
 * Security invariants:
 *   1. Secret HMAC keys are strictly private (`#runKeys`), generated via `randomBytes(32)` per
 *      `runId`, and NEVER returned by any public method or included in any stamp/error.
 *   2. Hot-path `mintStamp` / `bindStampToExchange` NEVER write to SQLite.
 *   3. `citeStamp` persists ONLY cited stamps (+ the run key) so restart re-verification works.
 *   4. Cross-run, cross-oracle, cross-exchange, cross-arm, and cross-origin reuse fails closed.
 */
export class NonceLedger {
  readonly #runKeys = new Map<string, Buffer>()
  readonly #runStampIds = new Map<string, Set<string>>()
  readonly #stampsById = new Map<string, InMemoryStampEntry>()
  readonly #persistence?: NonceLedgerPersistence

  constructor(options: NonceLedgerOptions = {}) {
    this.#persistence = options.persistence
    activeNonceLedgers.add(new WeakRef(this))
  }

  private getOrCreateRunKey(runId: string): Buffer {
    const existing = this.#runKeys.get(runId)
    if (existing) return existing
    const persistedHex = this.#persistence?.loadRunKey(runId)
    const key = persistedHex ? Buffer.from(persistedHex, 'hex') : randomBytes(32)
    this.#runKeys.set(runId, key)
    return key
  }

  private lookupRunKey(runId: string): Buffer | null {
    const existing = this.#runKeys.get(runId)
    if (existing) return existing
    const persistedHex = this.#persistence?.loadRunKey(runId)
    if (!persistedHex) return null
    const key = Buffer.from(persistedHex, 'hex')
    this.#runKeys.set(runId, key)
    return key
  }

  mintStamp(
    binding: NonceBinding,
    payload: unknown,
    options: { stampId?: string; mintedAtMs?: number; persistPayload?: boolean } = {},
  ): HostMinted<NonceStamp> {
    const runId = normNullable(binding.runId) ?? DEFAULT_NONCE_RUN_ID
    const key = this.getOrCreateRunKey(runId)
    const stampId = normNullable(options.stampId) ?? `nst_${binding.oracleId}_${randomUUID()}`
    const mintedAtMs = options.mintedAtMs ?? Date.now()
    const payloadJson = options.persistPayload === false
      ? null
      : (typeof payload === 'string' ? payload : JSON.stringify(payload ?? null))
    const payloadDigest = hashNoncePayload(payloadJson ?? payload)
    const body: Omit<NonceStamp, 'mac'> = {
      stampId,
      runId,
      oracleId: binding.oracleId,
      armRole: normArmRole(binding.armRole),
      origin: normOrigin(binding.origin),
      method: normMethod(binding.method),
      route: normRoute(binding.route),
      param: normNullable(binding.param),
      exchangeId: normNullable(binding.exchangeId),
      payloadDigest,
      mintedAtMs,
    }
    const mac = computeStampMac(key, body)
    const stamp = asHostMinted(Object.freeze({ ...body, mac }))
    this.storeInMemory(stamp, payloadJson)
    return stamp
  }

  /**
   * Derive a per-exchange HMAC-bound stamp from an existing minted stamp (in-memory only).
   * Binds `exchangeId` (and optional `armRole`) so the stamp cannot be cited on any other exchange.
   */
  bindStampToExchange(
    baseStamp: NonceStamp,
    exchangeId: string,
    armRole?: string | null,
  ): HostMinted<NonceStamp> | null {
    const entry = this.resolveEntry(baseStamp.stampId)
    if (!entry) return null
    const key = this.lookupRunKey(entry.stamp.runId)
    if (!key) return null
    const expectedMac = computeStampMac(key, entry.stamp)
    if (!constantTimeHexEqual(baseStamp.mac, expectedMac)) return null
    return this.mintStamp(
      {
        runId: entry.stamp.runId,
        oracleId: entry.stamp.oracleId,
        armRole: armRole !== undefined ? armRole : entry.stamp.armRole,
        origin: entry.stamp.origin,
        method: entry.stamp.method,
        route: entry.stamp.route,
        param: entry.stamp.param,
        exchangeId,
      },
      entry.payloadJson ?? entry.stamp.payloadDigest,
      { persistPayload: entry.payloadJson !== null },
    )
  }

  /**
   * Mark a minted stamp as **cited** and persist ONLY this stamp (and its run's HMAC key)
   * to SQLite so post-restart retest re-verification succeeds without DB writes on hot probes.
   */
  citeStamp(stampIdOrStamp: string | NonceStamp): boolean {
    const stampId = typeof stampIdOrStamp === 'string' ? stampIdOrStamp : stampIdOrStamp.stampId
    const entry = this.resolveEntry(stampId)
    if (!entry) return false
    const key = this.lookupRunKey(entry.stamp.runId)
    if (!key) return false
    entry.cited = true
    if (this.#persistence) {
      const now = Date.now()
      this.#persistence.saveRunKeyIfAbsent(entry.stamp.runId, key.toString('hex'), now)
      this.#persistence.saveCitedStamp({
        stamp: entry.stamp,
        payloadJson: entry.payloadJson,
        citedAtMs: now,
      })
    }
    return true
  }

  /** Load persisted/in-memory non-secret payload JSON for a verified stamp (used on restart retest). */
  getVerifiedPayload<T = unknown>(stampId: string): T | null {
    const entry = this.resolveEntry(stampId)
    if (!entry?.payloadJson) return null
    try {
      return JSON.parse(entry.payloadJson) as T
    } catch {
      return null
    }
  }

  /**
   * Cryptographically verify a `NonceStamp` against its per-run HMAC key AND expected binding tuple.
   * Rejects any cross-run, cross-oracle, cross-exchange, cross-arm, cross-origin, cross-method,
   * cross-route, cross-param, tampered-MAC, or unknown-stamp citation.
   */
  verifyStamp(
    stamp: NonceStamp | null | undefined,
    expected: NonceVerifyExpected,
    options: { citeOnVerify?: boolean } = {},
  ): HostMinted<NonceStamp> | null {
    if (!stamp || typeof stamp.stampId !== 'string' || typeof stamp.mac !== 'string') return null
    const entry = this.resolveEntry(stamp.stampId)
    if (!entry) return null
    const stored = entry.stamp
    const key = this.lookupRunKey(stored.runId)
    if (!key) return null

    // 1. Constant-time HMAC verification against the per-run secret key.
    const recomputedMac = computeStampMac(key, stored)
    if (!constantTimeHexEqual(stored.mac, recomputedMac)) return null
    if (!constantTimeHexEqual(stamp.mac, recomputedMac)) return null
    if (canonicalStampInput(stamp) !== canonicalStampInput(stored)) return null

    // 2. Strict binding tuple checks (fail closed on ANY cross-binding mismatch).
    if (NON_NONCE_ORACLE_BINDING_KINDS.has(stored.oracleId as unknown as OracleBindingKind)) {
      // Non-nonce binding kinds (e.g. persona_tenant, state_ledger, crypto_signature) are not nonce stamps;
      // canary may carry either a nonce stamp or an OOB callback signature.
      if (stored.oracleId !== 'canary') return null
    }
    if (stored.oracleId !== expected.oracleId) return null
    const expectedRunId = normNullable(expected.runId)
    if (expectedRunId !== null && stored.runId !== expectedRunId) return null
    if (expectedRunId === null && stored.runId !== DEFAULT_NONCE_RUN_ID) return null

    const expOrigin = normOrigin(expected.origin)
    if (expected.origin !== undefined && stored.origin !== null && stored.origin !== expOrigin) return null

    const expMethod = normMethod(expected.method)
    if (expected.method !== undefined && stored.method !== null && stored.method !== expMethod) return null

    const expRoute = normRoute(expected.route)
    if (expected.route !== undefined && stored.route !== null && stored.route !== expRoute) return null

    const expParam = normNullable(expected.param)
    if (expected.param !== undefined && stored.param !== null && stored.param !== expParam) return null

    const expArmRole = normArmRole(expected.armRole)
    if (expected.armRole !== undefined && stored.armRole !== null && stored.armRole !== expArmRole) return null

    const expExchangeId = normNullable(expected.exchangeId)
    if (stored.exchangeId !== null && stored.exchangeId !== expExchangeId) return null

    if (expected.payloadDigest && stored.payloadDigest !== expected.payloadDigest) return null

    if (options.citeOnVerify) {
      this.citeStamp(stored)
    }
    return stored
  }

  /** Number of in-memory stamps currently tracked for a run (diagnostic/test helper). */
  inMemoryStampCount(runId?: string): number {
    if (runId !== undefined) return this.#runStampIds.get(runId)?.size ?? 0
    return this.#stampsById.size
  }

  /** Dispose all in-memory keys and stamps for a completed/deleted run (registered via `registerRunDisposer`). */
  disposeRun(runId: string): void {
    this.#runKeys.delete(runId)
    const ids = this.#runStampIds.get(runId)
    if (ids) {
      for (const id of ids) this.#stampsById.delete(id)
      this.#runStampIds.delete(runId)
    }
  }

  private resolveEntry(stampId: string): InMemoryStampEntry | null {
    const inMem = this.#stampsById.get(stampId)
    if (inMem) return inMem
    const persisted = this.#persistence?.loadCitedStamp(stampId)
    if (!persisted) return null
    const hydrated: InMemoryStampEntry = {
      stamp: asHostMinted(persisted.stamp),
      payloadJson: persisted.payloadJson,
      cited: true,
    }
    this.storeInMemory(hydrated.stamp, hydrated.payloadJson, true)
    return hydrated
  }

  private storeInMemory(stamp: HostMinted<NonceStamp>, payloadJson: string | null, cited = false): void {
    let runIds = this.#runStampIds.get(stamp.runId)
    if (!runIds) {
      runIds = new Set<string>()
      this.#runStampIds.set(stamp.runId, runIds)
    }
    runIds.add(stamp.stampId)
    this.#stampsById.set(stamp.stampId, { stamp, payloadJson, cited })
    if (runIds.size > MAX_IN_MEMORY_STAMPS_PER_RUN) {
      const oldest = runIds.values().next().value
      if (oldest !== undefined) {
        runIds.delete(oldest)
        this.#stampsById.delete(oldest)
      }
    }
  }
}
