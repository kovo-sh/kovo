/**
 * Focused regression tests for M-15 + isolated benchmark credentials resolution:
 * - M-15 anti-symlink hardening stays 100% strict on default workspace credentials/ and files.
 * - KOVO_CREDENTIALS_DIR allows read-only host credentials without copying or symlinking keys.
 * - KOVO_CREDENTIALS_DIR rejects symlinked dirs (even with trailing slash), bad modes, and symlinked files.
 * - prepareIsolatedDataDir + acquireCredentialsDirEnv cleanly isolates concurrent cells (--concurrency 3)
 *   without creating any symlinks or copying key material, and without mutating read-only host credentials.
 * - benchmark-multihop fails fast with exit code 2 instead of silently falling back to deterministic-no-llm
 *   when --no-llm is NOT set and 0 usable profiles load.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import { promisify } from 'node:util'
import { eq } from 'drizzle-orm'
import {
  CREDENTIALS_DIR_ENV,
  inspectModelProfileLoad,
  privateModelProfiles,
  resolveCredentialsDir,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import { modelProfiles } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { assertMultihopPreflight } from '../scripts/benchmark-multihop.ts'
import {
  PreflightError,
  acquireCredentialsDirEnv,
  openCellStore,
  prepareIsolatedDataDir,
} from '../scripts/benchmark-realistic.ts'

const execFileAsync = promisify(execFile)

const TEST_KEY_CANARY = 'sk-or-v1-test-canary-never-copy-9f8e7d6c5b4a'

function createSourceWorkspace(opts: { legacyUnpinned?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-cred-src-'))
  const storage = new Store(dir)
  const workspaceId = storage.workspace.id
  const credDir = join(dir, 'credentials')
  mkdirSync(credDir, { recursive: true, mode: 0o700 })
  chmodSync(credDir, 0o700)
  const credentialId = `model-${randomUUID()}`
  const credPath = join(credDir, credentialId)
  writeFileSync(credPath, TEST_KEY_CANARY, { mode: 0o600 })
  chmodSync(credPath, 0o600)

  storage.db.$client.prepare(
    'insert into model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, '
    + 'enabled, context_window, max_tokens, thinking_level, role_affinity, input_cost_per_mtok, '
    + 'cached_input_cost_per_mtok, output_cost_per_mtok, health_state, cooldown_until, last_error, updated_at) '
    + 'values (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, null, null, ?)',
  ).run(
    randomUUID(),
    workspaceId,
    'OpenRouter Test Profile',
    'https://openrouter.ai/api/v1',
    'deepseek/deepseek-v4.1-flash-1017',
    'responses',
    credentialId,
    100,
    128_000,
    4_096,
    'off',
    'any',
    0,
    0,
    0,
    'closed',
    Date.now(),
  )
  storage.close()

  if (!opts.legacyUnpinned) {
    // Trigger normal save/pin creation via Store if pinned mode requested
    const s2 = new Store(dir)
    const profiles = privateModelProfiles(s2)
    assert.equal(profiles.length, 1)
    s2.close()
  }

  return {
    dir,
    credDir,
    credentialId,
    credPath,
    workspaceId,
    cleanup: () => {
      try { chmodSync(credDir, 0o700) } catch { /* ignore */ }
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

function walkRegularFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isSymbolicLink()) continue
    if (entry.isDirectory()) out.push(...walkRegularFiles(full))
    else if (entry.isFile()) out.push(full)
  }
  return out
}

describe('M-15 anti-symlink protection + KOVO_CREDENTIALS_DIR host override', () => {
  test('M-15 still strictly rejects symlinked credentials/ dir and symlinked credential files', async t => {
    const prevEnv = process.env[CREDENTIALS_DIR_ENV]
    delete process.env[CREDENTIALS_DIR_ENV]
    t.after(() => {
      if (prevEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
      else process.env[CREDENTIALS_DIR_ENV] = prevEnv
    })

    const realSource = createSourceWorkspace({ legacyUnpinned: true })
    t.after(() => realSource.cleanup())

    // 1) Symlinked workspace credentials/ directory -> rejected
    const wsDir = mkdtempSync(join(tmpdir(), 'kovo-m15-symlink-dir-'))
    t.after(() => rmSync(wsDir, { recursive: true, force: true }))
    const storage = new Store(wsDir)
    t.after(() => storage.close())
    storage.db.$client.prepare(
      'insert into model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, '
      + 'enabled, context_window, max_tokens, thinking_level, role_affinity, input_cost_per_mtok, '
      + 'cached_input_cost_per_mtok, output_cost_per_mtok, health_state, cooldown_until, last_error, updated_at) '
      + 'values (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, null, null, ?)',
    ).run(
      randomUUID(), storage.workspace.id, 'Symlinked Dir Profile', 'https://openrouter.ai/api/v1',
      'deepseek/deepseek-v4.1-flash-1017', 'responses', realSource.credentialId, 100,
      128_000, 4_096, 'off', 'any', 0, 0, 0, 'closed', Date.now(),
    )
    rmSync(join(wsDir, 'credentials'), { recursive: true, force: true })
    symlinkSync(realSource.credDir, join(wsDir, 'credentials'), 'dir')

    assert.throws(() => resolveCredentialsDir(wsDir), /symbolic link/i)
    const load1 = inspectModelProfileLoad(storage)
    assert.equal(load1.profiles.length, 0, 'symlinked credentials/ directory must fail closed')
    assert.match(load1.errors.join(' '), /symbolic link/i)
    assert.equal(privateModelProfiles(storage).length, 0)

    // 2) Symlinked credential file inside real credentials/ directory -> rejected
    unlinkSync(join(wsDir, 'credentials'))
    mkdirSync(join(wsDir, 'credentials'), { mode: 0o700 })
    chmodSync(join(wsDir, 'credentials'), 0o700)
    symlinkSync(realSource.credPath, join(wsDir, 'credentials', realSource.credentialId))

    const load2 = inspectModelProfileLoad(storage)
    assert.equal(load2.profiles.length, 0, 'symlinked credential file must fail closed')
    assert.match(load2.errors.join(' '), /symbolic link/i)
    assert.equal(privateModelProfiles(storage).length, 0)
  })

  test('KOVO_CREDENTIALS_DIR loads real non-symlink 0700 and read-only 0500 host credentials without writing to host dir', t => {
    const prevEnv = process.env[CREDENTIALS_DIR_ENV]
    t.after(() => {
      if (prevEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
      else process.env[CREDENTIALS_DIR_ENV] = prevEnv
    })

    const host = createSourceWorkspace({ legacyUnpinned: true })
    t.after(() => host.cleanup())

    const outDir = mkdtempSync(join(tmpdir(), 'kovo-cred-override-out-'))
    t.after(() => rmSync(outDir, { recursive: true, force: true }))

    const cellDir = join(outDir, 'cell-ro')
    const iso = prepareIsolatedDataDir({ sourceDataDir: host.dir, targetDir: cellDir })
    assert.equal(iso.credentialsDir, host.credDir)

    // Make host credentials dir strictly read-only (mode 0500) to prove zero writes happen there!
    chmodSync(host.credDir, 0o500)
    const hostEntriesBefore = readdirSync(host.credDir).sort()

    process.env[CREDENTIALS_DIR_ENV] = host.credDir
    const cellStore = openCellStore(iso.directory)
    t.after(() => cellStore.close())

    const loaded = privateModelProfiles(cellStore)
    assert.equal(loaded.length, 1, 'real non-symlink read-only KOVO_CREDENTIALS_DIR must load cleanly')
    assert.equal(loaded[0]!.name, 'OpenRouter Test Profile')
    assert.equal(loaded[0]!.key, TEST_KEY_CANARY)

    // Host credentials dir was NEVER mutated (no .pin-ledger.json or .pin-hmac.key created there)
    assert.deepEqual(readdirSync(host.credDir).sort(), hostEntriesBefore)
    assert.equal(existsSync(join(host.credDir, '.pin-ledger.json')), false)

    // Meanwhile, per-workspace SQLite tampering in the isolated cell STILL fails closed via local ledger!
    cellStore.db.update(modelProfiles)
      .set({ endpoint: 'https://attacker.example/v1' })
      .where(eq(modelProfiles.workspaceId, cellStore.workspace.id))
      .run()
    assert.equal(
      privateModelProfiles(cellStore).length,
      0,
      'tampering endpoint in isolated workspace SQLite must fail closed against local pin ledger',
    )
  })

  test('KOVO_CREDENTIALS_DIR rejects symlinked dir (with or without trailing slash), bad permissions, and symlinked credential files', async t => {
    const prevEnv = process.env[CREDENTIALS_DIR_ENV]
    t.after(() => {
      if (prevEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
      else process.env[CREDENTIALS_DIR_ENV] = prevEnv
    })

    const host = createSourceWorkspace({ legacyUnpinned: true })
    t.after(() => host.cleanup())

    const tmpRoot = mkdtempSync(join(tmpdir(), 'kovo-cred-reject-'))
    t.after(() => {
      try { chmodSync(host.credDir, 0o700) } catch { /* ignore */ }
      rmSync(tmpRoot, { recursive: true, force: true })
    })

    const cellDir = join(tmpRoot, 'cell')
    const iso = prepareIsolatedDataDir({ sourceDataDir: host.dir, targetDir: cellDir })
    const cellStore = openCellStore(iso.directory)
    t.after(() => cellStore.close())

    // 1) KOVO_CREDENTIALS_DIR pointing at a symlink (without trailing slash) -> REJECTED
    const symlinkDir = join(tmpRoot, 'cred-link')
    symlinkSync(host.credDir, symlinkDir, 'dir')
    process.env[CREDENTIALS_DIR_ENV] = symlinkDir
    assert.throws(() => resolveCredentialsDir(iso.directory), /symbolic link/i)
    assert.equal(privateModelProfiles(cellStore).length, 0)

    // 2) KOVO_CREDENTIALS_DIR pointing at a symlink WITH trailing slash -> STILL REJECTED
    process.env[CREDENTIALS_DIR_ENV] = `${symlinkDir}/`
    assert.throws(() => resolveCredentialsDir(iso.directory), /symbolic link/i)
    assert.equal(privateModelProfiles(cellStore).length, 0)

    // 3) KOVO_CREDENTIALS_DIR with loose permissions (mode 0755) -> REJECTED
    chmodSync(host.credDir, 0o755)
    process.env[CREDENTIALS_DIR_ENV] = host.credDir
    assert.throws(() => resolveCredentialsDir(iso.directory), /0700/)
    assert.equal(privateModelProfiles(cellStore).length, 0)
    chmodSync(host.credDir, 0o700)

    // 4) Real 0700 KOVO_CREDENTIALS_DIR containing a symlinked credential file -> REJECTED
    const badHostCreds = join(tmpRoot, 'bad-host-creds')
    mkdirSync(badHostCreds, { mode: 0o700 })
    chmodSync(badHostCreds, 0o700)
    symlinkSync(host.credPath, join(badHostCreds, host.credentialId))
    process.env[CREDENTIALS_DIR_ENV] = badHostCreds
    const loadSymFile = inspectModelProfileLoad(cellStore)
    assert.equal(loadSymFile.profiles.length, 0)
    assert.match(loadSymFile.errors.join(' '), /symbolic link/i)

    // 5) Real 0700 KOVO_CREDENTIALS_DIR with a pinned credential mismatched against SQLite -> REJECTED
    const pinnedDir = mkdtempSync(join(tmpdir(), 'kovo-cred-pinned-'))
    t.after(() => rmSync(pinnedDir, { recursive: true, force: true }))
    delete process.env[CREDENTIALS_DIR_ENV]
    const pinnedStore = new Store(pinnedDir)
    t.after(() => pinnedStore.close())
    const saved = await saveModelProfile({
      name: 'Pinned Host',
      endpoint: 'https://api.openai.com/v1',
      model: 'gpt-5',
      protocol: 'responses',
      key: 'sk-pinned-host-secret-123456',
    }, pinnedStore, { skipConnectionCheck: true })
    const pinnedRow = pinnedStore.db.select().from(modelProfiles).where(eq(modelProfiles.id, saved.id)).get()!
    // Point cellStore row at pinnedRow.credentialId (which is pinned to openai.com, NOT openrouter.ai)
    cellStore.db.update(modelProfiles)
      .set({ credentialId: pinnedRow.credentialId })
      .where(eq(modelProfiles.workspaceId, cellStore.workspace.id))
      .run()
    process.env[CREDENTIALS_DIR_ENV] = join(pinnedDir, 'credentials')
    assert.equal(privateModelProfiles(cellStore).length, 0, 'host .pin mismatch must fail closed via KOVO_CREDENTIALS_DIR')
  })

  test('concurrency=3 isolated cells share read-only KOVO_CREDENTIALS_DIR without symlinks, key copies, or lock contention', async t => {
    const prevEnv = process.env[CREDENTIALS_DIR_ENV]
    delete process.env[CREDENTIALS_DIR_ENV]
    t.after(() => {
      if (prevEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
      else process.env[CREDENTIALS_DIR_ENV] = prevEnv
    })

    const host = createSourceWorkspace({ legacyUnpinned: true })
    t.after(() => host.cleanup())

    const outDir = mkdtempSync(join(tmpdir(), 'kovo-cred-c3-'))
    t.after(() => rmSync(outDir, { recursive: true, force: true }))

    const cellTargets = ['paygrid', 'shipforge', 'nexusiam'].map(app => join(outDir, 'data', `${app}-seed1`))
    const prepared = await Promise.all(
      cellTargets.map(targetDir => Promise.resolve().then(() => prepareIsolatedDataDir({
        sourceDataDir: host.dir,
        targetDir,
      }))),
    )

    // Lock host credentials dir read-only (0500) before concurrent cells open and read
    chmodSync(host.credDir, 0o500)

    const releases: Array<() => void> = []
    const stores: Store[] = []
    try {
      for (const iso of prepared) {
        assert.equal(iso.credentialsDir, host.credDir)
        const targetCreds = join(iso.directory, 'credentials')
        assert.equal(lstatSync(targetCreds).isSymbolicLink(), false, 'isolated cell credentials/ must NOT be a symlink')
        assert.equal(lstatSync(targetCreds).isDirectory(), true, 'isolated cell credentials/ must be a real directory')
        releases.push(acquireCredentialsDirEnv(iso.credentialsDir))
        stores.push(openCellStore(iso.directory))
      }

      assert.equal(process.env[CREDENTIALS_DIR_ENV], host.credDir)

      // All 3 concurrent cell Stores read the enabled model profile cleanly
      for (const s of stores) {
        const profiles = privateModelProfiles(s)
        assert.equal(profiles.length, 1)
        assert.equal(profiles[0]!.name, 'OpenRouter Test Profile')
        assert.equal(profiles[0]!.key, TEST_KEY_CANARY)
      }

      // Releasing cell 1 & cell 2 keeps KOVO_CREDENTIALS_DIR active for cell 3!
      releases[0]!()
      releases[1]!()
      assert.equal(process.env[CREDENTIALS_DIR_ENV], host.credDir)
      assert.equal(privateModelProfiles(stores[2]!).length, 1)

      // Releasing last cell restores KOVO_CREDENTIALS_DIR to unset
      releases[2]!()
      assert.equal(process.env[CREDENTIALS_DIR_ENV], undefined)
    } finally {
      for (const r of releases) r()
      for (const s of stores) { try { s.close() } catch { /* ignore */ } }
    }

    // Verify ZERO copies of the API key exist anywhere in the isolated outDir
    const leaked = walkRegularFiles(outDir).filter(file => readFileSync(file, 'utf8').includes(TEST_KEY_CANARY))
    assert.deepEqual(leaked, [], 'API key must NEVER be copied into isolated cell directories')
  })

  test('prepareIsolatedDataDir refuses symlinked source credentials dir and symlinked source credential file', t => {
    const host = createSourceWorkspace({ legacyUnpinned: true })
    t.after(() => host.cleanup())

    const tmpRoot = mkdtempSync(join(tmpdir(), 'kovo-prep-reject-'))
    t.after(() => rmSync(tmpRoot, { recursive: true, force: true }))

    // Replace source credentials/ with a symlink
    const realMoved = join(tmpRoot, 'moved-creds')
    mkdirSync(realMoved, { mode: 0o700 })
    chmodSync(realMoved, 0o700)
    writeFileSync(join(realMoved, host.credentialId), TEST_KEY_CANARY, { mode: 0o600 })
    rmSync(host.credDir, { recursive: true, force: true })
    symlinkSync(realMoved, host.credDir, 'dir')

    assert.throws(
      () => prepareIsolatedDataDir({ sourceDataDir: host.dir, targetDir: join(tmpRoot, 'out-1') }),
      /symbolic link/i,
    )

    // Restore real credentials/ dir but symlink the credential file inside it
    unlinkSync(host.credDir)
    mkdirSync(host.credDir, { mode: 0o700 })
    chmodSync(host.credDir, 0o700)
    symlinkSync(join(realMoved, host.credentialId), host.credPath)

    assert.throws(
      () => prepareIsolatedDataDir({ sourceDataDir: host.dir, targetDir: join(tmpRoot, 'out-2') }),
      /symbolic link/i,
    )
  })
})

describe('benchmark-multihop fail-fast (no silent fallback to deterministic-no-llm)', () => {
  test('assertMultihopPreflight throws PreflightError (exit 2) when --no-llm is NOT set and 0 profiles loaded', () => {
    assert.throws(
      () => assertMultihopPreflight({
        hasProfiles: false,
        noLlm: false,
        allowInertWorkers: false,
        backendKind: 'docker',
        workerSessions: true,
        workerSessionsDetail: 'ok',
        profileLoadError: 'The workspace KOVO_CREDENTIALS_DIR credentials directory must not be a symbolic link.',
      }),
      (err: unknown) =>
        err instanceof PreflightError
        && err.exitCode === 2
        && /refusing silent fallback to deterministic-no-llm/i.test(err.message)
        && /symbolic link/i.test(err.message),
    )

    // --no-llm explicitly requested still passes with 0 profiles
    assert.doesNotThrow(() => assertMultihopPreflight({
      hasProfiles: false,
      noLlm: true,
      allowInertWorkers: false,
      backendKind: 'local-jq',
      workerSessions: false,
      workerSessionsDetail: 'local-jq is replay-only',
    }))
  })

  test('benchmark-multihop CLI fails fast with exit code 2 when agentic mode has 0 profiles (empty data-dir or symlinked KOVO_CREDENTIALS_DIR)', async t => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'kovo-mh-failfast-'))
    t.after(() => rmSync(tmpRoot, { recursive: true, force: true }))

    const outDir = join(tmpRoot, 'out')
    const emptyDataDir = join(tmpRoot, 'empty-data')
    const emptyStore = new Store(emptyDataDir)
    emptyStore.close()

    const env: NodeJS.ProcessEnv = { ...process.env, KOVO_ALLOW_LOCAL_LAB: '1' }
    delete env.KOVO_DATA_DIR
    delete env[CREDENTIALS_DIR_ENV]

    await assert.rejects(
      execFileAsync(process.execPath, [
        'scripts/benchmark-multihop.ts',
        '--app', 'paygrid',
        '--seed', '1',
        '--mode', 'white-box',
        '--verifier', 'local-jq',
        '--no-isolate-data-dir',
        '--data-dir', emptyDataDir,
        '--out-dir', outDir,
      ], { env, timeout: 20_000 }),
      (err: unknown) => {
        const e = err as { code?: number; stderr?: string }
        assert.equal(e.code, 2, `expected exit code 2, got ${String(e.code)}; stderr=${e.stderr ?? ''}`)
        assert.match(e.stderr ?? '', /refusing silent fallback to deterministic-no-llm/i)
        return true
      },
    )

    // Also test with a valid source data-dir BUT KOVO_CREDENTIALS_DIR overridden to a symlink -> must exit 2!
    const host = createSourceWorkspace({ legacyUnpinned: true })
    t.after(() => host.cleanup())
    const badSymlink = join(tmpRoot, 'bad-cred-symlink')
    symlinkSync(host.credDir, badSymlink, 'dir')

    await assert.rejects(
      execFileAsync(process.execPath, [
        'scripts/benchmark-multihop.ts',
        '--app', 'paygrid',
        '--seed', '1',
        '--mode', 'white-box',
        '--verifier', 'local-jq',
        '--isolate-data-dir',
        '--data-dir', host.dir,
        '--out-dir', join(tmpRoot, 'out-sym'),
      ], { env: { ...env, [CREDENTIALS_DIR_ENV]: badSymlink }, timeout: 20_000 }),
      (err: unknown) => {
        const e = err as { code?: number; stderr?: string }
        assert.equal(e.code, 2, `expected exit code 2, got ${String(e.code)}; stderr=${e.stderr ?? ''}`)
        assert.match(e.stderr ?? '', /refusing silent fallback to deterministic-no-llm/i)
        assert.match(e.stderr ?? '', /symbolic link/i)
        return true
      },
    )
  })
})
