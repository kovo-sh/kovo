// Regression tests for non-root Docker worker `/repos` EACCES under restrictive host umask (0077).
// Verifies both white-box materialization permissions and worker-backend repo mount staging without Docker.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { generateDomainVariant } from '../benchmarks/multihop-saas/lib/domain-variant.ts'
import { materialize } from '../benchmarks/multihop-saas/lib/materialize.ts'
import { LinuxWorkerBackend, prepareReposMount } from '../src/server/worker-backend.ts'

function walkTree(dir: string): { dirs: string[]; files: string[] } {
  const dirs: string[] = [dir]
  const files: string[] = []
  const visit = (current: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name)
      const st = lstatSync(full)
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) {
        dirs.push(full)
        visit(full)
      } else if (st.isFile()) {
        files.push(full)
      }
    }
  }
  visit(dir)
  return { dirs, files }
}

function withUmask077<T>(fn: () => T): T {
  const prev = process.umask(0o077)
  try {
    return fn()
  } finally {
    process.umask(prev)
  }
}

async function withUmask077Async<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.umask(0o077)
  try {
    return await fn()
  } finally {
    process.umask(prev)
  }
}

test('materialize sets explicit 0o755 dirs (including created ancestors) and 0o644 files under umask 0077', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'guardian-mat-umask-'))
  try {
    withUmask077(() => {
      const outRoot = join(scratch, 'nested-out-root')
      const plan = generateDomainVariant('paygrid', 42)
      const mat = materialize({ app: 'paygrid', plan, outRoot })
      try {
        assert.equal(statSync(outRoot).mode & 0o777, 0o755, 'created outRoot ancestor must be 0o755')
        assert.equal(
          statSync(join(outRoot, 'multihop-saas')).mode & 0o777,
          0o755,
          'multihop-saas parent dir must be 0o755',
        )

        const { dirs, files } = walkTree(mat.root)
        assert.ok(dirs.length >= 4, 'materialized tree should include root, apps/<app>/src, and lib')
        assert.ok(files.length >= 5, 'materialized tree should include source files, runtime helpers, and metadata')

        for (const dir of dirs) {
          assert.equal(statSync(dir).mode & 0o777, 0o755, `dir must be 0o755: ${dir}`)
        }
        for (const file of files) {
          assert.equal(statSync(file).mode & 0o777, 0o644, `file must be 0o644: ${file}`)
        }

        // Also ensure pre-existing 0o700 suiteRoot is repaired to 0o755 on subsequent materialize calls.
        chmodSync(join(outRoot, 'multihop-saas'), 0o700)
        const mat2 = materialize({ app: 'paygrid', plan, outRoot })
        try {
          assert.equal(statSync(join(outRoot, 'multihop-saas')).mode & 0o777, 0o755)
          assert.equal(statSync(mat2.root).mode & 0o777, 0o755)
        } finally {
          mat2.cleanup()
        }
      } finally {
        mat.cleanup()
      }
    })
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('prepareReposMount stages 0o700/0o600 repos into container-readable 0o755/0o644 copy under umask 0077 while excluding secrets', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'guardian-repos-eacces-'))
  try {
    withUmask077(() => {
      // Simulate host umask 0077 + locked-down /repos/bench/<app> layout.
      const reposDir = join(scratch, 'repos-root')
      const appDir = join(reposDir, 'bench', 'sample-app')
      const srcDir = join(appDir, 'src')
      const srcCredsDir = join(srcDir, 'credentials')
      const gitDir = join(appDir, '.git')
      const gitHooksDir = join(gitDir, 'hooks')
      const vaultCredsDir = join(appDir, 'credentials')

      mkdirSync(srcCredsDir, { recursive: true })
      mkdirSync(gitHooksDir, { recursive: true })
      mkdirSync(vaultCredsDir, { recursive: true })

      const serverFile = join(srcDir, 'server.ts')
      const credHandlerFile = join(srcCredsDir, 'handler.ts')
      const envExampleFile = join(appDir, '.env.example')
      const gitConfigFile = join(gitDir, 'config')
      const gitHookFile = join(gitHooksDir, 'post-checkout')
      const envFile = join(appDir, '.env')
      const keyFile = join(appDir, 'tls.key')
      const patFile = join(vaultCredsDir, 'github.pat')
      const modelCredFile = join(vaultCredsDir, 'model-12345')
      const escapeLink = join(appDir, 'escape-link')

      writeFileSync(serverFile, 'export const ok = true\n')
      writeFileSync(credHandlerFile, 'export function checkAuth() { return true }\n')
      writeFileSync(envExampleFile, 'PORT=3000\n')
      writeFileSync(gitConfigFile, '[remote "origin"]\n\turl = https://x-access-token:tok_unit_test@github.com/org/repo.git\n')
      writeFileSync(gitHookFile, '#!/bin/sh\necho hook\n')
      writeFileSync(envFile, 'API_SECRET=unit_test_secret_value\n')
      writeFileSync(keyFile, 'unit-test-key-material\n')
      writeFileSync(patFile, 'unit_test_pat_value\n')
      writeFileSync(modelCredFile, 'unit_test_model_credential\n')
      symlinkSync('/etc/passwd', escapeLink)

      // Confirm restrictive host permissions were applied under umask 0077.
      assert.equal(statSync(reposDir).mode & 0o777, 0o700)
      assert.equal(statSync(serverFile).mode & 0o777, 0o600)
      assert.equal(statSync(envFile).mode & 0o777, 0o600)
      assert.equal(statSync(patFile).mode & 0o777, 0o600)
      assert.equal(statSync(modelCredFile).mode & 0o777, 0o600)
      assert.equal(statSync(gitConfigFile).mode & 0o777, 0o600)

      const prepared = prepareReposMount(reposDir)
      assert.ok(prepared, 'prepareReposMount must return a prepared mount')
      try {
        assert.equal(prepared.staged, true, '0o700/0o600 tree must be staged for UID 10001 readability')
        assert.notEqual(prepared.mountDir, realpathSync(reposDir))
        assert.ok(prepared.excludedCount >= 7, `expected sensitive/symlink entries excluded, got ${prepared.excludedCount}`)

        // Every directory and regular file in the staged mount must be readable/traversable by UID 10001.
        const { dirs, files } = walkTree(prepared.mountDir)
        for (const dir of dirs) {
          const mode = statSync(dir).mode & 0o777
          assert.equal(mode, 0o755, `staged dir must be 0o755: ${dir}`)
          assert.equal(mode & 0o005, 0o005, `staged dir must have o+rx: ${dir}`)
        }
        for (const file of files) {
          const mode = statSync(file).mode & 0o777
          assert.equal(mode, 0o644, `staged file must be 0o644: ${file}`)
          assert.equal(mode & 0o004, 0o004, `staged file must have o+r: ${file}`)
        }

        // Source files (including source code under src/credentials/) and .env.example are preserved.
        assert.equal(
          readFileSync(join(prepared.mountDir, 'bench', 'sample-app', 'src', 'server.ts'), 'utf8'),
          'export const ok = true\n',
        )
        assert.equal(
          readFileSync(join(prepared.mountDir, 'bench', 'sample-app', 'src', 'credentials', 'handler.ts'), 'utf8'),
          'export function checkAuth() { return true }\n',
        )
        assert.equal(
          readFileSync(join(prepared.mountDir, 'bench', 'sample-app', '.env.example'), 'utf8'),
          'PORT=3000\n',
        )

        // Secret/credential/token files, git hooks, and symlinks must NOT exist in the staged tree.
        assert.equal(existsSync(join(prepared.mountDir, 'bench', 'sample-app', '.git', 'config')), false)
        assert.equal(existsSync(join(prepared.mountDir, 'bench', 'sample-app', '.git', 'hooks')), false)
        assert.equal(existsSync(join(prepared.mountDir, 'bench', 'sample-app', '.env')), false)
        assert.equal(existsSync(join(prepared.mountDir, 'bench', 'sample-app', 'tls.key')), false)
        assert.equal(existsSync(join(prepared.mountDir, 'bench', 'sample-app', 'credentials', 'github.pat')), false)
        assert.equal(existsSync(join(prepared.mountDir, 'bench', 'sample-app', 'credentials', 'model-12345')), false)
        assert.equal(existsSync(join(prepared.mountDir, 'bench', 'sample-app', 'escape-link')), false)

        // Original host files MUST keep their exact permissions (0600 secrets stay strictly 0600).
        assert.equal(statSync(reposDir).mode & 0o777, 0o700)
        assert.equal(statSync(gitConfigFile).mode & 0o777, 0o600)
        assert.equal(statSync(envFile).mode & 0o777, 0o600)
        assert.equal(statSync(keyFile).mode & 0o777, 0o600)
        assert.equal(statSync(patFile).mode & 0o777, 0o600)
        assert.equal(statSync(modelCredFile).mode & 0o777, 0o600)
      } finally {
        const stagedPath = prepared.mountDir
        prepared.cleanup()
        prepared.cleanup() // idempotent
        assert.equal(existsSync(stagedPath), false, 'cleanup must remove staged directory')
      }
    })
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('prepareReposMount binds directly without copying when tree is already 0o755/0o644 and clean, but stages if .git/config has tokens', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'guardian-repos-clean-'))
  try {
    const reposDir = join(scratch, 'clean-repos')
    const appDir = join(reposDir, 'acme', 'demo')
    const gitDir = join(appDir, '.git')
    mkdirSync(gitDir, { recursive: true })
    const srcFile = join(appDir, 'index.ts')
    const gitConfig = join(gitDir, 'config')
    writeFileSync(srcFile, 'export const v = 1\n')
    writeFileSync(gitConfig, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/acme/demo.git\n')

    chmodSync(reposDir, 0o755)
    chmodSync(join(reposDir, 'acme'), 0o755)
    chmodSync(appDir, 0o755)
    chmodSync(gitDir, 0o755)
    chmodSync(srcFile, 0o644)
    chmodSync(gitConfig, 0o644)

    const direct = prepareReposMount(reposDir)
    assert.ok(direct)
    assert.equal(direct.staged, false, 'clean world-readable repo should bind directly')
    assert.equal(direct.mountDir, realpathSync(reposDir))
    assert.equal(direct.excludedCount, 0)
    direct.cleanup()
    assert.equal(existsSync(reposDir), true, 'direct mount cleanup must never delete caller reposDir')

    // Adding an auth header to a world-readable .git/config forces clean staging that strips it.
    writeFileSync(gitConfig, '[http "https://github.com/"]\n\textraheader = AUTHORIZATION: basic dGVzdA==\n')
    chmodSync(gitConfig, 0o644)
    const staged = prepareReposMount(reposDir)
    assert.ok(staged)
    try {
      assert.equal(staged.staged, true)
      assert.equal(existsSync(join(staged.mountDir, 'acme', 'demo', '.git', 'config')), false)
      assert.equal(existsSync(join(staged.mountDir, 'acme', 'demo', 'index.ts')), true)
    } finally {
      staged.cleanup()
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('LinuxWorkerBackend run() and verifyStaticAst() mount staged readable /repos and clean up afterwards', async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'guardian-repos-backend-'))
  try {
    await withUmask077Async(async () => {
      const reposDir = join(scratch, 'restricted-repos')
      const appDir = join(reposDir, 'bench', 'app')
      mkdirSync(appDir, { recursive: true })
      const sourceFile = join(appDir, 'app.ts')
      const secretFile = join(appDir, 'github.pat')
      writeFileSync(sourceFile, 'export const answer = 42\n')
      writeFileSync(secretFile, 'top-secret-token\n')

      let observedMountDir = ''
      const runner = async (args: string[]) => {
        if (args[0] === 'container' && args[1] === 'ls') return ''
        if (args[0] === 'container' && args[1] === 'create') {
          const mountIdx = args.findIndex((a, i) => i > 0 && args[i - 1] === '--mount' && a.includes('target=/repos,readonly'))
          assert.ok(mountIdx !== -1, 'container create must include readonly /repos bind mount')
          const match = /^type=bind,source=([^,]+),target=\/repos,readonly$/.exec(args[mountIdx]!)
          assert.ok(match, `unexpected mount spec: ${args[mountIdx]}`)
          observedMountDir = match[1]!
          assert.notEqual(observedMountDir, realpathSync(reposDir))
          assert.equal(statSync(observedMountDir).mode & 0o777, 0o755)
          assert.equal(statSync(join(observedMountDir, 'bench', 'app', 'app.ts')).mode & 0o777, 0o644)
          assert.equal(existsSync(join(observedMountDir, 'bench', 'app', 'github.pat')), false)
          return 'created'
        }
        if (args[0] === 'container' && args[1] === 'start') {
          return JSON.stringify({ exitCode: 0, stdout: 'ok', stderr: '', outputs: {} })
        }
        return ''
      }

      const backend = new LinuxWorkerBackend({ dockerRunner: runner })
      const res = await backend.run(
        { assignmentId: randomUUID(), files: [], command: 'true', outputs: [] },
        AbortSignal.timeout(5_000),
        { reposDir },
      )
      assert.equal(res.exitCode, 0)
      assert.ok(observedMountDir, 'mount dir should have been captured during create')
      assert.equal(existsSync(observedMountDir), false, 'staged mount dir must be cleaned up after run()')
      assert.equal(statSync(secretFile).mode & 0o777, 0o600, 'original secret file mode must remain 0o600')

      // Verify cleanup also runs on container start failure during verifyStaticAst().
      let astMountDir = ''
      const failingRunner = async (args: string[]) => {
        if (args[0] === 'container' && args[1] === 'ls') return ''
        if (args[0] === 'container' && args[1] === 'create') {
          const mountArg = args.find(a => a.includes('target=/repos,readonly')) ?? ''
          astMountDir = /^type=bind,source=([^,]+),target=\/repos,readonly$/.exec(mountArg)?.[1] ?? ''
          assert.ok(astMountDir && existsSync(astMountDir))
          return 'created'
        }
        if (args[0] === 'container' && args[1] === 'start') {
          throw new Error('simulated start failure')
        }
        return ''
      }
      const failingBackend = new LinuxWorkerBackend({ dockerRunner: failingRunner })
      await assert.rejects(
        () => failingBackend.verifyStaticAst(
          randomUUID(),
          { repo: 'bench/app', file: 'app.ts', startLine: 1, endLine: 1, engine: 'ast-grep', ruleOrPattern: 'const $X = 42' },
          AbortSignal.timeout(5_000),
          { reposDir },
        ),
        /simulated start failure/,
      )
      assert.ok(astMountDir)
      assert.equal(existsSync(astMountDir), false, 'staged mount dir must be cleaned up on verifyStaticAst() failure')
    })
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})
