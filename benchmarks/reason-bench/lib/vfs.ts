// In-memory virtual filesystem. App file features (downloads, template loads, XXE file://, exports)
// read ONLY through this — the real filesystem is never touched (no node:fs anywhere). readWithin
// enforces a jail: it normalizes an attacker-supplied path (POSIX style, one layer of percent
// decoding, backslash separators, ./ and ../ collapsing) and, if the result escapes the jail,
// emits path_escape while still returning the virtual file content so the simulated attacker "sees"
// what a real traversal would have leaked.
import type { Oracle } from './oracle.ts'

export interface Vfs {
  read(path: string): string | null
  list(dir: string): string[]
  write(path: string, data: string): void
  exists(path: string): boolean
  readWithin(jailDir: string, userPath: string): string | null
}

/** Collapse a path into an absolute POSIX virtual path (no leading drive, always rooted at '/'). */
function normalize(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/')
  const stack: string[] = []
  for (const seg of parts) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      stack.pop()
      continue
    }
    stack.push(seg)
  }
  return '/' + stack.join('/')
}

/** Decode a single layer of percent-encoding, limited to separator/dot bytes (upper or lower). */
function decodeOneLayer(s: string): string {
  return s.replace(/%2e/gi, '.').replace(/%2f/gi, '/').replace(/%5c/gi, '\\')
}

function dirnameOf(path: string): string {
  const i = path.lastIndexOf('/')
  return i <= 0 ? '/' : path.slice(0, i)
}

export function createVfs(oracle: Oracle, files: Record<string, string> = {}): Vfs {
  const store = new Map<string, string>()
  for (const [k, v] of Object.entries(files)) store.set(normalize(k), v)

  return {
    read(path) {
      return store.get(normalize(path)) ?? null
    },
    list(dir) {
      const base = normalize(dir)
      const out: string[] = []
      for (const key of store.keys()) {
        if (dirnameOf(key) === base) out.push(key)
      }
      return out.sort()
    },
    write(path, data) {
      store.set(normalize(path), data)
    },
    exists(path) {
      return store.has(normalize(path))
    },
    readWithin(jailDir, userPath) {
      const jail = normalize(jailDir)
      const decoded = decodeOneLayer(userPath).replace(/\\/g, '/')
      const combined = decoded.startsWith('/') ? decoded : jail + '/' + decoded
      const resolved = normalize(combined)
      const inside = resolved === jail || resolved.startsWith(jail + '/')
      if (!inside) {
        oracle.emit('path_escape', { jailDir: jail, resolved }, `vfs:${jail}`)
      }
      return store.get(resolved) ?? null
    },
  }
}

/** Synthetic system files an app might expose; secrets are clearly fake rbs_/rb_fake tokens. */
export function defaultSystemFiles(canaries: { passwdUsers?: string[]; secretEnv?: string }): Record<string, string> {
  const users = canaries.passwdUsers ?? ['app', 'deploy']
  const passwdLines = ['root:x:0:0:root:/root:/bin/bash', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin']
  users.forEach((u, i) => passwdLines.push(`${u}:x:${1000 + i}:${1000 + i}:${u}:/home/${u}:/bin/bash`))
  const secret = canaries.secretEnv ?? 'rbs_fake_000000000000'
  return {
    '/etc/passwd': passwdLines.join('\n') + '\n',
    '/app/config/secrets.env': `API_KEY=${secret}\nDB_PASSWORD=rb_fake_db_pw\n`,
    '/app/.env': 'NODE_ENV=production\nSESSION_SECRET=rb_fake_session_secret\n',
  }
}
