// Small in-memory virtual filesystem for export/treasury surfaces. No real path is ever touched.
export interface VirtualFile {
  path: string
  body: string
}

export interface Vfs {
  read(path: string): string | null
  readWithin(prefix: string, relative: string): string | null
  readPrefix(prefix: string): string | null
  list(prefix: string): string[]
  write(file: VirtualFile): void
}

function normalize(path: string): string {
  const parts: string[] = []
  for (const raw of path.split('/')) {
    if (!raw || raw === '.') continue
    if (raw === '..') {
      parts.pop()
      continue
    }
    parts.push(raw)
  }
  return `/${parts.join('/')}`
}

export function createVfs(files: readonly VirtualFile[] = []): Vfs {
  const store = new Map<string, string>()
  for (const file of files) store.set(normalize(file.path), file.body)

  return {
    read(path) {
      return store.get(normalize(path)) ?? null
    },
    readWithin(prefix, relative) {
      const base = normalize(prefix).replace(/\/$/, '')
      const resolved = normalize(`${base}/${relative}`)
      if (!resolved.startsWith(`${base}/`)) return null
      return store.get(resolved) ?? null
    },
    readPrefix(prefix) {
      const base = normalize(prefix).replace(/\/$/, '')
      for (const [path, body] of store) {
        if (path.startsWith(base)) return body
      }
      return null
    },
    list(prefix) {
      const base = normalize(prefix).replace(/\/$/, '')
      return [...store.keys()].filter((path) => path.startsWith(base))
    },
    write(file) {
      store.set(normalize(file.path), file.body)
    },
  }
}
