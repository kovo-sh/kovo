// Minimal git object writer/reader for the white-box fixture. Writes real loose
// objects (blob/tree/commit, zlib + SHA-1) so the repo has inspectable history
// without invoking git (no child_process anywhere in this suite).
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { deflateSync, inflateSync } from 'node:zlib'

export interface GitCommit {
  sha: string
  tree: string
  parents: string[]
  message: string
  ts: number
  files: string[]
}

export interface CommitSpec {
  message: string
  ts: number
  files: Record<string, string>
}

interface TreeNode {
  files: Map<string, string>
  dirs: Map<string, TreeNode>
}

function emptyNode(): TreeNode {
  return { files: new Map(), dirs: new Map() }
}

function insertFile(root: TreeNode, path: string, content: string): void {
  const parts = path.split('/').filter(Boolean)
  let node = root
  for (let i = 0; i < parts.length - 1; i++) {
    let next = node.dirs.get(parts[i])
    if (!next) {
      next = emptyNode()
      node.dirs.set(parts[i], next)
    }
    node = next
  }
  node.files.set(parts[parts.length - 1], content)
}

function writeObject(gitDir: string, type: string, body: Buffer): string {
  const header = Buffer.from(`${type} ${body.length}\0`, 'utf8')
  const full = Buffer.concat([header, body])
  const sha = createHash('sha1').update(full).digest('hex')
  const dir = join(gitDir, 'objects', sha.slice(0, 2))
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, sha.slice(2)), deflateSync(full))
  return sha
}

function writeBlob(gitDir: string, content: string): string {
  return writeObject(gitDir, 'blob', Buffer.from(content, 'utf8'))
}

function writeTree(gitDir: string, node: TreeNode): string {
  type Entry = { mode: string; name: string; sha: string; sortKey: string }
  const entries: Entry[] = []
  for (const [name, content] of node.files) {
    entries.push({ mode: '100644', name, sha: writeBlob(gitDir, content), sortKey: name })
  }
  for (const [name, child] of node.dirs) {
    entries.push({ mode: '40000', name, sha: writeTree(gitDir, child), sortKey: `${name}/` })
  }
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.sortKey, 'utf8'), Buffer.from(b.sortKey, 'utf8')))
  const chunks: Buffer[] = []
  for (const entry of entries) {
    chunks.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'))
    chunks.push(Buffer.from(entry.sha, 'hex'))
  }
  return writeObject(gitDir, 'tree', Buffer.concat(chunks))
}

function writeCommitObject(
  gitDir: string,
  tree: string,
  parents: string[],
  ts: number,
  message: string,
  author: string,
): string {
  const lines = [`tree ${tree}`]
  for (const parent of parents) lines.push(`parent ${parent}`)
  lines.push(`author ${author} <${author.replace(/\s+/g, '.')}@qa.example.invalid> ${ts} +0000`)
  lines.push(`committer ${author} <${author.replace(/\s+/g, '.')}@qa.example.invalid> ${ts} +0000`)
  const body = Buffer.from(`${lines.join('\n')}\n\n${message}\n`, 'utf8')
  return writeObject(gitDir, 'commit', body)
}

function readObject(gitDir: string, sha: string): { type: string; body: Buffer } {
  const raw = inflateSync(readFileSync(join(gitDir, 'objects', sha.slice(0, 2), sha.slice(2))))
  const nul = raw.indexOf(0)
  if (nul < 0) throw new Error(`git: corrupt object ${sha}`)
  const header = raw.subarray(0, nul).toString('utf8')
  const type = header.slice(0, header.indexOf(' '))
  return { type, body: raw.subarray(nul + 1) }
}

function parseCommitBody(body: Buffer): { tree: string; parents: string[]; ts: number; message: string } {
  const text = body.toString('utf8')
  const split = text.indexOf('\n\n')
  const head = split < 0 ? text : text.slice(0, split)
  const message = split < 0 ? '' : text.slice(split + 2).replace(/\n$/, '')
  let tree = ''
  let ts = 0
  const parents: string[] = []
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim()
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim())
    else if (line.startsWith('author ')) {
      const match = / (\d+) [+-]\d{4}$/.exec(line)
      if (match) ts = Number(match[1])
    }
  }
  return { tree, parents, ts, message }
}

/** Write a fresh repository (HEAD + refs + loose objects + working tree) from snapshots. */
export function createGitRepo(dir: string, commits: CommitSpec[], author = 'Kovo QA'): GitCommit[] {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  const gitDir = join(dir, '.git')
  mkdirSync(gitDir, { recursive: true })
  writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
  mkdirSync(join(gitDir, 'refs', 'heads'), { recursive: true })
  writeFileSync(
    join(gitDir, 'config'),
    '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n',
  )

  const out: GitCommit[] = []
  let parent: string | null = null
  for (const spec of commits) {
    const root = emptyNode()
    const paths = Object.keys(spec.files).sort()
    for (const path of paths) insertFile(root, path, spec.files[path])
    const tree = writeTree(gitDir, root)
    const sha = writeCommitObject(gitDir, tree, parent ? [parent] : [], spec.ts, spec.message, author)
    out.push({ sha, tree, parents: parent ? [parent] : [], message: spec.message, ts: spec.ts, files: paths })
    parent = sha
  }

  const head = parent ?? ''
  writeFileSync(join(gitDir, 'refs', 'heads', 'main'), `${head}\n`)
  const latest = commits[commits.length - 1]
  for (const [path, content] of Object.entries(latest.files)) {
    const target = join(dir, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return out
}

/** Read the first-parent history, newest first. */
export function readGitLog(dir: string): GitCommit[] {
  const gitDir = join(dir, '.git')
  const head = readFileSync(join(gitDir, 'HEAD'), 'utf8').trim()
  if (!head.startsWith('ref: ')) throw new Error('git: detached HEAD is not supported')
  const ref = head.slice(5).trim()
  let sha: string | null = readFileSync(join(gitDir, ref), 'utf8').trim()
  const out: GitCommit[] = []
  while (sha) {
    const obj = readObject(gitDir, sha)
    if (obj.type !== 'commit') throw new Error(`git: ${sha} is not a commit`)
    const parsed = parseCommitBody(obj.body)
    out.push({ sha, tree: parsed.tree, parents: parsed.parents, message: parsed.message, ts: parsed.ts, files: [] })
    sha = parsed.parents[0] ?? null
  }
  return out
}

function walkTree(gitDir: string, treeSha: string, prefix: string, out: Map<string, string>): void {
  const obj = readObject(gitDir, treeSha)
  if (obj.type !== 'tree') throw new Error(`git: ${treeSha} is not a tree`)
  let offset = 0
  while (offset < obj.body.length) {
    const space = obj.body.indexOf(0x20, offset)
    const nul = obj.body.indexOf(0, space)
    const mode = obj.body.subarray(offset, space).toString('utf8')
    const name = obj.body.subarray(space + 1, nul).toString('utf8')
    const sha = obj.body.subarray(nul + 1, nul + 21).toString('hex')
    offset = nul + 21
    const path = prefix ? `${prefix}/${name}` : name
    if (mode === '40000') walkTree(gitDir, sha, path, out)
    else {
      const blob = readObject(gitDir, sha)
      if (blob.type === 'blob') out.set(path, blob.body.toString('utf8'))
    }
  }
}

/** Read a file's content as of a given commit. */
export function readFileAtCommit(dir: string, commitSha: string, path: string): string | null {
  const gitDir = join(dir, '.git')
  const obj = readObject(gitDir, commitSha)
  if (obj.type !== 'commit') return null
  const { tree } = parseCommitBody(obj.body)
  const files = new Map<string, string>()
  walkTree(gitDir, tree, '', files)
  return files.get(path) ?? null
}

export function listFilesAtCommit(dir: string, commitSha: string): string[] {
  const gitDir = join(dir, '.git')
  const obj = readObject(gitDir, commitSha)
  if (obj.type !== 'commit') return []
  const { tree } = parseCommitBody(obj.body)
  const files = new Map<string, string>()
  walkTree(gitDir, tree, '', files)
  return [...files.keys()].sort()
}
