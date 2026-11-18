import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Bash, InMemoryFs, MountableFs, OverlayFs } from 'just-bash'

type Input = {
  files: Array<{ name: string; content: string }>
  command: string
  outputs: string[]
}

const maxOutput = 32_768
const cleanName = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/

async function main() {
  const source = readFileSync(0, 'utf8')
  if (Buffer.byteLength(source) > 512 * 1024) throw new Error('Assignment inputs exceed the worker limit.')
  const job = JSON.parse(source) as Input
  const inputDirectory = await mkdtemp(join(tmpdir(), 'guardian-inputs-'))
  for (const input of job.files) {
    if (!cleanName.test(input.name)) throw new Error('Invalid input name.')
    await writeFile(join(inputDirectory, input.name), input.content, { flag: 'wx', mode: 0o400 })
  }

  const scratch = new InMemoryFs({}, { maxTotalBytes: 512 * 1024 })
  scratch.mkdirSync('/work')
  const fs = new MountableFs({
    base: scratch,
    mounts: [{ mountPoint: '/evidence', filesystem: new OverlayFs({
      root: inputDirectory, mountPoint: '/', readOnly: true, allowSymlinks: false, maxFileReadSize: 65_536,
    }) }],
  })
  const shell = new Bash({
    cwd: '/work', fs, executionLimitProfile: 'hardened', python: false, javascript: false,
  })
  const result = await shell.exec(job.command)
  const outputs: Record<string, string> = {}
  for (const name of job.outputs) {
    const path = '/work/' + name
    if (!cleanName.test(name) || !await scratch.exists(path)) continue
    const info = await scratch.lstat(path)
    if (info.isFile && !info.isSymbolicLink && info.size <= maxOutput) outputs[name] = await scratch.readFile(path)
  }
  process.stdout.write(JSON.stringify({
    exitCode: result.exitCode,
    stdout: result.stdout.slice(0, maxOutput),
    stderr: result.stderr.slice(0, maxOutput),
    outputs,
  }))
}

main().catch(() => {
  process.stderr.write('The evidence worker could not execute the operation.\n')
  process.exitCode = 1
})
