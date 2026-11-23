// Pure-JS shell SIMULATOR. No real process is ever spawned (no node:child_process / eval / vm). It
// substitutes args into a command template, tokenizes POSIX-ishly (quotes, ; && || | newline,
// $(...) / `...` command substitution, > redirects) and interprets a tiny whitelist of fake programs
// with deterministic output. If parsing reveals more than the single intended command — a second
// command, a command substitution, or a pipe — it emits command_injection_simulated.
import type { Oracle } from './oracle.ts'

const WHITELIST = new Set(['echo', 'id', 'ls', 'cat', 'tar', 'gzip', 'ping', 'nslookup', 'whoami'])

export interface SimResult {
  output: string
  commands: string[]
}

interface Parsed {
  segments: string[]
  substitutions: string[]
  hadPipe: boolean
  hadRedirect: boolean
  unexpectedProgram: boolean
}

function substitute(template: string, args: string[]): string {
  return template.replace(/\{(\d+)\}/g, (_m, d) => args[Number(d)] ?? '')
}

function parse(line: string): Parsed {
  const segments: string[] = []
  const substitutions: string[] = []
  let hadPipe = false
  let hadRedirect = false
  let buf = ''
  let quote: '"' | "'" | null = null
  const push = () => {
    const t = buf.trim()
    if (t) segments.push(t)
    buf = ''
  }
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) {
      if (c === quote) quote = null
      else buf += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      continue
    }
    if (c === '$' && line[i + 1] === '(') {
      let depth = 1
      let inner = ''
      i += 2
      for (; i < line.length && depth > 0; i++) {
        if (line[i] === '(') depth++
        else if (line[i] === ')') {
          depth--
          if (depth === 0) break
        }
        inner += line[i]
      }
      substitutions.push(inner.trim())
      continue
    }
    if (c === '`') {
      let inner = ''
      i++
      for (; i < line.length && line[i] !== '`'; i++) inner += line[i]
      substitutions.push(inner.trim())
      continue
    }
    if (c === '|') {
      hadPipe = true
      if (line[i + 1] === '|') i++
      push()
      continue
    }
    if (c === '&' && line[i + 1] === '&') {
      i++
      push()
      continue
    }
    if (c === ';' || c === '\n') {
      push()
      continue
    }
    if (c === '>') {
      hadRedirect = true
      if (line[i + 1] === '>') i++
      // consume redirect target (a filename, not a command)
      push()
      i++
      while (i < line.length && line[i] === ' ') i++
      while (i < line.length && !/[\s;|&\n]/.test(line[i])) i++
      i--
      continue
    }
    buf += c
  }
  push()
  const commandLikes = [...segments, ...substitutions]
  const unexpectedProgram = commandLikes.some((cmd) => {
    const prog = cmd.trim().split(/\s+/)[0]
    return prog ? !WHITELIST.has(prog) : false
  })
  return { segments, substitutions, hadPipe, hadRedirect, unexpectedProgram }
}

function runProgram(cmd: string): string {
  const parts = cmd.trim().split(/\s+/)
  const prog = parts[0]
  const rest = parts.slice(1)
  switch (prog) {
    case 'echo':
      return rest.join(' ') + '\n'
    case 'id':
      return 'uid=1000(app) gid=1000(app) groups=1000(app)\n'
    case 'whoami':
      return 'app\n'
    case 'ls':
      return 'file1.txt\nfile2.txt\n'
    case 'cat':
      return `[contents of ${rest.join(' ') || 'file'}]\n`
    case 'tar':
      return 'tar: simulated archive created\n'
    case 'gzip':
      return 'gzip: simulated compression done\n'
    case 'ping':
      return `PING ${rest[rest.length - 1] ?? 'host'}: 56 data bytes\n`
    case 'nslookup':
      return `Name: ${rest[0] ?? 'host'}\nAddress: 127.0.0.1\n`
    default:
      return ''
  }
}

export function simulateCommand(template: string, args: string[], oracle?: Oracle): SimResult {
  const line = substitute(template, args)
  const p = parse(line)
  const commands = [...p.segments, ...p.substitutions]
  const injection =
    p.substitutions.length > 0 || p.segments.length > 1 || p.hadPipe || p.hadRedirect || p.unexpectedProgram
  if (injection && oracle) {
    oracle.emit('command_injection_simulated', { parsed: commands.join(' ; ') }, 'shell')
  }
  const output = commands.map(runProgram).join('')
  return { output, commands }
}
