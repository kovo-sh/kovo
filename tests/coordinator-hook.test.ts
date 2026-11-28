import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HOOK_SCRIPT = join(REPO_ROOT, 'scripts', 'coordinator-pretool-hook.mjs')
const HOOKS_CONFIG_PATH = join(REPO_ROOT, '.agents', 'hooks.json')
const SKILL_PATH = join(REPO_ROOT, '.agents', 'skills', 'coordinator', 'SKILL.md')

interface HookOutput {
  decision: 'allow' | 'deny' | 'ask' | 'force_ask'
  reason?: string
}

function runHook(
  stdinPayload: unknown,
  envOverrides: Record<string, string | undefined> = {},
): HookOutput {
  const input =
    typeof stdinPayload === 'string' ? stdinPayload : JSON.stringify(stdinPayload)
  const cleanEnv: Record<string, string> = {}
  for (const [k, v] of Object.entries(process.env)) {
    if (
      v !== undefined &&
      k !== 'KOVO_COORDINATOR_MODE' &&
      k !== 'KOVO_COORDINATOR_HOOK_BYPASS' &&
      k !== 'ANTIGRAVITY_CONVERSATION_ID' &&
      k !== 'ANTIGRAVITY_APP_DATA_DIR'
    ) {
      cleanEnv[k] = v
    }
  }
  for (const [k, v] of Object.entries(envOverrides)) {
    if (v === undefined) delete cleanEnv[k]
    else cleanEnv[k] = v
  }

  const res = spawnSync(process.execPath, [HOOK_SCRIPT], {
    input,
    encoding: 'utf8',
    cwd: join(REPO_ROOT, '.agents'),
    env: cleanEnv,
    timeout: 5000,
  })
  assert.equal(res.status, 0, `hook exited with ${res.status}, stderr=${res.stderr}`)
  assert.ok(res.stdout.trim().length > 0, 'hook produced empty stdout')
  return JSON.parse(res.stdout.trim()) as HookOutput
}

function makeFakeBrain(opts: {
  convId: string
  withSwarmJson?: boolean
  swarmIdOverride?: string
  step0Source?: 'USER_EXPLICIT' | 'SYSTEM'
  step0Type?: 'USER_INPUT' | 'SYSTEM_MESSAGE'
}): { brainDir: string; transcriptPath: string; cleanup: () => void } {
  const base = mkdtempSync(join(tmpdir(), 'kovo-coord-hook-test-'))
  const brainDir = join(base, opts.convId)
  const logsDir = join(brainDir, '.system_generated', 'logs')
  mkdirSync(logsDir, { recursive: true })
  const transcriptPath = join(logsDir, 'transcript.jsonl')
  if (opts.step0Source && opts.step0Type) {
    writeFileSync(
      transcriptPath,
      JSON.stringify({
        step_index: 0,
        source: opts.step0Source,
        type: opts.step0Type,
        content: 'test',
      }) + '\n',
      'utf8',
    )
  }
  if (opts.withSwarmJson) {
    const swarmDir = join(brainDir, '.system_generated', 'swarm')
    mkdirSync(swarmDir, { recursive: true })
    writeFileSync(
      join(swarmDir, 'swarm.json'),
      JSON.stringify({
        version: 1,
        backend: 'local',
        swarm_id: opts.swarmIdOverride ?? opts.convId,
      }),
      'utf8',
    )
  }
  return {
    brainDir,
    transcriptPath,
    cleanup: () => rmSync(base, { recursive: true, force: true }),
  }
}

describe('coordinator PreToolUse hook & config (A4 #1)', () => {
  it('configures .agents/hooks.json with valid Antigravity PreToolUse schema and resolvable script', () => {
    const raw = readFileSync(HOOKS_CONFIG_PATH, 'utf8')
    const cfg = JSON.parse(raw) as Record<
      string,
      {
        enabled?: boolean
        PreToolUse?: Array<{
          matcher: string
          hooks: Array<{ type?: string; command: string; timeout?: number }>
        }>
      }
    >
    const guard = cfg['coordinator-delegation-guard']
    assert.ok(guard, 'expected coordinator-delegation-guard hook entry')
    assert.equal(guard.enabled, true)
    assert.ok(Array.isArray(guard.PreToolUse) && guard.PreToolUse.length === 1)

    const matcherRe = new RegExp(`^(?:${guard.PreToolUse[0].matcher})$`)
    assert.ok(matcherRe.test('run_command'))
    assert.ok(matcherRe.test('read_file'))
    assert.ok(matcherRe.test('view_file'))

    const handler = guard.PreToolUse[0].hooks[0]
    assert.equal(handler.type, 'command')
    assert.equal(handler.command, 'node ../scripts/coordinator-pretool-hook.mjs')
    assert.ok((handler.timeout ?? 30) <= 10)
  })

  it('documents the 1-Call Budget & Subagent Routing Table and Brief Hygiene Rule in .agents/skills/coordinator/SKILL.md', () => {
    const skill = readFileSync(SKILL_PATH, 'utf8')
    assert.match(skill, /## 1-Call Budget & Subagent Routing Table/)
    assert.match(skill, /invoke_subagent\(typeName:\s*"research"\)/)
    assert.match(skill, /invoke_subagent\(typeName:\s*"self"\)/)
    assert.match(skill, /swarm\(action="add",\s*workspace="share"\)/)
    assert.match(skill, /KOVO_COORDINATOR_HOOK_BYPASS=1/)
    assert.match(skill, /Brief Hygiene Rule/)
    assert.match(skill, /file:line` \+ symbol\/function name/)
  })

  it('allows whitelisted orchestration commands in coordinator mode', () => {
    const brain = makeFakeBrain({
      convId: 'coord-conv-001',
      withSwarmJson: true,
      step0Source: 'USER_EXPLICIT',
      step0Type: 'USER_INPUT',
    })
    try {
      const allowedCommands = [
        'git status -sb',
        'git log --oneline -n 10',
        'git commit -m "docs: mention ssh and grep in message"',
        'git log --grep=ssh -n 5',
        'scripts/merge-stream.sh agents/coord-hook-delegation',
        'bash scripts/merge-stream.sh agents/foo',
        'npx tsx scripts/certify-v8.ts --out /tmp/score.json',
        'node scripts/certify-v8.ts',
        'KOVO_WORKER_IMAGE=kovo-worker:abc npx tsx scripts/benchmark-multihop.ts --smoke',
        "newgrp docker -c 'npx tsx scripts/benchmark-multihop.ts --smoke'",
        'scripts/parallel-pulse.sh',
        'bash scripts/worker-source-hash.sh --tag kovo-worker:v4',
        'npm run worker:build',
        'uptime',
        'df -h',
        'ls -la',
        'git status -sb && uptime && df -h',
      ]

      for (const cmd of allowedCommands) {
        const out = runHook({
          conversationId: 'coord-conv-001',
          artifactDirectoryPath: brain.brainDir,
          transcriptPath: brain.transcriptPath,
          cwd: '/home/omarchy/kovo',
          workspacePaths: ['/home/omarchy/kovo'],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_allow',
            name: 'run_command',
            args: { CommandLine: cmd },
          },
        })
        assert.equal(out.decision, 'allow', `expected allow for whitelisted command: ${cmd}`)
      }
    } finally {
      brain.cleanup()
    }
  })

  it('hard-blocks ssh, docker exec, sqlite3, rg, grep, and git grep in coordinator mode', () => {
    const brain = makeFakeBrain({
      convId: 'coord-conv-002',
      withSwarmJson: true,
      step0Source: 'USER_EXPLICIT',
      step0Type: 'USER_INPUT',
    })
    try {
      const blockedCases: Array<{ cmd: string; expectedSubagent: 'self' | 'research' }> = [
        { cmd: 'ssh kovo-vm "docker ps"', expectedSubagent: 'self' },
        { cmd: 'git status && ssh -i ~/.ssh/id user@vm uptime', expectedSubagent: 'self' },
        { cmd: 'timeout 10 ssh kovo-vm ls', expectedSubagent: 'self' },
        { cmd: 'docker exec kovo-worker-1 ps aux', expectedSubagent: 'self' },
        { cmd: "newgrp docker -c 'docker exec -it kovo-worker ls'", expectedSubagent: 'self' },
        { cmd: 'sqlite3 ~/guardian-data/kovo.db "SELECT count(*) FROM runs"', expectedSubagent: 'self' },
        { cmd: 'rg -n "verifyClaim" src/server/', expectedSubagent: 'research' },
        { cmd: 'grep -rn "verifyClaim" src/', expectedSubagent: 'research' },
        { cmd: 'git status && grep -n foo benchmarks/multihop-saas/README.md', expectedSubagent: 'research' },
        { cmd: 'git grep "verifyClaim" src/', expectedSubagent: 'research' },
        { cmd: 'echo $(rg "token" worker/)', expectedSubagent: 'research' },
      ]

      for (const tc of blockedCases) {
        const out = runHook({
          conversationId: 'coord-conv-002',
          artifactDirectoryPath: brain.brainDir,
          transcriptPath: brain.transcriptPath,
          cwd: '/home/omarchy/kovo',
          workspacePaths: ['/home/omarchy/kovo'],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_deny',
            name: 'run_command',
            args: { CommandLine: tc.cmd },
          },
        })
        assert.equal(out.decision, 'deny', `expected deny for command: ${tc.cmd}`)
        assert.ok(out.reason && out.reason.includes(`invoke_subagent(typeName: '${tc.expectedSubagent}')`),
          `expected reason for "${tc.cmd}" to point to invoke_subagent(typeName: '${tc.expectedSubagent}'), got: ${out.reason}`)
      }
    } finally {
      brain.cleanup()
    }
  })

  it('hard-blocks coordinator inline read_file/view_file on src/, worker/, benchmarks/ while allowing plans/docs/skills', () => {
    const brain = makeFakeBrain({
      convId: 'coord-conv-003',
      withSwarmJson: true,
    })
    try {
      const blockedPaths = [
        '/home/omarchy/kovo/src/server/verify-rpc.ts',
        '/home/omarchy/kovo/worker/runner.ts',
        '/home/omarchy/kovo/benchmarks/multihop-saas/apps/demo/truth/blueprint.ts',
        'src/domain.ts',
        './worker/package.json',
        'docs/../src/server/index.ts',
      ]
      for (const p of blockedPaths) {
        const out = runHook({
          conversationId: 'coord-conv-003',
          artifactDirectoryPath: brain.brainDir,
          cwd: '/home/omarchy/kovo',
          workspacePaths: ['/home/omarchy/kovo'],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_read_deny',
            name: 'read_file',
            args: { Path: p },
          },
        })
        assert.equal(out.decision, 'deny', `expected deny for read_file on ${p}`)
        assert.match(out.reason ?? '', /invoke_subagent\(typeName: 'research'\)/)
      }

      const allowedPaths = [
        '/home/omarchy/kovo/plans/ROADMAP-v5.md',
        '/home/omarchy/kovo/.agents/skills/coordinator/SKILL.md',
        '/home/omarchy/kovo/AGENTS.md',
        '/home/omarchy/.gemini/antigravity-cli/brain/coord-conv-003/scratch/summary.md',
      ]
      for (const p of allowedPaths) {
        const out = runHook({
          conversationId: 'coord-conv-003',
          artifactDirectoryPath: brain.brainDir,
          cwd: '/home/omarchy/kovo',
          workspacePaths: ['/home/omarchy/kovo'],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_read_allow',
            name: 'read_file',
            args: { Path: p },
          },
        })
        assert.equal(out.decision, 'allow', `expected allow for read_file on ${p}`)
      }
    } finally {
      brain.cleanup()
    }
  })

  it('NEVER blocks swarm workers (worktree OR inherit) or research/self subagents', () => {
    const workerBrain = makeFakeBrain({
      convId: 'worker-conv-001',
      withSwarmJson: false,
      step0Source: 'SYSTEM',
      step0Type: 'SYSTEM_MESSAGE',
    })
    const subagentBrain = makeFakeBrain({
      convId: 'subagent-conv-001',
      withSwarmJson: false,
      step0Source: 'SYSTEM',
      step0Type: 'SYSTEM_MESSAGE',
    })
    const coordBrain = makeFakeBrain({
      convId: 'coord-conv-004',
      withSwarmJson: true,
    })

    try {
      // 1. Swarm worker in worktrees/<id>/swarm-* — NEVER blocked even if KOVO_COORDINATOR_MODE=1 or swarm.json were present
      const wtOut = runHook(
        {
          conversationId: 'coord-conv-004',
          artifactDirectoryPath: coordBrain.brainDir,
          cwd: '/home/omarchy/.gemini/antigravity-cli/worktrees/coord-conv-004/swarm-worker-abc123',
          workspacePaths: [
            '/home/omarchy/.gemini/antigravity-cli/worktrees/coord-conv-004/swarm-worker-abc123',
          ],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_wt',
            name: 'run_command',
            args: { CommandLine: 'rg "foo" src/ && ssh vm uptime' },
          },
        },
        { KOVO_COORDINATOR_MODE: '1' },
      )
      assert.equal(wtOut.decision, 'allow', 'worker worktree must never be blocked')

      // 2. Swarm inherit worker in main checkout (no swarm.json, SYSTEM step 0) — NEVER blocked even with KOVO_COORDINATOR_MODE=1
      const inheritWorkerOut = runHook(
        {
          conversationId: 'worker-conv-001',
          artifactDirectoryPath: workerBrain.brainDir,
          transcriptPath: workerBrain.transcriptPath,
          cwd: '/home/omarchy/kovo',
          workspacePaths: ['/home/omarchy/kovo'],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_inherit',
            name: 'read_file',
            args: { Path: '/home/omarchy/kovo/src/server/verify-rpc.ts' },
          },
        },
        { KOVO_COORDINATOR_MODE: '1' },
      )
      assert.equal(inheritWorkerOut.decision, 'allow', 'inherit swarm worker must never be blocked')

      // 3. Research / self subagent in main checkout — NEVER blocked
      const subagentOut = runHook(
        {
          conversationId: 'subagent-conv-001',
          artifactDirectoryPath: subagentBrain.brainDir,
          transcriptPath: subagentBrain.transcriptPath,
          cwd: '/home/omarchy/kovo',
          workspacePaths: ['/home/omarchy/kovo'],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_subagent',
            name: 'run_command',
            args: { CommandLine: 'ssh kovo-vm "docker exec kovo-worker sqlite3 db.sqlite .tables"' },
          },
        },
        { KOVO_COORDINATOR_MODE: '1' },
      )
      assert.equal(subagentOut.decision, 'allow', 'research/self subagent must never be blocked')

      // 4. Normal standalone session (no swarm.json, no KOVO_COORDINATOR_MODE) — NEVER blocked
      const normalOut = runHook({
        conversationId: 'standalone-conv-001',
        artifactDirectoryPath: subagentBrain.brainDir,
        cwd: '/home/omarchy/kovo',
        workspacePaths: ['/home/omarchy/kovo'],
        hookEventName: 'PreToolUse',
        toolCall: {
          id: 'toolu_normal',
          name: 'read_file',
          args: { Path: '/home/omarchy/kovo/src/server/verify-rpc.ts' },
        },
      })
      assert.equal(normalOut.decision, 'allow', 'standalone non-coordinator session must not be blocked')
    } finally {
      workerBrain.cleanup()
      subagentBrain.cleanup()
      coordBrain.cleanup()
    }
  })

  it('honors emergency KOVO_COORDINATOR_HOOK_BYPASS=1 escape hatch', () => {
    const brain = makeFakeBrain({
      convId: 'coord-conv-005',
      withSwarmJson: true,
    })
    try {
      const out = runHook(
        {
          conversationId: 'coord-conv-005',
          artifactDirectoryPath: brain.brainDir,
          cwd: '/home/omarchy/kovo',
          workspacePaths: ['/home/omarchy/kovo'],
          hookEventName: 'PreToolUse',
          toolCall: {
            id: 'toolu_bypass',
            name: 'run_command',
            args: { CommandLine: 'ssh kovo-vm "docker exec kovo-worker ps"' },
          },
        },
        { KOVO_COORDINATOR_HOOK_BYPASS: '1' },
      )
      assert.equal(out.decision, 'allow')
    } finally {
      brain.cleanup()
    }
  })

  it('fails open safely on empty, malformed, or incomplete stdin payloads', () => {
    const malformedInputs = [
      '',
      '   ',
      '{not valid json',
      'null',
      '[]',
      '{}',
      JSON.stringify({ toolCall: null }),
      JSON.stringify({ toolCall: { name: 'run_command' } }),
      JSON.stringify({ toolCall: { name: 'read_file', args: { Path: 12345 } } }),
    ]
    for (const raw of malformedInputs) {
      const out = runHook(raw, { KOVO_COORDINATOR_MODE: '1' })
      assert.equal(out.decision, 'allow', `expected fail-open allow for malformed input: ${raw}`)
    }
  })
})
