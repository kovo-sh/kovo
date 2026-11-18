import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { DEFAULT_PROVIDER } from '../src/domain.ts'
import { agentTurn, coordinatorPrompt, transportEvidence, workerPrompt } from '../src/server/agent-session.ts'
import { derivedResult } from '../src/server/execution.ts'
import { testProvider } from '../src/server/provider.ts'
import type { ProviderCall } from '../src/server/provider.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import { healthy, healthyGoal, mainGoal, primary, unavailable } from '../tests/scenarios.ts'
import { saveRecording } from './fixture-record.ts'

const path = join(homedir(), '.config', 'guardian-fixtures', 'openrouter.key')
if ((statSync(path).mode & 0o077) !== 0) throw new Error('The capture credential must have owner-only permissions.')
const key = readFileSync(path, 'utf8').trim()
const selected = process.argv[2]
const options = ['responses', 'messages', 'workflow', 'coordinator-main', 'coordinator-healthy', 'primary', 'unavailable', 'healthy']
if (selected && !options.includes(selected)) throw new Error('Unknown recording scenario.')
for (const protocol of ['responses', 'messages'] as const) {
  if (selected && protocol !== selected) continue
  const calls: ProviderCall[] = []
  await testProvider({ ...DEFAULT_PROVIDER, protocol, key }, call => calls.push(call))
  if (calls.length !== 1 || calls[0].status !== 200 || !calls[0].body.includes('guardian_connection')) {
    throw new Error(`Expected one complete streamed ${protocol} capture.`)
  }
  saveRecording('connection', protocol, calls, key)
}

if (selected !== 'responses' && selected !== 'messages') {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-record-'))
  const backend = new LinuxWorkerBackend()
  try {
    const record = async (name: string, prompt: string, scenario: 'coordinator' | 'worker-analysis',
      derive?: (command: string, signal: AbortSignal) => Promise<string>) => {
      if (selected && selected !== 'workflow' && selected !== name) return
      const calls: ProviderCall[] = []
      await agentTurn({
        scenario, directory, prompt, derive,
        sessionId: randomUUID(), requestId: name,
        settings: { ...DEFAULT_PROVIDER, key }, signal: AbortSignal.timeout(80_000),
        record: call => calls.push(call),
      })
      if (!calls.length || calls.some(call => call.status !== 200)) throw new Error('The provider did not complete this recording.')
      saveRecording(name, 'responses', calls, key)
    }
    await record('coordinator-main', coordinatorPrompt({
      phase: 'analysis', status: 'running', approved: 2, queued: 2, complete: 1, question: mainGoal,
    }), 'coordinator')
    await record('coordinator-healthy', coordinatorPrompt({
      phase: 'analysis', status: 'running', approved: 1, queued: 1, complete: 1, question: healthyGoal,
    }), 'coordinator')
    for (const [name, observation] of Object.entries({ primary, unavailable, healthy })) {
      await record(name, workerPrompt(observation), 'worker-analysis', async (command, signal) => {
        const result = await backend.run({
          assignmentId: randomUUID(), files: [{ name: 'observed.json', content: JSON.stringify(transportEvidence(observation)) }],
          command, outputs: ['result.txt'],
        }, signal)
        return derivedResult({ exitStatus: result.exitCode, stdout: result.stdout, result: result.outputs['result.txt'] ?? '' })
      })
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}
