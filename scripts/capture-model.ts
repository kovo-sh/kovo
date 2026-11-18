import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { DEFAULT_PROVIDER, responseCheckIds } from '../src/domain.ts'
import type { ResponseCheckId } from '../src/domain.ts'
import { agentTurn, coordinatorPrompt, workerInput } from '../src/server/agent-session.ts'
import type { AgentScenario } from '../src/server/agent-session.ts'
import type { PublicObservation } from '../src/server/broker.ts'
import { derivedResult } from '../src/server/execution.ts'
import { testProvider } from '../src/server/provider.ts'
import type { ProviderCall } from '../src/server/provider.ts'
import { parseReviewPlan, reviewPlanPrompt } from '../src/server/review-plan.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import { allChecksGoal, healthy, healthyGoal, mainGoal, primary, referrerGoal, statusQuestion, unavailable } from '../tests/scenarios.ts'
import { saveRecording } from './fixture-record.ts'

type Scenario = {
  name: string
  prompt: string
  scenario: AgentScenario
  evidence?: object
  expectedChecks?: readonly ResponseCheckId[]
  historical?: boolean
}

function workerScenario(name: string, observation: PublicObservation, checks?: readonly ResponseCheckId[]): Scenario {
  return { name, ...workerInput(observation, checks), historical: !checks }
}

const onlyReferrer = ['referrer-policy'] as const
const scenarios: Scenario[] = [
  { name: 'plan-all', scenario: 'coordinator-plan', prompt: reviewPlanPrompt(allChecksGoal, 'public'), expectedChecks: responseCheckIds },
  { name: 'plan-referrer', scenario: 'coordinator-plan', prompt: reviewPlanPrompt(referrerGoal, 'public'), expectedChecks: onlyReferrer },
  workerScenario('response-primary', primary, responseCheckIds),
  workerScenario('response-unavailable', unavailable, responseCheckIds),
  workerScenario('response-healthy', healthy, responseCheckIds),
  workerScenario('response-referrer', primary, onlyReferrer),
  {
    name: 'coordinator-status', scenario: 'coordinator',
    prompt: coordinatorPrompt({ phase: 'analysis', status: 'running', approved: 2, queued: 0, complete: 1, question: statusQuestion }),
  },
  {
    name: 'coordinator-main', scenario: 'coordinator', historical: true,
    prompt: coordinatorPrompt({ phase: 'analysis', status: 'running', approved: 2, queued: 2, complete: 1, question: mainGoal }),
  },
  {
    name: 'coordinator-healthy', scenario: 'coordinator', historical: true,
    prompt: coordinatorPrompt({ phase: 'analysis', status: 'running', approved: 1, queued: 1, complete: 1, question: healthyGoal }),
  },
  workerScenario('primary', primary),
  workerScenario('unavailable', unavailable),
  workerScenario('healthy', healthy),
]

const selected = process.argv[2]
const options = ['responses', 'messages', 'workflow', ...scenarios.map(item => item.name)]
if (selected && !options.includes(selected)) throw new Error('Unknown recording scenario.')
const path = join(homedir(), '.config', 'guardian-fixtures', 'openrouter.key')
if ((statSync(path).mode & 0o077) !== 0) throw new Error('The capture credential must have owner-only permissions.')
const key = readFileSync(path, 'utf8').trim()

for (const protocol of ['responses', 'messages'] as const) {
  if (selected && protocol !== selected) continue
  const calls: ProviderCall[] = []
  await testProvider({ ...DEFAULT_PROVIDER, protocol, key }, call => calls.push(call))
  if (calls.length !== 1 || calls[0].status !== 200 || !calls[0].body.includes('guardian_connection')) {
    throw new Error(`Expected one complete streamed ${protocol} capture.`)
  }
  saveRecording('connection', protocol, calls, key)
}

const selectedScenarios = scenarios.filter(item => selected === item.name ||
  (!selected || selected === 'workflow') && !item.historical)
if (selectedScenarios.length) {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-record-'))
  const backend = new LinuxWorkerBackend()
  try {
    for (const { name, prompt, scenario, evidence, expectedChecks } of selectedScenarios) {
      const calls: ProviderCall[] = []
      const answer = await agentTurn({
        scenario, directory, prompt,
        derive: evidence && (async (command, signal) => {
          const result = await backend.run({
            assignmentId: randomUUID(), files: [{ name: 'observed.json', content: JSON.stringify(evidence) }],
            command, outputs: ['result.txt'],
          }, signal)
          return derivedResult({ exitStatus: result.exitCode, stdout: result.stdout, result: result.outputs['result.txt'] ?? '' })
        }),
        sessionId: randomUUID(), requestId: name,
        settings: { ...DEFAULT_PROVIDER, key }, signal: AbortSignal.timeout(80_000),
        record: call => calls.push(call),
      })
      if (!calls.length || calls.some(call => call.status !== 200)) throw new Error('The provider did not complete ' + name + '.')
      if (expectedChecks && parseReviewPlan(answer)?.checks.join(',') !== expectedChecks.join(',')) {
        throw new Error('The recorded coordinator response did not select the expected checks for ' + name + '.')
      }
      saveRecording(name, 'responses', calls, key)
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}
