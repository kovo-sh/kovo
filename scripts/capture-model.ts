import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { assessmentCheckIds, DEFAULT_PROVIDER, publicResponseCheckIds, responseCheckIds } from '../src/domain.ts'
import type { AssessmentCheckId, ResponseCheckId } from '../src/domain.ts'
import { agentTurn, coordinatorPrompt, workerInput } from '../src/server/agent-session.ts'
import type { AgentScenario } from '../src/server/agent-session.ts'
import type { PublicObservation } from '../src/server/broker.ts'
import { derivedResult } from '../src/server/execution.ts'
import { testProvider } from '../src/server/provider.ts'
import type { ProviderCall } from '../src/server/provider.ts'
import { parseReviewPlan, reviewPlanPrompt } from '../src/server/review-plan.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import {
  accessPolicyGoal, allChecksGoal, combinedGoal, deepPrimary, healthy, healthyGoal, mainGoal, primary, referrerGoal, statusQuestion, unavailable,
} from '../tests/scenarios.ts'
import { saveRecording } from './fixture-record.ts'

type Scenario = {
  name: string
  prompt: string
  scenario: AgentScenario
  evidence?: object
  expectedChecks?: readonly AssessmentCheckId[]
  availableChecks?: readonly AssessmentCheckId[]
  historical?: boolean
}

function workerScenario(name: string, observation: PublicObservation, checks?: readonly ResponseCheckId[]): Scenario {
  return { name, ...workerInput(observation, checks), historical: !checks }
}

const onlyReferrer = ['referrer-policy'] as const
const publicAssessmentChecks = [...publicResponseCheckIds, 'access-policy'] as const
const scenarios: Scenario[] = [
  { name: 'plan-all', scenario: 'coordinator-plan', prompt: reviewPlanPrompt(allChecksGoal, 'public', publicResponseCheckIds),
    availableChecks: publicResponseCheckIds, expectedChecks: publicResponseCheckIds },
  { name: 'plan-prepared-all', scenario: 'coordinator-plan', prompt: reviewPlanPrompt(allChecksGoal, 'prepared', responseCheckIds),
    availableChecks: responseCheckIds, expectedChecks: responseCheckIds },
  { name: 'plan-referrer', scenario: 'coordinator-plan', prompt: reviewPlanPrompt(referrerGoal, 'public'), expectedChecks: onlyReferrer },
  {
    name: 'plan-access-policy', scenario: 'coordinator-plan',
    prompt: reviewPlanPrompt(accessPolicyGoal, 'public', publicAssessmentChecks),
    availableChecks: publicAssessmentChecks, expectedChecks: ['access-policy'],
  },
  {
    name: 'plan-combined', scenario: 'coordinator-plan',
    prompt: reviewPlanPrompt(combinedGoal, 'public', publicAssessmentChecks),
    availableChecks: publicAssessmentChecks, expectedChecks: publicAssessmentChecks,
  },
  {
    name: 'plan-combined-narrowed', scenario: 'coordinator-plan',
    prompt: reviewPlanPrompt(combinedGoal, 'public', publicResponseCheckIds),
    availableChecks: publicResponseCheckIds, expectedChecks: publicResponseCheckIds,
  },
  workerScenario('response-primary', primary, publicResponseCheckIds),
  workerScenario('response-prepared-primary', deepPrimary, responseCheckIds),
  workerScenario('response-unavailable', unavailable, publicResponseCheckIds),
  workerScenario('response-healthy', healthy, publicResponseCheckIds),
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

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { protocol: { type: 'string' } },
})
const [selected] = positionals
const options = ['responses', 'messages', 'workflow', ...scenarios.map(item => item.name)]
if (positionals.length > 1 || (selected && !options.includes(selected))) throw new Error('Unknown recording scenario.')
const workflowProtocol = values.protocol ?? DEFAULT_PROVIDER.protocol
if (workflowProtocol !== 'responses' && workflowProtocol !== 'messages') throw new Error('Choose the responses or messages protocol.')
if (values.protocol && (selected === 'responses' || selected === 'messages') && selected !== workflowProtocol) {
  throw new Error('The connection scenario and protocol must match.')
}
const path = join(homedir(), '.config', 'guardian-fixtures', 'openrouter.key')
if ((statSync(path).mode & 0o077) !== 0) throw new Error('The capture credential must have owner-only permissions.')
const key = readFileSync(path, 'utf8').trim()

for (const protocol of ['responses', 'messages'] as const) {
  if (selected && protocol !== selected) continue
  if (values.protocol && protocol !== workflowProtocol) continue
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
    for (const { name, prompt, scenario, evidence, expectedChecks, availableChecks } of selectedScenarios) {
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
        settings: { ...DEFAULT_PROVIDER, protocol: workflowProtocol, key }, signal: AbortSignal.timeout(80_000),
        record: call => calls.push(call),
      })
      if (!calls.length || calls.some(call => call.status !== 200)) throw new Error('The provider did not complete ' + name + '.')
      if (expectedChecks && parseReviewPlan(answer, availableChecks)?.checks.join(',') !== expectedChecks.join(',')) {
        throw new Error('The recorded coordinator response did not select the expected checks for ' + name + '.')
      }
      saveRecording(name, workflowProtocol, calls, key)
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}
