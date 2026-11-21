import { randomUUID } from 'node:crypto'
import {
  defaultBudgetRequests,
  defaultBudgetUsd,
  defaultMaxRpsPerOrigin,
  defaultWorkerConcurrency,
  defaultWorkerMaxTurns,
} from '../src/domain.ts'
import { dataDirectory, Store } from '../src/server/store.ts'
import type { Assignment } from '../src/server/store.ts'

const storage = new Store(dataDirectory())
const main = 'https://northstar.example'
const portal = 'https://portal.northstar.example'
const docs = 'https://docs.northstar.example'
const { id: projectId } = storage.createProject({
  requestId: randomUUID(),
  name: 'Northstar sample',
  seeds: [main, portal, docs],
  environment: 'public',
})
storage.addProjectAsset({
  requestId: randomUUID(),
  projectId,
  origin: 'https://help.vendor.example',
  source: 'Supplier inventory',
  thirdParty: true,
})
const { id: runId } = storage.createRun({
  requestId: randomUUID(),
  projectId,
  goal: 'Review the supplied Northstar sample evidence.',
  sourceMode: 'prepared',
  capabilityTier: 0,
  budgetUsd: defaultBudgetUsd,
  budgetRequests: defaultBudgetRequests,
  maxRpsPerOrigin: defaultMaxRpsPerOrigin,
  workerConcurrency: defaultWorkerConcurrency,
  workerMaxTurns: defaultWorkerMaxTurns,
})
storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })

const phases = {
  discovery: [
    'Domain ownership', 'Portal inventory', 'Documentation inventory', 'Service catalog import',
    'Duplicate asset review', 'Third-party classification', 'Scope review preparation',
  ],
  investigation: [
    'Portal security headers', 'Main site security headers', 'Docs security headers', 'Portal session settings',
    'Main site cookie settings', 'Docs cookie settings', 'Portal TLS configuration', 'Site TLS configuration',
    'Docs TLS configuration', 'Portal deploy settings', 'Site deploy settings', 'Docs deploy settings',
    'Portal dependencies', 'Site dependencies', 'Docs dependencies', 'Coverage review', 'Evidence quality review', 'Candidate finding triage',
  ],
  verification: [
    'Evidence validation', 'Header baseline check', 'Session cross-check', 'TLS baseline comparison',
    'Deployment cross-check', 'Dependency cross-check', 'Coverage reconciliation', 'Final finding review',
  ],
} as const
const verificationInputs = [
  'Evidence quality review', 'Main site security headers', 'Portal session settings', 'Docs TLS configuration',
  'Portal deploy settings', 'Site dependencies', 'Coverage review', 'Candidate finding triage',
]
storage.db.transaction(() => {
  const run = storage.run(runId)
  const inventory = new Map<string, Assignment>()
  const investigations = new Map<string, Assignment>()
  for (const phase of ['discovery', 'investigation', 'verification'] as const) {
    const origins = phase === 'investigation' ? [portal, main, docs] : [main, portal, docs]
    for (const [index, title] of phases[phase].entries()) {
      const investigation = phase === 'verification' ? investigations.get(verificationInputs[index]) : undefined
      const asset = run.candidates.find(item => investigation ? item.id === investigation.assetId : item.origin === origins[index % 3])
      if (!asset) throw new Error('Sample asset is missing.')
      const input = phase === 'investigation' ? inventory.get(asset.id) : investigation
      const worker = storage.makeWorker(run, phase, asset, title,
        'Inspect the prepared record for ' + title.toLowerCase() + '.', { input })
      if (phase === 'investigation') investigations.set(title, worker)
      if (phase === 'discovery') {
        if (!inventory.has(asset.id)) inventory.set(asset.id, worker)
        storage.updateWorker(worker.id, { status: 'complete', outcome: 'Reviewed a synthetic service inventory record.' })
        const evidence = storage.addArtifact(run, worker, 'inventory', 'Sample inventory note', 'Northstar synthetic project evidence.')
        storage.message(runId, worker.id, 'worker', 'Attribution is from the supplied synthetic inventory.', undefined, [evidence.id])
      }
    }
  }
  storage.event(runId, 'sample.ready', 'Synthetic worker graph is ready for scope review.')
})
console.log('/runs/' + runId)
