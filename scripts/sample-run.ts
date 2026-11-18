import { randomUUID } from 'node:crypto'
import { dataDirectory, Store } from '../src/server/store.ts'

const storage = new Store(dataDirectory())
const { id: projectId } = storage.createProject({
  requestId: randomUUID(), name: 'Northstar sample',
  seeds: ['https://northstar.example', 'https://portal.northstar.example', 'https://docs.northstar.example'],
})
storage.addProjectAsset({
  requestId: randomUUID(), projectId, origin: 'https://help.vendor.example',
  source: 'Supplier inventory', thirdParty: true,
})
const { id: runId } = storage.createRun({
  requestId: randomUUID(), projectId, goal: 'Review the supplied Northstar sample evidence.',
  sourceMode: 'prepared',
})
storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })

const phases = {
  discovery: ['Domain ownership', 'Portal inventory', 'Documentation inventory', 'Service catalog import',
    'Duplicate asset review', 'Third-party classification', 'Scope review preparation'],
  analysis: ['Portal security headers', 'Main site security headers', 'Docs security headers', 'Portal session settings',
    'Main site cookie settings', 'Docs cookie settings', 'Portal TLS configuration', 'Site TLS configuration',
    'Docs TLS configuration', 'Portal deploy settings', 'Site deploy settings', 'Docs deploy settings',
    'Portal dependencies', 'Site dependencies', 'Docs dependencies', 'Coverage review', 'Evidence quality review', 'Candidate finding triage'],
  verification: ['Evidence validation', 'Header baseline check', 'Session cross-check', 'TLS baseline comparison',
    'Deployment cross-check', 'Dependency cross-check', 'Coverage reconciliation', 'Final finding review'],
} as const
storage.db.transaction(() => {
  const run = storage.run(runId)
  for (const phase of ['discovery', 'analysis', 'verification'] as const) {
    for (const [index, title] of phases[phase].entries()) {
      const worker = storage.makeWorker(run, phase, run.candidates[index % 3], title,
        'Inspect the prepared record for ' + title.toLowerCase() + '.')
      if (phase === 'discovery') {
        storage.updateWorker(worker.id, { status: 'complete', outcome: 'Reviewed a synthetic service inventory record.' })
        storage.message(runId, worker.id, 'worker', 'Attribution is from the supplied synthetic inventory.')
        storage.addArtifact(run, worker, 'inventory', 'Sample inventory note', 'Northstar synthetic project evidence.')
      }
    }
  }
  storage.event(runId, 'sample.ready', 'Synthetic worker graph is ready for scope review.')
})
console.log('/runs/' + runId)
