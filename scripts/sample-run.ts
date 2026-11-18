import { randomUUID } from 'node:crypto'
import { dataDirectory, Store } from '../src/server/store.ts'
import type { Assignment } from '../src/server/store.ts'

const storage = new Store(dataDirectory())
const main = 'https://northstar.example'
const portal = 'https://portal.northstar.example'
const docs = 'https://docs.northstar.example'
const { id: projectId } = storage.createProject({
  requestId: randomUUID(), name: 'Northstar sample',
  seeds: [main, portal, docs],
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
const verificationInputs = [
  'Evidence quality review', 'Main site security headers', 'Portal session settings', 'Docs TLS configuration',
  'Portal deploy settings', 'Site dependencies', 'Coverage review', 'Candidate finding triage',
]
storage.db.transaction(() => {
  const run = storage.run(runId)
  const inventory = new Map<string, Assignment>()
  const analyses = new Map<string, Assignment>()
  for (const phase of ['discovery', 'analysis', 'verification'] as const) {
    const origins = phase === 'analysis' ? [portal, main, docs] : [main, portal, docs]
    for (const [index, title] of phases[phase].entries()) {
      const analysis = phase === 'verification' ? analyses.get(verificationInputs[index]) : undefined
      const asset = run.candidates.find(item => analysis ? item.id === analysis.assetId : item.origin === origins[index % 3])
      if (!asset) throw new Error('Sample asset is missing.')
      const input = phase === 'analysis' ? inventory.get(asset.id) : analysis
      const worker = storage.makeWorker(run, phase, asset, title,
        'Inspect the prepared record for ' + title.toLowerCase() + '.', input)
      if (phase === 'analysis') analyses.set(title, worker)
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
