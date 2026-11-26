import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import test from 'node:test'
import ts from 'typescript'
import { isProjectTab, PROJECT_TABS } from '../src/components/project/types.ts'
import { assertNever, isRunInProgress } from '../src/server/run-status.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function readSrc(relPath: string): string {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8')
}

function loadExportedTsxSymbols<T extends Record<string, unknown>>(
  relPath: string,
  symbolNames: readonly string[],
  scopeVars: Record<string, unknown> = {},
): T {
  const fullPath = join(REPO_ROOT, relPath)
  const src = readFileSync(fullPath, 'utf8')
  const sf = ts.createSourceFile(fullPath, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  const wanted = new Set(symbolNames)
  const chunks: string[] = []

  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && wanted.has(stmt.name.text)) {
      chunks.push(src.slice(stmt.getStart(sf), stmt.getEnd()).replace(/^export\s+/, ''))
    } else if (ts.isVariableStatement(stmt) && stmt.declarationList.declarations.some(d => ts.isIdentifier(d.name) && wanted.has(d.name.text))) {
      chunks.push(src.slice(stmt.getStart(sf), stmt.getEnd()).replace(/^export\s+/, ''))
    }
  }

  assert.equal(chunks.length, symbolNames.length, `Expected all symbols (${symbolNames.join(', ')}) in ${relPath}`)
  const js = ts.transpileModule(chunks.join('\n\n'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText

  const factory = new Function(
    ...Object.keys(scopeVars),
    `${js}\nreturn { ${symbolNames.join(', ')} };`,
  )
  return factory(...Object.values(scopeVars)) as T
}

test('PROJECT_TABS renames Overview & Runs to Overview and adds dedicated Runs tab right after it', () => {
  assert.equal(PROJECT_TABS[0]?.id, 'overview')
  assert.equal(PROJECT_TABS[0]?.label, 'Overview')
  assert.equal(PROJECT_TABS[1]?.id, 'runs')
  assert.equal(PROJECT_TABS[1]?.label, 'Runs')
  assert.equal(isProjectTab('runs'), true)
  assert.equal(isProjectTab('overview'), true)
  assert.equal(isProjectTab('nonexistent'), false)
})

test('partitionRailRuns caps current project to 5 runs and groups other projects with 3-run cap', () => {
  type PartitionFn = <T extends { projectId: string; projectName: string }>(
    runs: readonly T[],
    currentProjectId: string,
    currentProjectLimit?: number,
    otherProjectLimit?: number,
  ) => {
    currentProjectRuns: T[]
    currentProjectTotal: number
    otherProjects: { projectId: string; projectName: string; runs: T[]; totalCount: number }[]
    otherProjectsRunCount: number
  }

  const { partitionRailRuns } = loadExportedTsxSymbols<{
    partitionRailRuns: PartitionFn
  }>(
    'src/components/run/rail.tsx',
    ['RAIL_CURRENT_PROJECT_RUN_LIMIT', 'RAIL_OTHER_PROJECT_RUN_LIMIT', 'partitionRailRuns'],
  )

  const runs = [
    ...Array.from({ length: 7 }, (_, i) => ({
      id: `cur-${i + 1}`,
      projectId: 'proj-a',
      projectName: 'Alpha',
    })),
    ...Array.from({ length: 5 }, (_, i) => ({
      id: `b-${i + 1}`,
      projectId: 'proj-b',
      projectName: 'Beta',
    })),
    { id: 'c-1', projectId: 'proj-c', projectName: 'Gamma' },
  ]

  const res = partitionRailRuns(runs, 'proj-a')
  assert.equal(res.currentProjectTotal, 7)
  assert.deepEqual(res.currentProjectRuns.map(r => r.id), ['cur-1', 'cur-2', 'cur-3', 'cur-4', 'cur-5'])
  assert.equal(res.otherProjectsRunCount, 6)
  assert.equal(res.otherProjects.length, 2)
  assert.equal(res.otherProjects[0]?.projectId, 'proj-b')
  assert.equal(res.otherProjects[0]?.totalCount, 5)
  assert.deepEqual(res.otherProjects[0]?.runs.map(r => r.id), ['b-1', 'b-2', 'b-3'])
  assert.equal(res.otherProjects[1]?.projectId, 'proj-c')
  assert.equal(res.otherProjects[1]?.totalCount, 1)
  assert.deepEqual(res.otherProjects[1]?.runs.map(r => r.id), ['c-1'])

  const singleProj = partitionRailRuns(runs.slice(0, 3), 'proj-a')
  assert.equal(singleProj.currentProjectTotal, 3)
  assert.equal(singleProj.otherProjects.length, 0)
  assert.equal(singleProj.otherProjectsRunCount, 0)
})

test('readTelemetryOpenPreference and writeTelemetryOpenPreference persist kovo.rail.telemetryOpen safely', () => {
  const {
    TELEMETRY_OPEN_STORAGE_KEY,
    readTelemetryOpenPreference,
    writeTelemetryOpenPreference,
  } = loadExportedTsxSymbols<{
    TELEMETRY_OPEN_STORAGE_KEY: string
    readTelemetryOpenPreference: (storage?: Pick<Storage, 'getItem'> | null) => boolean
    writeTelemetryOpenPreference: (open: boolean, storage?: Pick<Storage, 'setItem'> | null) => void
  }>(
    'src/components/run/rail.tsx',
    ['TELEMETRY_OPEN_STORAGE_KEY', 'readTelemetryOpenPreference', 'writeTelemetryOpenPreference'],
  )

  assert.equal(TELEMETRY_OPEN_STORAGE_KEY, 'kovo.rail.telemetryOpen')

  const mem = new Map<string, string>()
  const mockStorage: Pick<Storage, 'getItem' | 'setItem'> = {
    getItem: k => mem.get(k) ?? null,
    setItem: (k, v) => { mem.set(k, v) },
  }

  assert.equal(readTelemetryOpenPreference(null), false)
  assert.equal(readTelemetryOpenPreference(mockStorage), false)

  writeTelemetryOpenPreference(true, mockStorage)
  assert.equal(mem.get('kovo.rail.telemetryOpen'), 'true')
  assert.equal(readTelemetryOpenPreference(mockStorage), true)

  writeTelemetryOpenPreference(false, mockStorage)
  assert.equal(mem.get('kovo.rail.telemetryOpen'), 'false')
  assert.equal(readTelemetryOpenPreference(mockStorage), false)
})

test('ProjectRunsTab status filter pills, scan mode badge mapping, and search filtering work accurately', () => {
  type FilterId = 'all' | 'running' | 'completed' | 'stopped' | 'failed'
  type RunLike = {
    id: string
    goal: string
    status: string
    phase: string
    capabilityTier: 0 | 1 | 2 | 3
    approvalPolicy: 'auto_review' | 'yolo' | 'strict'
    isActive: boolean
  }

  const {
    RUN_STATUS_FILTERS,
    matchesRunStatusFilter,
    scanModeBadgeInfo,
    filterProjectRuns,
  } = loadExportedTsxSymbols<{
    RUN_STATUS_FILTERS: readonly { id: FilterId; label: string }[]
    matchesRunStatusFilter: (run: Pick<RunLike, 'status' | 'isActive'>, filter: FilterId) => boolean
    scanModeBadgeInfo: (run: Pick<RunLike, 'capabilityTier' | 'approvalPolicy'>) => { label: string; variant: string }
    filterProjectRuns: (runs: readonly RunLike[], opts: { statusFilter: FilterId; query: string }) => RunLike[]
  }>(
    'src/components/project/ProjectRunsTab.tsx',
    ['RUN_STATUS_FILTERS', 'matchesRunStatusFilter', 'scanModeBadgeInfo', 'filterProjectRuns'],
    {
      assertNever,
      isRunInProgress,
      runStatusLabel: (s: string) => s,
      phaseNames: { investigation: 'Investigation', complete: 'Complete', consent: 'Discovery consent' },
    },
  )

  assert.deepEqual(
    RUN_STATUS_FILTERS.map(f => f.label),
    ['All', 'Running', 'Completed', 'Stopped', 'Failed'],
  )

  assert.deepEqual(scanModeBadgeInfo({ capabilityTier: 0, approvalPolicy: 'auto_review' }), { label: 'Offline Review', variant: 'neutral' })
  assert.deepEqual(scanModeBadgeInfo({ capabilityTier: 1, approvalPolicy: 'auto_review' }), { label: 'Passive Scan', variant: 'neutral' })
  assert.deepEqual(scanModeBadgeInfo({ capabilityTier: 2, approvalPolicy: 'auto_review' }), { label: 'Passive Scan', variant: 'neutral' })
  assert.deepEqual(scanModeBadgeInfo({ capabilityTier: 3, approvalPolicy: 'auto_review' }), { label: 'Supervised Scan', variant: 'accent' })
  assert.deepEqual(scanModeBadgeInfo({ capabilityTier: 3, approvalPolicy: 'yolo' }), { label: 'Autonomous Scan', variant: 'warn' })

  const sampleRuns: RunLike[] = [
    { id: 'r-run', goal: 'Audit auth flow', status: 'running', phase: 'investigation', capabilityTier: 3, approvalPolicy: 'auto_review', isActive: true },
    { id: 'r-wait', goal: 'Scope review run', status: 'waiting', phase: 'consent', capabilityTier: 1, approvalPolicy: 'auto_review', isActive: false },
    { id: 'r-done', goal: 'Nightly regression', status: 'complete', phase: 'complete', capabilityTier: 3, approvalPolicy: 'yolo', isActive: false },
    { id: 'r-stop', goal: 'Manual stop test', status: 'stopped', phase: 'investigation', capabilityTier: 2, approvalPolicy: 'auto_review', isActive: false },
    { id: 'r-fail', goal: 'Broken target probe', status: 'failed', phase: 'investigation', capabilityTier: 1, approvalPolicy: 'strict', isActive: false },
  ]

  assert.equal(matchesRunStatusFilter(sampleRuns[0]!, 'running'), true)
  assert.equal(matchesRunStatusFilter(sampleRuns[1]!, 'running'), true)
  assert.equal(matchesRunStatusFilter(sampleRuns[2]!, 'completed'), true)
  assert.equal(matchesRunStatusFilter(sampleRuns[3]!, 'stopped'), true)
  assert.equal(matchesRunStatusFilter(sampleRuns[4]!, 'failed'), true)
  assert.equal(matchesRunStatusFilter(sampleRuns[2]!, 'running'), false)

  assert.equal(filterProjectRuns(sampleRuns, { statusFilter: 'all', query: '' }).length, 5)
  assert.deepEqual(filterProjectRuns(sampleRuns, { statusFilter: 'running', query: '' }).map(r => r.id), ['r-run', 'r-wait'])
  assert.deepEqual(filterProjectRuns(sampleRuns, { statusFilter: 'all', query: 'autonomous' }).map(r => r.id), ['r-done'])
  assert.deepEqual(filterProjectRuns(sampleRuns, { statusFilter: 'completed', query: 'nightly' }).map(r => r.id), ['r-done'])
  assert.deepEqual(filterProjectRuns(sampleRuns, { statusFilter: 'failed', query: 'nightly' }), [])
})

test('Sidebar Option 1 spacing, section ordering, All runs link, and ProjectRunsTab structural invariants hold', () => {
  const railSrc = readSrc('src/components/run/rail.tsx')
  const shellSrc = readSrc('src/components/shell/AppShell.tsx')
  const runsTabSrc = readSrc('src/components/project/ProjectRunsTab.tsx')

  // Sweet-spot spacing across rail.tsx and AppShell.tsx
  assert.match(railSrc, /h-\[30px\][\s\S]*?py-1/)
  assert.match(railSrc, /flex flex-col gap-px/)
  assert.match(railSrc, /pb-1 pt-2\.5/)
  assert.match(railSrc, /py-1\.5/)

  assert.match(shellSrc, /nav:\s*'h-\[30px\] py-1'/)
  assert.match(shellSrc, /className="flex flex-col gap-px"/)
  assert.match(shellSrc, /pb-1 pt-2\.5/)
  assert.match(shellSrc, /py-1\.5/)
  assert.match(shellSrc, /<span className="min-w-0 flex-1 truncate">Settings<\/span>/)

  // Option 1 hierarchy order in rail.tsx: Investigation -> Runs -> Telemetry -> Workspace -> Local session footer
  const invIdx = railSrc.indexOf('<span>Investigation</span>')
  const runsIdx = railSrc.indexOf('<span>Runs</span>')
  const telIdx = railSrc.indexOf('<span>Telemetry</span>')
  const wsIdx = railSrc.indexOf('<span>Workspace</span>')
  const sessIdx = railSrc.indexOf('Local session')
  assert.ok(invIdx > 0 && runsIdx > invIdx && telIdx > runsIdx && wsIdx > telIdx && sessIdx > wsIdx,
    'Rail section order must be Investigation -> Runs -> Telemetry -> Workspace -> Local session')

  // All runs link + Other projects disclosure + Telemetry persistence
  assert.match(railSrc, /search=\{\{\s*tab:\s*'runs'\s*\}\}/)
  assert.match(railSrc, /All runs \(\{currentProjectTotal\}\) →/)
  assert.match(railSrc, /<Disclosure defaultOpen=\{false\}/)
  assert.match(railSrc, /Other projects/)
  assert.match(railSrc, /kovo\.rail\.telemetryOpen/)

  // ProjectRunsTab has search input, status pills, scan mode badge, cost/findings, New run button, and /runs/$runId links
  assert.match(runsTabSrc, /placeholder="Search runs…"/)
  assert.match(runsTabSrc, /RUN_STATUS_FILTERS/)
  assert.match(runsTabSrc, /scanModeBadgeInfo/)
  assert.match(runsTabSrc, /formatUsd\(run\.spentUsd\)/)
  assert.match(runsTabSrc, /plural\(run\.findingCount,\s*'finding'\)/)
  assert.match(runsTabSrc, /New run/)
  assert.match(runsTabSrc, /to="\/runs\/\$runId"/)
})
