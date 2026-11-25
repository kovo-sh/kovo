import { createFileRoute, useRouterState } from '@tanstack/react-router'
import { runData } from '../actions.ts'
import { isViewId } from '../components/run/meta.ts'
import type { ViewId } from '../components/run/meta.ts'
import { parseSel } from '../components/run/nav.tsx'
import { landingView, RunShell } from '../components/run/shell.tsx'

// `trace` is the previous name of the workflow view; old links still use it.
type RunSearch = { view?: ViewId | 'trace'; sel?: string }

export const Route = createFileRoute('/runs/$runId')({
  validateSearch: (search: Record<string, unknown>): RunSearch => ({
    view: isViewId(search.view) || search.view === 'trace' ? search.view : undefined,
    sel: typeof search.sel === 'string' && search.sel ? search.sel : undefined,
  }),
  loader: ({ params }) => runData({ data: { runId: params.runId } }),
  // Live updates come over SSE inside the shell; view/selection changes must not refetch the run.
  staleTime: Infinity,
  component: RunPage,
})

function RunPage() {
  const detail = Route.useLoaderData()
  const search = Route.useSearch()
  const workerId = useRouterState({
    select: state => state.matches.find(match => match.routeId === '/runs/$runId/workers/$workerId')?.params.workerId,
  })
  // The worker sub-route maps to the Workflow view with that worker selected.
  const view: ViewId = workerId ? 'workflow' : search.view === 'trace' ? 'workflow' : search.view ?? landingView(detail)
  const sel = workerId ? { kind: 'worker', id: workerId } : parseSel(search.sel)
  return <RunShell key={detail.run.id} detail={detail} view={view} sel={sel} />
}
