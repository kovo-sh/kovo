import { createFileRoute, useRouterState } from '@tanstack/react-router'
import { runData } from '../actions.ts'
import { RunWorkspace } from '../components/run-workspace.tsx'

export const Route = createFileRoute('/runs/$runId')({
  validateSearch: (search): { view?: 'overview' | 'trace' | 'exchanges' | 'report' } => ({
    view: search.view === 'trace' || search.view === 'report' || search.view === 'overview' || search.view === 'exchanges'
      ? search.view
      : undefined,
  }),
  loader: ({ params }) => runData({ data: { runId: params.runId } }),
  component: RunPage,
})

function RunPage() {
  const detail = Route.useLoaderData()
  const { view } = Route.useSearch()
  const workerId = useRouterState({
    select: state => state.matches.find(match => match.routeId === '/runs/$runId/workers/$workerId')?.params.workerId,
  })
  return <RunWorkspace key={detail.run.id} detail={detail} view={view ?? (workerId ? 'trace' : 'overview')} workerId={workerId} />
}
