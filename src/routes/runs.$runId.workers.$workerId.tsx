import { createFileRoute } from '@tanstack/react-router'

// Legacy deep link: the run shell maps it to the Workflow view with this worker selected.
export const Route = createFileRoute('/runs/$runId/workers/$workerId')({})
