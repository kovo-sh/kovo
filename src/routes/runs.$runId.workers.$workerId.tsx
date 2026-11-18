import { createFileRoute } from '@tanstack/react-router'

// The parent workspace renders the thread in its dock and keeps the graph mounted.
export const Route = createFileRoute('/runs/$runId/workers/$workerId')({})
