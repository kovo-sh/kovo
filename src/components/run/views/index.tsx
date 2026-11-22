// View router registry (foundation-owned). Each view module exports its
// component and the inspectors it owns, keyed by selection kind. View agents
// edit their own module only; this file does not need to change.
import type { ComponentType } from 'react'
import type { ViewId } from '../meta.ts'
import { EvidenceInspector } from '../pane.tsx'
import type { InspectorMap } from '../pane.tsx'
import { ActivityView, activityInspectors } from './activity.tsx'
import { ExchangesView, exchangesInspectors } from './exchanges.tsx'
import { FindingsView, findingsInspectors } from './findings.tsx'
import { OverviewView } from './overview.tsx'
import { QueueView, queueInspectors } from './queue.tsx'
import { ReportView, reportInspectors } from './report.tsx'
import { SurfaceView, surfaceInspectors } from './surface.tsx'
import { WorkflowView, workflowInspectors } from './workflow.tsx'

export const VIEW_COMPONENTS: Record<ViewId, ComponentType> = {
  overview: OverviewView,
  queue: QueueView,
  findings: FindingsView,
  workflow: WorkflowView,
  surface: SurfaceView,
  exchanges: ExchangesView,
  activity: ActivityView,
  report: ReportView,
}

/** Selection kind → inspector. Later entries never override earlier ones silently: kinds must be unique. */
export const INSPECTORS: InspectorMap = {
  evidence: EvidenceInspector,
  ...queueInspectors,
  ...findingsInspectors,
  ...workflowInspectors,
  ...surfaceInspectors,
  ...exchangesInspectors,
  ...activityInspectors,
  ...reportInspectors,
}

/** Views whose pane shows the coordinator unless something is explicitly selected. */
export const CHAT_FIRST_VIEWS: ViewId[] = ['overview', 'report']
