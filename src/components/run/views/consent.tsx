// Consent sheet for waiting runs (rendered by Overview), and the scope
// editor it shares with the header's "Edit scope" dialog (@base-ui/react Dialog).
import { Link } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { approvalPolicies, canReviewScope, maxBudgetRequests, maxRpsPerOriginCeiling, maxScopeHosts } from '../../../domain.ts'
import type { ApprovalPolicy, CapabilityTier } from '../../../domain.ts'
import { approvalPolicyMeta, capabilityTierMeta } from '../../run-state.ts'
import { Dialog, DialogContent, DialogTitle } from '../../ui/dialog.tsx'
import { useRun } from '../data.tsx'
import type { Command } from '../data.tsx'
import { useDecisions } from '../decisions.tsx'
import { Kbd } from '../display.tsx'
import { fmtN, fmtUsd, host, plural, words } from '../format.ts'
import { StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { runStatusLabel } from '../meta.ts'
import { consentKey } from '../model.ts'
import { useOverlays } from '../overlays.tsx'
import { useToast } from '../toast.tsx'
import { cn, runBtn, RW } from '../tw.ts'
import { LabPanel } from './lab.tsx'

const PUBLIC_MAX_RPS_CAP = 20

interface Draft {
  assetIds: string[]
  capabilityTier: CapabilityTier
  approvalPolicy: ApprovalPolicy
  approvedPersonaIds: string[]
  budgetUsd: number
  budgetRequests: number
  maxRpsPerOrigin: number
}

/**
 * Resolve default checked candidate IDs for scope review.
 * When `projectDefaultScope` is non-empty, explicit project defaults override `!thirdParty`
 * so previously approved third-party hosts stay checked on subsequent runs.
 */
export function defaultScopeAssetIds(
  run: {
    scopeRevision: number
    approved: readonly string[]
    candidates: readonly { id: string; origin: string; thirdParty: boolean; dnsSource?: unknown }[]
  },
  projectDefaultScope: readonly string[],
): string[] {
  if (run.scopeRevision > 0) return [...run.approved]
  if (projectDefaultScope.length > 0) {
    const saved = new Set(projectDefaultScope)
    return run.candidates.filter(a => saved.has(a.origin)).map(a => a.id)
  }
  return run.candidates.filter(a => !a.thirdParty && !a.dnsSource).map(a => a.id)
}

/** Hosts and default selection for the scope sheet, per phase. */
function useScopeModel() {
  const { detail } = useRun()
  const r = detail.run
  const p = detail.project
  return useMemo(() => {
    const discovery = r.phase === 'consent'
    const hosts = discovery
      ? p.seeds.map(s => ({ id: s, origin: s, thirdParty: false, source: 'Project seed', externalCname: null as string | null }))
      : r.candidates.map(c => ({
        id: c.id,
        origin: c.origin,
        thirdParty: c.thirdParty,
        source: c.source,
        externalCname: c.dnsSource?.externalAliases?.[0] ?? null,
      }))
    const defaults = defaultScopeAssetIds(r, p.defaultScope)
    return { discovery, hosts, defaults }
  }, [r, p])
}

function initialDraft(r: ReturnType<typeof useRun>['detail']['run'], defaults: string[], rpsMax: number): Draft {
  return {
    assetIds: defaults, capabilityTier: r.capabilityTier, approvalPolicy: r.approvalPolicy ?? 'auto_review',
    approvedPersonaIds: [...r.approvedPersonaIds], budgetUsd: r.budgetUsd, budgetRequests: r.budgetRequests,
    maxRpsPerOrigin: Math.min(r.maxRpsPerOrigin, rpsMax),
  }
}

function scopeCommand(
  r: ReturnType<typeof useRun>['detail']['run'],
  d: Draft,
  opts: { saveProject?: boolean; scopeOnly?: boolean; expectedScopeRevision?: number } = {},
): Command {
  const { saveProject = false, scopeOnly = false, expectedScopeRevision = r.scopeRevision } = opts
  return {
    action: 'scope',
    assetIds: d.assetIds,
    expectedScopeRevision,
    consent: true,
    saveProject,
    capabilityTier: d.capabilityTier,
    approvedPersonaIds: d.capabilityTier >= 2 ? d.approvedPersonaIds : [],
    ...(scopeOnly
      ? {}
      : {
          approvalPolicy: d.approvalPolicy,
          budgetUsd: d.budgetUsd,
          budgetRequests: d.budgetRequests,
          maxRpsPerOrigin: d.maxRpsPerOrigin,
        }),
  }
}

const selectClass =
  'mt-[3px] h-[26px] max-w-full rounded-control border-0 bg-panel px-1.5 font-sans text-[12.5px] font-medium text-fg shadow-hairline outline-none focus:shadow-[0_0_0_1px_var(--accent-line),0_0_0_3px_var(--accent-soft)]'

/**
 * The scope card: testing mode / test accounts (plus budget / approvals / rate on consent),
 * the host grid, and a footer with the primary action. Editable when `editing`.
 */
function ScopeCard({ editing, draft, setDraft, footer, inDialog = false, scopeOnly = false }: {
  editing: boolean
  draft: Draft
  setDraft: (fn: (d: Draft) => Draft) => void
  footer: ReactNode
  inDialog?: boolean
  scopeOnly?: boolean
}) {
  const { detail } = useRun()
  const rpsMax = detail.project.environment === 'local-lab' ? maxRpsPerOriginCeiling : PUBLIC_MAX_RPS_CAP
  const { discovery, hosts } = useScopeModel()
  const selected = new Set(draft.assetIds)
  const shownHosts = editing || discovery ? hosts : hosts.filter(h => selected.has(h.id))
  const canEditConfig = editing && !discovery
  const kvItems: [string, ReactNode][] = scopeOnly
    ? [
        ['Testing mode', canEditConfig
          ? <select className={selectClass} value={draft.capabilityTier} onChange={e => setDraft(d => ({ ...d, capabilityTier: Number(e.target.value) as CapabilityTier }))} aria-label="Testing mode">
            {([0, 1, 2, 3] as const).map(t => <option key={t} value={t}>{capabilityTierMeta[t].name}</option>)}
          </select>
          : <span title={capabilityTierMeta[draft.capabilityTier].summary}>{capabilityTierMeta[draft.capabilityTier].name}</span>],
        ['Test accounts', draft.approvedPersonaIds.length && draft.capabilityTier >= 2 ? plural(draft.approvedPersonaIds.length, 'test account') : 'None (anonymous)'],
      ]
    : [
        ['Testing mode', canEditConfig
          ? <select className={selectClass} value={draft.capabilityTier} onChange={e => setDraft(d => ({ ...d, capabilityTier: Number(e.target.value) as CapabilityTier }))} aria-label="Testing mode">
            {([0, 1, 2, 3] as const).map(t => <option key={t} value={t}>{capabilityTierMeta[t].name}</option>)}
          </select>
          : <span title={capabilityTierMeta[draft.capabilityTier].summary}>{capabilityTierMeta[draft.capabilityTier].name}</span>],
        ['Budget', canEditConfig
          ? <span className="mt-[3px] flex gap-1">
            <input className={cn(RW.fieldInput, 'num h-[26px] w-[74px]')} type="number" min={0.1} max={500} step="any" value={draft.budgetUsd} aria-label="Budget USD" onChange={e => setDraft(d => ({ ...d, budgetUsd: Number(e.target.value) }))} />
            <input className={cn(RW.fieldInput, 'num h-[26px] w-[74px]')} type="number" min={0} max={maxBudgetRequests} step={1} value={draft.budgetRequests} aria-label="Request cap (0 = uncapped)" title="Request cap (0 = uncapped)" onChange={e => setDraft(d => ({ ...d, budgetRequests: Number(e.target.value) }))} />
          </span>
          : <>{fmtUsd(draft.budgetUsd)} · {draft.budgetRequests ? fmtN(draft.budgetRequests) + ' requests' : 'uncapped requests'}</>],
        ['Approvals', canEditConfig && draft.capabilityTier === 3
          ? <select className={selectClass} value={draft.approvalPolicy} onChange={e => setDraft(d => ({ ...d, approvalPolicy: e.target.value as ApprovalPolicy }))} aria-label="Approval policy">
            {approvalPolicies.map(p => <option key={p} value={p}>{approvalPolicyMeta[p].label}</option>)}
          </select>
          : draft.capabilityTier === 3
            ? <span title={approvalPolicyMeta[draft.approvalPolicy].summary}>{approvalPolicyMeta[draft.approvalPolicy].label}</span>
            : <span className="font-normal text-fg-subtle" title="Approval policy only applies to Active Testing (Tier 3)">Not needed (read-only)</span>],
        ['Rate limit', canEditConfig
          ? <input className={cn(RW.fieldInput, 'num mt-[3px] h-[26px] w-[74px]')} type="number" min={1} max={rpsMax} step={1} value={draft.maxRpsPerOrigin} aria-label="Requests per second per origin" onChange={e => setDraft(d => ({ ...d, maxRpsPerOrigin: Math.min(rpsMax, Math.max(1, Number(e.target.value))) }))} />
          : <>{Math.min(draft.maxRpsPerOrigin, rpsMax)} req/s per origin</>],
        ['Test accounts', draft.approvedPersonaIds.length && draft.capabilityTier >= 2 ? plural(draft.approvedPersonaIds.length, 'test account') : 'None (anonymous)'],
      ]

  return <div className={inDialog ? 'overflow-hidden bg-panel' : RW.sheet}>
    <div className={RW.sheetH}>
      <Icon name="globe" />
      {inDialog
        ? <DialogTitle className="text-[13px] font-medium text-fg">Proposed scope</DialogTitle>
        : <span>Proposed scope</span>}
      <span className="num font-normal text-fg-subtle">
        {discovery
          ? plural(hosts.length, 'host') + ' from project seeds'
          : `${selected.size} of ${plural(hosts.length, 'discovered host')} selected`}
      </span>
      {editing && !discovery && <span className="ml-auto flex gap-1">
        <button type="button" className={runBtn({ variant: 'ghost', size: 'xs' })} onClick={() => setDraft(d => ({ ...d, assetIds: hosts.filter(h => !h.thirdParty).slice(0, maxScopeHosts).map(h => h.id) }))}>First-party</button>
        <button type="button" className={runBtn({ variant: 'ghost', size: 'xs' })} onClick={() => setDraft(d => ({ ...d, assetIds: [] }))}>Clear</button>
      </span>}
    </div>
    <div className={cn('num grid border-b border-line', scopeOnly ? 'grid-cols-2' : 'grid-cols-3')}>
      {kvItems.map(([k, v], i) => (
        <div
          key={k}
          className={cn(
            'px-4 py-2.5',
            scopeOnly
              ? i === 0 && 'border-r border-line'
              : cn(i % 3 !== 2 && i !== kvItems.length - 1 && 'border-r border-line', i >= 3 && 'border-t border-line', i === 4 && 'col-span-2'),
          )}
        >
          <div className="text-[11.5px] text-fg-subtle">{k}</div>
          <div className="font-medium text-fg">{v}</div>
        </div>
      ))}
    </div>
    {canEditConfig && detail.personas.length > 0 && <div className="flex flex-col gap-2 border-t border-line px-4 pb-3 pt-2.5">
      <span className="text-[12px] text-fg-subtle">Bind test accounts{draft.capabilityTier < 2 ? ' (requires Authenticated or Active mode)' : ''}</span>
      {detail.personas.map(p => <label key={p.id} className="flex cursor-pointer select-none items-center gap-2 text-[12.5px] text-fg-muted">
        <input
          className="m-0 size-[13px] accent-[var(--accent)]"
          type="checkbox"
          disabled={draft.capabilityTier < 2}
          checked={draft.approvedPersonaIds.includes(p.id)}
          onChange={e => setDraft(d => ({ ...d, approvedPersonaIds: e.target.checked ? [...d.approvedPersonaIds, p.id] : d.approvedPersonaIds.filter(x => x !== p.id) }))}
        />
        <b className="font-medium text-fg">{p.handle}</b> · {p.roleLabel}
      </label>)}
    </div>}
    {editing && !discovery
      ? <div className="grid max-h-[224px] grid-cols-3 overflow-auto p-2 font-mono text-[12px]">
        {hosts.map(h => {
          const on = selected.has(h.id)
          return <label
            key={h.id}
            className={cn(
              'flex cursor-pointer items-center gap-[7px] overflow-hidden whitespace-nowrap rounded-[4px] px-2 py-[3px] hover:bg-hover',
              on ? 'text-fg-muted' : 'text-fg-faint',
            )}
            title={`${h.origin} · ${h.source}`}
          >
            <input
              className="m-0 flex-none accent-[var(--accent)]"
              type="checkbox"
              aria-label={'Include ' + host(h.origin)}
              checked={on}
              onChange={e => setDraft(d => ({ ...d, assetIds: e.target.checked ? [...d.assetIds, h.id] : d.assetIds.filter(x => x !== h.id) }))}
            />
            <span className="truncate">{host(h.origin)}</span>
            {h.thirdParty && <span className="ml-1 text-[10.5px] text-fg-subtle" title={h.externalCname ? `Third-party CNAME (${h.externalCname}) — unchecked by default` : 'Third-party host — unchecked by default'}>
              {h.externalCname ? `Third-party CNAME (${h.externalCname})` : '3P'}
            </span>}
          </label>
        })}
      </div>
      : <div className="grid max-h-[224px] grid-cols-3 overflow-auto p-2 font-mono text-[12px]">
        {shownHosts.map(h => <span key={h.id} className="truncate px-2 py-[3px] text-fg-muted" title={`${h.origin} · ${h.source}`}>{host(h.origin)}</span>)}
        {!shownHosts.length && <span className="px-2 py-[3px] text-fg-subtle">No hosts selected.</span>}
        {!discovery && hosts.length > shownHosts.length && (
          <span className="col-span-3 px-2 pt-1 font-sans text-[11.5px] text-fg-subtle">
            {plural(hosts.length - shownHosts.length, 'discovered host')} unchecked by default (e.g. third-party or subdomains). Click Edit scope to review all {hosts.length}.
          </span>
        )}
      </div>}
    {editing && discovery && <div className="flex flex-col gap-2 border-t border-line px-4 pb-3 pt-2.5">
      <span className="text-[12px] text-fg-subtle">
        Discovery runs on the project seeds. Hosts it finds come back here for scope review; edit the seeds on the{' '}
        <Link to="/projects/$projectId" params={{ projectId: detail.project.id }} className="underline">project page</Link>.
      </span>
    </div>}
    {footer}
  </div>
}

const STEPS: [string, string][] = [
  ['Consent', 'Approve hosts, mode, and budget.'],
  ['Threat model', 'Rank hosts by attack surface.'],
  ['Investigation', 'Workers test through the safety proxy.'],
  ['Verification', 'Automated replay confirms every finding.'],
  ['Report', 'Findings, coverage, and gaps.'],
]

/** Overview for a waiting run: "Nothing has been sent yet." */
export function ConsentView() {
  const { detail } = useRun()
  const q = useDecisions()
  const r = detail.run
  const rpsMax = detail.project.environment === 'local-lab' ? maxRpsPerOriginCeiling : PUBLIC_MAX_RPS_CAP
  const { discovery, hosts, defaults } = useScopeModel()
  const [editing, setEditing] = useState(false)
  const syncKey = `${r.id}:${r.phase}:${r.scopeRevision}:${defaults.join(',')}`
  const [syncedKey, setSyncedKey] = useState(syncKey)
  const [draft, setDraftState] = useState<Draft>(() => initialDraft(r, defaults, rpsMax))
  const setDraft = (fn: (d: Draft) => Draft) => setDraftState(fn)
  const ck = consentKey(r)
  const decision = q.get(ck)
  const scoped = Boolean(decision)
  if (syncedKey !== syncKey && !editing && !scoped) {
    setSyncedKey(syncKey)
    setDraftState(initialDraft(r, defaults, rpsMax))
  }
  const nw = (r.goal || '').split(/\s+/).filter(Boolean).length
  const count = discovery ? hosts.length : draft.assetIds.length
  const overLimit = draft.assetIds.length > maxScopeHosts
  const canApprove = q.canAct(ck, 'scope') && (discovery || (count > 0 && !overLimit))
  const footerNote = overLimit
    ? `Choose up to ${maxScopeHosts} hosts.`
    : !discovery && count === 0
      ? 'Select at least one host to start the assessment.'
      : draft.capabilityTier === 3
        ? draft.approvalPolicy === 'yolo'
          ? 'Active checks run autonomously in scope; hard safety guardrails stay enforced.'
          : draft.approvalPolicy === 'strict'
            ? 'Every state-changing request will pause for your explicit approval.'
            : 'Safe checks auto-approve; deletes, uploads, and execution proofs ask first.'
        : `Approving authorizes a scoped defensive assessment (${capabilityTierMeta[draft.capabilityTier].short}).`

  const approve = () => {
    if (!canApprove) return
    const command: Command = discovery ? { action: 'discover', consent: true } : scopeCommand(r, draft)
    q.decide(ck, 'scope', {
      command,
      message: discovery ? `Discovery approved for ${plural(hosts.length, 'host')}` : `Scope approved for ${plural(count, 'host')} (${capabilityTierMeta[draft.capabilityTier].short})`,
    })
    setEditing(false)
  }
  useShortcuts([{ key: 'a', run: () => { if (!canApprove) return false; approve() } }])

  const eyebrow = scoped
    ? decision!.state === 'sent' ? 'Approved · the coordinator is starting' : 'Approved · sends when the undo window closes'
    : r.phase === 'review' ? 'Waiting on your scope approval' : 'Waiting on your consent'
  return <div className="min-h-0 flex-1 overflow-auto px-10 pb-12 pt-11">
    <div className="mx-auto max-w-[680px]">
      <span className="inline-flex items-center gap-2 text-[12px] font-medium text-fg-muted">
        <StatusGlyph status={scoped ? 'complete' : 'waiting'} />{eyebrow}
      </span>
      <div className="mb-2 mt-3 text-[24px] font-semibold leading-[31px] tracking-[-0.02em] text-fg">
        Nothing has been sent <em className="not-italic text-fg-subtle">yet.</em>
      </div>
      <p className="m-0 mb-[22px] max-w-[560px] text-[13.5px] leading-[21px] text-fg-muted">
        {discovery
          ? `The coordinator received the goal “${r.goal}” and is holding until you approve discovery below. No request leaves Kovo Hunter before that.`
          : `Subdomain discovery found ${plural(hosts.length, 'candidate host')} for “${r.goal}”. Confirm the target hosts, mode, and approval policy below before testing begins.`}
      </p>
      {nw < 6 && <div className="mb-[18px] flex items-start gap-2.5 rounded-lg bg-warn-soft px-3 py-2.5 text-[12.5px] leading-[19px] text-fg-muted shadow-[inset_0_0_0_1px_var(--warn-line)]">
        <Icon name="alert" className="mt-[3px] flex-none text-warn" />
        <div>This goal is {words(nw)} word{nw === 1 ? '' : 's'} long. The coordinator will plan broadly across all {plural(count, 'host')}. Sharpen it in the coordinator chat to focus the {fmtUsd(draft.budgetUsd)} budget.</div>
      </div>}
      <ScopeCard
        editing={editing}
        draft={draft}
        setDraft={setDraft}
        footer={
          <div className={RW.sheetF}>
            <span className="mr-auto text-[12px] text-fg-subtle">
              {footerNote}
            </span>
            {scoped
              ? decision!.state !== 'sent' && <button type="button" className={runBtn()} onClick={() => q.reopen(ck)}><Icon name="undo" />Undo</button>
              : <>
                {!discovery && <button type="button" className={runBtn({ variant: 'ghost' })} onClick={() => { if (editing) setDraftState(initialDraft(r, defaults, rpsMax)); setEditing(!editing) }}>{editing ? 'Reset' : 'Edit scope'}</button>}
                <button type="button" className={runBtn({ variant: 'primary' })} disabled={!canApprove} onClick={approve}>
                  Approve &amp; start<Kbd inverted className="ml-0.5">A</Kbd>
                </button>
              </>}
          </div>
        }
      />
      <div className="mt-[26px] grid grid-cols-5 border-t border-line">
        {STEPS.map((s, i) => {
          const cur = (scoped ? 1 : 0) === i
          return <div
            key={s[0]}
            className={cn(
              'relative pr-3 pt-3 text-[12px] leading-[18px] text-fg-subtle before:absolute before:-top-px before:left-0 before:w-7 before:content-[""]',
              cur ? 'before:h-0.5 before:bg-accent' : 'before:h-px before:bg-fg-subtle',
            )}
          >
            <b className={cn('mb-0.5 block font-medium', cur ? 'text-fg' : 'text-fg-muted')}>{s[0]}</b>
            {s[1]}
          </div>
        })}
      </div>
      <LabPanel className="mt-[26px] border-t border-line" />
    </div>
  </div>
}

/** Header "Edit scope" dialog for runs past consent: save a scope revision or add a candidate host. */
export function ScopeOverlay() {
  const { detail, send, refresh, pending } = useRun()
  const overlays = useOverlays()
  const toast = useToast()
  const r = detail.run
  const rpsMax = detail.project.environment === 'local-lab' ? maxRpsPerOriginCeiling : PUBLIC_MAX_RPS_CAP
  const { discovery, defaults } = useScopeModel()
  const [draft, setDraftState] = useState<Draft>(() => initialDraft(r, defaults, rpsMax))
  const [draftRevision, setDraftRevision] = useState(r.scopeRevision)
  const [saveProject, setSaveProject] = useState(false)
  const [adding, setAdding] = useState(false)
  const [origin, setOrigin] = useState('')
  const [source, setSource] = useState('')
  const [thirdParty, setThirdParty] = useState(false)
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveErr, setSaveErr] = useState('')
  const [conflict, setConflict] = useState(false)
  const [reloading, setReloading] = useState(false)
  const [pendingReload, setPendingReload] = useState(false)
  const editable = canReviewScope(r.phase, r.status) && !discovery
  const isRevisionConflict = conflict || r.scopeRevision !== draftRevision

  useEffect(() => {
    if (!pendingReload) return
    setDraftState(initialDraft(r, defaults, rpsMax))
    setDraftRevision(r.scopeRevision)
    setPendingReload(false)
  }, [pendingReload, r, defaults, rpsMax])

  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => { if (!saving) overlays.closeScope() } }], { priority: 100, exclusive: true })

  const reloadLatestScope = async () => {
    setReloading(true)
    setSaveErr('')
    setConflict(false)
    try {
      await refresh()
    } finally {
      setReloading(false)
      setPendingReload(true)
    }
  }

  const save = async () => {
    if (saving || !editable) return
    const command = scopeCommand(r, draft, {
      saveProject,
      scopeOnly: true,
      expectedScopeRevision: draftRevision,
    })
    setSaving(true)
    setSaveErr('')
    setConflict(false)
    try {
      await send(command)
      toast.show(`Saved scope revision ${draftRevision + 1} (${plural(draft.assetIds.length, 'host')})`, { icon: 'globe' })
      overlays.closeScope()
    } catch (failure) {
      const msg = failure instanceof Error ? failure.message : 'Could not save scope revision.'
      setSaveErr(msg)
      if (/scope changed|scope_revision|revision/i.test(msg)) {
        setConflict(true)
      }
    } finally {
      setSaving(false)
    }
  }

  return <Dialog open closeOnEscape={!saving} onOpenChange={open => { if (!open && !saving) overlays.closeScope() }}>
    <DialogContent className="max-h-[80vh] max-w-[720px] overflow-auto rounded-2xl border-line-2 p-0" aria-label="Edit scope">
      <ScopeCard
        inDialog
        scopeOnly
        editing={editable}
        draft={draft}
        setDraft={fn => setDraftState(fn)}
        footer={<>
          {adding && <form
            className="flex flex-col gap-2 border-t border-line px-4 pb-3 pt-2.5"
            onSubmit={e => {
              e.preventDefault()
              setErr('')
              send({ action: 'candidate', candidate: { origin, source, thirdParty } }).then(() => { setAdding(false); setOrigin(''); setSource('') }, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not add the host'))
            }}
          >
            <span className="text-[12px] text-fg-subtle">Add a candidate host for scope review</span>
            <div className="flex gap-1.5">
              <input className={cn(RW.fieldInput, 'flex-1')} required placeholder="docs.example.com" value={origin} onChange={e => setOrigin(e.target.value)} aria-label="Host" />
              <input className={cn(RW.fieldInput, 'flex-1')} required maxLength={160} placeholder="Source (e.g. service inventory)" value={source} onChange={e => setSource(e.target.value)} aria-label="Source" />
            </div>
            <label className="flex cursor-pointer select-none items-center gap-2 text-[12.5px] text-fg-muted">
              <input className="m-0 size-[13px] accent-[var(--accent)]" type="checkbox" checked={thirdParty} onChange={e => setThirdParty(e.target.checked)} />
              Third-party service
            </label>
            {err && <span className="text-[12px] text-danger">{err}</span>}
            <div className="flex justify-end gap-1.5">
              <button type="button" className={runBtn({ variant: 'ghost' })} onClick={() => setAdding(false)}>Cancel</button>
              <button type="submit" className={runBtn()} disabled={pending > 0}>Add for review</button>
            </div>
          </form>}
          {isRevisionConflict && <div className="flex items-center gap-2.5 border-t border-line bg-warn-soft px-4 py-2.5 text-[12px] leading-[17px] text-fg" role="alert">
            <Icon name="alert" className="flex-none text-warn" />
            <span className="min-w-0 flex-1">
              {saveErr || `Scope changed on the server (now revision ${r.scopeRevision}) while you were editing.`} Reload the latest scope before saving.
            </span>
            <button type="button" className={runBtn({ size: 'xs' })} disabled={reloading || saving} onClick={() => void reloadLatestScope()}>
              {reloading ? 'Reloading…' : 'Reload latest scope'}
            </button>
          </div>}
          {!isRevisionConflict && saveErr && <div className="flex items-center gap-2 border-t border-line px-4 py-2 text-[12px] text-danger" role="alert">
            <Icon name="alert" className="flex-none" />
            <span>{saveErr}</span>
          </div>}
          <div className={RW.sheetF}>
            {editable
              ? <label className="mr-auto flex cursor-pointer select-none items-center gap-2 text-[12px] text-fg-subtle">
                <input className="m-0 size-[13px] accent-[var(--accent)]" type="checkbox" disabled={saving} checked={saveProject} onChange={e => setSaveProject(e.target.checked)} />
                Save as the project default
              </label>
              : <span className="mr-auto text-[12px] text-fg-subtle">{discovery ? 'Scope is reviewed after discovery.' : `Scope can’t change while the run is ${runStatusLabel(r.status).toLowerCase()}.`}</span>}
            {r.phase !== 'complete' && !discovery && !adding && <button type="button" className={runBtn({ variant: 'ghost' })} disabled={saving} onClick={() => setAdding(true)}><Icon name="plus" />Add host</button>}
            <button type="button" className={runBtn({ variant: 'ghost' })} disabled={saving} onClick={() => overlays.closeScope()}>Close</button>
            {editable && <button type="button" className={runBtn({ variant: 'primary' })} disabled={saving || reloading || isRevisionConflict || !draft.assetIds.length || draft.assetIds.length > maxScopeHosts} onClick={() => void save()}>{saving ? 'Saving…' : (r.phase === 'review' ? 'Approve scope' : 'Save scope revision')}</button>}
          </div>
        </>}
      />
    </DialogContent>
  </Dialog>
}
