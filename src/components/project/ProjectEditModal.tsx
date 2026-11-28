import { useEffect, useRef, useState } from 'react'
import { updateProjectAction } from '../../actions.ts'
import { FormError, useAction } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
import { Button } from '../ui/button.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { Input, NativeSelect, Textarea } from '../ui/input.tsx'
import type { ProjectLoaderData } from './types.ts'

interface Props {
  open: boolean
  project: ProjectLoaderData['project']
  onClose: () => void
  onSaved?: () => void
}

/**
 * Client-side mirror of the server's seed rule: an http(s) URL, or a bare
 * hostname (optionally with a port) such as `example.com` or `localhost:3000`.
 * The server stays authoritative; this only catches obvious typos inline.
 */
function isHttpOrigin(token: string): boolean {
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(token)
  try {
    const url = new URL(hasScheme ? token : `https://${token}`)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
    const hostname = url.hostname.replace(/^\[|\]$/g, '')
    return hostname === 'localhost' || hostname.includes('.') || hostname.includes(':')
  } catch {
    return false
  }
}

/**
 * Split seed text on new lines/commas, then on spaces only when every part is
 * an origin — so "a.com b.com" still yields two seeds but a phrase like
 * "not a url" is reported as one invalid token instead of three.
 */
export function parseSeedOrigins(text: string): { seeds: string[]; invalid: string[] } {
  const seeds: string[] = []
  for (const chunk of text.split(/[\n,]+/)) {
    const trimmed = chunk.trim()
    if (!trimmed) continue
    const parts = trimmed.split(/\s+/)
    if (parts.length > 1 && !parts.every(isHttpOrigin)) seeds.push(trimmed)
    else seeds.push(...parts)
  }
  return { seeds, invalid: seeds.filter(token => !isHttpOrigin(token)) }
}

/** "12 origins · 1 invalid" */
export function formatSeedCount(seeds: number, invalid: number): string {
  return [
    `${seeds.toLocaleString('en-US')} ${seeds === 1 ? 'origin' : 'origins'}`,
    invalid > 0 ? `${invalid.toLocaleString('en-US')} invalid` : '',
  ].filter(Boolean).join(' · ')
}

export function ProjectEditModal({ open, project, onClose, onSaved }: Props) {
  const [name, setName] = useState(() => project.name)
  const [environment, setEnvironment] = useState<'public' | 'local-lab'>(() => project.environment)
  const [seedsText, setSeedsText] = useState(() => project.seeds.join('\n'))
  const action = useAction()
  const nameRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    if (!open) return
    setName(project.name)
    setEnvironment(project.environment)
    setSeedsText(project.seeds.join('\n'))
  }, [open, project.id, project.name, project.environment, project.seeds])

  const { seeds: parsedSeeds, invalid: invalidSeeds } = parseSeedOrigins(seedsText)
  const nameMissing = !name.trim()
  const switchingToPublicWithLab = project.environment === 'local-lab' && environment === 'public' && Boolean(project.labConfig)

  return (
    <Dialog
      open={open}
      closeOnEscape={!action.pending}
      onOpenChange={nextOpen => {
        if (!nextOpen && !action.pending) {
          onClose()
        }
      }}
    >
      <DialogContent
        aria-label="Edit project"
        initialFocus={nameRef}
        className="mb-auto mt-[min(12vh,96px)] flex max-h-[calc(100vh-min(12vh,96px)-32px)] max-w-[520px] flex-col overflow-hidden rounded-2xl border-line-2 bg-panel p-0"
      >
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={event => {
            event.preventDefault()
            if (nameMissing || parsedSeeds.length === 0 || invalidSeeds.length > 0) return
            void action.submit(() => updateProjectAction({
              data: {
                requestId: crypto.randomUUID(),
                projectId: project.id,
                name: name.trim(),
                environment,
                seeds: parsedSeeds,
              },
            }), () => {
              onSaved?.()
              onClose()
            })
          }}
        >
          <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
            <DialogTitle className="text-[13px] font-semibold text-fg">Edit project</DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px]"
              disabled={action.pending}
              onClick={onClose}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </Button>
          </DialogHeader>
          <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
            <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
              Project name
              <Input
                ref={nameRef}
                className="w-full"
                name="name"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Acme Web"
                maxLength={160}
                required
                aria-invalid={nameMissing ? true : undefined}
                aria-describedby={nameMissing ? 'edit-project-name-err' : undefined}
                disabled={action.pending}
              />
              {nameMissing && (
                <span id="edit-project-name-err" className="form-error text-[11.5px] font-normal">
                  Name is required
                </span>
              )}
            </label>
            <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
              Seed origins
              <Textarea
                className="w-full font-mono text-[12px]"
                name="seeds"
                rows={Math.min(8, Math.max(3, parsedSeeds.length))}
                aria-invalid={invalidSeeds.length > 0 ? true : undefined}
                aria-describedby="edit-project-seeds-help"
                value={seedsText}
                onChange={e => setSeedsText(e.target.value)}
                placeholder={environment === 'local-lab' ? 'http://localhost:3000' : 'https://app.example.com'}
                required
                disabled={action.pending}
              />
              <span id="edit-project-seeds-help" className="grid gap-0.5 text-[11.5px] font-normal">
                <span className="flex flex-wrap items-baseline justify-between gap-x-3 text-fg-subtle">
                  <span>Separate multiple origins with spaces, commas, or new lines.</span>
                  {parsedSeeds.length > 0 && (
                    <span className="tabular-nums" data-slot="seed-count">
                      {formatSeedCount(parsedSeeds.length, invalidSeeds.length)}
                    </span>
                  )}
                </span>
                {invalidSeeds.length > 0 && (
                  <span className="form-error [overflow-wrap:anywhere]" data-slot="seed-invalid">
                    Not a valid host or origin: {invalidSeeds.slice(0, 5).join(', ')}
                    {invalidSeeds.length > 5 ? ` and ${invalidSeeds.length - 5} more` : ''}
                  </span>
                )}
              </span>
            </label>
            <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
              Environment
              <NativeSelect
                className="w-full"
                name="environment"
                value={environment}
                disabled={action.pending}
                onChange={e => setEnvironment(e.target.value === 'local-lab' ? 'local-lab' : 'public')}
              >
                <option value="public">Public website</option>
                <option value="local-lab">Local lab (localhost / private staging)</option>
              </NativeSelect>
            </label>
            {switchingToPublicWithLab && (
              <p
                role="status"
                className="m-0 rounded-lg border border-warn-line bg-warn-soft px-3 py-2 text-[12px] text-fg"
              >
                Switching to a public project will clear this project&apos;s local lab configuration.
              </p>
            )}
            <FormError error={action.error} />
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={action.pending}
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="default"
              disabled={action.pending || nameMissing || parsedSeeds.length === 0 || invalidSeeds.length > 0}
            >
              {action.pending ? 'Saving…' : 'Save changes'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
