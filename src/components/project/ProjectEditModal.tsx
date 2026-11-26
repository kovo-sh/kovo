import { useEffect, useState } from 'react'
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

export function ProjectEditModal({ open, project, onClose, onSaved }: Props) {
  const [name, setName] = useState(() => project.name)
  const [environment, setEnvironment] = useState<'public' | 'local-lab'>(() => project.environment)
  const [seedsText, setSeedsText] = useState(() => project.seeds.join('\n'))
  const action = useAction()

  useEffect(() => {
    if (!open) return
    setName(project.name)
    setEnvironment(project.environment)
    setSeedsText(project.seeds.join('\n'))
  }, [open, project.id, project.name, project.environment, project.seeds])

  const parsedSeeds = seedsText.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)
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
        className="flex max-h-[calc(100vh-56px)] max-w-[520px] flex-col overflow-hidden rounded-2xl border-line-2 bg-panel p-0"
      >
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={event => {
            event.preventDefault()
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
                className="w-full"
                name="name"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Acme Web"
                maxLength={160}
                required
                disabled={action.pending}
              />
            </label>
            <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
              Seed origins
              <Textarea
                className="w-full font-mono text-[12px]"
                name="seeds"
                rows={3}
                value={seedsText}
                onChange={e => setSeedsText(e.target.value)}
                placeholder={environment === 'local-lab' ? 'http://localhost:3000' : 'https://app.example.com'}
                required
                disabled={action.pending}
              />
              <span className="text-[11.5px] font-normal text-fg-subtle">
                Separate multiple origins with spaces, commas, or new lines.
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
              disabled={action.pending || !name.trim() || parsedSeeds.length === 0}
            >
              {action.pending ? 'Saving…' : 'Save changes'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
