import { useEffect, useState } from 'react'
import { registerPersona, updatePersona } from '../../actions.ts'
import type { PersonaAuthKind, PersonaLoginAdapter, PublicPersona } from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { parseCurlOrHeader } from '../curl-parser.ts'
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
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { Input, NativeSelect, Textarea } from '../ui/input.tsx'
import type { ProjectLoaderData } from './types.ts'
import { LOGIN_URL_PLACEHOLDERS } from './types.ts'

export type PersonaSignInMethod = PersonaAuthKind | 'clerk_client'

interface Props {
  open: boolean
  onClose: () => void
  project: ProjectLoaderData['project']
  existingPersonas: readonly Pick<PublicPersona, 'handle' | 'roleLabel'>[]
  editingPersona?: PublicPersona | null
  onCreated: (created: { id: string; handle: string }) => void
  submitLabel?: string
}

export function deriveUniqueHandle(
  label: string,
  existingHandles: readonly string[],
): string {
  const base = label
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/-+$/g, '')
    .slice(0, 48) || 'account'

  const taken = new Set(existingHandles.map(h => h.toLowerCase()))
  if (!taken.has(base)) return base

  for (let n = 2; n < 10_000; n += 1) {
    const suffix = `-${n}`
    const candidate = `${base.slice(0, 48 - suffix.length).replace(/-+$/g, '') || 'account'}${suffix}`
    if (!taken.has(candidate)) return candidate
  }
  return `${base.slice(0, 39)}-${Date.now().toString(36).slice(-8)}`
}

export function suggestNextAccountLabel(
  existingPersonas: readonly Pick<PublicPersona, 'handle' | 'roleLabel'>[],
): string {
  const handles = new Set(existingPersonas.map(p => p.handle.toLowerCase()))
  const labels = existingPersonas.map(p => p.roleLabel.trim().toLowerCase())

  const isTaken = (token: string): boolean => {
    const lower = token.toLowerCase()
    if (handles.has(`user-${lower}`) || handles.has(`user_${lower}`)) return true
    const re = new RegExp(`^user\\s+${lower}(?:$|[^a-z0-9])`, 'i')
    return labels.some(l => re.test(l))
  }

  for (let code = 65; code <= 90; code += 1) {
    const letter = String.fromCharCode(code)
    if (!isTaken(letter)) return `User ${letter}`
  }

  for (let n = 1; n < 10_000; n += 1) {
    const token = String(n)
    if (!isTaken(token)) return `User ${token}`
  }
  return 'User'
}

export function PersonaFormModal({
  open,
  onClose,
  project,
  existingPersonas,
  editingPersona = null,
  onCreated,
  submitLabel = 'Save test account',
}: Props) {
  const [signInMethod, setSignInMethod] = useState<PersonaSignInMethod>('login')
  const [loginAdapter, setLoginAdapter] = useState<PersonaLoginAdapter>('auto')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [roleLabel, setRoleLabel] = useState(() => suggestNextAccountLabel(existingPersonas))
  const [headerName, setHeaderName] = useState('')
  const [origins, setOrigins] = useState(() => project.seeds.join('\n'))
  const [secret, setSecret] = useState('')
  const [curlPaste, setCurlPaste] = useState('')
  const [curlNote, setCurlNote] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const personaAction = useAction()

  const isClerkClient = signInMethod === 'clerk_client'
  const effectiveAuthKind: PersonaAuthKind = isClerkClient ? 'login' : signInMethod
  const editingIsClerkClient = Boolean(
    editingPersona && editingPersona.authKind === 'login' && editingPersona.loginConfig?.adapter === 'clerk_client',
  )
  const keepingSameAuthKind = Boolean(
    editingPersona && editingPersona.authKind === effectiveAuthKind && editingIsClerkClient === isClerkClient,
  )
  const secretRequired = !keepingSameAuthKind

  useEffect(() => {
    if (!open) return
    if (editingPersona) {
      const isClerkClientMethod = editingPersona.loginConfig?.adapter === 'clerk_client'
      setRoleLabel(editingPersona.roleLabel)
      setSignInMethod(isClerkClientMethod ? 'clerk_client' : editingPersona.authKind)
      setLoginAdapter(editingPersona.loginConfig?.adapter ?? 'auto')
      setLoginEmail(editingPersona.loginConfig?.email ?? '')
      setLoginUrl(editingPersona.loginConfig?.loginUrl ?? '')
      setHeaderName(editingPersona.headerName ?? '')
      setOrigins(editingPersona.originAllowlist.join('\n'))
      setSecret('')
      setCurlPaste('')
      setCurlNote('')
      setAdvancedOpen(false)
      return
    }
    setRoleLabel(suggestNextAccountLabel(existingPersonas))
    setHeaderName('')
    setSignInMethod('login')
    setLoginAdapter('auto')
    setLoginEmail('')
    setLoginUrl('')
    setOrigins(project.seeds.join('\n'))
    setSecret('')
    setCurlPaste('')
    setCurlNote('')
    setAdvancedOpen(false)
  }, [open, project.id, project.seeds, existingPersonas, editingPersona])

  function resetForm() {
    setRoleLabel(suggestNextAccountLabel(existingPersonas))
    setHeaderName('')
    setSignInMethod('login')
    setLoginAdapter('auto')
    setLoginEmail('')
    setLoginUrl('')
    setOrigins(project.seeds.join('\n'))
    setSecret('')
    setCurlPaste('')
    setCurlNote('')
    setAdvancedOpen(false)
  }

  function applyCurlParse(rawText: string) {
    const parsed = parseCurlOrHeader(rawText)
    if (!parsed) {
      setCurlNote('Could not detect a Cookie:, Authorization: Bearer, or custom auth header.')
      return
    }
    setSignInMethod(parsed.authKind)
    if (parsed.headerName) setHeaderName(parsed.headerName)
    if (parsed.origin && !origins.includes(parsed.origin)) {
      setOrigins(prev => prev.trim() ? `${prev.trim()}\n${parsed.origin}` : parsed.origin!)
    }
    setSecret(parsed.secret)
    setCurlPaste('')
    setCurlNote(parsed.summary)
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const cleanLabel = roleLabel.trim() || suggestNextAccountLabel(existingPersonas)
    const generatedHandle = deriveUniqueHandle(
      cleanLabel,
      existingPersonas.map(p => p.handle),
    )
    const allowlist = origins.split(/[\s,]+/).filter(Boolean)
    if (allowlist.length === 0) {
      setAdvancedOpen(true)
    }
    const headerNameRaw = headerName.trim()
    const loginUrlRaw = loginUrl.trim()
    if (editingPersona) {
      void personaAction.submit(() => updatePersona({ data: {
        requestId: crypto.randomUUID(),
        projectId: project.id,
        personaId: editingPersona.id,
        roleLabel: cleanLabel,
        originAllowlist: allowlist,
        authKind: effectiveAuthKind,
        ...(effectiveAuthKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
        ...(effectiveAuthKind === 'login' ? {
          loginConfig: {
            adapter: isClerkClient ? 'clerk_client' : loginAdapter,
            ...(!isClerkClient ? { email: loginEmail.trim() } : {}),
            ...(loginUrlRaw ? { loginUrl: loginUrlRaw } : {}),
          },
        } : {}),
        ...(secret.trim() ? { secret } : {}),
      } }), updated => {
        resetForm()
        onClose()
        onCreated(updated)
      })
      return
    }
    void personaAction.submit(() => registerPersona({ data: {
      requestId: crypto.randomUUID(),
      projectId: project.id,
      handle: generatedHandle,
      roleLabel: cleanLabel,
      originAllowlist: allowlist,
      authKind: effectiveAuthKind,
      ...(effectiveAuthKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
      ...(effectiveAuthKind === 'login' ? {
        loginConfig: {
          adapter: isClerkClient ? 'clerk_client' : loginAdapter,
          ...(!isClerkClient ? { email: loginEmail.trim() } : {}),
          ...(loginUrlRaw ? { loginUrl: loginUrlRaw } : {}),
        },
      } : {}),
      secret,
      canaryMarkers: [],
    } }), created => {
      resetForm()
      onClose()
      onCreated(created)
    })
  }

  return (
    <Dialog
      open={open}
      closeOnEscape={!personaAction.pending}
      onOpenChange={nextOpen => {
        if (!nextOpen && !personaAction.pending) onClose()
      }}
    >
      <DialogContent className="flex max-h-[calc(100vh-56px)] max-w-[680px] flex-col overflow-hidden p-0">
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={handleSubmit}>
          <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
            <DialogTitle className="text-[13px] font-semibold text-fg">
              {editingPersona ? 'Edit test account' : 'Add test account'}
            </DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px]"
              onClick={onClose}
              disabled={personaAction.pending}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </Button>
          </DialogHeader>
          <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
            <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
              <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                Account label
                <Input
                  className="w-full"
                  name="roleLabel"
                  required
                  maxLength={160}
                  placeholder="User A"
                  value={roleLabel}
                  onChange={e => setRoleLabel(e.target.value)}
                />
              </label>
              <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                Sign-in method
                <NativeSelect
                  className="w-full"
                  name="authKind"
                  value={signInMethod}
                  onChange={e => setSignInMethod(e.target.value as PersonaSignInMethod)}
                >
                  <option value="login">Email + Password (auto-login &amp; refresh)</option>
                  <option value="clerk_client">Clerk __client cookie (auto-refresh)</option>
                  <option value="cookie">Session cookie (Cookie: …)</option>
                  <option value="bearer">Bearer token (Authorization: Bearer …)</option>
                  <option value="header">Custom request header</option>
                </NativeSelect>
              </label>
            </div>

            {effectiveAuthKind !== 'login' && (
              <div className="grid gap-1.5">
                <div className="flex items-center gap-1.5">
                  <Input
                    className="flex-1 font-mono text-[12px]"
                    value={curlPaste}
                    onChange={e => setCurlPaste(e.target.value)}
                    onPaste={e => {
                      const pasted = e.clipboardData.getData('text')
                      if (pasted) {
                        e.preventDefault()
                        applyCurlParse(pasted)
                      }
                    }}
                    placeholder="Paste cURL or Cookie / Authorization header to auto-extract credentials…"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => applyCurlParse(curlPaste)}
                    disabled={!curlPaste.trim()}
                  >
                    Parse
                  </Button>
                </div>
                {curlNote && <span className="text-[11.5px] text-fg-subtle">{curlNote}</span>}
              </div>
            )}

            {isClerkClient ? (
              <div className="grid gap-2.5">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Clerk __client cookie
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="secret"
                    type="password"
                    required={secretRequired}
                    maxLength={4096}
                    autoComplete="off"
                    value={secret}
                    onChange={e => setSecret(e.target.value)}
                    placeholder={
                      keepingSameAuthKind
                        ? 'Leave blank to keep existing secret'
                        : 'Paste __client cookie value from DevTools (clerk.yourdomain.com)'
                    }
                  />
                  <small className="text-[11.5px] font-normal text-fg-subtle">
                    In your signed-in browser, open DevTools → Application → Cookies on <code className="font-mono">clerk.&lt;domain&gt;</code> or <code className="font-mono">*.clerk.accounts.dev</code> and copy <code className="font-mono">__client</code>. Accepts raw value, <code className="font-mono">__client=…</code>, or a full <code className="font-mono">Cookie:</code> header.
                  </small>
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Clerk Frontend API URL (optional)
                  <Input
                    className="w-full"
                    name="loginUrl"
                    type="url"
                    maxLength={500}
                    autoComplete="off"
                    value={loginUrl}
                    onChange={e => setLoginUrl(e.target.value)}
                    placeholder={LOGIN_URL_PLACEHOLDERS.clerk_client}
                  />
                </label>
              </div>
            ) : effectiveAuthKind === 'login' ? (
              <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Email
                  <Input
                    className="w-full"
                    name="loginEmail"
                    type="email"
                    required
                    maxLength={320}
                    autoComplete="off"
                    value={loginEmail}
                    onChange={e => setLoginEmail(e.target.value)}
                    placeholder="test-a@example.com"
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Password
                  <Input
                    className="w-full"
                    name="secret"
                    type="password"
                    required={secretRequired}
                    maxLength={4096}
                    autoComplete="off"
                    value={secret}
                    onChange={e => setSecret(e.target.value)}
                    placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Encrypted on your machine'}
                  />
                </label>
              </div>
            ) : effectiveAuthKind === 'header' ? (
              <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Header name
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="headerName"
                    required
                    pattern="[A-Za-z0-9-]{1,64}"
                    placeholder="X-Api-Key"
                    value={headerName}
                    onChange={e => setHeaderName(e.target.value)}
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Credential secret
                  <Input
                    className="w-full"
                    name="secret"
                    type="password"
                    required={secretRequired}
                    maxLength={4096}
                    autoComplete="off"
                    value={secret}
                    onChange={e => setSecret(e.target.value)}
                    placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Never displayed back after saving'}
                  />
                </label>
              </div>
            ) : (
              <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                Credential secret
                <Input
                  className="w-full"
                  name="secret"
                  type="password"
                  required={secretRequired}
                  maxLength={4096}
                  autoComplete="off"
                  value={secret}
                  onChange={e => setSecret(e.target.value)}
                  placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Never displayed back after saving'}
                />
              </label>
            )}

            <Disclosure
              open={advancedOpen}
              onOpenChange={setAdvancedOpen}
              className="border-t border-line pt-2.5"
            >
              <DisclosureTrigger className="h-auto bg-transparent px-0 py-1 text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
                Advanced configuration
              </DisclosureTrigger>
              <DisclosureContent className="grid gap-2.5 pt-2.5">
                {effectiveAuthKind === 'login' && !isClerkClient && (
                  <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Auth provider
                      <NativeSelect
                        className="w-full"
                        name="loginAdapter"
                        value={loginAdapter}
                        onChange={e => {
                          const next = e.target.value as PersonaLoginAdapter
                          if (next === 'clerk_client') {
                            setSignInMethod('clerk_client')
                            setLoginAdapter('auto')
                          } else {
                            setLoginAdapter(next)
                          }
                        }}
                      >
                        <option value="auto">Auto-detect</option>
                        <option value="clerk">Clerk (auto-refresh 60s JWT)</option>
                        <option value="clerk_client">Clerk __client cookie (auto-refresh)</option>
                        <option value="json">JSON API / Better Auth</option>
                        <option value="supabase">Supabase Auth</option>
                        <option value="form">Login Form (Browser)</option>
                      </NativeSelect>
                    </label>
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Login URL (optional)
                      <Input
                        className="w-full"
                        name="loginUrl"
                        type="url"
                        maxLength={500}
                        autoComplete="off"
                        value={loginUrl}
                        onChange={e => setLoginUrl(e.target.value)}
                        placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]}
                      />
                    </label>
                  </div>
                )}

                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Allowed sites (one per line or comma-separated)
                  <Textarea
                    className="w-full font-mono text-[12px]"
                    name="originAllowlist"
                    rows={2}
                    value={origins}
                    onChange={e => setOrigins(e.target.value)}
                  />
                </label>
              </DisclosureContent>
            </Disclosure>

            <FormError error={personaAction.error} />
          </DialogBody>
          <DialogFooter className="flex-wrap">
            <span className="mr-auto text-[12px] text-fg-subtle">
              Credentials stay encrypted on your machine and are never sent to AI models.
            </span>
            <Button
              type="button"
              variant="ghost"
              disabled={personaAction.pending}
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button type="submit" variant="default" disabled={personaAction.pending}>
              {personaAction.pending ? 'Saving…' : editingPersona ? 'Save changes' : submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
