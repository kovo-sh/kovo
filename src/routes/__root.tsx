import { createRootRoute, HeadContent, Link, Outlet, Scripts, useRouter, useRouterState } from '@tanstack/react-router'
import type { ErrorComponentProps } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { workspaceData } from '../actions.ts'
import appStyles from '../app.css?url'
import { Icon } from '../components/run/icons.tsx'
import { AppShell } from '../components/shell/AppShell.tsx'
import { Button, buttonVariants } from '../components/ui/button.tsx'
import { EmptyState } from '../components/ui/empty-state.tsx'
import { cn } from '../lib/cn.ts'
import designSystemStyles from '../styles/tailwind.css?url'

export const Route = createRootRoute({
  loader: () => workspaceData(),
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'Kovo' },
    ],
    links: [
      { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
      // Base tokens and element defaults load before Tailwind v4 utilities so
      // utility classes always win cleanly on same-specificity ties.
      { rel: 'stylesheet', href: appStyles },
      { rel: 'stylesheet', href: designSystemStyles },
    ],
  }),
  component: Shell,
  shellComponent: Document,
  // Root-loader failures cannot render the shell (its data is missing), so they
  // get the same friendly treatment full-page. Child-route errors use the
  // router's defaultErrorComponent and render inside AppShell's Outlet.
  errorComponent: props => (
    <div className="flex min-h-screen bg-panel text-fg">
      <RouteErrorView {...props} />
    </div>
  ),
})

/** Keep the document title in sync with an in-shell status view, restoring it on exit. */
function useDocumentTitle(title: string) {
  useEffect(() => {
    const previous = document.title
    document.title = title
    return () => { document.title = previous }
  }, [title])
}

/** Styled 404 rendered inside the AppShell, so the rail, ⌘K and theme toggle stay available. */
export function NotFoundView() {
  const pathname = useRouterState({ select: state => state.location.pathname })
  useDocumentTitle('Not found · Kovo')
  return (
    <main className="flex flex-1 items-center justify-center px-6 py-10">
      <EmptyState
        title="Page not found"
        description={<>Nothing lives at <code className="font-mono text-[12px] [overflow-wrap:anywhere]">{pathname}</code>.</>}
        action={<Link className={buttonVariants({ variant: 'default' })} to="/">Go to Projects</Link>}
      />
    </main>
  )
}

function errorDetail(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === 'string') return error
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') return error.message
  return ''
}

/** False during SSR and the hydration pass, true after mount. */
function useHydrated(): boolean {
  const [hydrated, setHydrated] = useState(false)
  useEffect(() => setHydrated(true), [])
  return hydrated
}

/**
 * Friendly, recoverable route error: plain-language copy, a retry that re-runs
 * the loaders, a way home, and the raw message only behind "Technical details"
 * (never a ZodError array or a JS exception in the body copy).
 */
export function RouteErrorView({ error, reset, className }: ErrorComponentProps & { className?: string }) {
  const router = useRouter()
  // The serialized error the client hydrates with can differ from the server's
  // instance, so the raw details render only after mount (no hydration mismatch).
  const hydrated = useHydrated()
  const detail = hydrated ? errorDetail(error) : ''
  useDocumentTitle('Something went wrong · Kovo')
  return (
    <main className={cn('flex flex-1 items-center justify-center px-6 py-10', className)}>
      <div role="alert" className="flex w-full max-w-[460px] flex-col items-center gap-3 text-center">
        <span className="grid size-8 place-items-center rounded-full bg-warn-soft text-warn-text" aria-hidden="true">
          <Icon name="alert" />
        </span>
        <div className="flex flex-col gap-1">
          <h1 className="text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">Kovo couldn’t open this view</h1>
          <p className="text-[12.5px] leading-5 text-fg-muted text-balance">
            Something went wrong while loading this page. Try again, or head back to your projects.
          </p>
        </div>
        <div className="mt-1 flex flex-wrap items-center justify-center gap-2">
          <Button
            type="button"
            variant="default"
            onClick={() => {
              reset()
              void router.invalidate()
            }}
          >
            Try again
          </Button>
          <Link className={buttonVariants({ variant: 'outline' })} to="/">Go to Projects</Link>
        </div>
        {detail && (
          <details className="mt-2 w-full rounded-lg border border-line bg-sunk px-3 py-2 text-left text-[12px] text-fg-muted">
            <summary className="cursor-pointer select-none font-medium">Technical details</summary>
            <pre className="mt-2 max-h-[240px] overflow-auto whitespace-pre-wrap font-mono text-[11.5px] text-fg-muted [overflow-wrap:anywhere]">
              {detail}
            </pre>
          </details>
        )}
      </div>
    </main>
  )
}

function Shell() {
  // The run workspace is full-screen with its own rail, palette, and header.
  const isRunRoute = useRouterState({
    select: state => state.matches.some(match => match.routeId.startsWith('/runs/$runId')),
  })
  const data = Route.useLoaderData()
  if (isRunRoute) return <Outlet />
  return <AppShell data={data}><Outlet /></AppShell>
}

const THEME_BOOT_SCRIPT = `(function(){try{var s=localStorage.getItem('kovo-appearance');var a=(s==='dark'||s==='light'||s==='system')?s:'light';document.documentElement.dataset.appearance=a;var d=a==='dark'||(a==='system'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=d?'dark':'light';}catch(e){}})();`

function Document({ children }: { children: ReactNode }) {
  return <html lang="en" data-appearance="light" data-theme="light">
    <head>
      <HeadContent />
      <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
    </head>
    <body>{children}<Scripts /></body>
  </html>
}
