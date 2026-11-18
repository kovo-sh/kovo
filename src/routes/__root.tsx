import { createRootRoute, HeadContent, Link, Outlet, Scripts } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { useEffect, useState } from 'react'
import { Brand } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuLabel,
  DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu.tsx'
import styles from '../app.css?url'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'Guardian' },
    ],
    links: [{ rel: 'stylesheet', href: styles }],
  }),
  component: Shell,
  shellComponent: Document,
  errorComponent: ({ error }) => <main className="workspace-page">
    <h1>Guardian couldn’t open this view</h1>
    <p className="muted">{error instanceof Error ? error.message : 'This view is unavailable.'}</p>
    <Link to="/">Return to workspace</Link>
  </main>,
})

type Appearance = 'system' | 'light' | 'dark'

function ViewPreferences() {
  const [appearance, setAppearance] = useState<Appearance>('system')
  const [layout, setLayout] = useState('workspace')
  useEffect(() => {
    const saved = localStorage.getItem('guardian-appearance')
    if (saved === 'light' || saved === 'dark') setAppearance(saved)
    const savedLayout = localStorage.getItem('guardian-app-layout')
    if (savedLayout === 'canvas' || savedLayout === 'review') setLayout(savedLayout)
  }, [])
  useEffect(() => {
    document.documentElement.dataset.appearance = appearance
    document.documentElement.dataset.appLayout = layout
  }, [appearance, layout])

  return <DropdownMenu>
    <DropdownMenuTrigger render={<Button variant="ghost" />}>View</DropdownMenuTrigger>
    <DropdownMenuContent>
      <DropdownMenuGroup>
        <DropdownMenuLabel>Appearance</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={appearance} onValueChange={(choice: Appearance) => {
          localStorage.setItem('guardian-appearance', choice)
          setAppearance(choice)
        }}>
          <DropdownMenuRadioItem value="system">System</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="light">Light</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">Dark</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuGroup>
      <DropdownMenuGroup>
        <DropdownMenuLabel>Layout</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={layout} onValueChange={(choice: string) => {
          localStorage.setItem('guardian-app-layout', choice)
          setLayout(choice)
        }}>
          <DropdownMenuRadioItem value="workspace">Workspace</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="canvas">Canvas</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="review">Review</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuGroup>
    </DropdownMenuContent>
  </DropdownMenu>
}

function Shell() {
  return <>
    <header className="app-nav">
      <Brand />
      <nav aria-label="Workspace"><Link to="/">Projects</Link></nav>
      <div className="nav-right"><Link to="/settings">Model settings</Link><ViewPreferences /></div>
    </header>
    <Outlet />
  </>
}

function Document({ children }: { children: ReactNode }) {
  return <html lang="en">
    <head><HeadContent /></head>
    <body>{children}<Scripts /></body>
  </html>
}
