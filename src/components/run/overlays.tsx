// Shell-level overlays that several places can open (the header menu, the
// consent sheet, the palette): currently the scope editor.
import { createContext, useContext, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

interface OverlaysApi { editScope: () => void; closeScope: () => void; scopeOpen: boolean }
const OverlaysContext = createContext<OverlaysApi | null>(null)

export function useOverlays() {
  const v = useContext(OverlaysContext)
  if (!v) throw new Error('useOverlays() must be used inside <OverlaysProvider>')
  return v
}

export function OverlaysProvider({ children }: { children: ReactNode }) {
  const [scopeOpen, setScopeOpen] = useState(false)
  const value = useMemo(() => ({ editScope: () => setScopeOpen(true), closeScope: () => setScopeOpen(false), scopeOpen }), [scopeOpen])
  return <OverlaysContext.Provider value={value}>{children}</OverlaysContext.Provider>
}
