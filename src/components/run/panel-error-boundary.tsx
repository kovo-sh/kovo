import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { Icon } from './icons.tsx'
import { runBtn } from './tw.ts'

export interface PanelErrorBoundaryProps {
  /** Human-readable panel name shown in the isolated recovery card. */
  panelName: string
  /** When this key changes (e.g., view or selected entity changed), the boundary auto-recovers. */
  resetKey?: string
  /** Optional entity or view identifier included in the diagnostic summary. */
  entityId?: string
  /** Optional close handler (e.g., close the right-hand inspector pane). */
  onClose?: () => void
  /** Optional error hook for diagnostics or unit tests. */
  onError?: (error: Error, componentStack: string) => void
  children: ReactNode
}

interface PanelErrorBoundaryState {
  hasError: boolean
  errorMessage: string
  diagnostic: string
  copied: boolean
  retryNonce: number
}

function safeErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim().slice(0, 240)
  }
  if (typeof error === 'string' && error.trim()) {
    return error.trim().slice(0, 240)
  }
  return 'Unexpected rendering error.'
}

/**
 * Isolated React Error Boundary for RunShell panels (`<View />` and right-hand `<aside>` panes).
 * Keeps SSE streaming, navigation, and sibling panes alive if a malformed finding/event field throws.
 */
export class PanelErrorBoundary extends Component<PanelErrorBoundaryProps, PanelErrorBoundaryState> {
  override state: PanelErrorBoundaryState = {
    hasError: false,
    errorMessage: '',
    diagnostic: '',
    copied: false,
    retryNonce: 0,
  }

  static getDerivedStateFromError(error: unknown): Partial<PanelErrorBoundaryState> {
    return {
      hasError: true,
      errorMessage: safeErrorMessage(error),
      copied: false,
    }
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    const stackLines = (info.componentStack ?? '')
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean)
      .slice(0, 6)
    const diagnostic = [
      `Panel: ${this.props.panelName}`,
      ...(this.props.entityId ? [`Entity: ${this.props.entityId}`] : []),
      `Error: ${safeErrorMessage(error)}`,
      ...(stackLines.length ? [`Stack:\n${stackLines.join('\n')}`] : []),
    ].join('\n')
    this.setState({ diagnostic })
    this.props.onError?.(error, info.componentStack ?? '')
  }

  override componentDidUpdate(prevProps: PanelErrorBoundaryProps): void {
    if (this.state.hasError && prevProps.resetKey !== this.props.resetKey) {
      this.setState({
        hasError: false,
        errorMessage: '',
        diagnostic: '',
        copied: false,
      })
    }
  }

  private readonly handleReload = () => {
    this.setState(prev => ({
      hasError: false,
      errorMessage: '',
      diagnostic: '',
      copied: false,
      retryNonce: prev.retryNonce + 1,
    }))
  }

  private readonly handleCopyDiagnostic = () => {
    const text = this.state.diagnostic || `Panel: ${this.props.panelName}\nError: ${this.state.errorMessage}`
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(text).then(() => {
        this.setState({ copied: true })
      }).catch(() => undefined)
    }
  }

  override render(): ReactNode {
    if (!this.state.hasError) {
      return <div key={this.state.retryNonce} className="flex min-h-0 min-w-0 flex-1 flex-col">
        {this.props.children}
      </div>
    }

    return (
      <div
        className="flex min-h-0 min-w-0 flex-1 items-center justify-center p-6"
        role="alert"
        data-testid="panel-error-boundary"
        data-panel-name={this.props.panelName}
      >
        <div className="flex w-full max-w-[420px] flex-col gap-3 rounded-[8px] border border-line bg-raise p-4 shadow-sm">
          <div className="flex items-start gap-2.5">
            <Icon name="alert" className="mt-0.5 flex-none text-danger" />
            <div className="min-w-0 flex-1">
              <h2 className="m-0 text-[13px] font-semibold text-fg">
                This panel encountered an error
              </h2>
              <p className="mt-1 mb-0 text-[12px] text-fg-muted">
                {this.props.panelName}
                {this.props.entityId ? ` (${this.props.entityId})` : ''}
                {' '}failed to render. Live updates and other panels remain active.
              </p>
            </div>
          </div>

          {this.state.errorMessage && (
            <pre className="m-0 max-h-24 overflow-auto rounded-[5px] border border-line bg-sunk px-2.5 py-2 font-mono text-[11px] leading-relaxed text-fg-muted whitespace-pre-wrap break-words">
              {this.state.errorMessage}
            </pre>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              className={runBtn({ variant: 'primary', size: 'sm' })}
              data-testid="panel-error-reload"
              onClick={this.handleReload}
            >
              Reload panel
            </button>
            <button
              type="button"
              className={runBtn({ variant: 'default', size: 'sm' })}
              data-testid="panel-error-copy"
              onClick={this.handleCopyDiagnostic}
            >
              {this.state.copied ? 'Diagnostic copied' : 'Copy diagnostic'}
            </button>
            {this.props.onClose && (
              <button
                type="button"
                className={runBtn({ variant: 'ghost', size: 'sm' })}
                data-testid="panel-error-close"
                onClick={this.props.onClose}
              >
                Close panel
              </button>
            )}
          </div>
        </div>
      </div>
    )
  }
}
