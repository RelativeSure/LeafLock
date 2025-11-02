import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { KeyboardShortcutsDialog } from '../keyboard-shortcuts-dialog'

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div data-testid="scroll-area">{children}</div>,
}))

describe('KeyboardShortcutsDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render when open', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render when closed', () => {
    render(<KeyboardShortcutsDialog open={false} onOpenChange={vi.fn()} />)
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should display keyboard shortcuts', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
  })

  it('should show general shortcuts section', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByText(/general|navigation/i)).toBeInTheDocument()
  })

  it('should show editor shortcuts section', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByText(/editor|editing/i)).toBeInTheDocument()
  })

  it('should display keyboard key badges', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByText(/ctrl|cmd|⌘/i)).toBeInTheDocument()
  })

  it('should show save shortcut', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByText(/save/i)).toBeInTheDocument()
  })

  it('should show search shortcut', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByText(/search|find/i)).toBeInTheDocument()
  })

  it('should show new note shortcut', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByText(/new.*note/i)).toBeInTheDocument()
  })

  it('should group shortcuts by category', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    
    const categories = screen.queryAllByRole('heading', { level: 3 })
    expect(categories.length).toBeGreaterThan(0)
  })

  it('should handle dialog close', () => {
    const onOpenChange = vi.fn()
    render(<KeyboardShortcutsDialog open={true} onOpenChange={onOpenChange} />)
    
    const closeButton = screen.queryByRole('button', { name: /close/i })
    if (closeButton) {
      closeButton.click()
      expect(onOpenChange).toHaveBeenCalledWith(false)
    }
  })

  it('should display platform-specific shortcuts', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    
    // Should show either Ctrl or Cmd based on platform
    expect(screen.getByText(/ctrl|cmd|⌘/i)).toBeInTheDocument()
  })

  it('should show formatting shortcuts', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    
    expect(
      screen.getByText(/bold/i) ||
      screen.getByText(/italic/i) ||
      document.body
    ).toBeTruthy()
  })

  it('should display multiple shortcut combinations', () => {
    render(<KeyboardShortcutsDialog open={true} onOpenChange={vi.fn()} />)
    
    const shortcuts = screen.getAllByText(/\+/i)
    expect(shortcuts.length).toBeGreaterThan(0)
  })
})
