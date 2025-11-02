import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { KeyboardShortcutsDialog } from '../keyboard-shortcuts-dialog'

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span data-testid="badge">{children}</span>,
}))

describe('KeyboardShortcutsDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render when open event is triggered', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render initially', () => {
    render(<KeyboardShortcutsDialog />)
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should display keyboard shortcuts list', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    expect(screen.getByTestId('dialog-content')).toBeInTheDocument()
  })

  it('should show shortcuts title', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    expect(screen.getByText(/keyboard shortcuts/i)).toBeInTheDocument()
  })

  it('should display shortcut descriptions', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    expect(screen.getByText(/create new note/i)).toBeInTheDocument()
  })

  it('should display keyboard key badges', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    const badges = screen.getAllByText(/cmd\/ctrl/i)
    expect(badges.length).toBeGreaterThan(0)
  })

  it('should show save shortcut', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    expect(screen.getByText(/save/i)).toBeInTheDocument()
  })

  it('should show search shortcut', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    expect(screen.getByText(/search/i)).toBeInTheDocument()
  })

  it('should show new note shortcut', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))
    expect(screen.getByText(/create new note/i)).toBeInTheDocument()
  })

  it('should display all shortcuts', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))

    // Component has 14 shortcuts defined
    expect(screen.getByText(/create new note/i)).toBeInTheDocument()
    expect(screen.getByText(/search notes/i)).toBeInTheDocument()
    expect(screen.getByText(/save note/i)).toBeInTheDocument()
  })

  it('should display badge components', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))

    const badges = screen.getAllByTestId('badge')
    expect(badges.length).toBeGreaterThan(0)
  })

  it('should show bold formatting shortcut', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))

    expect(screen.getByText(/bold text/i)).toBeInTheDocument()
  })

  it('should show italic formatting shortcut', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))

    expect(screen.getByText(/italic text/i)).toBeInTheDocument()
  })

  it('should display multiple shortcut combinations with plus signs', () => {
    render(<KeyboardShortcutsDialog />)
    fireEvent(window, new Event('open-keyboard-shortcuts'))

    const plusSigns = screen.getAllByText('+')
    expect(plusSigns.length).toBeGreaterThan(0)
  })
})
