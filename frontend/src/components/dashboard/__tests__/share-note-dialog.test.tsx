import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ShareNoteDialog } from '../share-note-dialog'

const shareNoteMock = vi.fn()
const unshareNoteMock = vi.fn()
const getSharedUsersMock = vi.fn()
const getSessionUsersMock = vi.fn()

let sharedUsers: Array<{ id: string; name: string; email: string }> = []
let activeUsers: Array<{ id: string; name: string; color: string }> = []

vi.mock('@/lib/collaboration-context', () => ({
  useCollaboration: vi.fn(() => ({
    shareNote: shareNoteMock,
    unshareNote: unshareNoteMock,
    getSharedUsers: getSharedUsersMock,
    getSessionUsers: getSessionUsersMock,
  })),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button type="button" onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, ...props }: any) => (
    <input value={value} onChange={onChange} {...props} />
  ),
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children }: any) => <label>{children}</label>,
}))

vi.mock('@/components/ui/avatar', () => ({
  Avatar: ({ children }: any) => <div>{children}</div>,
  AvatarFallback: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('lucide-react', () => ({
  Share2: () => <span>share icon</span>,
  UserPlus: () => <span>add</span>,
  X: () => <span>remove</span>,
  Mail: () => <span />,
  Users: () => <span />,
}))

describe('ShareNoteDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sharedUsers = []
    activeUsers = []
    shareNoteMock.mockResolvedValue(undefined)
    getSharedUsersMock.mockImplementation(() => sharedUsers)
    getSessionUsersMock.mockImplementation(() => activeUsers)
  })

  it('renders dialog content when open', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByTestId('dialog')).toBeInTheDocument()
    expect(screen.getByText(/share note/i)).toBeInTheDocument()
  })

  it('shares note with provided email', async () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-123" />)

    const emailInput = screen.getByPlaceholderText('user@example.com')
    fireEvent.change(emailInput, { target: { value: 'teammate@example.com' } })

    const shareButton = screen.getByRole('button', { name: /add/i })
    fireEvent.click(shareButton)

    await waitFor(() => {
      expect(shareNoteMock).toHaveBeenCalledWith('note-123', 'teammate@example.com')
    })
  })

  it('renders shared users list', () => {
    sharedUsers = [
      { id: 'user-1', name: 'Alice', email: 'alice@example.com' },
      { id: 'user-2', name: 'Bob', email: 'bob@example.com' },
    ]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
  })

  it('unshares user when remove button is clicked', () => {
    sharedUsers = [{ id: 'user-7', name: 'Charlie', email: 'charlie@example.com' }]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-77" />)

    const removeButton = screen.getByRole('button', { name: /remove/i })
    fireEvent.click(removeButton)

    expect(unshareNoteMock).toHaveBeenCalledWith('note-77', 'user-7')
  })
})
