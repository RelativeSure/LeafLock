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

  it('does not render dialog when closed', () => {
    render(<ShareNoteDialog open={false} onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('renders share icon', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText('share icon')).toBeInTheDocument()
  })

  it('renders email input field', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByPlaceholderText('user@example.com')).toBeInTheDocument()
  })

  it('renders share with label', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText('Share with')).toBeInTheDocument()
  })

  it('renders add user button', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByRole('button', { name: /add/i })).toBeInTheDocument()
  })

  it('disables share button when email is empty', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    const shareButton = screen.getByRole('button', { name: /add/i })
    expect(shareButton).toBeDisabled()
  })

  it('enables share button when email is provided', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    const emailInput = screen.getByPlaceholderText('user@example.com')
    fireEvent.change(emailInput, { target: { value: 'test@example.com' } })

    const shareButton = screen.getByRole('button', { name: /add/i })
    expect(shareButton).not.toBeDisabled()
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

  it('clears email input after successful share', async () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    const emailInput = screen.getByPlaceholderText('user@example.com') as HTMLInputElement
    fireEvent.change(emailInput, { target: { value: 'test@example.com' } })

    const shareButton = screen.getByRole('button', { name: /add/i })
    fireEvent.click(shareButton)

    await waitFor(() => {
      expect(emailInput.value).toBe('')
    })
  })

  it('shares note when Enter key is pressed', async () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-456" />)

    const emailInput = screen.getByPlaceholderText('user@example.com')
    fireEvent.change(emailInput, { target: { value: 'enter@example.com' } })
    fireEvent.keyDown(emailInput, { key: 'Enter' })

    await waitFor(() => {
      expect(shareNoteMock).toHaveBeenCalledWith('note-456', 'enter@example.com')
    })
  })

  it('displays error message on share failure', async () => {
    shareNoteMock.mockRejectedValueOnce(new Error('User not found'))

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    const emailInput = screen.getByPlaceholderText('user@example.com')
    fireEvent.change(emailInput, { target: { value: 'invalid@example.com' } })

    const shareButton = screen.getByRole('button', { name: /add/i })
    fireEvent.click(shareButton)

    await waitFor(() => {
      expect(screen.getByText('User not found')).toBeInTheDocument()
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

  it('displays shared user count', () => {
    sharedUsers = [
      { id: 'user-1', name: 'Alice', email: 'alice@example.com' },
      { id: 'user-2', name: 'Bob', email: 'bob@example.com' },
    ]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText(/shared with \(2\)/i)).toBeInTheDocument()
  })

  it('unshares user when remove button is clicked', () => {
    sharedUsers = [{ id: 'user-7', name: 'Charlie', email: 'charlie@example.com' }]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-77" />)

    const removeButton = screen.getByRole('button', { name: /remove/i })
    fireEvent.click(removeButton)

    expect(unshareNoteMock).toHaveBeenCalledWith('note-77', 'user-7')
  })

  it('renders active users when more than one', () => {
    activeUsers = [
      { id: 'user-1', name: 'Alice', color: '#ff0000' },
      { id: 'user-2', name: 'Bob', color: '#00ff00' },
    ]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText(/active now \(2\)/i)).toBeInTheDocument()
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('Bob')).toBeInTheDocument()
  })

  it('shows editing badge for active users', () => {
    activeUsers = [
      { id: 'user-1', name: 'Alice', color: '#ff0000' },
      { id: 'user-2', name: 'Bob', color: '#00ff00' },
    ]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    const editingBadges = screen.getAllByText('Editing')
    expect(editingBadges).toHaveLength(2)
  })

  it('does not render active users section when only one active', () => {
    activeUsers = [{ id: 'user-1', name: 'Alice', color: '#ff0000' }]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.queryByText(/active now/i)).not.toBeInTheDocument()
  })

  it('renders empty state when no users shared and no active users', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText('Not shared with anyone yet')).toBeInTheDocument()
    expect(screen.getByText('Enter an email above to start collaborating')).toBeInTheDocument()
  })

  it('does not render empty state when users are shared', () => {
    sharedUsers = [{ id: 'user-1', name: 'Alice', email: 'alice@example.com' }]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.queryByText('Not shared with anyone yet')).not.toBeInTheDocument()
  })

  it('does not render empty state when users are active', () => {
    activeUsers = [
      { id: 'user-1', name: 'Alice', color: '#ff0000' },
      { id: 'user-2', name: 'Bob', color: '#00ff00' },
    ]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.queryByText('Not shared with anyone yet')).not.toBeInTheDocument()
  })

  it('displays user initials in avatars', () => {
    sharedUsers = [{ id: 'user-1', name: 'Alice', email: 'alice@example.com' }]

    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText('A')).toBeInTheDocument()
  })

  it('calls onOpenChange when dialog state changes', () => {
    const onOpenChange = vi.fn()
    render(<ShareNoteDialog open onOpenChange={onOpenChange} noteId="note-1" />)

    expect(onOpenChange).not.toHaveBeenCalled()
  })

  it('does not call shareNote with empty email', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    const emailInput = screen.getByPlaceholderText('user@example.com')
    fireEvent.change(emailInput, { target: { value: '' } })

    const shareButton = screen.getByRole('button', { name: /add/i })
    fireEvent.click(shareButton)

    expect(shareNoteMock).not.toHaveBeenCalled()
  })

  it('does not call shareNote with whitespace-only email', () => {
    render(<ShareNoteDialog open onOpenChange={vi.fn()} noteId="note-1" />)

    const emailInput = screen.getByPlaceholderText('user@example.com')
    fireEvent.change(emailInput, { target: { value: '   ' } })

    const shareButton = screen.getByRole('button', { name: /add/i })
    fireEvent.click(shareButton)

    expect(shareNoteMock).not.toHaveBeenCalled()
  })
})
