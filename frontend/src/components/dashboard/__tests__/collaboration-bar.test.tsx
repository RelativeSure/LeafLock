import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CollaborationBar } from '../collaboration-bar'

vi.mock('@/components/ui/avatar', () => ({
  Avatar: ({ children }: any) => <div data-testid="avatar">{children}</div>,
  AvatarImage: ({ src }: any) => <img src={src} alt="avatar" />,
  AvatarFallback: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('@/components/ui/tooltip', () => ({
  Tooltip: ({ children }: any) => <div>{children}</div>,
  TooltipTrigger: ({ children }: any) => <div>{children}</div>,
  TooltipContent: ({ children }: any) => <div>{children}</div>,
  TooltipProvider: ({ children }: any) => <div>{children}</div>,
}))

const mockGetSessionUsers = vi.fn()

vi.mock('@/lib/collaboration-context', () => ({
  useCollaboration: () => ({
    getSessionUsers: mockGetSessionUsers,
    joinSession: vi.fn(),
    leaveSession: vi.fn(),
    shareNote: vi.fn(),
    unshareNote: vi.fn(),
    getSharedUsers: vi.fn(),
  }),
}))

describe('CollaborationBar', () => {
  const mockUsers = [
    { id: '1', email: 'user1@example.com', name: 'User One', color: '#ff0000' },
    { id: '2', email: 'user2@example.com', name: 'User Two', color: '#00ff00' },
  ]

  const testNoteId = 'test-note-123'

  beforeEach(() => {
    vi.clearAllMocks()
    mockGetSessionUsers.mockReturnValue([])
  })

  it('should render nothing when only one user or less', () => {
    mockGetSessionUsers.mockReturnValue([mockUsers[0]])
    const { container } = render(<CollaborationBar noteId={testNoteId} />)
    expect(container.firstChild).toBeNull()
  })

  it('should display collaboration bar with multiple users', () => {
    mockGetSessionUsers.mockReturnValue(mockUsers)
    render(<CollaborationBar noteId={testNoteId} />)
    expect(screen.getByText('2 people editing')).toBeInTheDocument()
  })

  it('should display user avatars', () => {
    mockGetSessionUsers.mockReturnValue(mockUsers)
    render(<CollaborationBar noteId={testNoteId} />)
    const avatars = screen.getAllByTestId('avatar')
    expect(avatars.length).toBeGreaterThan(0)
  })

  it('should display user initials', () => {
    mockGetSessionUsers.mockReturnValue(mockUsers)
    render(<CollaborationBar noteId={testNoteId} />)
    const initials = screen.getAllByText('U')
    expect(initials.length).toBe(2)
  })

  it('should handle exactly two users', () => {
    mockGetSessionUsers.mockReturnValue(mockUsers)
    render(<CollaborationBar noteId={testNoteId} />)
    expect(screen.getByText('2 people editing')).toBeInTheDocument()
    expect(screen.getAllByTestId('avatar').length).toBe(2)
  })

  it('should limit display to 5 users and show overflow count', () => {
    const manyUsers = Array.from({ length: 8 }, (_, i) => ({
      id: `user-${i}`,
      email: `user${i}@example.com`,
      name: `User ${i}`,
      color: '#000000',
    }))

    mockGetSessionUsers.mockReturnValue(manyUsers)
    render(<CollaborationBar noteId={testNoteId} />)

    expect(screen.getByText('8 people editing')).toBeInTheDocument()
    expect(screen.getByText('+3')).toBeInTheDocument()
  })

  it('should call getSessionUsers with correct noteId', () => {
    mockGetSessionUsers.mockReturnValue(mockUsers)
    render(<CollaborationBar noteId={testNoteId} />)
    expect(mockGetSessionUsers).toHaveBeenCalledWith(testNoteId)
  })

  it('should not render when no users are active', () => {
    mockGetSessionUsers.mockReturnValue([])
    const { container } = render(<CollaborationBar noteId={testNoteId} />)
    expect(container.firstChild).toBeNull()
  })
})
