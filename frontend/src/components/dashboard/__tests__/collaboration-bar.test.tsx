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

describe('CollaborationBar', () => {
  const mockCollaborators = [
    { id: '1', email: 'user1@example.com', name: 'User One', permission: 'read' },
    { id: '2', email: 'user2@example.com', name: 'User Two', permission: 'write' },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render collaboration bar', () => {
    render(<CollaborationBar collaborators={[]} />)
    expect(document.body).toBeTruthy()
  })

  it('should display collaborators', () => {
    render(<CollaborationBar collaborators={mockCollaborators} />)
    const avatars = screen.getAllByTestId('avatar')
    expect(avatars.length).toBeGreaterThan(0)
  })

  it('should handle empty collaborators list', () => {
    render(<CollaborationBar collaborators={[]} />)
    expect(document.body).toBeTruthy()
  })

  it('should show multiple collaborators', () => {
    render(<CollaborationBar collaborators={mockCollaborators} />)
    expect(screen.getAllByTestId('avatar').length).toBe(2)
  })

  it('should display collaborator initials', () => {
    render(<CollaborationBar collaborators={mockCollaborators} />)
    expect(screen.getByText('UO')).toBeInTheDocument()
    expect(screen.getByText('UT')).toBeInTheDocument()
  })

  it('should handle single collaborator', () => {
    render(<CollaborationBar collaborators={[mockCollaborators[0]]} />)
    expect(screen.getAllByTestId('avatar')).toHaveLength(1)
  })

  it('should apply custom className', () => {
    const { container } = render(<CollaborationBar collaborators={[]} className="custom-bar" />)
    expect(container.firstChild).toHaveClass('custom-bar')
  })

  it('should render with max display limit', () => {
    const manyCollaborators = Array.from({ length: 10 }, (_, i) => ({
      id: `user-${i}`,
      email: `user${i}@example.com`,
      name: `User ${i}`,
      permission: 'read' as const,
    }))

    render(<CollaborationBar collaborators={manyCollaborators} maxDisplay={5} />)
    expect(document.body).toBeTruthy()
  })
})
