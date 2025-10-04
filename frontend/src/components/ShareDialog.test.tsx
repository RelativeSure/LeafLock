import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ShareDialog } from './ShareDialog'
import { useCollaborationStore } from '../stores/collaborationStore'
import { useShareLinksStore } from '../stores/shareLinksStore'

// Mock stores
vi.mock('../stores/collaborationStore')
vi.mock('../stores/shareLinksStore')
vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

describe('ShareDialog', () => {
  const mockNoteId = 'note-123'
  const mockCollaborators = [
    {
      id: 'collab-1',
      note_id: mockNoteId,
      user_id: 'user-1',
      user_email: 'user1@example.com',
      permission: 'read' as const,
      created_at: new Date().toISOString(),
    },
  ]

  const mockShareLinks = [
    {
      id: 'link-1',
      token: 'token-abc',
      note_id: mockNoteId,
      permission: 'read' as const,
      use_count: 5,
      is_active: true,
      has_password: false,
      share_url: 'https://example.com/share/token-abc',
      created_at: new Date().toISOString(),
    },
  ]

  const mockFetchCollaborators = vi.fn()
  const mockShareNote = vi.fn()
  const mockRemoveCollaborator = vi.fn()
  const mockFetchNoteShareLinks = vi.fn()
  const mockCreateShareLink = vi.fn()
  const mockRevokeShareLink = vi.fn()
  const mockCopyLinkToClipboard = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()

    // Setup collaboration store mock
    ;(useCollaborationStore as any).mockReturnValue({
      collaborators: mockCollaborators,
      shareNote: mockShareNote,
      removeCollaborator: mockRemoveCollaborator,
      fetchCollaborators: mockFetchCollaborators,
    })

    // Setup share links store mock
    ;(useShareLinksStore as any).mockReturnValue({
      currentNoteLinks: mockShareLinks,
      createShareLink: mockCreateShareLink,
      fetchNoteShareLinks: mockFetchNoteShareLinks,
      revokeShareLink: mockRevokeShareLink,
      copyLinkToClipboard: mockCopyLinkToClipboard,
    })
  })

  describe('Dialog Opening', () => {
    it('should render trigger button', () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      expect(triggerButton).toBeInTheDocument()
    })

    it('should open dialog and fetch data when clicked', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      await waitFor(() => {
        expect(mockFetchCollaborators).toHaveBeenCalledWith(mockNoteId)
        expect(mockFetchNoteShareLinks).toHaveBeenCalledWith(mockNoteId)
      })
    })
  })

  describe('Collaborators Tab', () => {
    it('should display collaborators list', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      await waitFor(() => {
        expect(screen.getByText('user1@example.com')).toBeInTheDocument()
      })
    })

    it('should show add collaborator form for owner', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/enter email address/i)).toBeInTheDocument()
      })
    })

    it('should not show add collaborator form for non-owner', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={false} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      await waitFor(() => {
        expect(screen.queryByPlaceholderText(/enter email address/i)).not.toBeInTheDocument()
      })
    })

    it('should add collaborator when form submitted', async () => {
      mockShareNote.mockResolvedValueOnce(undefined)

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const emailInput = await screen.findByPlaceholderText(/enter email address/i)
      await userEvent.type(emailInput, 'newuser@example.com')

      const shareButton = screen.getByRole('button', { name: /share note/i })
      await userEvent.click(shareButton)

      await waitFor(() => {
        expect(mockShareNote).toHaveBeenCalledWith(
          mockNoteId,
          'newuser@example.com',
          expect.any(String)
        )
      })
    })
  })

  describe('Share Links Tab', () => {
    it('should switch to share links tab', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.getByText(/create share link/i)).toBeInTheDocument()
      })
    })

    it('should display active share links', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.getByText(/active share links \(1\)/i)).toBeInTheDocument()
        expect(screen.getByDisplayValue(/https:\/\/example.com\/share\/token-abc/i)).toBeInTheDocument()
      })
    })

    it('should create share link with configuration', async () => {
      const newLink = {
        id: 'link-new',
        token: 'new-token',
        note_id: mockNoteId,
        permission: 'write' as const,
        share_url: 'https://example.com/share/new-token',
        use_count: 0,
        is_active: true,
        has_password: false,
        created_at: new Date().toISOString(),
      }

      mockCreateShareLink.mockResolvedValueOnce(newLink)
      mockCopyLinkToClipboard.mockResolvedValueOnce(undefined)

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      // Select write permission
      const permissionSelect = screen.getAllByRole('combobox')[0]
      await userEvent.click(permissionSelect)
      const writeOption = await screen.findByText(/read & write/i)
      await userEvent.click(writeOption)

      // Click create button
      const createButton = screen.getByRole('button', { name: /create share link/i })
      await userEvent.click(createButton)

      await waitFor(() => {
        expect(mockCreateShareLink).toHaveBeenCalledWith(
          mockNoteId,
          expect.objectContaining({
            permission: 'write',
          })
        )
        expect(mockCopyLinkToClipboard).toHaveBeenCalledWith(newLink.share_url)
      })
    })

    it('should copy link to clipboard when copy button clicked', async () => {
      mockCopyLinkToClipboard.mockResolvedValueOnce(undefined)

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      const copyButtons = await screen.findAllByTitle(/copy link/i)
      await userEvent.click(copyButtons[0])

      await waitFor(() => {
        expect(mockCopyLinkToClipboard).toHaveBeenCalledWith(mockShareLinks[0].share_url)
      })
    })

    it('should revoke link when revoke button clicked', async () => {
      mockRevokeShareLink.mockResolvedValueOnce(undefined)

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      const revokeButtons = await screen.findAllByTitle(/revoke link/i)
      await userEvent.click(revokeButtons[0])

      await waitFor(() => {
        expect(mockRevokeShareLink).toHaveBeenCalledWith(mockShareLinks[0].token)
      })
    })

    it('should show password protected badge', async () => {
      const protectedLink = {
        ...mockShareLinks[0],
        has_password: true,
      }

      ;(useShareLinksStore as any).mockReturnValue({
        currentNoteLinks: [protectedLink],
        createShareLink: mockCreateShareLink,
        fetchNoteShareLinks: mockFetchNoteShareLinks,
        revokeShareLink: mockRevokeShareLink,
        copyLinkToClipboard: mockCopyLinkToClipboard,
      })

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.getByText(/protected/i)).toBeInTheDocument()
      })
    })

    it('should show expiration information', async () => {
      const expiringLink = {
        ...mockShareLinks[0],
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      }

      ;(useShareLinksStore as any).mockReturnValue({
        currentNoteLinks: [expiringLink],
        createShareLink: mockCreateShareLink,
        fetchNoteShareLinks: mockFetchNoteShareLinks,
        revokeShareLink: mockRevokeShareLink,
        copyLinkToClipboard: mockCopyLinkToClipboard,
      })

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.getByText(/expires/i)).toBeInTheDocument()
      })
    })

    it('should show usage statistics', async () => {
      const linkWithUses = {
        ...mockShareLinks[0],
        use_count: 7,
        max_uses: 10,
      }

      ;(useShareLinksStore as any).mockReturnValue({
        currentNoteLinks: [linkWithUses],
        createShareLink: mockCreateShareLink,
        fetchNoteShareLinks: mockFetchNoteShareLinks,
        revokeShareLink: mockRevokeShareLink,
        copyLinkToClipboard: mockCopyLinkToClipboard,
      })

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.getByText(/uses: 7 \/ 10/i)).toBeInTheDocument()
      })
    })

    it('should hide create form for non-owner', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={false} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.queryByRole('button', { name: /create share link/i })).not.toBeInTheDocument()
      })
    })

    it('should show empty state when no links', async () => {
      ;(useShareLinksStore as any).mockReturnValue({
        currentNoteLinks: [],
        createShareLink: mockCreateShareLink,
        fetchNoteShareLinks: mockFetchNoteShareLinks,
        revokeShareLink: mockRevokeShareLink,
        copyLinkToClipboard: mockCopyLinkToClipboard,
      })

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.getByText(/no active share links/i)).toBeInTheDocument()
      })
    })
  })

  describe('Permission Badges', () => {
    it('should display correct badge for read permission', async () => {
      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        const readBadges = screen.getAllByText(/^read$/i)
        expect(readBadges.length).toBeGreaterThan(0)
      })
    })

    it('should display correct badge for write permission', async () => {
      const writeLink = {
        ...mockShareLinks[0],
        permission: 'write' as const,
      }

      ;(useShareLinksStore as any).mockReturnValue({
        currentNoteLinks: [writeLink],
        createShareLink: mockCreateShareLink,
        fetchNoteShareLinks: mockFetchNoteShareLinks,
        revokeShareLink: mockRevokeShareLink,
        copyLinkToClipboard: mockCopyLinkToClipboard,
      })

      render(<ShareDialog noteId={mockNoteId} isOwner={true} />)

      const triggerButton = screen.getByRole('button', { name: /share/i })
      await userEvent.click(triggerButton)

      const linksTab = await screen.findByRole('tab', { name: /share links/i })
      await userEvent.click(linksTab)

      await waitFor(() => {
        expect(screen.getByText(/^write$/i)).toBeInTheDocument()
      })
    })
  })
})
