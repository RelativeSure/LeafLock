import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { BacklinksSection } from '../note-linking-utils'
import { useNotesStore } from '@/stores/notesStore'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/hooks/use-decrypted-notes', () => ({
  useDecryptedNotes: vi.fn(() => ({
    decryptedNotes: {},
    isUnlocked: true,
    isDecrypting: false,
  })),
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children, ...props }: any) => <span {...props}>{children}</span>,
}))

describe('note-linking-utils', () => {
  describe('BacklinksSection', () => {
    const mockOnNoteSelect = vi.fn()

    beforeEach(() => {
      vi.clearAllMocks()
    })

    it('should render backlinks section when no backlinks', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
      } as any)

      const { container } = render(
        <BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />
      )
      // BacklinksSection returns null when there are no backlinks
      expect(container.firstChild).toBeNull()
    })

    it('should display backlinks when note is referenced', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '', createdAt: '', updatedAt: '' },
          {
            id: 'note-2',
            title: 'Source Note',
            content: 'This links to [[Target Note]]',
            createdAt: '',
            updatedAt: '',
          },
        ],
      } as any)

      render(<BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />)

      await waitFor(() => {
        expect(screen.getByText(/backlinks/i)).toBeInTheDocument()
      })
      expect(screen.getByText('Source Note')).toBeInTheDocument()
    })

    it('should show empty state when no backlinks', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '' },
          { id: 'note-2', title: 'Source Note', content: 'No links here' },
        ],
      } as any)

      const { container } = render(
        <BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />
      )
      // BacklinksSection returns null when there are no backlinks
      expect(container.firstChild).toBeNull()
    })

    it('should handle multiple backlinks', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '', createdAt: '', updatedAt: '' },
          {
            id: 'note-2',
            title: 'Source Note 1',
            content: 'Links to [[Target Note]]',
            createdAt: '',
            updatedAt: '',
          },
          {
            id: 'note-3',
            title: 'Source Note 2',
            content: 'Also links to [[Target Note]]',
            createdAt: '',
            updatedAt: '',
          },
        ],
      } as any)

      render(<BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />)

      await waitFor(() => {
        expect(screen.getByText('Source Note 1')).toBeInTheDocument()
      })
      expect(screen.getByText('Source Note 2')).toBeInTheDocument()
    })

    it('should handle click on backlink', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '', createdAt: '', updatedAt: '' },
          {
            id: 'note-2',
            title: 'Source Note',
            content: 'Links to [[Target Note]]',
            createdAt: '',
            updatedAt: '',
          },
        ],
      } as any)

      render(<BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />)

      const backlinkButton = await waitFor(() => screen.getByText('Source Note').closest('button'))
      expect(backlinkButton).toBeInTheDocument()
      backlinkButton?.click()
      expect(mockOnNoteSelect).toHaveBeenCalledWith('note-2')
    })
  })

  describe('BacklinksSection - edge cases', () => {
    const mockOnNoteSelect = vi.fn()

    beforeEach(() => {
      vi.clearAllMocks()
    })

    it('should not display current note as backlink', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [{ id: 'note-1', title: 'Target Note', content: 'Self reference [[Target Note]]' }],
      } as any)

      const { container } = render(
        <BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />
      )
      // Should not show backlink to itself
      expect(container.firstChild).toBeNull()
    })

    it('should handle notes without titles', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '', createdAt: '', updatedAt: '' },
          {
            id: 'note-2',
            title: '',
            content: 'Links to [[Target Note]]',
            createdAt: '',
            updatedAt: '',
          },
        ],
      } as any)

      render(<BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />)

      await waitFor(() => {
        expect(screen.getByText('Untitled')).toBeInTheDocument()
      })
    })

    it('should be case-insensitive when matching backlinks', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '', createdAt: '', updatedAt: '' },
          {
            id: 'note-2',
            title: 'Source Note',
            content: 'Links to [[target note]]',
            createdAt: '',
            updatedAt: '',
          },
        ],
      } as any)

      render(<BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />)

      await waitFor(() => {
        expect(screen.getByText('Source Note')).toBeInTheDocument()
      })
    })

    it('should display backlink count in header', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '', createdAt: '', updatedAt: '' },
          {
            id: 'note-2',
            title: 'Source Note 1',
            content: 'Links to [[Target Note]]',
            createdAt: '',
            updatedAt: '',
          },
          {
            id: 'note-3',
            title: 'Source Note 2',
            content: 'Also links to [[Target Note]]',
            createdAt: '',
            updatedAt: '',
          },
        ],
      } as any)

      render(<BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />)

      await waitFor(() => {
        expect(screen.getByText(/backlinks \(2\)/i)).toBeInTheDocument()
      })
    })

    it('should handle notes without content', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          { id: 'note-1', title: 'Target Note', content: '' },
          { id: 'note-2', title: 'Source Note', content: undefined },
        ],
      } as any)

      const { container } = render(
        <BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />
      )
      // Should not crash, should return null (no backlinks)
      expect(container.firstChild).toBeNull()
    })
  })
})
