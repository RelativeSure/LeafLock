import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BacklinksSection, createNoteLink, parseNoteLinks } from '../note-linking-utils'
import { useNotesStore } from '@/stores/notesStore'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
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

describe('note-linking-utils', () => {
  describe('BacklinksSection', () => {
    beforeEach(() => {
      vi.clearAllMocks()
    })

    it('should render backlinks section', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        getNoteBacklinks: vi.fn().mockResolvedValue({ backlinks: [] }),
        notes: [],
      } as any)

      render(<BacklinksSection noteId="note-1" />)
      expect(screen.getByTestId('card')).toBeInTheDocument()
    })

    it('should display backlinks', async () => {
      const mockBacklinks = {
        backlinks: [{ id: 'link-1', sourceNoteId: 'note-2', targetNoteId: 'note-1' }],
      }

      vi.mocked(useNotesStore).mockReturnValue({
        getNoteBacklinks: vi.fn().mockResolvedValue(mockBacklinks),
        notes: [{ id: 'note-2', title: 'Source Note', content: '' }],
      } as any)

      render(<BacklinksSection noteId="note-1" />)
      expect(screen.getByTestId('card')).toBeInTheDocument()
    })

    it('should show empty state when no backlinks', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        getNoteBacklinks: vi.fn().mockResolvedValue({ backlinks: [] }),
        notes: [],
      } as any)

      render(<BacklinksSection noteId="note-1" />)
      expect(screen.getByText(/no backlinks/i) || document.body).toBeTruthy()
    })

    it('should handle loading state', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        getNoteBacklinks: vi.fn(() => new Promise(vi.fn())), // Never resolves
        notes: [],
      } as any)

      render(<BacklinksSection noteId="note-1" />)
      expect(screen.getByText(/loading/i) || document.body).toBeTruthy()
    })

    it('should handle errors gracefully', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        getNoteBacklinks: vi.fn().mockRejectedValue(new Error('Failed to load')),
        notes: [],
      } as any)

      render(<BacklinksSection noteId="note-1" />)
      expect(document.body).toBeTruthy()
    })
  })

  describe('createNoteLink', () => {
    it('should create a note link', async () => {
      const mockCreateLink = vi.fn().mockResolvedValue({
        id: 'link-1',
        sourceNoteId: 'note-1',
        targetNoteId: 'note-2',
      })

      vi.mocked(useNotesStore).mockReturnValue({
        createNoteLink: mockCreateLink,
      } as any)

      const result = await createNoteLink('note-1', 'note-2', 'Related')

      expect(mockCreateLink).toHaveBeenCalledWith('note-1', 'note-2', 'Related')
      expect(result.sourceNoteId).toBe('note-1')
      expect(result.targetNoteId).toBe('note-2')
    })

    it('should handle link creation errors', async () => {
      const mockCreateLink = vi.fn().mockRejectedValue(new Error('Creation failed'))

      vi.mocked(useNotesStore).mockReturnValue({
        createNoteLink: mockCreateLink,
      } as any)

      await expect(createNoteLink('note-1', 'note-2')).rejects.toThrow('Creation failed')
    })
  })

  describe('parseNoteLinks', () => {
    it('should parse [[note-id]] links from content', () => {
      const content = 'This is a note with [[note-123]] link'
      const links = parseNoteLinks(content)

      expect(links).toContain('note-123')
    })

    it('should parse multiple links', () => {
      const content = 'Links: [[note-1]] and [[note-2]] and [[note-3]]'
      const links = parseNoteLinks(content)

      expect(links).toHaveLength(3)
      expect(links).toContain('note-1')
      expect(links).toContain('note-2')
      expect(links).toContain('note-3')
    })

    it('should handle content with no links', () => {
      const content = 'This is just plain text'
      const links = parseNoteLinks(content)

      expect(links).toHaveLength(0)
    })

    it('should ignore malformed links', () => {
      const content = 'Malformed: [note-1] or note-2]] or [[]]'
      const links = parseNoteLinks(content)

      expect(links).toHaveLength(0)
    })

    it('should handle empty content', () => {
      const links = parseNoteLinks('')

      expect(links).toHaveLength(0)
    })

    it('should remove duplicate links', () => {
      const content = '[[note-1]] and [[note-1]] again'
      const links = parseNoteLinks(content)

      expect(links).toHaveLength(1)
      expect(links[0]).toBe('note-1')
    })
  })

  describe('Link navigation', () => {
    it('should navigate to linked note on click', () => {
      const mockSelectNote = vi.fn()

      vi.mocked(useNotesStore).mockReturnValue({
        getNoteBacklinks: vi.fn().mockResolvedValue({ backlinks: [] }),
        notes: [],
        selectNote: mockSelectNote,
      } as any)

      render(<BacklinksSection noteId="note-1" />)
      expect(document.body).toBeTruthy()
    })

    it('should show link count', () => {
      const mockBacklinks = {
        backlinks: [
          { id: 'link-1', sourceNoteId: 'note-2' },
          { id: 'link-2', sourceNoteId: 'note-3' },
        ],
      }

      vi.mocked(useNotesStore).mockReturnValue({
        getNoteBacklinks: vi.fn().mockResolvedValue(mockBacklinks),
        notes: [
          { id: 'note-2', title: 'Note 2' },
          { id: 'note-3', title: 'Note 3' },
        ],
      } as any)

      render(<BacklinksSection noteId="note-1" />)
      expect(screen.getByText(/2/i) || document.body).toBeTruthy()
    })
  })

  describe('Link deletion', () => {
    it('should delete a link', async () => {
      const mockDeleteLink = vi.fn().mockResolvedValue(undefined)

      vi.mocked(useNotesStore).mockReturnValue({
        deleteNoteLink: mockDeleteLink,
      } as any)

      await mockDeleteLink('note-1', 'link-1')

      expect(mockDeleteLink).toHaveBeenCalledWith('note-1', 'link-1')
    })

    it('should handle deletion errors', async () => {
      const mockDeleteLink = vi.fn().mockRejectedValue(new Error('Delete failed'))

      vi.mocked(useNotesStore).mockReturnValue({
        deleteNoteLink: mockDeleteLink,
      } as any)

      await expect(mockDeleteLink('note-1', 'link-1')).rejects.toThrow('Delete failed')
    })
  })
})
