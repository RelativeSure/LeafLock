import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react'
import { BacklinksSection, NoteLinkPreview, NoteLinkingUtils } from '../note-linking-utils'
import { useNotesStore } from '@/stores/notesStore'
import { useDecryptedNotes } from '@/hooks/use-decrypted-notes'

const useNotesStoreMock = vi.hoisted(() => vi.fn())
const useDecryptedNotesMock = vi.hoisted(() =>
  vi.fn(() => ({
    decryptedNotes: {},
    isUnlocked: true,
    isDecrypting: false,
  }))
)

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: useNotesStoreMock,
}))

vi.mock('@/hooks/use-decrypted-notes', () => ({
  useDecryptedNotes: (...args: unknown[]) => useDecryptedNotesMock(...args),
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children, asChild }: any) => (asChild ? <>{children}</> : <p>{children}</p>),
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
  const setupNotesStore = (state: any) => {
    useNotesStoreMock.mockReturnValue(state)
  }

  const setupDecryptedNotes = (override: Partial<ReturnType<typeof useDecryptedNotes>>) => {
    useDecryptedNotesMock.mockReturnValue({
      decryptedNotes: {},
      isUnlocked: true,
      isDecrypting: false,
      ...override,
    })
  }

  describe('BacklinksSection', () => {
    const mockOnNoteSelect = vi.fn()

    beforeEach(() => {
      vi.clearAllMocks()
    })

    it('should render backlinks section when no backlinks', () => {
      setupNotesStore({
        notes: [],
      } as any)

      const { container } = render(
        <BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />
      )
      // BacklinksSection returns null when there are no backlinks
      expect(container.firstChild).toBeNull()
    })

    it('should display backlinks when note is referenced', async () => {
      setupNotesStore({
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
      setupNotesStore({
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
      setupNotesStore({
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
      setupNotesStore({
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
      setupNotesStore({
        notes: [{ id: 'note-1', title: 'Target Note', content: 'Self reference [[Target Note]]' }],
      } as any)

      const { container } = render(
        <BacklinksSection currentNoteId="note-1" onNoteSelect={mockOnNoteSelect} />
      )
      // Should not show backlink to itself
      expect(container.firstChild).toBeNull()
    })

    it('should handle notes without titles', async () => {
      setupNotesStore({
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
      setupNotesStore({
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
      setupNotesStore({
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
      setupNotesStore({
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

  describe('NoteLinkPreview', () => {
    const baseNote = {
      id: 'note-123',
      title: 'Encrypted title',
      content: 'Encrypted content',
      tags: ['project', 'urgent', 'next'],
      updatedAt: new Date().toISOString(),
    }

    beforeEach(() => {
      setupNotesStore({ notes: [baseNote] })
      setupDecryptedNotes({
        decryptedNotes: {
          'note-123': { title: 'Decrypted Title', content: '<p>Hello world</p>' },
        },
        isUnlocked: true,
        isDecrypting: false,
      })
    })

    it('renders loading spinner before note resolves', () => {
      setupNotesStore({ notes: [baseNote] })
      const { container } = render(
        <NoteLinkPreview noteId="note-123" onClose={vi.fn()} onNavigate={vi.fn()} />
      )
      expect(container.querySelector('.animate-spin')).toBeTruthy()
    })

    it('shows not found state when note missing', async () => {
      setupNotesStore({ notes: [] })

      render(<NoteLinkPreview noteId="missing" onClose={vi.fn()} onNavigate={vi.fn()} />)

      await waitFor(() => {
        expect(screen.getByText('Note not found')).toBeInTheDocument()
      })
    })

    it('shows locked message when encryption locked', async () => {
      setupDecryptedNotes({
        decryptedNotes: {},
        isUnlocked: false,
        isDecrypting: false,
      })

      render(<NoteLinkPreview noteId="note-123" onClose={vi.fn()} onNavigate={vi.fn()} />)

      await waitFor(() => {
        expect(screen.getByText('Unlock your notes to preview linked content.')).toBeInTheDocument()
      })
    })

    it('shows decrypting state while unlocking', async () => {
      setupDecryptedNotes({
        decryptedNotes: {},
        isUnlocked: true,
        isDecrypting: true,
      })

      const { container } = render(
        <NoteLinkPreview noteId="note-123" onClose={vi.fn()} onNavigate={vi.fn()} />
      )

      await waitFor(() => {
        expect(container.querySelectorAll('.animate-spin').length).toBeGreaterThan(0)
      })
    })

    it('renders decrypted preview with tags and actions', async () => {
      const onClose = vi.fn()
      const onNavigate = vi.fn()

      render(<NoteLinkPreview noteId="note-123" onClose={onClose} onNavigate={onNavigate} />)

      await waitFor(() => {
        expect(screen.getByText('Decrypted Title')).toBeInTheDocument()
      })
      expect(screen.getByText('Open Note')).toBeInTheDocument()
      expect(screen.getByText('project')).toBeInTheDocument()

      const [closeButton] = screen.getAllByRole('button')
      fireEvent.click(closeButton)
      expect(onClose).toHaveBeenCalled()

      fireEvent.click(screen.getByRole('button', { name: /open note/i }))
      expect(onNavigate).toHaveBeenCalledWith('note-123')
    })
  })

  describe('NoteLinkingUtils', () => {
    const baseNotes = [
      {
        id: 'note-123',
        title: 'Sample Note',
        content: '',
        tags: ['tag-a'],
        updatedAt: new Date().toISOString(),
        isTrashed: false,
        encrypted: true,
      },
    ]

    const setupLinkingContext = (overrideNotes = baseNotes) => {
      setupNotesStore({ notes: overrideNotes })
      setupDecryptedNotes({
        decryptedNotes: {
          'note-123': { title: 'Sample Note', content: '<p>Preview content</p>' },
        },
        isUnlocked: true,
        isDecrypting: false,
      })
    }

    afterEach(() => {
      vi.useRealTimers()
    })

    it('renders content with clickable note links', async () => {
      setupLinkingContext()
      const onSelect = vi.fn()
      const { container } = render(
        <NoteLinkingUtils content="Open [[Sample Note]] today" onNoteSelect={onSelect} />
      )

      const link = container.querySelector('.note-link') as HTMLElement
      expect(link).toBeTruthy()
      expect(link.classList.contains('note-link-found')).toBe(true)

      fireEvent.click(link)
      expect(onSelect).toHaveBeenCalledWith('note-123')
    })

    it('shows preview when hovering note link', async () => {
      setupLinkingContext()
      render(<NoteLinkingUtils content="See [[Sample Note]] for details" onNoteSelect={vi.fn()} />)

      const hoverHandler = (window as any).handleNoteLinkHover
      expect(typeof hoverHandler).toBe('function')

      await act(async () => {
        hoverHandler(new MouseEvent('mousemove', { clientX: 50, clientY: 60 }), 'Sample Note')
      })
      await screen.findByRole('button', { name: /open note/i })
    })

    it('does not navigate for missing links', () => {
      setupLinkingContext([])
      const onSelect = vi.fn()
      const { container } = render(
        <NoteLinkingUtils content="Unknown [[Missing Note]] link" onNoteSelect={onSelect} />
      )

      const link = container.querySelector('.note-link') as HTMLElement
      expect(link.classList.contains('note-link-not-found')).toBe(true)
      fireEvent.click(link)
      expect(onSelect).not.toHaveBeenCalled()
    })

    it('handles locked workspace by skipping link resolution', () => {
      setupNotesStore({ notes: baseNotes })
      setupDecryptedNotes({
        decryptedNotes: {},
        isUnlocked: false,
        isDecrypting: false,
      })

      const { container } = render(
        <NoteLinkingUtils content="Content with [[Sample Note]]" onNoteSelect={vi.fn()} />
      )

      const link = container.querySelector('.note-link') as HTMLElement
      expect(link.classList.contains('note-link-not-found')).toBe(true)
    })
  })
})
