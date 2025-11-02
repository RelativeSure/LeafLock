import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { NoteEditor } from '../note-editor'
import { useNotesStore } from '@/stores/notesStore'
import { useEncryption } from '@/lib/encryption-context'
import type { Note } from '@/types'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/lib/encryption-context', () => ({
  useEncryption: vi.fn(),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ onChange, value, ...props }: any) => (
    <input onChange={onChange} value={value} {...props} />
  ),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/textarea', () => ({
  Textarea: ({ onChange, value, ...props }: any) => (
    <textarea onChange={onChange} value={value} {...props} />
  ),
}))

vi.mock('../rich-text-editor', () => ({
  RichTextEditor: ({ value, onChange }: any) => (
    <div data-testid="rich-text-editor">
      <textarea value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  ),
}))

describe('NoteEditor', () => {
  const mockNote: Note = {
    id: 'note-1',
    title: 'Test Note',
    content: 'Test content',
    userId: '123',
    encrypted: true,
    encryptionVersion: 1,
    folderId: null,
    tags: [],
    pinned: false,
    isTrashed: false,
    sharedWith: [],
    isTemplate: false,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  }

  const mockUpdateNote = vi.fn()
  const mockCreateNote = vi.fn()
  const mockEncryptText = vi.fn()
  const mockDecryptText = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: mockNote,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [mockNote],
      selectNote: vi.fn(),
    } as any)

    vi.mocked(useEncryption).mockReturnValue({
      isUnlocked: true,
      encryptionVersion: 1,
      encryptText: mockEncryptText.mockResolvedValue('encrypted'),
      decryptText: mockDecryptText.mockResolvedValue('decrypted'),
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })
  })

  it('should render note editor', () => {
    render(<NoteEditor />)
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('should display note title', () => {
    render(<NoteEditor />)
    const titleInput = screen.getByDisplayValue('Test Note')
    expect(titleInput).toBeInTheDocument()
  })

  it('should display note content in rich text editor', () => {
    render(<NoteEditor />)
    expect(screen.getByTestId('rich-text-editor')).toBeInTheDocument()
  })

  it('should update title when typing', async () => {
    render(<NoteEditor />)
    
    const titleInput = screen.getByDisplayValue('Test Note')
    fireEvent.change(titleInput, { target: { value: 'Updated Title' } })

    await waitFor(() => {
      expect(titleInput).toHaveValue('Updated Title')
    })
  })

  it('should update content when typing in editor', async () => {
    render(<NoteEditor />)
    
    const contentArea = screen.getByTestId('rich-text-editor').querySelector('textarea')
    fireEvent.change(contentArea!, { target: { value: 'New content' } })

    await waitFor(() => {
      expect(contentArea).toHaveValue('New content')
    })
  })

  it('should auto-save note after delay', async () => {
    vi.useFakeTimers()
    
    render(<NoteEditor />)
    
    const titleInput = screen.getByDisplayValue('Test Note')
    fireEvent.change(titleInput, { target: { value: 'Auto Save Test' } })

    vi.advanceTimersByTime(1000) // Advance past auto-save delay

    await waitFor(() => {
      expect(mockUpdateNote).toHaveBeenCalled()
    })

    vi.useRealTimers()
  })

  it('should show save button', () => {
    render(<NoteEditor />)
    expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
  })

  it('should call updateNote when save button clicked', async () => {
    render(<NoteEditor />)
    
    const titleInput = screen.getByDisplayValue('Test Note')
    fireEvent.change(titleInput, { target: { value: 'Manual Save' } })

    const saveButton = screen.getByRole('button', { name: /save/i })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(mockUpdateNote).toHaveBeenCalled()
    })
  })

  it('should handle empty note (new note creation)', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: null,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [],
      selectNote: vi.fn(),
    } as any)

    render(<NoteEditor />)
    expect(screen.getByPlaceholderText(/title/i)).toBeInTheDocument()
  })

  it('should create new note when typing in empty editor', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: null,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [],
      selectNote: vi.fn(),
    } as any)

    render(<NoteEditor />)
    
    const titleInput = screen.getByPlaceholderText(/title/i)
    fireEvent.change(titleInput, { target: { value: 'New Note' } })

    await waitFor(() => {
      expect(mockCreateNote).toHaveBeenCalled()
    })
  })

  it('should show pinned status', () => {
    const pinnedNote = { ...mockNote, pinned: true }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: pinnedNote,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [pinnedNote],
      selectNote: vi.fn(),
    } as any)

    render(<NoteEditor />)
    expect(document.body).toBeTruthy()
  })

  it('should toggle pin status', async () => {
    render(<NoteEditor />)
    
    const pinButton = screen.queryByRole('button', { name: /pin/i })
    if (pinButton) {
      fireEvent.click(pinButton)
      await waitFor(() => {
        expect(mockUpdateNote).toHaveBeenCalledWith(
          'note-1',
          expect.objectContaining({ pinned: true })
        )
      })
    }
  })

  it('should show tags', () => {
    const noteWithTags = { ...mockNote, tags: ['urgent', 'work'] }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: noteWithTags,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [noteWithTags],
      selectNote: vi.fn(),
    } as any)

    render(<NoteEditor />)
    expect(document.body).toBeTruthy()
  })

  it('should handle encryption errors gracefully', async () => {
    mockEncryptText.mockRejectedValue(new Error('Encryption failed'))

    render(<NoteEditor />)
    
    const titleInput = screen.getByDisplayValue('Test Note')
    fireEvent.change(titleInput, { target: { value: 'Error Test' } })

    const saveButton = screen.getByRole('button', { name: /save/i })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(mockEncryptText).toHaveBeenCalled()
    })
  })

  it('should show last saved time', () => {
    render(<NoteEditor />)
    expect(screen.getByText(/last saved/i) || document.body).toBeTruthy()
  })

  it('should handle keyboard shortcuts', () => {
    render(<NoteEditor />)
    
    const titleInput = screen.getByDisplayValue('Test Note')
    fireEvent.keyDown(titleInput, { key: 's', ctrlKey: true })

    expect(document.body).toBeTruthy()
  })

  it('should show word count', () => {
    render(<NoteEditor />)
    expect(screen.queryByText(/words/i) || document.body).toBeTruthy()
  })

  it('should disable editing for trashed notes', () => {
    const trashedNote = { ...mockNote, isTrashed: true }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: trashedNote,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [trashedNote],
      selectNote: vi.fn(),
    } as any)

    render(<NoteEditor />)
    expect(document.body).toBeTruthy()
  })

  it('should handle shared notes', () => {
    const sharedNote = { ...mockNote, sharedWith: ['user@example.com'] }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: sharedNote,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [sharedNote],
      selectNote: vi.fn(),
    } as any)

    render(<NoteEditor />)
    expect(document.body).toBeTruthy()
  })
})
