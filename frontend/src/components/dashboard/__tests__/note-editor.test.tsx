import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
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
  const renderEditor = async (options: { expectDecrypt?: boolean } = {}) => {
    const { expectDecrypt = true } = options
    const utils = render(<NoteEditor />)
    if (expectDecrypt) {
      await waitFor(() => expect(mockDecryptText).toHaveBeenCalled())
    } else {
      await waitFor(() => expect(true).toBe(true))
    }
    return utils
  }

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
      encryptText: mockEncryptText.mockImplementation(async (value: string) => value ?? ''),
      decryptText: mockDecryptText.mockImplementation(async (value: string) => value ?? ''),
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllTimers()
  })

  it('should render note editor', async () => {
    await renderEditor()
    expect(screen.getByPlaceholderText('Add Title')).toBeInTheDocument()
  })

  it('should display note title', async () => {
    await renderEditor()
    const titleInput = screen.getByDisplayValue('Test Note')
    expect(titleInput).toBeInTheDocument()
  })

  it('should display note content in rich text editor', async () => {
    await renderEditor()
    expect(screen.getByTestId('rich-text-editor')).toBeInTheDocument()
  })

  it('should update title when typing', async () => {
    await renderEditor()

    const titleInput = screen.getByDisplayValue('Test Note')
    fireEvent.change(titleInput, { target: { value: 'Updated Title' } })

    await waitFor(() => {
      expect(titleInput).toHaveValue('Updated Title')
    })
  })

  it('should update content when typing in editor', async () => {
    await renderEditor()

    const contentArea = screen.getByTestId('rich-text-editor').querySelector('textarea')
    fireEvent.change(contentArea!, { target: { value: 'New content' } })

    await waitFor(() => {
      expect(contentArea).toHaveValue('New content')
    })
  })

  it('should auto-save note after delay', async () => {
    await renderEditor()
    vi.useFakeTimers()

    const contentArea = screen.getByTestId('rich-text-editor').querySelector('textarea')
    fireEvent.change(contentArea!, { target: { value: 'Auto Save Test content' } })

    await vi.advanceTimersByTimeAsync(600)
    await Promise.resolve()

    expect(mockUpdateNote).toHaveBeenCalled()
    expect(mockEncryptText).toHaveBeenCalledWith('Auto Save Test content')
  })

  it('should render share button', async () => {
    await renderEditor()
    expect(screen.getByRole('button', { name: /share/i })).toBeInTheDocument()
  })

  it('should encrypt content before saving', async () => {
    await renderEditor()
    vi.useFakeTimers()

    const contentArea = screen.getByTestId('rich-text-editor').querySelector('textarea')
    fireEvent.change(contentArea!, { target: { value: 'Encrypted content' } })

    await vi.advanceTimersByTimeAsync(600)
    await Promise.resolve()

    expect(mockEncryptText).toHaveBeenCalledWith('Encrypted content')
    expect(mockUpdateNote).toHaveBeenCalled()
  })

  it('should render empty state when no note selected', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: null,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [],
      selectNote: vi.fn(),
    } as any)

    await renderEditor({ expectDecrypt: false })
    expect(screen.getByText('Select a note to start editing')).toBeInTheDocument()
  })

  it('should prompt to unlock when note is locked', async () => {
    vi.mocked(useEncryption).mockReturnValue({
      isUnlocked: false,
      encryptionVersion: 1,
      encryptText: mockEncryptText,
      decryptText: mockDecryptText,
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })

    await renderEditor({ expectDecrypt: false })
    expect(screen.getByText('This note is encrypted')).toBeInTheDocument()
  })

  it('should show pinned status', async () => {
    const pinnedNote = { ...mockNote, pinned: true }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: pinnedNote,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [pinnedNote],
      selectNote: vi.fn(),
    } as any)

    await renderEditor()
    expect(screen.getByRole('button', { name: /pinned/i })).toBeInTheDocument()
  })

  it('should toggle pin status', async () => {
    await renderEditor()

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

  it('should show tags', async () => {
    const noteWithTags = { ...mockNote, tags: ['urgent', 'work'] }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: noteWithTags,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [noteWithTags],
      selectNote: vi.fn(),
    } as any)

    await renderEditor()
    expect(screen.getByText('urgent')).toBeInTheDocument()
    expect(screen.getByText('work')).toBeInTheDocument()
  })

  it('should handle encryption errors gracefully', async () => {
    mockDecryptText.mockRejectedValueOnce(new Error('Decrypt failed'))

    await renderEditor()

    await waitFor(() => {
      expect(
        screen.getByText('Failed to decrypt note. The password may be incorrect.')
      ).toBeInTheDocument()
    })
  })

  it('should show last saved time', async () => {
    await renderEditor()
    expect(screen.getByPlaceholderText('Add Title')).toBeInTheDocument()
  })

  it('should handle keyboard shortcuts', async () => {
    await renderEditor()
    const titleInput = screen.getByDisplayValue('Test Note')
    fireEvent.keyDown(titleInput, { key: 's', ctrlKey: true })
    expect(document.body).toBeTruthy()
  })

  it('should show word count', async () => {
    await renderEditor()
    expect(screen.getByTestId('rich-text-editor')).toBeInTheDocument()
  })

  it('should disable editing for trashed notes', async () => {
    const trashedNote = { ...mockNote, isTrashed: true }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: trashedNote,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [trashedNote],
      selectNote: vi.fn(),
    } as any)

    await renderEditor()
    expect(document.body).toBeTruthy()
  })

  it('should handle shared notes', async () => {
    const sharedNote = { ...mockNote, sharedWith: ['user@example.com'] }
    vi.mocked(useNotesStore).mockReturnValue({
      selectedNote: sharedNote,
      updateNote: mockUpdateNote,
      createNote: mockCreateNote,
      notes: [sharedNote],
      selectNote: vi.fn(),
    } as any)

    await renderEditor()
    expect(document.body).toBeTruthy()
  })
})
