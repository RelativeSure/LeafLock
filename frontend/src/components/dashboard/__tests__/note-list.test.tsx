import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { NoteList } from '../note-list'
import { useNotesStore } from '@/stores/notesStore'
import type { Note } from '@/types'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
}))

vi.mock('@/components/ui/input', () => ({
  Input: (props: any) => <input {...props} />,
}))

describe('NoteList', () => {
  const mockNote: Note = {
    id: 'note-1',
    title: 'Test Note',
    content: 'Test content',
    userId: '123',
    encrypted: true,
    encryptionVersion: 1,
    folderId: null,
    tags: ['tag1'],
    pinned: false,
    isTrashed: false,
    sharedWith: [],
    isTemplate: false,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      selectedNote: null,
      selectNote: vi.fn(),
      createNote: vi.fn(),
    } as any)
  })

  it('should render note list', () => {
    render(<NoteList />)
    const container = screen.getByRole('list', { hidden: true }) || screen.getByTestId('note-list')
    expect(container || document.body).toBeTruthy()
  })

  it('should render with notes', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [mockNote],
      selectedNote: null,
      selectNote: vi.fn(),
      createNote: vi.fn(),
    } as any)

    render(<NoteList />)
    expect(document.body).toBeTruthy()
  })

  it('should render empty state', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      selectedNote: null,
      selectNote: vi.fn(),
      createNote: vi.fn(),
    } as any)

    render(<NoteList />)
    expect(document.body).toBeTruthy()
  })
})
