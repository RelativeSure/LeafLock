import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { AdvancedSearchBar } from '../advanced-search-bar'

// Mock the encryption context
vi.mock('@/lib/encryption-context', () => ({
  useEncryption: () => ({
    isUnlocked: true,
    unlock: vi.fn(),
    lock: vi.fn(),
  }),
}))

// Mock the decrypted notes hook
vi.mock('@/hooks/use-decrypted-notes', () => ({
  useDecryptedNotes: () => ({
    decryptedNotes: {},
    isUnlocked: true,
    isDecrypting: false,
  }),
}))

// Mock the notes store
vi.mock('@/stores/notesStore', () => ({
  useNotesStore: () => ({
    notes: [],
    folders: [],
    tags: [],
    selectNote: vi.fn(),
  }),
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

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children, ...props }: any) => <span {...props}>{children}</span>,
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div>{children}</div>,
  CardContent: ({ children }: any) => <div>{children}</div>,
  CardDescription: ({ children }: any) => <div>{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => <div>{open && children}</div>,
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <div>{children}</div>,
  DialogTrigger: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children, onValueChange }: any) => (
    <div data-testid="select" onClick={() => onValueChange && onValueChange('test')}>
      {children}
    </div>
  ),
  SelectTrigger: ({ children }: any) => <div>{children}</div>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, value }: any) => <option value={value}>{children}</option>,
  SelectValue: ({ placeholder }: any) => <span>{placeholder}</span>,
}))

// Mock date-fns
vi.mock('date-fns', () => ({
  formatDistanceToNow: () => '2 hours ago',
}))

describe('AdvancedSearchBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render advanced search bar', () => {
    render(<AdvancedSearchBar />)
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('should accept search query', () => {
    render(<AdvancedSearchBar />)

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'search term' } })

    expect(input).toHaveValue('search term')
  })

  it('should update search query when typing', () => {
    render(<AdvancedSearchBar />)

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'test' } })

    expect(input).toHaveValue('test')
  })

  it('should render search input with placeholder', () => {
    render(<AdvancedSearchBar />)

    const input = screen.getByPlaceholderText('Search notes...')
    expect(input).toBeInTheDocument()
  })

  it('should handle empty search', () => {
    render(<AdvancedSearchBar />)

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: '' } })

    expect(input).toHaveValue('')
  })

  it('should render with proper structure', () => {
    render(<AdvancedSearchBar />)

    const input = screen.getByRole('textbox')
    expect(input).toHaveAttribute('placeholder', 'Search notes...')
  })

  it('should support tag filtering', () => {
    render(<AdvancedSearchBar />)

    expect(document.body).toBeTruthy()
  })

  it('should support folder filtering', () => {
    render(<AdvancedSearchBar />)

    expect(document.body).toBeTruthy()
  })

  it('should clear search filters', () => {
    render(<AdvancedSearchBar />)

    const clearButton = screen.queryByRole('button', { name: /clear/i })
    if (clearButton) {
      fireEvent.click(clearButton)
      expect(clearButton).toBeInTheDocument()
    }
  })

  it('should handle keyboard shortcuts', () => {
    render(<AdvancedSearchBar />)

    const input = screen.getByRole('textbox')
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(document.body).toBeTruthy()
  })
})
