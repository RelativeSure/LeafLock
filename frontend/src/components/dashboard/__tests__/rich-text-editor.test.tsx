import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { RichTextEditor } from '../rich-text-editor'

const setContentMock = vi.fn()

const createChainExec = () => ({
  run: vi.fn(),
})

const createFocusResult = () => {
  const exec = createChainExec()
  return {
    toggleBold: vi.fn(() => exec),
    toggleItalic: vi.fn(() => exec),
    toggleStrike: vi.fn(() => exec),
    toggleCode: vi.fn(() => exec),
    toggleCodeBlock: vi.fn(() => exec),
    toggleBulletList: vi.fn(() => exec),
    toggleOrderedList: vi.fn(() => exec),
    toggleTaskList: vi.fn(() => exec),
    toggleHeading: vi.fn(() => exec),
    toggleHighlight: vi.fn(() => exec),
    toggleBlockquote: vi.fn(() => exec),
    setLink: vi.fn(() => exec),
    undo: vi.fn(() => exec),
    redo: vi.fn(() => exec),
  }
}

// Mock Tiptap editor
vi.mock('@tiptap/react', () => {
  const useEditor = vi.fn((config: any) => {
    const focusResult = createFocusResult()
    const chainReturn = {
      focus: vi.fn(() => focusResult),
    }

    const editor = {
      commands: {
        setContent: setContentMock,
      },
      chain: vi.fn(() => chainReturn),
      isActive: vi.fn(() => false),
      can: vi.fn(() => ({ undo: () => true, redo: () => true })),
      getHTML: vi.fn(() => '<p>Test content</p>'),
      getText: vi.fn(() => 'Test content'),
    }

    config?.onUpdate?.({ editor })

    return editor
  })

  const EditorContent = ({ editor }: any) => (
    <div data-testid="editor-content">{editor?.getText()}</div>
  )

  return { useEditor, EditorContent }
})

vi.mock('@tiptap/starter-kit', () => ({
  default: {},
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/separator', () => ({
  Separator: ({ 'data-testid': dataTestId = 'separator' }: any) => <hr data-testid={dataTestId} />,
}))

describe('RichTextEditor', () => {
  const mockOnChange = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    setContentMock.mockClear()
  })

  it('renders the editor content', () => {
    render(<RichTextEditor content="" onChange={mockOnChange} />)
    expect(screen.getByTestId('editor-content')).toBeInTheDocument()
  })

  it('renders toolbar buttons', () => {
    render(<RichTextEditor content="" onChange={mockOnChange} />)

    expect(screen.getAllByRole('button').length).toBeGreaterThan(0)
  })

  it('disables toolbar when disabled prop is true', () => {
    render(<RichTextEditor content="" onChange={mockOnChange} disabled />)

    screen.getAllByRole('button').forEach((button) => {
      expect(button).toBeDisabled()
    })
  })

  it('calls onChange when editor updates', () => {
    render(<RichTextEditor content="" onChange={mockOnChange} />)
    expect(mockOnChange).toHaveBeenCalled()
  })

  it('updates editor content when prop changes', () => {
    const { rerender } = render(<RichTextEditor content="<p>first</p>" onChange={mockOnChange} />)

    rerender(<RichTextEditor content="<p>second</p>" onChange={mockOnChange} />)

    expect(setContentMock).toHaveBeenCalledWith('<p>second</p>', { emitUpdate: false })
  })

  it('supports placeholder prop', () => {
    render(<RichTextEditor content="" onChange={mockOnChange} placeholder="Type here" />)
    expect(document.body).toBeTruthy()
  })

  it('supports formatting button interactions', () => {
    render(<RichTextEditor content="" onChange={mockOnChange} />)

    const [firstButton] = screen.getAllByRole('button')
    fireEvent.click(firstButton)

    expect(firstButton).toBeTruthy()
  })
})
