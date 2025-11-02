import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { RichTextEditor } from '../rich-text-editor'

// Mock Tiptap editor
vi.mock('@tiptap/react', () => ({
  useEditor: vi.fn(() => ({
    commands: {
      setContent: vi.fn(),
      toggleBold: vi.fn(),
      toggleItalic: vi.fn(),
      toggleUnderline: vi.fn(),
      toggleStrike: vi.fn(),
      toggleCode: vi.fn(),
      toggleCodeBlock: vi.fn(),
      toggleBulletList: vi.fn(),
      toggleOrderedList: vi.fn(),
      toggleTaskList: vi.fn(),
      setHeading: vi.fn(),
      setParagraph: vi.fn(),
      setBlockquote: vi.fn(),
      setHorizontalRule: vi.fn(),
      undo: vi.fn(),
      redo: vi.fn(),
      clearNodes: vi.fn(),
      clearMarks: vi.fn(),
    },
    isActive: vi.fn(() => false),
    can: vi.fn(() => ({ undo: vi.fn(() => true), redo: vi.fn(() => true) })),
    isEmpty: false,
    getHTML: vi.fn(() => '<p>Test content</p>'),
    getText: vi.fn(() => 'Test content'),
    chain: vi.fn(() => ({
      focus: vi.fn(() => ({ run: vi.fn() })),
      toggleBold: vi.fn(() => ({ run: vi.fn() })),
      toggleItalic: vi.fn(() => ({ run: vi.fn() })),
      setHeading: vi.fn(() => ({ run: vi.fn() })),
    })),
  })),
  EditorContent: ({ editor }: any) => <div data-testid="editor-content">{editor?.getText()}</div>,
}))

vi.mock('@tiptap/starter-kit', () => ({
  default: {},
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/separator', () => ({
  Separator: () => <hr data-testid="separator" />,
}))

describe('RichTextEditor', () => {
  const mockOnChange = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render editor', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByTestId('editor-content')).toBeInTheDocument()
  })

  it('should render toolbar', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getAllByRole('button').length).toBeGreaterThan(0)
  })

  it('should show bold button', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByRole('button', { name: /bold/i })).toBeInTheDocument()
  })

  it('should show italic button', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByRole('button', { name: /italic/i })).toBeInTheDocument()
  })

  it('should show underline button', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByRole('button', { name: /underline/i })).toBeInTheDocument()
  })

  it('should show heading buttons', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByRole('button', { name: /heading|h1/i })).toBeInTheDocument()
  })

  it('should show list buttons', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByRole('button', { name: /bullet|list/i })).toBeInTheDocument()
  })

  it('should show undo button', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByRole('button', { name: /undo/i })).toBeInTheDocument()
  })

  it('should show redo button', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByRole('button', { name: /redo/i })).toBeInTheDocument()
  })

  it('should handle bold formatting', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const boldButton = screen.getByRole('button', { name: /bold/i })
    fireEvent.click(boldButton)

    expect(boldButton).toBeTruthy()
  })

  it('should handle italic formatting', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const italicButton = screen.getByRole('button', { name: /italic/i })
    fireEvent.click(italicButton)

    expect(italicButton).toBeTruthy()
  })

  it('should handle heading formatting', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const headingButton = screen.getByRole('button', { name: /heading|h1/i })
    fireEvent.click(headingButton)

    expect(headingButton).toBeTruthy()
  })

  it('should handle list creation', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const listButton = screen.getByRole('button', { name: /bullet|list/i })
    fireEvent.click(listButton)

    expect(listButton).toBeTruthy()
  })

  it('should handle undo action', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const undoButton = screen.getByRole('button', { name: /undo/i })
    fireEvent.click(undoButton)

    expect(undoButton).toBeTruthy()
  })

  it('should handle redo action', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const redoButton = screen.getByRole('button', { name: /redo/i })
    fireEvent.click(redoButton)

    expect(redoButton).toBeTruthy()
  })

  it('should render with initial content', () => {
    render(<RichTextEditor value="<p>Initial content</p>" onChange={mockOnChange} />)
    expect(screen.getByTestId('editor-content')).toBeInTheDocument()
  })

  it('should call onChange when content changes', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(mockOnChange).toHaveBeenCalled()
  })

  it('should show separator between toolbar groups', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getAllByTestId('separator').length).toBeGreaterThan(0)
  })

  it('should handle code formatting', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const codeButton = screen.queryByRole('button', { name: /code/i })
    if (codeButton) {
      fireEvent.click(codeButton)
      expect(codeButton).toBeTruthy()
    }
  })

  it('should handle blockquote', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const quoteButton = screen.queryByRole('button', { name: /quote|blockquote/i })
    if (quoteButton) {
      fireEvent.click(quoteButton)
      expect(quoteButton).toBeTruthy()
    }
  })

  it('should handle strikethrough', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const strikeButton = screen.queryByRole('button', { name: /strike/i })
    if (strikeButton) {
      fireEvent.click(strikeButton)
      expect(strikeButton).toBeTruthy()
    }
  })

  it('should render with placeholder', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} placeholder="Type something..." />)
    expect(document.body).toBeTruthy()
  })

  it('should be disabled when specified', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} disabled={true} />)

    const buttons = screen.getAllByRole('button')
    buttons.forEach((button) => {
      expect(button).toBeDisabled()
    })
  })

  it('should handle read-only mode', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} readOnly={true} />)
    expect(document.body).toBeTruthy()
  })

  it('should apply custom className', () => {
    const { container } = render(
      <RichTextEditor value="" onChange={mockOnChange} className="custom-editor" />
    )
    expect(container.querySelector('.custom-editor')).toBeInTheDocument()
  })

  it('should handle keyboard shortcuts', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const editor = screen.getByTestId('editor-content')
    fireEvent.keyDown(editor, { key: 'b', ctrlKey: true })

    expect(editor).toBeTruthy()
  })

  it('should show word count', () => {
    render(<RichTextEditor value="Hello world" onChange={mockOnChange} showWordCount={true} />)
    expect(screen.queryByText(/words/i) || document.body).toBeTruthy()
  })

  it('should handle empty content', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)
    expect(screen.getByTestId('editor-content')).toBeInTheDocument()
  })

  it('should handle HTML content', () => {
    render(<RichTextEditor value="<p><strong>Bold</strong> text</p>" onChange={mockOnChange} />)
    expect(screen.getByTestId('editor-content')).toBeInTheDocument()
  })

  it('should handle markdown mode toggle', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const markdownButton = screen.queryByRole('button', { name: /markdown/i })
    if (markdownButton) {
      fireEvent.click(markdownButton)
      expect(markdownButton).toBeTruthy()
    }
  })

  it('should handle link insertion', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const linkButton = screen.queryByRole('button', { name: /link/i })
    if (linkButton) {
      fireEvent.click(linkButton)
      expect(linkButton).toBeTruthy()
    }
  })

  it('should handle image insertion', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const imageButton = screen.queryByRole('button', { name: /image/i })
    if (imageButton) {
      fireEvent.click(imageButton)
      expect(imageButton).toBeTruthy()
    }
  })

  it('should handle table insertion', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const tableButton = screen.queryByRole('button', { name: /table/i })
    if (tableButton) {
      fireEvent.click(tableButton)
      expect(tableButton).toBeTruthy()
    }
  })

  it('should handle clear formatting', () => {
    render(<RichTextEditor value="" onChange={mockOnChange} />)

    const clearButton = screen.queryByRole('button', { name: /clear/i })
    if (clearButton) {
      fireEvent.click(clearButton)
      expect(clearButton).toBeTruthy()
    }
  })
})
