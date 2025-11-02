import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SaveTemplateDialog } from '../save-template-dialog'

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
  DialogFooter: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ onChange, value, ...props }: any) => (
    <input onChange={onChange} value={value} {...props} />
  ),
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, ...props }: any) => <label {...props}>{children}</label>,
}))

describe('SaveTemplateDialog', () => {
  const mockOnSave = vi.fn()
  const mockOnOpenChange = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render when open', () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render when closed', () => {
    render(
      <SaveTemplateDialog
        open={false}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should show template name input', () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('should accept template name input', () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'My Template' } })

    expect(input).toHaveValue('My Template')
  })

  it('should call onSave with template data', async () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'My Template' } })

    const saveButton = screen.getByRole('button', { name: /save/i })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(mockOnSave).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'My Template',
        })
      )
    })
  })

  it('should disable save button when name is empty', () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    const saveButton = screen.getByRole('button', { name: /save/i })
    expect(saveButton).toBeDisabled()
  })

  it('should enable save button when name is provided', () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'My Template' } })

    const saveButton = screen.getByRole('button', { name: /save/i })
    expect(saveButton).not.toBeDisabled()
  })

  it('should show cancel button', () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
  })

  it('should call onOpenChange when cancel is clicked', () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    const cancelButton = screen.getByRole('button', { name: /cancel/i })
    fireEvent.click(cancelButton)

    expect(mockOnOpenChange).toHaveBeenCalledWith(false)
  })

  it('should reset form after save', async () => {
    render(
      <SaveTemplateDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        onSave={mockOnSave}
        noteTitle="Test Note"
        noteContent="Test Content"
      />
    )

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'My Template' } })

    const saveButton = screen.getByRole('button', { name: /save/i })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(mockOnSave).toHaveBeenCalled()
    })
  })
})
