import { type ComponentProps } from 'react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SaveTemplateDialog } from '../save-template-dialog'

const createTemplateMock = vi.fn()

vi.mock('@/stores/templatesStore', () => ({
  useTemplatesStore: vi.fn(() => ({
    createTemplate: createTemplateMock,
  })),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button type="button" onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, ...props }: any) => (
    <input value={value} onChange={onChange} {...props} />
  ),
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, ...props }: any) => <label {...props}>{children}</label>,
}))

vi.mock('@/components/ui/switch', () => ({
  Switch: ({ checked, onCheckedChange }: any) => (
    <input
      type="checkbox"
      role="switch"
      checked={checked}
      onChange={(event) => onCheckedChange?.(event.target.checked)}
    />
  ),
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('lucide-react', () => ({
  FileText: () => <span />,
  Globe: () => <span />,
  TagIcon: () => <span />,
  X: () => <span />,
}))

describe('SaveTemplateDialog', () => {
  const onOpenChange = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  const renderDialog = (props?: Partial<ComponentProps<typeof SaveTemplateDialog>>) =>
    render(
      <SaveTemplateDialog
        open
        onOpenChange={onOpenChange}
        content="<p>content</p>"
        tags={['tag-a', 'tag-b']}
        {...props}
      />
    )

  it('renders dialog when open', () => {
    renderDialog()
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('does not render when closed', () => {
    renderDialog({ open: false })
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('renders dialog title', () => {
    renderDialog()
    expect(screen.getByText('Save as Template')).toBeInTheDocument()
  })

  it('renders template name label', () => {
    renderDialog()
    expect(screen.getByText('Template Name')).toBeInTheDocument()
  })

  it('renders input with placeholder', () => {
    renderDialog()
    expect(screen.getByPlaceholderText('My Template')).toBeInTheDocument()
  })

  it('renders tags label when tags present', () => {
    renderDialog()
    expect(screen.getByText('Tags')).toBeInTheDocument()
  })

  it('renders provided tags', () => {
    renderDialog()
    expect(screen.getByText('tag-a')).toBeInTheDocument()
    expect(screen.getByText('tag-b')).toBeInTheDocument()
  })

  it('does not render tags section when no tags', () => {
    renderDialog({ tags: [] })
    expect(screen.queryByText('Tags')).not.toBeInTheDocument()
  })

  it('removes tag when X button clicked', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Template Name' } })

    const removeButtons = screen.getAllByRole('button')
    const firstTagRemoveBtn = removeButtons[0]
    fireEvent.click(firstTagRemoveBtn)

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    expect(createTemplateMock).toHaveBeenCalledWith(
      expect.objectContaining({
        tags: ['tag-b'],
      })
    )
  })

  it('renders share publicly label', () => {
    renderDialog()
    expect(screen.getByText('Share Publicly')).toBeInTheDocument()
  })

  it('renders share publicly description', () => {
    renderDialog()
    expect(screen.getByText('Make this template available to everyone')).toBeInTheDocument()
  })

  it('renders public switch in unchecked state by default', () => {
    renderDialog()
    const shareToggle = screen.getByRole('switch')
    expect(shareToggle).not.toBeChecked()
  })

  it('renders save template button', () => {
    renderDialog()
    expect(screen.getByRole('button', { name: /save template/i })).toBeInTheDocument()
  })

  it('renders cancel button', () => {
    renderDialog()
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
  })

  it('disables save button when name is empty', () => {
    renderDialog()
    const saveButton = screen.getByRole('button', { name: /save template/i })
    expect(saveButton).toBeDisabled()
  })

  it('disables save button when name is only whitespace', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: '   ' } })

    const saveButton = screen.getByRole('button', { name: /save template/i })
    expect(saveButton).toBeDisabled()
  })

  it('enables save button when name is provided', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Template Name' } })

    const saveButton = screen.getByRole('button', { name: /save template/i })
    expect(saveButton).not.toBeDisabled()
  })

  it('calls createTemplate and closes dialog on save', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'My Template' } })

    const saveButton = screen.getByRole('button', { name: /save template/i })
    fireEvent.click(saveButton)

    expect(createTemplateMock).toHaveBeenCalledWith({
      name: 'My Template',
      content: '<p>content</p>',
      tags: ['tag-a', 'tag-b'],
      isPublic: false,
    })
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('trims whitespace from template name', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: '  Trimmed Name  ' } })

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    expect(createTemplateMock).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'Trimmed Name',
      })
    )
  })

  it('resets fields after saving', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Another Template' } })

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    expect(nameInput).toHaveValue('')
  })

  it('resets isPublic flag after saving', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Template' } })

    const shareToggle = screen.getByRole('switch')
    fireEvent.click(shareToggle)

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    // Open dialog again to check if reset
    expect(shareToggle).not.toBeChecked()
  })

  it('sets template as public when switch is toggled', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Public Template' } })

    const shareToggle = screen.getByRole('switch')
    fireEvent.click(shareToggle)

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    expect(createTemplateMock).toHaveBeenLastCalledWith({
      name: 'Public Template',
      content: '<p>content</p>',
      tags: ['tag-a', 'tag-b'],
      isPublic: true,
    })
  })

  it('closes dialog when cancel button clicked', () => {
    renderDialog()

    const cancelButton = screen.getByRole('button', { name: /cancel/i })
    fireEvent.click(cancelButton)

    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('does not call createTemplate when cancel button clicked', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Template Name' } })

    const cancelButton = screen.getByRole('button', { name: /cancel/i })
    fireEvent.click(cancelButton)

    expect(createTemplateMock).not.toHaveBeenCalled()
  })

  it('passes content prop to createTemplate', () => {
    renderDialog({ content: '<h1>Custom Content</h1>' })

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Content Template' } })

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    expect(createTemplateMock).toHaveBeenCalledWith(
      expect.objectContaining({
        content: '<h1>Custom Content</h1>',
      })
    )
  })

  it('initializes with provided tags', () => {
    renderDialog({ tags: ['custom-tag-1', 'custom-tag-2'] })

    expect(screen.getByText('custom-tag-1')).toBeInTheDocument()
    expect(screen.getByText('custom-tag-2')).toBeInTheDocument()
  })

  it('allows removing all tags', () => {
    renderDialog({ tags: ['only-tag'] })

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'No Tags Template' } })

    const removeButtons = screen.getAllByRole('button')
    const tagRemoveBtn = removeButtons[0]
    fireEvent.click(tagRemoveBtn)

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    expect(createTemplateMock).toHaveBeenCalledWith(
      expect.objectContaining({
        tags: [],
      })
    )
  })

  it('updates name input value when typing', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox') as HTMLInputElement
    fireEvent.change(nameInput, { target: { value: 'Updated Name' } })

    expect(nameInput.value).toBe('Updated Name')
  })
})
