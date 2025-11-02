import { type ComponentProps } from 'react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SaveTemplateDialog } from '../save-template-dialog'

const createTemplateMock = vi.fn()

vi.mock('../../stores/templatesStore', () => ({
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

  it('disables save button when name is empty', () => {
    renderDialog()
    const saveButton = screen.getByRole('button', { name: /save template/i })
    expect(saveButton).toBeDisabled()
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

  it('resets fields after saving', () => {
    renderDialog()

    const nameInput = screen.getByRole('textbox')
    fireEvent.change(nameInput, { target: { value: 'Another Template' } })

    fireEvent.click(screen.getByRole('button', { name: /save template/i }))

    expect(nameInput).toHaveValue('')
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
})
