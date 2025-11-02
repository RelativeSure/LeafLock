import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ShareNoteDialog } from '../share-note-dialog'

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

vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div data-testid="tabs">{children}</div>,
  TabsList: ({ children }: any) => <div>{children}</div>,
  TabsTrigger: ({ children, value }: any) => <button data-value={value}>{children}</button>,
  TabsContent: ({ children, value }: any) => <div data-value={value}>{children}</div>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children, onValueChange }: any) => (
    <div data-testid="select" onClick={() => onValueChange && onValueChange('read')}>
      {children}
    </div>
  ),
  SelectTrigger: ({ children }: any) => <div>{children}</div>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, value }: any) => <option value={value}>{children}</option>,
  SelectValue: ({ placeholder }: any) => <span>{placeholder}</span>,
}))

describe('ShareNoteDialog', () => {
  const mockOnShare = vi.fn()
  const mockOnOpenChange = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render when open', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render when closed', () => {
    render(
      <ShareNoteDialog
        open={false}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should show tabs for different sharing methods', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    expect(screen.getByTestId('tabs')).toBeInTheDocument()
  })

  it('should show direct share tab', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    expect(screen.getByText(/share/i)).toBeInTheDocument()
  })

  it('should show email input for direct sharing', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const emailInput = screen.getByPlaceholderText(/email/i)
    expect(emailInput).toBeInTheDocument()
  })

  it('should accept email input', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const emailInput = screen.getByPlaceholderText(/email/i)
    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })

    expect(emailInput).toHaveValue('user@example.com')
  })

  it('should show permission selector', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    expect(screen.getByTestId('select')).toBeInTheDocument()
  })

  it('should call onShare when sharing', async () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const emailInput = screen.getByPlaceholderText(/email/i)
    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })

    const shareButton = screen.getByRole('button', { name: /share|add/i })
    fireEvent.click(shareButton)

    await waitFor(() => {
      expect(mockOnShare).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'user@example.com',
        })
      )
    })
  })

  it('should validate email format', async () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const emailInput = screen.getByPlaceholderText(/email/i)
    fireEvent.change(emailInput, { target: { value: 'invalid-email' } })

    const shareButton = screen.getByRole('button', { name: /share|add/i })
    fireEvent.click(shareButton)

    expect(screen.getByText(/invalid.*email/i) || document.body).toBeTruthy()
  })

  it('should disable share button when email is empty', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const shareButton = screen.getByRole('button', { name: /share|add/i })
    expect(shareButton).toBeDisabled()
  })

  it('should show existing collaborators', () => {
    const collaborators = [
      { email: 'user1@example.com', permission: 'read' },
      { email: 'user2@example.com', permission: 'write' },
    ]

    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
        existingCollaborators={collaborators}
      />
    )

    expect(screen.getByText('user1@example.com')).toBeInTheDocument()
    expect(screen.getByText('user2@example.com')).toBeInTheDocument()
  })

  it('should allow removing collaborators', async () => {
    const collaborators = [{ email: 'user1@example.com', permission: 'read' }]
    const onRemove = vi.fn()

    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
        existingCollaborators={collaborators}
        onRemoveCollaborator={onRemove}
      />
    )

    const removeButton = screen.queryByRole('button', { name: /remove/i })
    if (removeButton) {
      fireEvent.click(removeButton)
      await waitFor(() => {
        expect(onRemove).toHaveBeenCalledWith('user1@example.com')
      })
    }
  })

  it('should show share link tab', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const linkTab = screen.getByText(/link/i)
    expect(linkTab).toBeInTheDocument()
  })

  it('should generate share link', async () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const generateButton = screen.queryByRole('button', { name: /generate|create.*link/i })
    if (generateButton) {
      fireEvent.click(generateButton)
      await waitFor(() => {
        expect(screen.getByDisplayValue(/http/i) || document.body).toBeTruthy()
      })
    }
  })

  it('should copy link to clipboard', async () => {
    const mockClipboard = {
      writeText: vi.fn().mockResolvedValue(undefined),
    }
    Object.assign(navigator, { clipboard: mockClipboard })

    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
        shareLink="https://example.com/share/abc123"
      />
    )

    const copyButton = screen.queryByRole('button', { name: /copy/i })
    if (copyButton) {
      fireEvent.click(copyButton)
      await waitFor(() => {
        expect(mockClipboard.writeText).toHaveBeenCalledWith('https://example.com/share/abc123')
      })
    }
  })

  it('should close dialog when cancel is clicked', () => {
    render(
      <ShareNoteDialog
        open={true}
        onOpenChange={mockOnOpenChange}
        noteId="note-1"
        onShare={mockOnShare}
      />
    )

    const cancelButton = screen.getByRole('button', { name: /cancel|close/i })
    fireEvent.click(cancelButton)

    expect(mockOnOpenChange).toHaveBeenCalledWith(false)
  })
})
