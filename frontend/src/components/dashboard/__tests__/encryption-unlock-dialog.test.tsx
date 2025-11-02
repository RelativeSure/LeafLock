import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { EncryptionUnlockDialog } from '../encryption-unlock-dialog'

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
  Input: ({ type, onChange, value, ...props }: any) => (
    <input type={type} onChange={onChange} value={value} {...props} />
  ),
}))

vi.mock('@/lib/encryption-context', () => ({
  useEncryption: () => ({
    setEncryptionKey: vi.fn(),
    isUnlocked: false,
  }),
}))

describe('EncryptionUnlockDialog', () => {
  const mockOnUnlock = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render unlock dialog when open', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render when closed', () => {
    render(<EncryptionUnlockDialog open={false} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should show password input', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    const passwordInput = screen.getByRole('textbox') || screen.getByLabelText(/password/i)
    expect(passwordInput).toBeInTheDocument()
  })

  it('should accept password input', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    const input = screen.getByRole('textbox') || screen.getAllByRole('textbox')[0]
    fireEvent.change(input, { target: { value: 'mypassword' } })

    expect(input).toHaveValue('mypassword')
  })

  it('should show unlock button', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    expect(screen.getByRole('button', { name: /unlock/i })).toBeInTheDocument()
  })

  it('should disable unlock button when password is empty', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    const unlockButton = screen.getByRole('button', { name: /unlock/i })
    expect(unlockButton).toBeDisabled()
  })

  it('should enable unlock button when password is provided', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    const input = screen.getByRole('textbox') || screen.getAllByRole('textbox')[0]
    fireEvent.change(input, { target: { value: 'mypassword' } })

    const unlockButton = screen.getByRole('button', { name: /unlock/i })
    expect(unlockButton).not.toBeDisabled()
  })

  it('should show cancel button', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
  })

  it('should call onUnlock when unlock button is clicked', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    const input = screen.getByRole('textbox') || screen.getAllByRole('textbox')[0]
    fireEvent.change(input, { target: { value: 'mypassword' } })

    const unlockButton = screen.getByRole('button', { name: /unlock/i })
    fireEvent.click(unlockButton)

    expect(mockOnUnlock).toHaveBeenCalled()
  })

  it('should hide password by default', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    const input = screen.getByRole('textbox') || screen.getAllByRole('textbox')[0]
    expect(input).toHaveAttribute('type', 'password')
  })

  it('should handle form submission', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)
    
    const input = screen.getByRole('textbox') || screen.getAllByRole('textbox')[0]
    fireEvent.change(input, { target: { value: 'mypassword' } })

    const form = input.closest('form')
    if (form) {
      fireEvent.submit(form)
      expect(mockOnUnlock).toHaveBeenCalled()
    }
  })
})
