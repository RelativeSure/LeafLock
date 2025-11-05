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

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, htmlFor }: any) => <label htmlFor={htmlFor}>{children}</label>,
}))

vi.mock('@/components/ui/alert', () => ({
  Alert: ({ children }: any) => <div>{children}</div>,
  AlertDescription: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('lucide-react', () => ({
  Lock: () => <div>Lock Icon</div>,
  Key: () => <div>Key Icon</div>,
  AlertCircle: () => <div>Alert Icon</div>,
}))

const mockSetEncryptionKey = vi.fn()

vi.mock('@/lib/encryption-context', () => ({
  useEncryption: () => ({
    setEncryptionKey: mockSetEncryptionKey,
    isUnlocked: false,
  }),
}))

describe('EncryptionUnlockDialog', () => {
  const mockOnUnlock = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    mockSetEncryptionKey.mockReset()
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

    const passwordInput = screen.getByLabelText(/encryption password/i)
    expect(passwordInput).toBeInTheDocument()
    expect(passwordInput).toHaveAttribute('type', 'password')
  })

  it('should accept password input', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    const input = screen.getByLabelText(/encryption password/i)
    fireEvent.change(input, { target: { value: 'mypassword' } })

    expect(input).toHaveValue('mypassword')
  })

  it('should show unlock button', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    expect(screen.getByRole('button', { name: /unlock/i })).toBeInTheDocument()
  })

  it('should not disable unlock button when password is empty', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    const unlockButton = screen.getByRole('button', { name: /unlock/i })
    // Button is not disabled - error is shown on click instead
    expect(unlockButton).not.toBeDisabled()
  })

  it('should enable unlock button when password is provided', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    const input = screen.getByLabelText(/encryption password/i)
    fireEvent.change(input, { target: { value: 'validpassword123' } })

    const unlockButton = screen.getByRole('button', { name: /unlock/i })
    expect(unlockButton).not.toBeDisabled()
  })

  it('should show cancel button', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
  })

  it('should call onUnlock when unlock button is clicked', async () => {
    mockSetEncryptionKey.mockResolvedValue(undefined)

    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    const input = screen.getByLabelText(/encryption password/i)
    fireEvent.change(input, { target: { value: 'validpassword123' } })

    const unlockButton = screen.getByRole('button', { name: /unlock/i })
    fireEvent.click(unlockButton)

    await vi.waitFor(() => {
      expect(mockOnUnlock).toHaveBeenCalled()
    })
  })

  it('should hide password by default', () => {
    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    const input = screen.getByLabelText(/encryption password/i)
    expect(input).toHaveAttribute('type', 'password')
  })

  it('should handle form submission', async () => {
    mockSetEncryptionKey.mockResolvedValue(undefined)

    render(<EncryptionUnlockDialog open={true} onOpenChange={vi.fn()} onUnlock={mockOnUnlock} />)

    const input = screen.getByLabelText(/encryption password/i)
    fireEvent.change(input, { target: { value: 'validpassword123' } })

    // Trigger Enter key submission
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })

    await vi.waitFor(() => {
      expect(mockOnUnlock).toHaveBeenCalled()
    })
  })
})
