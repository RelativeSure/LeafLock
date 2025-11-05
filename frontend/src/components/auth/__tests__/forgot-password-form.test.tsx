import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ForgotPasswordForm } from '../forgot-password-form'

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, disabled, type }: any) => (
    <button onClick={onClick} disabled={disabled} type={type}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: (props: any) => <input {...props} />,
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, htmlFor }: any) => <label htmlFor={htmlFor}>{children}</label>,
}))

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div>{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('lucide-react', () => ({
  Mail: () => <div>Mail Icon</div>,
  ArrowLeft: () => <div>Arrow Icon</div>,
}))

describe('ForgotPasswordForm', () => {
  const toggleMode = vi.fn()

  const renderForm = () => render(<ForgotPasswordForm onToggleMode={toggleMode} />)

  beforeEach(() => {
    vi.clearAllMocks()
    toggleMode.mockClear()
    global.fetch = vi.fn()
  })

  it('should render forgot password form', () => {
    renderForm()

    expect(screen.getByRole('heading', { name: /reset your password/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument()
  })

  it('should have email input field', () => {
    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    expect(emailInput).toBeInTheDocument()
    expect(emailInput).toHaveAttribute('type', 'email')
  })

  it('should have submit button', () => {
    renderForm()

    const submitButton = screen.getByRole('button', { name: /reset password|send/i })
    expect(submitButton).toBeInTheDocument()
  })

  it('should allow typing in email field', () => {
    renderForm()

    const emailInput = screen.getByLabelText(/email/i) as HTMLInputElement
    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })

    expect(emailInput.value).toBe('user@example.com')
  })

  it('should submit form with valid email', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ message: 'Reset link sent' }),
    } as Response)

    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/auth/forgot-password'),
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'user@example.com' }),
        })
      )
    })
  })

  it('should show success message after submission', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ message: 'Reset link sent' }),
    } as Response)

    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(screen.getByText(/check your email/i)).toBeInTheDocument()
    })
  })

  it('should show error message on failure', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      json: async () => ({ error: 'Email not found' }),
    } as Response)

    const { toast } = await import('sonner')
    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'nonexistent@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalled()
    })
  })

  it('should validate email format', async () => {
    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'invalid-email' } })
    fireEvent.click(submitButton)

    expect(emailInput).toHaveAttribute('type', 'email')
  })

  it('should disable submit button while loading', async () => {
    global.fetch = vi.fn().mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve({
        ok: true,
        json: async () => ({ message: 'Reset link sent' }),
      } as Response), 1000))
    )

    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(submitButton).toBeDisabled()
    })
  })

  it('should have link back to login', () => {
    renderForm()

    const loginLink = screen.getByText(/back to login|sign in/i)
    expect(loginLink).toBeInTheDocument()
  })
})
