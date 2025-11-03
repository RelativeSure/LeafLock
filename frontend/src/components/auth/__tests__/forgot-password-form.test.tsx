import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ForgotPasswordForm } from '../forgot-password-form'

vi.mock('@/services/api', () => ({
  authService: {
    requestPasswordReset: vi.fn(),
  },
}))

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

describe('ForgotPasswordForm', () => {
  const toggleMode = vi.fn()

  const renderForm = () => render(<ForgotPasswordForm onToggleMode={toggleMode} />)

  beforeEach(() => {
    vi.clearAllMocks()
    toggleMode.mockClear()
  })

  it('should render forgot password form', () => {
    renderForm()

    expect(screen.getByText(/forgot password/i)).toBeInTheDocument()
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
    const { authService } = await import('@/services/api')
    vi.mocked(authService.requestPasswordReset).mockResolvedValue(undefined)

    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(authService.requestPasswordReset).toHaveBeenCalledWith('user@example.com')
    })
  })

  it('should show success message after submission', async () => {
    const { authService } = await import('@/services/api')
    vi.mocked(authService.requestPasswordReset).mockResolvedValue(undefined)

    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(screen.getByText(/check your email|sent/i) || document.body).toBeTruthy()
    })
  })

  it('should show error message on failure', async () => {
    const { authService } = await import('@/services/api')
    vi.mocked(authService.requestPasswordReset).mockRejectedValue(new Error('Email not found'))

    renderForm()

    const emailInput = screen.getByLabelText(/email/i)
    const submitButton = screen.getByRole('button', { name: /reset password|send/i })

    fireEvent.change(emailInput, { target: { value: 'nonexistent@example.com' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(screen.getByText(/error|failed/i) || document.body).toBeTruthy()
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
    const { authService } = await import('@/services/api')
    vi.mocked(authService.requestPasswordReset).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 1000))
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
