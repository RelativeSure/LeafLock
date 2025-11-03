import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { LoginForm } from '../login-form'

// Mock the auth store
const mockLogin = vi.fn()
const mockVerifyMFA = vi.fn()
const mockUser = null
const mockCheckRegistrationEnabled = vi.fn()

vi.mock('@/stores/authStore', () => ({
  useAuthStore: () => ({
    login: mockLogin,
    verifyMFA: mockVerifyMFA,
    user: mockUser,
    checkRegistrationEnabled: mockCheckRegistrationEnabled,
  }),
}))

// Mock window.location
delete (window as any).location
window.location = { href: '' } as any

describe('LoginForm', () => {
  const mockOnToggleMode = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    window.location.href = ''
    mockCheckRegistrationEnabled.mockResolvedValue(true)
  })

  const getLoginElements = async () => {
    const emailInput = (await screen.findByLabelText(/email/i)) as HTMLInputElement
    const passwordInput = (await screen.findByLabelText(/password/i)) as HTMLInputElement
    const submitButton = await screen.findByRole('button', { name: /sign in/i })
    return { emailInput, passwordInput, submitButton }
  }

  describe('initial render', () => {
    it('should render login form with email and password fields', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      expect(await screen.findByLabelText(/email/i)).toBeInTheDocument()
      expect(await screen.findByLabelText(/password/i)).toBeInTheDocument()
      expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument()
    })

    it('should render animated title if provided', async () => {
      const animatedTitle = <div data-testid="animated-title">Welcome Back</div>
      render(<LoginForm onToggleMode={mockOnToggleMode} animatedTitle={animatedTitle} />)

      expect(await screen.findByTestId('animated-title')).toBeInTheDocument()
    })

    it('should have toggle mode link for registration', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const toggleLink = await screen.findByText(/don't have an account/i)
      expect(toggleLink).toBeInTheDocument()
    })
  })

  describe('form validation and input', () => {
    it('should update email field on change', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })

      expect(emailInput.value).toBe('test@example.com')
    })

    it('should update password field on change', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { passwordInput } = await getLoginElements()
      fireEvent.change(passwordInput, { target: { value: 'password123' } })

      expect(passwordInput.value).toBe('password123')
    })

    it('should mask password input', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { passwordInput } = await getLoginElements()
      expect(passwordInput).toHaveAttribute('type', 'password')
    })
  })

  describe('login submission', () => {
    it('should call login with email and password on form submit', async () => {
      mockLogin.mockResolvedValue({ requiresMFA: false })

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput, submitButton } = await getLoginElements()

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(mockLogin).toHaveBeenCalledWith('test@example.com', 'password123')
      })
    })

    it('should show loading state during login', async () => {
      mockLogin.mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 100)))

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput, submitButton } = await getLoginElements()

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      // Button should be disabled during loading
      expect(submitButton).toBeDisabled()

      await waitFor(() => {
        expect(mockLogin).toHaveBeenCalled()
      })
    })

    it('should display error message on login failure', async () => {
      mockLogin.mockRejectedValue(new Error('Invalid credentials'))

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput, submitButton } = await getLoginElements()

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'wrong-password' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument()
      })
    })

    it('should clear error message on new submission', async () => {
      mockLogin.mockRejectedValueOnce(new Error('Invalid credentials'))
      mockLogin.mockResolvedValueOnce({ requiresMFA: false })

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput, submitButton } = await getLoginElements()

      // First attempt - error
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'wrong' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument()
      })

      // Second attempt - should clear error
      fireEvent.change(passwordInput, { target: { value: 'correct' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.queryByText(/invalid credentials/i)).not.toBeInTheDocument()
      })
    })
  })

  describe('MFA flow', () => {
    it('should show MFA form when login requires MFA', async () => {
      mockLogin.mockResolvedValue({ requiresMFA: true })

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput, submitButton } = await getLoginElements()

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/two-factor authentication/i)).toBeInTheDocument()
        expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument()
      })
    })

    it('should accept MFA code input and verify', async () => {
      mockLogin.mockResolvedValue({ requiresMFA: true })
      mockVerifyMFA.mockResolvedValue(true)

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      // Login first
      const { emailInput, passwordInput, submitButton } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      // Wait for MFA form
      await waitFor(() => {
        expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument()
      })

      // Enter MFA code
      const mfaInput = screen.getByLabelText(/authentication code/i)
      fireEvent.change(mfaInput, { target: { value: '123456' } })

      // Submit MFA
      const verifyButton = screen.getByRole('button', { name: /verify/i })
      fireEvent.click(verifyButton)

      await waitFor(() => {
        expect(mockVerifyMFA).toHaveBeenCalledWith('123456')
      })
    })

    it('should only accept numeric MFA code', async () => {
      mockLogin.mockResolvedValue({ requiresMFA: true })

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      // Login to show MFA form
      const { emailInput, passwordInput, submitButton } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument()
      })

      const mfaInput = screen.getByLabelText(/authentication code/i) as HTMLInputElement
      fireEvent.change(mfaInput, { target: { value: 'abc123def' } })

      // Should strip non-numeric characters
      expect(mfaInput.value).toBe('123')
    })

    it('should limit MFA code to 6 digits', async () => {
      mockLogin.mockResolvedValue({ requiresMFA: true })

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      // Login to show MFA form
      const { emailInput, passwordInput, submitButton } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument()
      })

      const mfaInput = screen.getByLabelText(/authentication code/i) as HTMLInputElement
      fireEvent.change(mfaInput, { target: { value: '1234567890' } })

      // Should truncate to 6 digits
      expect(mfaInput.value).toBe('123456')
    })

    it('should show error on invalid MFA code', async () => {
      mockLogin.mockResolvedValue({ requiresMFA: true })
      mockVerifyMFA.mockResolvedValue(false)

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      // Login and enter MFA
      const { emailInput, passwordInput, submitButton } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument()
      })

      fireEvent.change(screen.getByLabelText(/authentication code/i), {
        target: { value: '000000' },
      })
      fireEvent.click(screen.getByRole('button', { name: /verify/i }))

      await waitFor(() => {
        expect(screen.getByText(/invalid mfa code/i)).toBeInTheDocument()
      })
    })

    it('should show error on MFA verification failure', async () => {
      mockLogin.mockResolvedValue({ requiresMFA: true })
      mockVerifyMFA.mockRejectedValue(new Error('Verification failed'))

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      // Login and enter MFA
      const { emailInput, passwordInput, submitButton } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument()
      })

      fireEvent.change(screen.getByLabelText(/authentication code/i), {
        target: { value: '123456' },
      })
      fireEvent.click(screen.getByRole('button', { name: /verify/i }))

      await waitFor(() => {
        expect(screen.getByText(/mfa verification failed/i)).toBeInTheDocument()
      })
    })
  })

  describe('toggle mode', () => {
    it('should call onToggleMode when clicking registration link', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const toggleLink = await screen.findByText(/sign up/i)
      fireEvent.click(toggleLink)

      expect(mockOnToggleMode).toHaveBeenCalled()
    })
  })

  describe('edge cases', () => {
    it('should have required fields for email and password', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput } = await getLoginElements()

      expect(emailInput).toBeRequired()
      expect(passwordInput).toBeRequired()
    })

    it('should handle non-Error exceptions during login', async () => {
      mockLogin.mockRejectedValue('String error')

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput, submitButton } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/login failed/i)).toBeInTheDocument()
      })
    })

    it('should prevent form submission while loading', async () => {
      let resolveLogin: any
      mockLogin.mockReturnValue(
        new Promise((resolve) => {
          resolveLogin = resolve
        })
      )

      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const { emailInput, passwordInput, submitButton } = await getLoginElements()
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'password123' } })
      fireEvent.click(submitButton)

      // Try to submit again while loading
      fireEvent.click(submitButton)

      // Should only call login once
      expect(mockLogin).toHaveBeenCalledTimes(1)

      await act(async () => {
        resolveLogin({ requiresMFA: false })
      })

      await waitFor(() => {
        expect(submitButton).not.toBeDisabled()
      })
    })
  })
})
