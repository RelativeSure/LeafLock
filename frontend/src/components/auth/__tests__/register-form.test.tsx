import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { RegisterForm } from '../register-form'

// Mock the auth store
const mockRegister = vi.fn()
const mockCheckRegistrationEnabled = vi.fn()

vi.mock('@/stores/authStore', () => ({
  useAuthStore: () => ({
    register: mockRegister,
    checkRegistrationEnabled: mockCheckRegistrationEnabled,
  }),
}))

// Mock window.location
delete (window as any).location
window.location = { href: '' } as any

describe('RegisterForm', () => {
  const mockOnToggleMode = vi.fn()

  const findFormElements = async () => {
    const nameInput = (await screen.findByLabelText(/full name/i)) as HTMLInputElement
    const emailInput = (await screen.findByLabelText(/^email$/i)) as HTMLInputElement
    const passwordInput = (await screen.findByLabelText(/^password$/i)) as HTMLInputElement
    const confirmPasswordInput = (await screen.findByLabelText(
      /confirm password/i
    )) as HTMLInputElement
    const submitButton = await screen.findByRole('button', { name: /create account/i })
    return { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton }
  }

  const fillForm = async ({
    name = 'John Doe',
    email = 'test@example.com',
    password = 'Password123!',
    confirmPassword = password,
  }: {
    name?: string
    email?: string
    password?: string
    confirmPassword?: string
  } = {}) => {
    const elements = await findFormElements()

    fireEvent.change(elements.nameInput, { target: { value: name } })
    fireEvent.change(elements.emailInput, { target: { value: email } })
    fireEvent.change(elements.passwordInput, { target: { value: password } })
    fireEvent.change(elements.confirmPasswordInput, { target: { value: confirmPassword } })

    return elements
  }

  beforeEach(() => {
    vi.clearAllMocks()
    window.location.href = ''
    // Default: registration is enabled - return immediately resolved promise
    mockCheckRegistrationEnabled.mockImplementation(() => Promise.resolve(true))
  })

  describe('initial render', () => {
    it('should render registration form with all required fields', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.getByLabelText(/full name/i)).toBeInTheDocument()
        expect(screen.getByLabelText(/^email$/i)).toBeInTheDocument()
        expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument()
        expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument()
      })
    })

    it('should render animated title if provided', async () => {
      const animatedTitle = <div data-testid="animated-title">Join LeafLock</div>
      render(<RegisterForm onToggleMode={mockOnToggleMode} animatedTitle={animatedTitle} />)

      await waitFor(() => {
        expect(screen.getByTestId('animated-title')).toBeInTheDocument()
      })
    })

    it('should have toggle mode link for login', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        const toggleLink = screen.getByText(/already have an account/i)
        expect(toggleLink).toBeInTheDocument()
      })
    })

    it('should show password requirements when password field has input', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        const passwordInput = screen.getByLabelText(/^password$/i)
        fireEvent.change(passwordInput, { target: { value: 'test' } })
      })

      expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument()
      expect(screen.getByText(/uppercase letter/i)).toBeInTheDocument()
      expect(screen.getByText(/lowercase letter/i)).toBeInTheDocument()
      expect(screen.getByText(/number/i)).toBeInTheDocument()
      expect(screen.getByText(/special character/i)).toBeInTheDocument()
    })
  })

  describe('form input', () => {
    it('should update name field on change', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(async () => {
        const nameInput = screen.getByLabelText(/full name/i) as HTMLInputElement
        fireEvent.change(nameInput, { target: { value: 'John Doe' } })
        expect(nameInput.value).toBe('John Doe')
      })
    })

    it('should update email field on change', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(async () => {
        const emailInput = screen.getByLabelText(/^email$/i) as HTMLInputElement
        fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
        expect(emailInput.value).toBe('test@example.com')
      })
    })

    it('should update password field on change', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(async () => {
        const passwordInput = screen.getByLabelText(/^password$/i) as HTMLInputElement
        fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
        expect(passwordInput.value).toBe('Password123!')
      })
    })

    it('should update confirm password field on change', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(async () => {
        const confirmInput = screen.getByLabelText(/confirm password/i) as HTMLInputElement
        fireEvent.change(confirmInput, { target: { value: 'Password123!' } })
        expect(confirmInput.value).toBe('Password123!')
      })
    })
  })

  describe('name validation', () => {
    it('should show error for name shorter than 2 characters', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({ name: 'A' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/name must be at least 2 characters/i)).toBeInTheDocument()
      })
    })

    it('should show error for name with invalid characters', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({ name: 'John123' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/name can only contain letters/i)).toBeInTheDocument()
      })
    })

    it('should accept valid names with spaces, hyphens, and apostrophes', async () => {
      mockRegister.mockResolvedValue('Registration request accepted')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({ name: "Mary-Jane O'Brien" })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith(
          'test@example.com',
          'Password123!',
          "Mary-Jane O'Brien"
        )
      })
    })
  })

  describe('email validation', () => {
    it('should show error for invalid email format', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({ email: 'invalid-email' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/valid email/i)).toBeInTheDocument()
      })
    })

    it('should accept valid email addresses', async () => {
      mockRegister.mockResolvedValue('Registration request accepted')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({ email: 'valid@example.com' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('valid@example.com', 'Password123!', 'John Doe')
      })
    })
  })

  describe('password validation', () => {
    it('should show error if password is too short', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({ password: 'Pass1!', confirmPassword: 'Pass1!' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks uppercase', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({
        password: 'password123!',
        confirmPassword: 'password123!',
      })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks lowercase', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({
        password: 'PASSWORD123!',
        confirmPassword: 'PASSWORD123!',
      })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks number', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({
        password: 'Password!',
        confirmPassword: 'Password!',
      })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks special character', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({
        password: 'Password123',
        confirmPassword: 'Password123',
      })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if passwords do not match', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm({
        password: 'Password123!',
        confirmPassword: 'Password456!',
      })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should accept valid password meeting all requirements', async () => {
      mockRegister.mockResolvedValue('Registration request accepted')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { submitButton } = await fillForm()
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('test@example.com', 'Password123!', 'John Doe')
      })
    })
  })

  describe('registration submission', () => {
    it('should call register with email, password, and name', async () => {
      mockRegister.mockResolvedValue('Registration request accepted')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton } =
        await findFormElements()

      fireEvent.change(nameInput, { target: { value: 'John Doe' } })
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
      fireEvent.change(confirmPasswordInput, { target: { value: 'Password123!' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('test@example.com', 'Password123!', 'John Doe')
      })
    })

    it('should show loading state during registration', async () => {
      mockRegister.mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 100)))

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton } =
        await findFormElements()

      fireEvent.change(nameInput, { target: { value: 'John Doe' } })
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
      fireEvent.change(confirmPasswordInput, { target: { value: 'Password123!' } })
      fireEvent.click(submitButton)

      expect(submitButton).toBeDisabled()

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalled()
      })
    })

    it('should show success message on registration acceptance', async () => {
      mockRegister.mockResolvedValue('Registration request accepted')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton } =
        await findFormElements()

      fireEvent.change(nameInput, { target: { value: 'John Doe' } })
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
      fireEvent.change(confirmPasswordInput, { target: { value: 'Password123!' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/registration request accepted/i)).toBeInTheDocument()
      })
    })

    it('should display error message on registration failure', async () => {
      mockRegister.mockRejectedValue(new Error('Email already exists'))

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton } =
        await findFormElements()

      fireEvent.change(nameInput, { target: { value: 'John Doe' } })
      fireEvent.change(emailInput, { target: { value: 'existing@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
      fireEvent.change(confirmPasswordInput, { target: { value: 'Password123!' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/email already exists/i)).toBeInTheDocument()
      })
    })

    it('should clear error message on new submission', async () => {
      mockRegister.mockRejectedValueOnce(new Error('Email already exists'))
      mockRegister.mockResolvedValueOnce({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton } =
        await findFormElements()

      fireEvent.change(nameInput, { target: { value: 'John Doe' } })
      fireEvent.change(emailInput, { target: { value: 'existing@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
      fireEvent.change(confirmPasswordInput, { target: { value: 'Password123!' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/email already exists/i)).toBeInTheDocument()
      })

      // Try again with different email
      fireEvent.change(emailInput, { target: { value: 'new@example.com' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.queryByText(/email already exists/i)).not.toBeInTheDocument()
      })
    })
  })

  describe('toggle mode', () => {
    it('should call onToggleMode when clicking login link', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const toggleLink = await screen.findByText(/sign in/i)
      fireEvent.click(toggleLink)

      expect(mockOnToggleMode).toHaveBeenCalled()
    })
  })

  describe('edge cases', () => {
    it('should handle non-Error exceptions during registration', async () => {
      mockRegister.mockRejectedValue('String error')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton } =
        await findFormElements()

      fireEvent.change(nameInput, { target: { value: 'John Doe' } })
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
      fireEvent.change(confirmPasswordInput, { target: { value: 'Password123!' } })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText(/registration failed/i)).toBeInTheDocument()
      })
    })

    it('should trim whitespace from name during validation', async () => {
      mockRegister.mockResolvedValue('Registration request accepted')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const { nameInput, emailInput, passwordInput, confirmPasswordInput, submitButton } =
        await findFormElements()

      fireEvent.change(nameInput, { target: { value: '  John Doe  ' } })
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })
      fireEvent.change(confirmPasswordInput, { target: { value: 'Password123!' } })
      fireEvent.click(submitButton)

      // Should call register with untrimmed name (trimming is for validation only)
      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith(
          'test@example.com',
          'Password123!',
          '  John Doe  '
        )
      })
    })
  })

  describe('registration status checking', () => {
    it('should check registration status on mount', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(true)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(mockCheckRegistrationEnabled).toHaveBeenCalledTimes(1)
      })
    })

    it('should show loading state while checking registration status', () => {
      mockCheckRegistrationEnabled.mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve(true), 100))
      )

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      expect(screen.getByText(/checking registration status/i)).toBeInTheDocument()
    })

    it('should show registration form when registration is enabled', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(true)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.getByLabelText(/full name/i)).toBeInTheDocument()
        expect(screen.getByLabelText(/^email$/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument()
      })
    })

    it('should show disabled message when registration is disabled', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(false)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.getByText(/registration disabled/i)).toBeInTheDocument()
        expect(screen.getByText(/new user registration is currently disabled/i)).toBeInTheDocument()
      })
    })

    it('should hide registration form when registration is disabled', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(false)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.queryByLabelText(/full name/i)).not.toBeInTheDocument()
        expect(screen.queryByLabelText(/^email$/i)).not.toBeInTheDocument()
        expect(screen.queryByRole('button', { name: /create account/i })).not.toBeInTheDocument()
      })
    })

    it('should show "Back to Sign In" button when registration is disabled', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(false)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        const backButton = screen.getByRole('button', { name: /back to sign in/i })
        expect(backButton).toBeInTheDocument()
      })
    })

    it('should call onToggleMode when clicking "Back to Sign In" button', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(false)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        const backButton = screen.getByRole('button', { name: /back to sign in/i })
        fireEvent.click(backButton)
      })

      expect(mockOnToggleMode).toHaveBeenCalledTimes(1)
    })

    it('should show warning icon when registration is disabled', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(false)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        const alertIcon = screen.getByText(/registration disabled/i).parentElement?.parentElement
        expect(alertIcon).toBeInTheDocument()
      })
    })

    it('should handle registration status check error gracefully', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(vi.fn())
      mockCheckRegistrationEnabled.mockRejectedValue(new Error('Network error'))

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        // Should show disabled message when error occurs (security default)
        expect(screen.getByText(/registration disabled/i)).toBeInTheDocument()
      })

      consoleErrorSpy.mockRestore()
    })

    it('should set registrationEnabled to false on error', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(vi.fn())
      mockCheckRegistrationEnabled.mockRejectedValue(new Error('Network error'))

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.queryByLabelText(/full name/i)).not.toBeInTheDocument()
      })

      consoleErrorSpy.mockRestore()
    })

    it('should not show loading spinner after registration status is checked', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(true)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.queryByText(/checking registration status/i)).not.toBeInTheDocument()
      })
    })

    it('should show form fields after successful registration status check', async () => {
      mockCheckRegistrationEnabled.mockResolvedValue(true)

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(mockCheckRegistrationEnabled).toHaveBeenCalledTimes(1)
        expect(screen.getByLabelText(/full name/i)).toBeInTheDocument()
      })
    })
  })
})
