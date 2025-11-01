import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { RegisterForm } from '../register-form'

// Mock the auth store
const mockRegister = vi.fn()

vi.mock('@/stores/authStore', () => ({
  useAuthStore: () => ({
    register: mockRegister,
  }),
}))

// Mock window.location
delete (window as any).location
window.location = { href: '' } as any

describe('RegisterForm', () => {
  const mockOnToggleMode = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    window.location.href = ''
  })

  describe('initial render', () => {
    it('should render registration form with all required fields', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      expect(screen.getByLabelText(/full name/i)).toBeInTheDocument()
      expect(screen.getByLabelText(/^email$/i)).toBeInTheDocument()
      expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument()
      expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument()
    })

    it('should render animated title if provided', () => {
      const animatedTitle = <div data-testid="animated-title">Join LeafLock</div>
      render(<RegisterForm onToggleMode={mockOnToggleMode} animatedTitle={animatedTitle} />)

      expect(screen.getByTestId('animated-title')).toBeInTheDocument()
    })

    it('should have toggle mode link for login', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const toggleLink = screen.getByText(/already have an account/i)
      expect(toggleLink).toBeInTheDocument()
    })

    it('should show password requirements when password field has input', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const passwordInput = screen.getByLabelText(/^password$/i)
      fireEvent.change(passwordInput, { target: { value: 'test' } })

      expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument()
      expect(screen.getByText(/uppercase letter/i)).toBeInTheDocument()
      expect(screen.getByText(/lowercase letter/i)).toBeInTheDocument()
      expect(screen.getByText(/number/i)).toBeInTheDocument()
      expect(screen.getByText(/special character/i)).toBeInTheDocument()
    })
  })

  describe('form input', () => {
    it('should update name field on change', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const nameInput = screen.getByLabelText(/full name/i) as HTMLInputElement
      fireEvent.change(nameInput, { target: { value: 'John Doe' } })

      expect(nameInput.value).toBe('John Doe')
    })

    it('should update email field on change', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/^email$/i) as HTMLInputElement
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })

      expect(emailInput.value).toBe('test@example.com')
    })

    it('should update password field on change', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const passwordInput = screen.getByLabelText(/^password$/i) as HTMLInputElement
      fireEvent.change(passwordInput, { target: { value: 'Password123!' } })

      expect(passwordInput.value).toBe('Password123!')
    })

    it('should update confirm password field on change', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const confirmInput = screen.getByLabelText(/confirm password/i) as HTMLInputElement
      fireEvent.change(confirmInput, { target: { value: 'Password123!' } })

      expect(confirmInput.value).toBe('Password123!')
    })
  })

  describe('name validation', () => {
    it('should show error for name shorter than 2 characters', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'A' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/name must be at least 2 characters/i)).toBeInTheDocument()
      })
    })

    it('should show error for name with invalid characters', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John123' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/name can only contain letters/i)).toBeInTheDocument()
      })
    })

    it('should accept valid names with spaces, hyphens, and apostrophes', async () => {
      mockRegister.mockResolvedValue({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: "Mary-Jane O'Brien" } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('test@example.com', 'Password123!', "Mary-Jane O'Brien")
      })
    })
  })

  describe('email validation', () => {
    it('should show error for invalid email format', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'invalid-email' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/valid email/i)).toBeInTheDocument()
      })
    })

    it('should accept valid email addresses', async () => {
      mockRegister.mockResolvedValue({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'valid@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('valid@example.com', 'Password123!', 'John Doe')
      })
    })
  })

  describe('password validation', () => {
    it('should show error if password is too short', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Pass1!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Pass1!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks uppercase', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks lowercase', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'PASSWORD123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'PASSWORD123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks number', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if password lacks special character', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should show error if passwords do not match', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password456!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/please meet all password requirements/i)).toBeInTheDocument()
      })
    })

    it('should accept valid password meeting all requirements', async () => {
      mockRegister.mockResolvedValue({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('test@example.com', 'Password123!', 'John Doe')
      })
    })
  })

  describe('registration submission', () => {
    it('should call register with email, password, and name', async () => {
      mockRegister.mockResolvedValue({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('test@example.com', 'Password123!', 'John Doe')
      })
    })

    it('should show loading state during registration', async () => {
      mockRegister.mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 100)))

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })

      const submitButton = screen.getByRole('button', { name: /create account/i })
      fireEvent.click(submitButton)

      expect(submitButton).toBeDisabled()

      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalled()
      })
    })

    it('should redirect to dashboard on successful registration', async () => {
      mockRegister.mockResolvedValue({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(window.location.href).toBe('/')
      })
    })

    it('should display error message on registration failure', async () => {
      mockRegister.mockRejectedValue(new Error('Email already exists'))

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'existing@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/email already exists/i)).toBeInTheDocument()
      })
    })

    it('should clear error message on new submission', async () => {
      mockRegister.mockRejectedValueOnce(new Error('Email already exists'))
      mockRegister.mockResolvedValueOnce({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'existing@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/email already exists/i)).toBeInTheDocument()
      })

      // Try again with different email
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'new@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.queryByText(/email already exists/i)).not.toBeInTheDocument()
      })
    })
  })

  describe('toggle mode', () => {
    it('should call onToggleMode when clicking login link', () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const toggleLink = screen.getByText(/sign in/i)
      fireEvent.click(toggleLink)

      expect(mockOnToggleMode).toHaveBeenCalled()
    })
  })

  describe('edge cases', () => {
    it('should handle non-Error exceptions during registration', async () => {
      mockRegister.mockRejectedValue('String error')

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      await waitFor(() => {
        expect(screen.getByText(/registration failed/i)).toBeInTheDocument()
      })
    })

    it('should trim whitespace from name during validation', async () => {
      mockRegister.mockResolvedValue({})

      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/full name/i), { target: { value: '  John Doe  ' } })
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: 'test@example.com' } })
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: 'Password123!' } })
      fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: 'Password123!' } })
      fireEvent.click(screen.getByRole('button', { name: /create account/i }))

      // Should call register with untrimmed name (trimming is for validation only)
      await waitFor(() => {
        expect(mockRegister).toHaveBeenCalledWith('test@example.com', 'Password123!', '  John Doe  ')
      })
    })
  })
})
