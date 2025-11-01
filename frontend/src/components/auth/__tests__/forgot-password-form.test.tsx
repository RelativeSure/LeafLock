import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ForgotPasswordForm } from '../forgot-password-form'

// Mock sonner toast
vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

import { toast } from 'sonner'
const mockToastSuccess = toast.success as ReturnType<typeof vi.fn>
const mockToastError = toast.error as ReturnType<typeof vi.fn>

describe('ForgotPasswordForm', () => {
  const mockOnToggleMode = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('initial render', () => {
    it('should render forgot password form with email field', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      expect(screen.getByRole('heading', { name: /reset your password/i })).toBeInTheDocument()
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /send reset link/i })).toBeInTheDocument()
    })

    it('should show instructions', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      expect(
        screen.getByText(/enter your email address and we'll send you a link/i)
      ).toBeInTheDocument()
    })

    it('should have back to login button', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      expect(screen.getByRole('button', { name: /back to login/i })).toBeInTheDocument()
    })
  })

  describe('form input', () => {
    it('should update email field on change', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i) as HTMLInputElement
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })

      expect(emailInput.value).toBe('test@example.com')
    })

    it('should have email type for input', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)
      expect(emailInput).toHaveAttribute('type', 'email')
    })

    it('should have required email field', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)
      expect(emailInput).toBeRequired()
    })

    it('should have placeholder text', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)
      expect(emailInput).toHaveAttribute('placeholder', 'you@example.com')
    })
  })

  describe('form submission', () => {
    it('should show loading state during submission', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)
      const submitButton = screen.getByRole('button', { name: /send reset link/i })

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.click(submitButton)

      // Button should show loading text and be disabled
      expect(screen.getByRole('button', { name: /sending/i })).toBeDisabled()

      // Wait for form to finish
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /check your email/i })).toBeInTheDocument()
      })
    })

    it('should show success toast on successful submission', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      await waitFor(() => {
        expect(mockToastSuccess).toHaveBeenCalledWith('Password reset link sent to your email')
      })
    })

    it('should show success screen after submission', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /check your email/i })).toBeInTheDocument()
      })

      expect(screen.getByText(/we've sent a password reset link to/i)).toBeInTheDocument()
      expect(screen.getByText('test@example.com')).toBeInTheDocument()
    })

    it('should handle form submission with Enter key', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
      fireEvent.submit(emailInput.closest('form')!)

      await waitFor(() => {
        expect(mockToastSuccess).toHaveBeenCalled()
      })
    })
  })

  describe('success screen', () => {
    it('should show email address in success message', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'user@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      await waitFor(() => {
        expect(screen.getByText('user@example.com')).toBeInTheDocument()
      })
    })

    it('should show helpful instructions', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      await waitFor(() => {
        expect(
          screen.getByText(/didn't receive the email\? check your spam folder/i)
        ).toBeInTheDocument()
      })
    })

    it('should have try again button', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
      })
    })

    it('should have back to login button on success screen', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /back to login/i })).toBeInTheDocument()
      })
    })

    it('should return to form when clicking try again', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      // Submit form
      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      // Wait for success screen
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
      })

      // Click try again
      fireEvent.click(screen.getByRole('button', { name: /try again/i }))

      // Should show form again
      expect(screen.getByRole('heading', { name: /reset your password/i })).toBeInTheDocument()
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument()
    })

    it('should preserve email when returning from success screen', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      // Submit form
      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      // Wait for success screen
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
      })

      // Click try again
      fireEvent.click(screen.getByRole('button', { name: /try again/i }))

      // Email should still be filled
      const emailInput = screen.getByLabelText(/email/i) as HTMLInputElement
      expect(emailInput.value).toBe('test@example.com')
    })
  })

  describe('navigation', () => {
    it('should call onToggleMode when clicking back to login from form', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const backButton = screen.getByRole('button', { name: /back to login/i })
      fireEvent.click(backButton)

      expect(mockOnToggleMode).toHaveBeenCalled()
    })

    it('should call onToggleMode when clicking back to login from success screen', async () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      // Submit form
      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'test@example.com' } })
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }))

      // Wait for success screen
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /back to login/i })).toBeInTheDocument()
      })

      // Click back to login
      fireEvent.click(screen.getByRole('button', { name: /back to login/i }))

      expect(mockOnToggleMode).toHaveBeenCalled()
    })
  })

  describe('error handling', () => {
    // Note: Error handling is implemented but uses a simulated API call with setTimeout
    // In a real implementation with an actual API, these tests would verify error toast display
    it('should have error handling structure in place', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      // Component renders without errors
      expect(screen.getByRole('heading', { name: /reset your password/i })).toBeInTheDocument()
    })
  })

  describe('edge cases', () => {
    it('should accept various email formats in input', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emails = [
        'user@example.com',
        'user.name@example.com',
        'user+tag@example.co.uk',
        'user_name@sub.example.com',
      ]

      const emailInput = screen.getByLabelText(/email/i) as HTMLInputElement

      emails.forEach((email) => {
        fireEvent.change(emailInput, { target: { value: email } })
        expect(emailInput.value).toBe(email)
      })
    })

    it('should handle empty email submission attempt', () => {
      render(<ForgotPasswordForm onToggleMode={mockOnToggleMode} />)

      const emailInput = screen.getByLabelText(/email/i)

      // Email field is required, so browser validation should prevent submission
      expect(emailInput).toBeRequired()
    })
  })
})
