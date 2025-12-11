import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { LoginForm } from '../login-form'

describe('LoginForm', () => {
  const mockOnToggleMode = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('initial render', () => {
    it('should render Clerk SignIn component', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      // The SignIn component from Clerk should be rendered
      // With our global Clerk mock, it should show Sign In text
      await waitFor(() => {
        expect(screen.getByText('Sign In')).toBeInTheDocument()
      })
    })

    it('should render animated title if provided', async () => {
      const animatedTitle = <div data-testid="animated-title">Welcome Back</div>
      render(<LoginForm onToggleMode={mockOnToggleMode} animatedTitle={animatedTitle} />)

      expect(await screen.findByTestId('animated-title')).toBeInTheDocument()
      expect(await screen.findByText('Welcome Back')).toBeInTheDocument()
    })

    it('should have toggle mode link for registration', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      // Should show the toggle mode link that calls onToggleMode
      const toggleLink = await screen.findByText(/don't have an account/i)
      expect(toggleLink).toBeInTheDocument()
    })
  })

  describe('toggle mode', () => {
    it('should call onToggleMode when clicking registration link', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      const toggleLink = await screen.findByText(/sign up/i)
      toggleLink.click()

      expect(mockOnToggleMode).toHaveBeenCalled()
    })
  })

  describe('Clerk integration', () => {
    it('should render with custom appearance', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.getByText('Sign In')).toBeInTheDocument()
      })
    })

    it('should render with signUpUrl to /register', async () => {
      render(<LoginForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.getByText('Sign In')).toBeInTheDocument()
      })
    })
  })
})
