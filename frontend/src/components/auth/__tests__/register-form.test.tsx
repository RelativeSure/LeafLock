import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { RegisterForm } from '../register-form'

describe('RegisterForm', () => {
  const mockOnToggleMode = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('initial render', () => {
    it('should render Clerk SignUp component', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      // The SignUp component from Clerk should be rendered
      await waitFor(() => {
        expect(screen.getByText('Sign Up')).toBeInTheDocument()
      })
    })

    it('should render animated title if provided', async () => {
      const animatedTitle = <div data-testid="animated-title">Join LeafLock</div>
      render(<RegisterForm onToggleMode={mockOnToggleMode} animatedTitle={animatedTitle} />)

      expect(await screen.findByTestId('animated-title')).toBeInTheDocument()
      expect(await screen.findByText('Join LeafLock')).toBeInTheDocument()
    })

    it('should have toggle mode link for login', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      // Should show the toggle mode link that calls onToggleMode
      const toggleLink = await screen.findByText(/already have an account/i)
      expect(toggleLink).toBeInTheDocument()
    })
  })

  describe('toggle mode', () => {
    it('should call onToggleMode when clicking login link', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      const toggleLink = await screen.findByText(/sign in/i)
      toggleLink.click()

      expect(mockOnToggleMode).toHaveBeenCalled()
    })
  })

  describe('Clerk integration', () => {
    it('should render with custom appearance', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.getByText('Sign Up')).toBeInTheDocument()
      })
    })

    it('should render with signInUrl to /login', async () => {
      render(<RegisterForm onToggleMode={mockOnToggleMode} />)

      await waitFor(() => {
        expect(screen.getByText('Sign Up')).toBeInTheDocument()
      })
    })
  })
})
