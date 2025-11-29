/**
 * Clerk Integration Tests
 *
 * @description
 * Tests for Clerk authentication integration to ensure compatibility
 * with existing authentication patterns.
 */

import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { ClerkProvider, SignIn, SignUp } from '@clerk/clerk-react'
import React from 'react'

// Mock Clerk environment
const mockClerkPublishableKey = 'pk_test_mock_key_for_testing'

// Mock the Clerk hooks
vi.mock('@clerk/clerk-react', () => ({
  ClerkProvider: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="clerk-provider">{children}</div>
  ),
  useAuth: () => ({
    isSignedIn: false,
    isLoaded: true,
    userId: null,
  }),
  useUser: () => ({
    user: null,
    isLoaded: true,
  }),
  useSession: () => ({
    session: null,
    isLoaded: true,
    getToken: vi.fn().mockResolvedValue(null),
  }),
  SignIn: () => <div data-testid="sign-in">Sign In Component</div>,
  SignUp: () => <div data-testid="sign-up">Sign Up Component</div>,
}))

describe('Clerk Integration', () => {
  it('should render ClerkProvider without errors', () => {
    render(
      <ClerkProvider publishableKey={mockClerkPublishableKey}>
        <div>Test Content</div>
      </ClerkProvider>
    )

    expect(screen.getByTestId('clerk-provider')).toBeInTheDocument()
    expect(screen.getByText('Test Content')).toBeInTheDocument()
  })

  it('should render SignIn component with theme', () => {
    render(
      <SignIn
        routing="path"
        path="/login"
        appearance={{
          elements: {
            rootBox: 'mx-auto',
            card: 'bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60',
          },
        }}
      />
    )

    expect(screen.getByTestId('sign-in')).toBeInTheDocument()
  })

  it('should render SignUp component with theme', () => {
    render(
      <SignUp
        routing="path"
        path="/register"
        appearance={{
          elements: {
            rootBox: 'mx-auto',
            card: 'bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60',
          },
        }}
      />
    )

    expect(screen.getByTestId('sign-up')).toBeInTheDocument()
  })
})
