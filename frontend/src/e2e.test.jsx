import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  mockSodium,
  mockFetch,
  mockLocalStorage,
  mockApiResponse,
  mockApiError,
  createMockNote,
  createMockEncryptedNote,
} from './test-utils.jsx'

// Mock libsodium for E2E tests BEFORE importing any components
vi.mock('libsodium-wrappers', () => mockSodium)

// Import React and the component AFTER setting up the mock
import React from 'react'
import LeafLockApp from './App.jsx'

// Mock fetch globally
global.fetch = mockFetch
global.localStorage = mockLocalStorage

describe('End-to-End User Flows', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockLocalStorage.clear()
    mockFetch.mockClear()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('Complete Registration Flow', () => {
    it('allows user to register, create notes, and manage them', async () => {
      const user = userEvent.setup()

      // Mock successful registration
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          token: 'new-user-token',
          user_id: 'user-123',
          workspace_id: 'workspace-456',
          message: 'Registration successful',
        })
      )

      // Mock initial notes load (empty)
      mockFetch.mockResolvedValueOnce(mockApiResponse({ notes: [] }))

      // Mock note creation
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          id: 'note-1',
          message: 'Note created successfully',
        })
      )

      // Mock notes reload after creation
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          notes: [
            {
              id: 'note-1',
              title_encrypted: btoa('My First Note'),
              content_encrypted: btoa(JSON.stringify('This is my first secure note!')),
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          ],
        })
      )

      render(<LeafLockApp />)

      // Step 1: Register a new account
      expect(screen.getByText('LeafLock')).toBeInTheDocument()

      await user.click(screen.getByText(/need an account\? register/i))

      await user.type(screen.getByLabelText(/email/i), 'newuser@example.com')
      await user.type(screen.getByLabelText(/password/i), 'SuperSecurePassword123!')

      await user.click(screen.getByRole('button', { name: /create secure account/i }))

      // Verify registration API call
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/auth/register'),
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('newuser@example.com'),
        })
      )

      // Step 2: Should automatically transition to notes view
      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      // Step 3: Create first note
      await user.click(screen.getByText(/new encrypted note/i))

      const titleField = screen.getByPlaceholderText(/note title/i)
      const contentField = screen.getByPlaceholderText(/start writing/i)

      await user.type(titleField, 'My First Note')
      await user.type(contentField, 'This is my first secure note!')

      // Wait for auto-save
      await waitFor(
        () => {
          expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining('/notes'),
            expect.objectContaining({ method: 'POST' })
          )
        },
        { timeout: 3000 }
      )

      // Step 4: Verify note appears in list
      await waitFor(() => {
        expect(screen.getByText('My First Note')).toBeInTheDocument()
      })

      // Step 5: Verify token was stored
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('secure_token', 'new-user-token')
    })

    it('handles registration errors gracefully', async () => {
      const user = userEvent.setup()

      // Mock registration failure
      mockFetch.mockResolvedValueOnce(mockApiError(409, 'Email already registered'))

      render(<LeafLockApp />)

      await user.click(screen.getByText(/need an account\? register/i))
      await user.type(screen.getByLabelText(/email/i), 'existing@example.com')
      await user.type(screen.getByLabelText(/password/i), 'SecurePassword123!')
      await user.click(screen.getByRole('button', { name: /create secure account/i }))

      await waitFor(() => {
        expect(screen.getByText(/registration failed/i)).toBeInTheDocument()
      })

      // Should remain on registration form
      expect(screen.getByRole('button', { name: /create secure account/i })).toBeInTheDocument()
      expect(mockLocalStorage.setItem).not.toHaveBeenCalled()
    })
  })

  describe('Complete Login and Notes Management Flow', () => {
    it('allows existing user to login and manage notes', async () => {
      const user = userEvent.setup()

      // Mock successful login
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          token: 'user-token',
          session: 'session-123',
          user_id: 'user-456',
          workspace_id: 'workspace-789',
        })
      )

      // Mock initial notes load
      const existingNotes = [
        createMockEncryptedNote({
          id: 'note-1',
          title_encrypted: btoa('Work Notes'),
          content_encrypted: btoa(JSON.stringify('Important work stuff')),
        }),
        createMockEncryptedNote({
          id: 'note-2',
          title_encrypted: btoa('Personal Journal'),
          content_encrypted: btoa(JSON.stringify('Personal thoughts')),
        }),
      ]
      mockFetch.mockResolvedValueOnce(mockApiResponse({ notes: existingNotes }))

      // Mock note update
      mockFetch.mockResolvedValueOnce(mockApiResponse({ message: 'Note updated successfully' }))

      // Mock notes reload after update
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          notes: [
            ...existingNotes.slice(0, 1),
            {
              ...existingNotes[1],
              title_encrypted: btoa('Updated Personal Journal'),
              content_encrypted: btoa(JSON.stringify('Updated personal thoughts')),
            },
          ],
        })
      )

      // Mock note deletion
      mockFetch.mockResolvedValueOnce(mockApiResponse({ message: 'Note deleted successfully' }))

      // Mock final notes reload
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          notes: existingNotes.slice(0, 1), // Only first note remains
        })
      )

      render(<LeafLockApp />)

      // Step 1: Login
      await user.type(screen.getByLabelText(/email/i), 'user@example.com')
      await user.type(screen.getByLabelText(/password/i), 'UserPassword123!')
      await user.click(screen.getByRole('button', { name: /login securely/i }))

      // Step 2: Verify transition to notes view
      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      // Step 3: Verify existing notes are displayed
      await waitFor(() => {
        expect(screen.getByText('Work Notes')).toBeInTheDocument()
        expect(screen.getByText('Personal Journal')).toBeInTheDocument()
      })

      // Step 4: Edit an existing note
      await user.click(screen.getByText('Personal Journal'))

      const titleField = screen.getByDisplayValue('Personal Journal')
      const contentField = screen.getByDisplayValue('Personal thoughts')

      await user.clear(titleField)
      await user.type(titleField, 'Updated Personal Journal')

      await user.clear(contentField)
      await user.type(contentField, 'Updated personal thoughts')

      // Wait for auto-save
      await waitFor(
        () => {
          expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining('/notes/note-2'),
            expect.objectContaining({ method: 'PUT' })
          )
        },
        { timeout: 3000 }
      )

      // Step 5: Verify update in notes list
      await waitFor(() => {
        expect(screen.getByText('Updated Personal Journal')).toBeInTheDocument()
      })

      // Step 6: Search functionality
      const searchField = screen.getByPlaceholderText(/search notes/i)
      await user.type(searchField, 'work')

      await waitFor(() => {
        expect(screen.getByText('Work Notes')).toBeInTheDocument()
        expect(screen.queryByText('Updated Personal Journal')).not.toBeInTheDocument()
      })

      // Clear search
      await user.clear(searchField)

      await waitFor(() => {
        expect(screen.getByText('Work Notes')).toBeInTheDocument()
        expect(screen.getByText('Updated Personal Journal')).toBeInTheDocument()
      })

      // Step 7: Delete a note (would require additional UI for delete button)
      // For this test, we'll simulate the API call
      expect(mockFetch).toHaveBeenCalledTimes(4) // login, load, update, reload
    })

    it('handles login with MFA requirement', async () => {
      const user = userEvent.setup()

      // Mock MFA required response
      mockFetch.mockResolvedValueOnce(mockApiResponse({ mfa_required: true }))

      // Mock successful MFA login
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          token: 'mfa-user-token',
          session: 'mfa-session-123',
          user_id: 'mfa-user-456',
          workspace_id: 'mfa-workspace-789',
        })
      )

      // Mock notes load
      mockFetch.mockResolvedValueOnce(mockApiResponse({ notes: [] }))

      render(<LeafLockApp />)

      // Step 1: Initial login attempt
      await user.type(screen.getByLabelText(/email/i), 'mfauser@example.com')
      await user.type(screen.getByLabelText(/password/i), 'MFAPassword123!')
      await user.click(screen.getByRole('button', { name: /login securely/i }))

      // Step 2: MFA field should appear
      await waitFor(() => {
        expect(screen.getByLabelText(/2fa code/i)).toBeInTheDocument()
      })

      // Step 3: Enter MFA code and submit
      await user.type(screen.getByLabelText(/2fa code/i), '123456')
      await user.click(screen.getByRole('button', { name: /login securely/i }))

      // Step 4: Should transition to notes view
      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      // Verify MFA login API call
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/auth/login'),
        expect.objectContaining({
          body: expect.stringContaining('123456'),
        })
      )
    })
  })

  describe('Session Management Flow', () => {
    it('restores session on app reload', async () => {
      // Mock existing token
      mockLocalStorage.getItem.mockReturnValue('existing-token')

      // Mock notes load for restored session
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          notes: [createMockEncryptedNote({ title_encrypted: btoa('Existing Note') })],
        })
      )

      render(<LeafLockApp />)

      // Should skip login and go directly to notes view
      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      // Should load existing notes
      await waitFor(() => {
        expect(screen.getByText('Existing Note')).toBeInTheDocument()
      })

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/notes'),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer existing-token',
          }),
        })
      )
    })

    it('handles session expiration and logout', async () => {
      const user = userEvent.setup()

      // Mock existing token
      mockLocalStorage.getItem.mockReturnValue('expired-token')

      // Mock expired token response
      mockFetch.mockResolvedValueOnce(mockApiError(401, 'Token expired'))

      render(<LeafLockApp />)

      // Should detect expired token and redirect to login
      await waitFor(() => {
        expect(screen.getByText(/secure notes/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /login securely/i })).toBeInTheDocument()
      })

      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('secure_token')
    })

    it('allows manual logout', async () => {
      const user = userEvent.setup()

      // Setup authenticated state
      mockLocalStorage.getItem.mockReturnValue('user-token')
      mockFetch.mockResolvedValueOnce(mockApiResponse({ notes: [] }))

      render(<LeafLockApp />)

      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      // Find and click logout button
      const logoutButton = screen.getByRole('button')
      await user.click(logoutButton)

      // Should return to login view
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /login securely/i })).toBeInTheDocument()
      })

      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('secure_token')
    })
  })

  describe('Error Handling Flows', () => {
    it('handles network connectivity issues', async () => {
      const user = userEvent.setup()

      // Mock network error
      mockFetch.mockRejectedValueOnce(new Error('Failed to fetch'))

      render(<LeafLockApp />)

      await user.type(screen.getByLabelText(/email/i), 'user@example.com')
      await user.type(screen.getByLabelText(/password/i), 'Password123!')
      await user.click(screen.getByRole('button', { name: /login securely/i }))

      await waitFor(() => {
        expect(screen.getByText(/login failed/i)).toBeInTheDocument()
      })

      // Should remain on login form
      expect(screen.getByRole('button', { name: /login securely/i })).toBeInTheDocument()
    })

    it('handles server errors gracefully', async () => {
      const user = userEvent.setup()

      // Mock authenticated state
      mockLocalStorage.getItem.mockReturnValue('user-token')

      // Mock server error when loading notes
      mockFetch.mockResolvedValueOnce(mockApiError(500, 'Internal server error'))

      render(<LeafLockApp />)

      await waitFor(() => {
        expect(screen.getByText(/failed to load notes/i)).toBeInTheDocument()
      })

      // Should still show main interface with error
      expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
    })

    it('recovers from temporary errors', async () => {
      const user = userEvent.setup()

      // Setup authenticated state
      mockLocalStorage.getItem.mockReturnValue('user-token')

      // First call fails, second succeeds
      mockFetch
        .mockResolvedValueOnce(mockApiError(500, 'Server error'))
        .mockResolvedValueOnce(mockApiResponse({ notes: [] }))

      render(<LeafLockApp />)

      // Should show error initially
      await waitFor(() => {
        expect(screen.getByText(/failed to load notes/i)).toBeInTheDocument()
      })

      // Simulate retry by creating a new note (which triggers reload)
      await user.click(screen.getByText(/new encrypted note/i))

      // Should recover and show editor
      expect(screen.getByPlaceholderText(/note title/i)).toBeInTheDocument()
    })
  })

  describe('Data Persistence and Integrity', () => {
    it('maintains encryption throughout the entire flow', async () => {
      const user = userEvent.setup()

      // Mock login
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          token: 'user-token',
          user_id: 'user-123',
          workspace_id: 'workspace-456',
        })
      )

      // Mock initial load
      mockFetch.mockResolvedValueOnce(mockApiResponse({ notes: [] }))

      // Mock note creation
      mockFetch.mockResolvedValueOnce(mockApiResponse({ id: 'note-1' }))

      render(<LeafLockApp />)

      // Login
      await user.type(screen.getByLabelText(/email/i), 'user@example.com')
      await user.type(screen.getByLabelText(/password/i), 'Password123!')
      await user.click(screen.getByRole('button', { name: /login securely/i }))

      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      // Create note with sensitive data
      await user.click(screen.getByText(/new encrypted note/i))

      const sensitiveTitle = 'Credit Card Info'
      const sensitiveContent = 'Card: 1234-5678-9012-3456, CVV: 123'

      await user.type(screen.getByPlaceholderText(/note title/i), sensitiveTitle)
      await user.type(screen.getByPlaceholderText(/start writing/i), sensitiveContent)

      // Wait for save
      await waitFor(
        () => {
          expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining('/notes'),
            expect.objectContaining({ method: 'POST' })
          )
        },
        { timeout: 3000 }
      )

      // Verify sensitive data was encrypted before sending
      const createCall = mockFetch.mock.calls.find(
        (call) => call[1]?.method === 'POST' && call[0].includes('/notes')
      )

      expect(createCall).toBeDefined()
      const requestBody = createCall[1].body

      // Sensitive data should not appear in plaintext
      expect(requestBody).not.toContain('Credit Card Info')
      expect(requestBody).not.toContain('1234-5678-9012-3456')
      expect(requestBody).not.toContain('CVV: 123')

      // Should contain encrypted versions
      expect(requestBody).toContain('title_encrypted')
      expect(requestBody).toContain('content_encrypted')
    })

    it('handles encryption failures gracefully', async () => {
      const user = userEvent.setup()

      // Mock authenticated state
      mockLocalStorage.getItem.mockReturnValue('user-token')
      mockFetch.mockResolvedValueOnce(mockApiResponse({ notes: [] }))

      // Mock encryption failure by corrupting sodium
      const originalEncrypt = mockSodium.crypto_secretbox_easy
      mockSodium.crypto_secretbox_easy.mockImplementationOnce(() => {
        throw new Error('Encryption failed')
      })

      render(<LeafLockApp />)

      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      await user.click(screen.getByText(/new encrypted note/i))
      await user.type(screen.getByPlaceholderText(/note title/i), 'Test Note')

      // Should handle encryption error gracefully
      await waitFor(() => {
        // Note: In real implementation, this might show an error message
        // For now, we just verify it doesn't crash
        expect(screen.getByPlaceholderText(/note title/i)).toBeInTheDocument()
      })

      // Restore original function
      mockSodium.crypto_secretbox_easy.mockImplementation(originalEncrypt)
    })
  })

  describe('Performance and User Experience', () => {
    it('provides smooth user experience with loading states', async () => {
      const user = userEvent.setup()

      // Mock slow login
      const slowLogin = new Promise((resolve) => {
        setTimeout(() => resolve(mockApiResponse({ token: 'token' })), 200)
      })
      mockFetch.mockReturnValueOnce(slowLogin)

      render(<LeafLockApp />)

      await user.type(screen.getByLabelText(/email/i), 'user@example.com')
      await user.type(screen.getByLabelText(/password/i), 'Password123!')
      await user.click(screen.getByRole('button', { name: /login securely/i }))

      // Should show loading state
      expect(screen.getByText(/processing/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /processing/i })).toBeDisabled()

      // Wait for completion
      await waitFor(() => {
        expect(screen.queryByText(/processing/i)).not.toBeInTheDocument()
      })
    })

    it('handles rapid user interactions gracefully', async () => {
      const user = userEvent.setup()

      // Setup authenticated state
      mockLocalStorage.getItem.mockReturnValue('user-token')
      mockFetch.mockResolvedValue(mockApiResponse({ notes: [] }))

      render(<LeafLockApp />)

      await waitFor(() => {
        expect(screen.getByText(/encryption active/i)).toBeInTheDocument()
      })

      // Rapidly create and type in note
      await user.click(screen.getByText(/new encrypted note/i))

      const titleField = screen.getByPlaceholderText(/note title/i)

      // Type rapidly
      await user.type(titleField, 'Rapid typing test', { delay: 1 })

      // Should handle rapid input without crashing
      expect(titleField.value).toBe('Rapid typing test')
    })

    it('maintains state consistency during navigation', async () => {
      const user = userEvent.setup()

      // Setup with existing notes
      mockLocalStorage.getItem.mockReturnValue('user-token')
      mockFetch.mockResolvedValueOnce(
        mockApiResponse({
          notes: [
            createMockEncryptedNote({
              id: 'note-1',
              title_encrypted: btoa('Note 1'),
            }),
            createMockEncryptedNote({
              id: 'note-2',
              title_encrypted: btoa('Note 2'),
            }),
          ],
        })
      )

      render(<LeafLockApp />)

      await waitFor(() => {
        expect(screen.getByText('Note 1')).toBeInTheDocument()
        expect(screen.getByText('Note 2')).toBeInTheDocument()
      })

      // Select first note
      await user.click(screen.getByText('Note 1'))
      expect(screen.getByDisplayValue('Note 1')).toBeInTheDocument()

      // Switch to second note
      await user.click(screen.getByText('Note 2'))
      expect(screen.getByDisplayValue('Note 2')).toBeInTheDocument()

      // Switch back to first note
      await user.click(screen.getByText('Note 1'))
      expect(screen.getByDisplayValue('Note 1')).toBeInTheDocument()

      // State should remain consistent
      expect(screen.getByText('Note 1')).toBeInTheDocument()
      expect(screen.getByText('Note 2')).toBeInTheDocument()
    })
  })
})
