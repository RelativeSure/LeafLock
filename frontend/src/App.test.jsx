import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  mockSodium,
  mockFetch,
  mockLocalStorage,
  mockCryptoSubtle,
  mockApiResponse,
  mockApiError,
  createMockNote,
  typeIntoField,
  clickButton,
  waitForLoading,
  MockCryptoService,
  checkForXSS
} from './test-utils.jsx';

// Mock libsodium-wrappers BEFORE importing any components
vi.mock('libsodium-wrappers', () => mockSodium);

// Import React and the component AFTER setting up the mock
import React from 'react';
import SecureNotesApp from './App.jsx';

describe('SecureNotesApp', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLocalStorage.clear();
    mockFetch.mockClear();
    global.__LEAFLOCK_REGISTRATION__ = true;
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Authentication Flow', () => {
    it('renders login form by default', () => {
      render(<SecureNotesApp />);
      
      expect(screen.getByText('LeafLock')).toBeInTheDocument();
      expect(screen.getByText(/End-to-end encrypted/)).toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /login securely/i })).toBeInTheDocument();
    });

    it('switches between login and register modes', async () => {
      const user = userEvent.setup();
      render(<SecureNotesApp />);
      
      // Initially shows login
      expect(screen.getByRole('button', { name: /login securely/i })).toBeInTheDocument();
      
      // Switch to register
      await user.click(screen.getByText(/need an account\? register/i));
      expect(screen.getByRole('button', { name: /create secure account/i })).toBeInTheDocument();
      expect(screen.getByText(/use 12\+ characters/i)).toBeInTheDocument();
      
      // Switch back to login
      await user.click(screen.getByText(/already have an account\? login/i));
      expect(screen.getByRole('button', { name: /login securely/i })).toBeInTheDocument();
    });

    it('hides registration toggle when registration is disabled', () => {
      global.__LEAFLOCK_REGISTRATION__ = false;
      render(<SecureNotesApp />);

      expect(screen.queryByText(/need an account\? register/i)).not.toBeInTheDocument();
      expect(screen.getByText(/registration is currently disabled/i)).toBeInTheDocument();
    });

    it('shows password strength indicator during registration', async () => {
      const user = userEvent.setup();
      render(<SecureNotesApp />);
      
      // Switch to register mode
      await user.click(screen.getByText(/need an account\? register/i));
      
      const passwordField = screen.getByLabelText(/password/i);
      
      // Test weak password
      await user.type(passwordField, 'weak');
      expect(screen.getByText(/use 12\+ characters/i)).toBeInTheDocument();
      
      // Test strong password
      await user.clear(passwordField);
      await user.type(passwordField, 'StrongPassword123!@#');
      
      // Should show strength indicator bars
      const strengthBars = screen.getAllByRole('generic').filter(el => 
        el.className.includes('bg-green-500') || 
        el.className.includes('bg-yellow-500') || 
        el.className.includes('bg-red-500')
      );
      expect(strengthBars.length).toBeGreaterThan(0);
    });

    it('handles successful registration', async () => {
      const user = userEvent.setup();
      
      mockFetch.mockResolvedValue(mockApiResponse({
        token: 'test-token',
        user_id: 'test-user-id',
        workspace_id: 'test-workspace-id',
        message: 'Registration successful'
      }));
      
      render(<SecureNotesApp />);
      
      // Switch to register
      await user.click(screen.getByText(/need an account\? register/i));
      
      // Fill form
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'SuperSecurePassword123!');
      
      // Submit
      await user.click(screen.getByRole('button', { name: /create secure account/i }));
      
      // Should call API
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/auth/register'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          }),
          body: expect.stringContaining('test@example.com')
        })
      );
      
      // Should store token
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('secure_token', 'test-token');
    });

    it('handles registration with weak password', async () => {
      const user = userEvent.setup();
      render(<SecureNotesApp />);
      
      // Switch to register
      await user.click(screen.getByText(/need an account\? register/i));
      
      // Fill form with weak password
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'weak');
      
      // Submit
      await user.click(screen.getByRole('button', { name: /create secure account/i }));
      
      // Should show error
      await waitFor(() => {
        expect(screen.getByText(/password must be at least 12 characters/i)).toBeInTheDocument();
      });
      
      // Should not call API
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('handles successful login', async () => {
      const user = userEvent.setup();
      
      mockFetch.mockResolvedValue(mockApiResponse({
        token: 'test-token',
        session: 'test-session',
        user_id: 'test-user-id',
        workspace_id: 'test-workspace-id'
      }));
      
      render(<SecureNotesApp />);
      
      // Fill login form
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'TestPassword123!');
      
      // Submit
      await user.click(screen.getByRole('button', { name: /login securely/i }));
      
      // Should call API
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/auth/login'),
        expect.objectContaining({
          method: 'POST'
        })
      );
    });

    it('handles MFA requirement', async () => {
      const user = userEvent.setup();
      
      mockFetch.mockResolvedValue(mockApiResponse({
        mfa_required: true
      }));
      
      render(<SecureNotesApp />);
      
      // Fill and submit login form
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'TestPassword123!');
      await user.click(screen.getByRole('button', { name: /login securely/i }));
      
      // Should show MFA field
      await waitFor(() => {
        expect(screen.getByLabelText(/2fa code/i)).toBeInTheDocument();
      });
      
      // Fill MFA code
      await user.type(screen.getByLabelText(/2fa code/i), '123456');
      await user.click(screen.getByRole('button', { name: /login securely/i }));
      
      // Should call API with MFA code
      expect(mockFetch).toHaveBeenLastCalledWith(
        expect.stringContaining('/auth/login'),
        expect.objectContaining({
          body: expect.stringContaining('123456')
        })
      );
    });

    it('handles login failure', async () => {
      const user = userEvent.setup();
      
      mockFetch.mockResolvedValue(mockApiError(401, 'Invalid credentials'));
      
      render(<SecureNotesApp />);
      
      // Fill and submit login form
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'WrongPassword');
      await user.click(screen.getByRole('button', { name: /login securely/i }));
      
      // Should show error
      await waitFor(() => {
        expect(screen.getByText(/login failed/i)).toBeInTheDocument();
      });
    });

    it('handles account lockout', async () => {
      const user = userEvent.setup();
      
      mockFetch.mockResolvedValue(mockApiError(403, 'Account locked. Try again later.'));
      
      render(<SecureNotesApp />);
      
      // Fill and submit login form
      await user.type(screen.getByLabelText(/email/i), 'locked@example.com');
      await user.type(screen.getByLabelText(/password/i), 'TestPassword123!');
      await user.click(screen.getByRole('button', { name: /login securely/i }));
      
      // Should show lockout message
      await waitFor(() => {
        expect(screen.getByText(/account locked/i)).toBeInTheDocument();
      });
    });

    it('restores session from localStorage', () => {
      mockLocalStorage.getItem.mockReturnValue('existing-token');
      mockFetch.mockResolvedValue(mockApiResponse({ notes: [] }));
      
      render(<SecureNotesApp />);
      
      // Should skip login screen and load notes
      expect(screen.queryByText(/secure notes/i)).not.toBeInTheDocument();
    });
  });

  describe('Notes Management', () => {
    beforeEach(() => {
      // Mock authenticated state
      mockLocalStorage.getItem.mockReturnValue('test-token');
    });

    it('displays empty state when no notes', () => {
      mockFetch.mockResolvedValue(mockApiResponse({ notes: [] }));
      
      render(<SecureNotesApp />);
      
      expect(screen.getByText(/select a note or create a new one/i)).toBeInTheDocument();
      expect(screen.getByText(/new encrypted note/i)).toBeInTheDocument();
    });

    it('displays notes list', async () => {
      const mockNotes = [
        createMockNote({ id: '1', title: 'Note 1', content: 'Content 1' }),
        createMockNote({ id: '2', title: 'Note 2', content: 'Content 2' })
      ];
      
      mockFetch.mockResolvedValue(mockApiResponse({ notes: mockNotes }));
      
      render(<SecureNotesApp />);
      
      await waitFor(() => {
        expect(screen.getByText('Note 1')).toBeInTheDocument();
        expect(screen.getByText('Note 2')).toBeInTheDocument();
      });
    });

    it('handles notes loading error', async () => {
      mockFetch.mockResolvedValue(mockApiError(500, 'Server error'));
      
      render(<SecureNotesApp />);
      
      await waitFor(() => {
        expect(screen.getByText(/failed to load notes/i)).toBeInTheDocument();
      });
    });

    it('creates new note', async () => {
      const user = userEvent.setup();
      
      mockFetch
        .mockResolvedValueOnce(mockApiResponse({ notes: [] })) // Initial load
        .mockResolvedValueOnce(mockApiResponse({ id: 'new-note-id', message: 'Note created successfully' })) // Create
        .mockResolvedValueOnce(mockApiResponse({ notes: [createMockNote({ id: 'new-note-id' })] })); // Reload
      
      render(<SecureNotesApp />);
      
      // Click new note button
      await user.click(screen.getByText(/new encrypted note/i));
      
      // Should show editor
      expect(screen.getByPlaceholderText(/note title/i)).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/start writing/i)).toBeInTheDocument();
    });

    it('searches notes', async () => {
      const user = userEvent.setup();
      const mockNotes = [
        createMockNote({ id: '1', title: 'JavaScript Notes', content: 'Programming content' }),
        createMockNote({ id: '2', title: 'Recipe Ideas', content: 'Cooking content' })
      ];
      
      mockFetch.mockResolvedValue(mockApiResponse({ notes: mockNotes }));
      
      render(<SecureNotesApp />);
      
      await waitFor(() => {
        expect(screen.getByText('JavaScript Notes')).toBeInTheDocument();
        expect(screen.getByText('Recipe Ideas')).toBeInTheDocument();
      });
      
      // Search for "javascript"
      const searchField = screen.getByPlaceholderText(/search notes/i);
      await user.type(searchField, 'javascript');
      
      // Should filter results
      await waitFor(() => {
        expect(screen.getByText('JavaScript Notes')).toBeInTheDocument();
        expect(screen.queryByText('Recipe Ideas')).not.toBeInTheDocument();
      });
    });

    it('selects and displays note', async () => {
      const user = userEvent.setup();
      const mockNotes = [
        createMockNote({ id: '1', title: 'Test Note', content: 'Test content' })
      ];
      
      mockFetch.mockResolvedValue(mockApiResponse({ notes: mockNotes }));
      
      render(<SecureNotesApp />);
      
      await waitFor(() => {
        expect(screen.getByText('Test Note')).toBeInTheDocument();
      });
      
      // Click on note
      await user.click(screen.getByText('Test Note'));
      
      // Should show note editor with content
      expect(screen.getByDisplayValue('Test Note')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Test content')).toBeInTheDocument();
    });

    it('auto-saves note changes', async () => {
      const user = userEvent.setup();
      
      mockFetch
        .mockResolvedValueOnce(mockApiResponse({ notes: [] }))
        .mockResolvedValueOnce(mockApiResponse({ id: 'test-note', message: 'Note created' }))
        .mockResolvedValueOnce(mockApiResponse({ notes: [] }));
      
      render(<SecureNotesApp />);
      
      // Create new note
      await user.click(screen.getByText(/new encrypted note/i));
      
      // Type in title
      const titleField = screen.getByPlaceholderText(/note title/i);
      await user.type(titleField, 'Auto-save Test');
      
      // Should trigger auto-save after debounce
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/notes'),
          expect.objectContaining({
            method: 'POST'
          })
        );
      }, { timeout: 3000 });
    });
  });

  describe('Encryption Status', () => {
    beforeEach(() => {
      mockLocalStorage.getItem.mockReturnValue('test-token');
      mockFetch.mockResolvedValue(mockApiResponse({ notes: [] }));
    });

    it('shows encryption status indicator', () => {
      render(<SecureNotesApp />);
      
      // Should show encryption active indicator
      expect(screen.getByText(/encryption active/i)).toBeInTheDocument();
    });

    it('shows encrypted indicator in note editor', async () => {
      const user = userEvent.setup();
      
      render(<SecureNotesApp />);
      
      // Create new note
      await user.click(screen.getByText(/new encrypted note/i));
      
      // Should show encrypted indicator
      expect(screen.getByText(/encrypted/i)).toBeInTheDocument();
    });
  });

  describe('Logout Functionality', () => {
    beforeEach(() => {
      mockLocalStorage.getItem.mockReturnValue('test-token');
      mockFetch.mockResolvedValue(mockApiResponse({ notes: [] }));
    });

    it('logs out user', async () => {
      const user = userEvent.setup();
      
      render(<SecureNotesApp />);
      
      // Click logout button
      const logoutButton = screen.getByRole('button');
      await user.click(logoutButton);
      
      // Should clear token and return to login
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('secure_token');
      expect(screen.getByText(/login securely/i)).toBeInTheDocument();
    });
  });

  describe('Loading States', () => {
    it('shows loading during authentication', async () => {
      const user = userEvent.setup();
      
      // Mock slow API response
      const slowPromise = new Promise(resolve => {
        setTimeout(() => resolve(mockApiResponse({ token: 'test-token' })), 100);
      });
      mockFetch.mockReturnValue(slowPromise);
      
      render(<SecureNotesApp />);
      
      // Fill and submit login form
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'TestPassword123!');
      await user.click(screen.getByRole('button', { name: /login securely/i }));
      
      // Should show processing state
      expect(screen.getByText(/processing/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /processing/i })).toBeDisabled();
    });

    it('shows saving indicator', async () => {
      const user = userEvent.setup();
      
      // Mock authenticated state
      mockLocalStorage.getItem.mockReturnValue('test-token');
      
      // Mock slow save
      const slowSave = new Promise(resolve => {
        setTimeout(() => resolve(mockApiResponse({ id: 'test-note' })), 100);
      });
      
      mockFetch
        .mockResolvedValueOnce(mockApiResponse({ notes: [] }))
        .mockReturnValueOnce(slowSave);
      
      render(<SecureNotesApp />);
      
      // Create new note
      await user.click(screen.getByText(/new encrypted note/i));
      
      // Start typing
      await user.type(screen.getByPlaceholderText(/note title/i), 'Test');
      
      // Should show saving indicator
      await waitFor(() => {
        expect(screen.getByText(/saving/i)).toBeInTheDocument();
      });
    });
  });

  describe('Security Tests', () => {
    it('prevents XSS in note content', () => {
      const maliciousContent = '<script>alert("xss")</script>';
      const mockNotes = [
        createMockNote({ id: '1', title: maliciousContent, content: maliciousContent })
      ];
      
      mockLocalStorage.getItem.mockReturnValue('test-token');
      mockFetch.mockResolvedValue(mockApiResponse({ notes: mockNotes }));
      
      render(<SecureNotesApp />);
      
      // Verify no script tags in DOM
      expect(document.body.innerHTML).not.toContain('<script>');
      expect(document.body.innerHTML).not.toContain('alert("xss")');
    });

    it('sanitizes user input in search', async () => {
      const user = userEvent.setup();
      
      mockLocalStorage.getItem.mockReturnValue('test-token');
      mockFetch.mockResolvedValue(mockApiResponse({ notes: [] }));
      
      render(<SecureNotesApp />);
      
      const searchField = screen.getByPlaceholderText(/search notes/i);
      await user.type(searchField, '<img src=x onerror=alert("xss")>');
      
      // Should not execute script
      expect(document.body.innerHTML).not.toContain('onerror=');
    });

    it('includes CSRF protection headers', async () => {
      const user = userEvent.setup();
      
      mockFetch.mockResolvedValue(mockApiResponse({ token: 'test-token' }));
      
      render(<SecureNotesApp />);
      
      // Fill and submit login form
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/password/i), 'TestPassword123!');
      await user.click(screen.getByRole('button', { name: /login securely/i }));
      
      // Verify proper headers
      expect(mockFetch).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          credentials: 'include',
          mode: 'cors',
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          })
        })
      );
    });
  });

  describe('Accessibility', () => {
    it('has proper ARIA labels', () => {
      render(<SecureNotesApp />);
      
      const emailField = screen.getByLabelText(/email/i);
      const passwordField = screen.getByLabelText(/password/i);
      
      expect(emailField).toHaveAttribute('aria-label', expect.any(String));
      expect(passwordField).toHaveAttribute('aria-label', expect.any(String));
    });

    it('has proper button types', () => {
      render(<SecureNotesApp />);
      
      const submitButton = screen.getByRole('button', { name: /login securely/i });
      expect(submitButton).toHaveAttribute('type', 'submit');
    });

    it('provides keyboard navigation', async () => {
      const user = userEvent.setup();
      render(<SecureNotesApp />);
      
      // Should be able to tab through form fields
      await user.tab();
      expect(screen.getByLabelText(/email/i)).toHaveFocus();
      
      await user.tab();
      expect(screen.getByLabelText(/password/i)).toHaveFocus();
      
      await user.tab();
      expect(screen.getByRole('button', { name: /login securely/i })).toHaveFocus();
    });
  });

  describe('Performance', () => {
    it('debounces search input', async () => {
      const user = userEvent.setup();
      
      mockLocalStorage.getItem.mockReturnValue('test-token');
      mockFetch.mockResolvedValue(mockApiResponse({ 
        notes: [createMockNote({ title: 'Test Note' })] 
      }));
      
      render(<SecureNotesApp />);
      
      const searchField = await screen.findByPlaceholderText(/search notes/i);
      
      // Type rapidly
      await user.type(searchField, 'test');
      
      // Should not trigger multiple API calls
      expect(mockFetch).toHaveBeenCalledTimes(1); // Only initial load
    });

    it('handles large notes list efficiently', async () => {
      const largeNotesList = Array.from({ length: 1000 }, (_, i) => 
        createMockNote({ id: `note-${i}`, title: `Note ${i}` })
      );
      
      mockLocalStorage.getItem.mockReturnValue('test-token');
      mockFetch.mockResolvedValue(mockApiResponse({ notes: largeNotesList }));
      
      const startTime = performance.now();
      render(<SecureNotesApp />);
      
      await waitFor(() => {
        expect(screen.getByText('Note 0')).toBeInTheDocument();
      });
      
      const endTime = performance.now();
      const renderTime = endTime - startTime;
      
      // Should render in reasonable time (less than 1 second)
      expect(renderTime).toBeLessThan(1000);
    });
  });

  describe('Error Boundaries', () => {
    it('handles component errors gracefully', () => {
      // Mock console.error to prevent error output in tests
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      // Create a component that throws
      const ThrowingComponent = () => {
        throw new Error('Test error');
      };
      
      const AppWithError = () => (
        <div>
          <ThrowingComponent />
          <SecureNotesApp />
        </div>
      );
      
      // Should not crash the entire app
      expect(() => render(<AppWithError />)).not.toThrow();
      
      consoleSpy.mockRestore();
    });
  });
});
