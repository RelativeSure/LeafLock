import React from 'react'
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { EncryptionProvider, useEncryption } from '../encryption-context'
import * as encryptionUtils from '../encryption-utils'

// Mock encryption utilities
vi.mock('../encryption-utils', () => ({
  deriveKey: vi.fn(),
  encryptTextWithKey: vi.fn(),
  decryptTextWithKey: vi.fn(),
  ensureEncryptionReady: vi.fn(),
  getStoredKey: vi.fn(),
  setStoredKey: vi.fn(),
  getStoredSalt: vi.fn(),
  ENCRYPTION_VERSION: 1,
}))

describe('EncryptionContext', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    vi.spyOn(console, 'error').mockImplementation(vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('EncryptionProvider', () => {
    it('should render children', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue(null)

      render(
        <EncryptionProvider>
          <div>Test Child</div>
        </EncryptionProvider>
      )

      expect(screen.getByText('Test Child')).toBeInTheDocument()
    })

    it('should initialize encryption on mount', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue(null)

      render(
        <EncryptionProvider>
          <div>Test</div>
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(encryptionUtils.ensureEncryptionReady).toHaveBeenCalled()
      })
    })

    it('should set unlocked state when stored key exists', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue('test-key-base64')

      function TestComponent() {
        const { isUnlocked } = useEncryption()
        return <div>{isUnlocked ? 'Unlocked' : 'Locked'}</div>
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText('Unlocked')).toBeInTheDocument()
      })
    })

    it('should handle initialization errors', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockRejectedValue(
        new Error('Encryption init failed')
      )

      render(
        <EncryptionProvider>
          <div>Test</div>
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(console.error).toHaveBeenCalledWith(
          'Failed to initialize encryption:',
          expect.any(Error)
        )
      })
    })
  })

  describe('useEncryption', () => {
    it('should throw error when used outside provider', () => {
      expect(() => {
        function TestComponent() {
          useEncryption()
          return <div>Test</div>
        }
        render(<TestComponent />)
      }).toThrow('useEncryption must be used within an EncryptionProvider')
    })

    it('should provide encryption context', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue('test-key')

      function TestComponent() {
        const context = useEncryption()
        return (
          <div>
            <div>Version: {context.encryptionVersion}</div>
            <div>Unlocked: {context.isUnlocked ? 'yes' : 'no'}</div>
          </div>
        )
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText(/Version: 1/)).toBeInTheDocument()
        expect(screen.getByText(/Unlocked: yes/)).toBeInTheDocument()
      })
    })
  })

  describe('encryptText', () => {
    it('should encrypt text when key is set', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue('test-key-base64')
      vi.mocked(encryptionUtils.encryptTextWithKey).mockResolvedValue('encrypted-text')

      function TestComponent() {
        const { encryptText } = useEncryption()
        const [result, setResult] = React.useState<string>('')

        React.useEffect(() => {
          encryptText('plain text').then(setResult)
        }, [encryptText])

        return <div>{result}</div>
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText('encrypted-text')).toBeInTheDocument()
      })

      expect(encryptionUtils.encryptTextWithKey).toHaveBeenCalledWith(
        'plain text',
        'test-key-base64'
      )
    })

    it('should throw error when encrypting without key', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue(null)

      function TestComponent() {
        const { encryptText } = useEncryption()
        const [error, setError] = React.useState<string>('')

        React.useEffect(() => {
          encryptText('plain text').catch((e) => setError(e.message))
        }, [encryptText])

        return <div>{error}</div>
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText('Encryption key not set')).toBeInTheDocument()
      })
    })
  })

  describe('decryptText', () => {
    it('should decrypt text when key is set', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue('test-key-base64')
      vi.mocked(encryptionUtils.decryptTextWithKey).mockResolvedValue('decrypted-text')

      function TestComponent() {
        const { decryptText } = useEncryption()
        const [result, setResult] = React.useState<string>('')

        React.useEffect(() => {
          decryptText('encrypted-payload').then(setResult)
        }, [decryptText])

        return <div>{result}</div>
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText('decrypted-text')).toBeInTheDocument()
      })

      expect(encryptionUtils.decryptTextWithKey).toHaveBeenCalledWith(
        'encrypted-payload',
        'test-key-base64'
      )
    })

    it('should throw error when decrypting without key', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue(null)

      function TestComponent() {
        const { decryptText } = useEncryption()
        const [error, setError] = React.useState<string>('')

        React.useEffect(() => {
          decryptText('encrypted-payload').catch((e) => setError(e.message))
        }, [decryptText])

        return <div>{error}</div>
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText('Encryption key not set')).toBeInTheDocument()
      })
    })
  })

  describe('setEncryptionKey', () => {
    it('should derive and store encryption key', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue(null)
      vi.mocked(encryptionUtils.getStoredSalt).mockReturnValue('stored-salt')
      vi.mocked(encryptionUtils.deriveKey).mockResolvedValue('derived-key-base64')
      vi.mocked(encryptionUtils.setStoredKey).mockImplementation(vi.fn())

      function TestComponent() {
        const { setEncryptionKey, isUnlocked } = useEncryption()
        const [status, setStatus] = React.useState<string>('initial')

        const handleSetKey = async () => {
          await setEncryptionKey('password123')
          setStatus('key-set')
        }

        return (
          <div>
            <button onClick={handleSetKey}>Set Key</button>
            <div>Status: {status}</div>
            <div>Unlocked: {isUnlocked ? 'yes' : 'no'}</div>
          </div>
        )
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText(/Status: initial/)).toBeInTheDocument()
      })

      const button = screen.getByRole('button', { name: /Set Key/i })
      button.click()

      await waitFor(() => {
        expect(encryptionUtils.deriveKey).toHaveBeenCalledWith('password123', 'stored-salt')
        expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith('derived-key-base64')
      })
    })
  })

  describe('clearEncryptionKey', () => {
    it('should clear encryption key', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue('test-key')

      function TestComponent() {
        const { clearEncryptionKey, isUnlocked } = useEncryption()

        return (
          <div>
            <button onClick={clearEncryptionKey}>Clear Key</button>
            <div>Unlocked: {isUnlocked ? 'yes' : 'no'}</div>
          </div>
        )
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText(/Unlocked: yes/)).toBeInTheDocument()
      })

      const button = screen.getByRole('button', { name: /Clear Key/i })
      button.click()

      await waitFor(() => {
        expect(screen.getByText(/Unlocked: no/)).toBeInTheDocument()
      })
    })
  })

  describe('encryption-key-updated event', () => {
    it('should update state when encryption key is updated', async () => {
      vi.mocked(encryptionUtils.ensureEncryptionReady).mockResolvedValue()
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue(null)

      function TestComponent() {
        const { isUnlocked } = useEncryption()
        return <div>Unlocked: {isUnlocked ? 'yes' : 'no'}</div>
      }

      render(
        <EncryptionProvider>
          <TestComponent />
        </EncryptionProvider>
      )

      await waitFor(() => {
        expect(screen.getByText(/Unlocked: no/)).toBeInTheDocument()
      })

      // Simulate key update event
      vi.mocked(encryptionUtils.getStoredKey).mockReturnValue('new-key')
      window.dispatchEvent(new Event('encryption-key-updated'))

      await waitFor(() => {
        expect(screen.getByText(/Unlocked: yes/)).toBeInTheDocument()
      })
    })
  })
})
