import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  deriveKey,
  encryptTextWithKey,
  decryptTextWithKey,
  getStoredKey,
  setStoredKey,
  getStoredSalt,
  encryptTextWithStoredKey,
  decryptTextWithStoredKey,
  ensureEncryptionReady,
  ENCRYPTION_KEY_STORAGE_KEY,
  ENCRYPTION_SALT_STORAGE_KEY,
} from '../encryption-utils'

// Mock libsodium-wrappers-sumo
const mockSodium = {
  ready: Promise.resolve(),
  crypto_pwhash_SALTBYTES: 16,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES: 32,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: 24,
  crypto_pwhash_OPSLIMIT_INTERACTIVE: 2,
  crypto_pwhash_MEMLIMIT_INTERACTIVE: 67108864,
  crypto_pwhash_ALG_DEFAULT: 2,
  base64_variants: {
    ORIGINAL: 1,
    NO_PADDING: 2,
    URLSAFE: 3,
    URLSAFE_NO_PADDING: 4,
  },
  from_base64: vi.fn((value: string) => new Uint8Array(16)),
  to_base64: vi.fn((bytes: Uint8Array) => 'base64encoded'),
  from_string: vi.fn((str: string) => new TextEncoder().encode(str)),
  to_string: vi.fn((bytes: Uint8Array) => new TextDecoder().decode(bytes)),
  from_hex: vi.fn(() => new Uint8Array(16)),
  crypto_pwhash: vi.fn(() => new Uint8Array(32)),
  crypto_generichash: vi.fn(() => new Uint8Array(16)),
  randombytes_buf: vi.fn(() => new Uint8Array(24)),
  crypto_aead_xchacha20poly1305_ietf_encrypt: vi.fn(() => new Uint8Array(10)),
  crypto_aead_xchacha20poly1305_ietf_decrypt: vi.fn(() => new Uint8Array(5)),
}

vi.mock('libsodium-wrappers-sumo', () => ({
  default: mockSodium,
}))

describe('encryption-utils', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: vi.fn(),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
      },
      writable: true,
    })
  })

  describe('deriveKey', () => {
    it('should derive key from password and salt', async () => {
      const password = 'test-password'
      const salt = 'base64salt=='

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
      expect(mockSodium.crypto_pwhash).toHaveBeenCalled()
    })

    it('should handle invalid salt format', async () => {
      const password = 'test-password'
      const salt = 'invalid-salt'

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('invalid base64')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(20)) // Wrong length

      await expect(deriveKey(password, salt)).rejects.toThrow(
        'Invalid encryption salt format'
      )
    })

    it('should handle quoted salt strings', async () => {
      const password = 'test-password'
      const salt = '"base64salt=="'

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })

    it('should handle single-quoted salt strings', async () => {
      const password = 'test-password'
      const salt = "'base64salt=='"

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })

    it('should try multiple base64 variants', async () => {
      const password = 'test-password'
      const salt = 'urlsafe-base64-salt'

      mockSodium.from_base64
        .mockImplementationOnce(() => {
          throw new Error('invalid variant')
        })
        .mockImplementationOnce(() => {
          throw new Error('invalid variant')
        })
        .mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })

    it('should handle hex-encoded salt', async () => {
      const password = 'test-password'
      const salt = '0123456789abcdef0123456789abcdef'

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('not base64')
      })
      mockSodium.from_hex.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })

    it('should normalize salt with wrong length using hash', async () => {
      const password = 'test-password'
      const salt = 'base64salt=='

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32)) // Wrong length
      mockSodium.crypto_generichash.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
      expect(mockSodium.crypto_generichash).toHaveBeenCalled()
    })
  })

  describe('encryptTextWithKey', () => {
    it('should encrypt text with given key', async () => {
      const plaintext = 'secret message'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.randombytes_buf.mockReturnValueOnce(new Uint8Array(24))
      mockSodium.from_string.mockReturnValueOnce(
        new Uint8Array(plaintext.length)
      )
      mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt.mockReturnValueOnce(
        new Uint8Array(10)
      )
      mockSodium.to_base64.mockReturnValueOnce('encrypted-base64')

      const encrypted = await encryptTextWithKey(plaintext, keyBase64)

      expect(encrypted).toBe('encrypted-base64')
      expect(
        mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt
      ).toHaveBeenCalled()
    })
  })

  describe('decryptTextWithKey', () => {
    it('should decrypt text with given key', async () => {
      const encryptedBase64 = 'encrypted-base64'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64
        .mockReturnValueOnce(new Uint8Array(34)) // payload (24 nonce + 10 ciphertext)
        .mockReturnValueOnce(new Uint8Array(32)) // key
      mockSodium.crypto_aead_xchacha20poly1305_ietf_decrypt.mockReturnValueOnce(
        new Uint8Array(5)
      )
      mockSodium.to_string.mockReturnValueOnce('decrypted text')

      const decrypted = await decryptTextWithKey(encryptedBase64, keyBase64)

      expect(decrypted).toBe('decrypted text')
    })

    it('should handle legacy payload (plaintext)', async () => {
      const encryptedBase64 = 'short'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(4)) // Too short
      mockSodium.to_string.mockReturnValueOnce('legacy text')

      const decrypted = await decryptTextWithKey(encryptedBase64, keyBase64)

      expect(decrypted).toBe('legacy text')
    })
  })

  describe('getStoredKey', () => {
    it('should return stored key from localStorage', () => {
      const mockGetItem = vi.fn(() => 'stored-key-base64')
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      const key = getStoredKey()

      expect(key).toBe('stored-key-base64')
      expect(mockGetItem).toHaveBeenCalledWith(ENCRYPTION_KEY_STORAGE_KEY)
    })

    it('should return null when window is undefined', () => {
      const originalWindow = global.window
      // @ts-expect-error - Testing SSR scenario
      global.window = undefined

      const key = getStoredKey()

      expect(key).toBeNull()

      global.window = originalWindow
    })
  })

  describe('setStoredKey', () => {
    it('should set key in localStorage', () => {
      const mockSetItem = vi.fn()
      const mockRemoveItem = vi.fn()
      const mockDispatchEvent = vi.fn()

      Object.defineProperty(window, 'localStorage', {
        value: {
          setItem: mockSetItem,
          removeItem: mockRemoveItem,
        },
        writable: true,
      })
      window.dispatchEvent = mockDispatchEvent

      setStoredKey('new-key-base64')

      expect(mockSetItem).toHaveBeenCalledWith(
        ENCRYPTION_KEY_STORAGE_KEY,
        'new-key-base64'
      )
      expect(mockDispatchEvent).toHaveBeenCalled()
    })

    it('should remove key when null is passed', () => {
      const mockRemoveItem = vi.fn()
      const mockDispatchEvent = vi.fn()

      Object.defineProperty(window, 'localStorage', {
        value: { removeItem: mockRemoveItem },
        writable: true,
      })
      window.dispatchEvent = mockDispatchEvent

      setStoredKey(null)

      expect(mockRemoveItem).toHaveBeenCalledWith(ENCRYPTION_KEY_STORAGE_KEY)
    })
  })

  describe('getStoredSalt', () => {
    it('should return stored salt from localStorage', () => {
      const mockGetItem = vi.fn(() => 'stored-salt-base64')
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      const salt = getStoredSalt()

      expect(salt).toBe('stored-salt-base64')
      expect(mockGetItem).toHaveBeenCalledWith(ENCRYPTION_SALT_STORAGE_KEY)
    })
  })

  describe('encryptTextWithStoredKey', () => {
    it('should encrypt using stored key', async () => {
      const mockGetItem = vi.fn(() => 'stored-key-base64')
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.randombytes_buf.mockReturnValueOnce(new Uint8Array(24))
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(5))
      mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt.mockReturnValueOnce(
        new Uint8Array(10)
      )
      mockSodium.to_base64.mockReturnValueOnce('encrypted')

      const encrypted = await encryptTextWithStoredKey('test')

      expect(encrypted).toBe('encrypted')
    })

    it('should throw error when no key is stored', async () => {
      const mockGetItem = vi.fn(() => null)
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      await expect(encryptTextWithStoredKey('test')).rejects.toThrow(
        'Encryption key not available'
      )
    })
  })

  describe('decryptTextWithStoredKey', () => {
    it('should decrypt using stored key', async () => {
      const mockGetItem = vi.fn(() => 'stored-key-base64')
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      mockSodium.from_base64
        .mockReturnValueOnce(new Uint8Array(34))
        .mockReturnValueOnce(new Uint8Array(32))
      mockSodium.crypto_aead_xchacha20poly1305_ietf_decrypt.mockReturnValueOnce(
        new Uint8Array(5)
      )
      mockSodium.to_string.mockReturnValueOnce('decrypted')

      const decrypted = await decryptTextWithStoredKey('encrypted-base64')

      expect(decrypted).toBe('decrypted')
    })

    it('should throw error when no key is stored', async () => {
      const mockGetItem = vi.fn(() => null)
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      await expect(decryptTextWithStoredKey('encrypted')).rejects.toThrow(
        'Encryption key not available'
      )
    })
  })

  describe('ensureEncryptionReady', () => {
    it('should wait for sodium to be ready', async () => {
      await expect(ensureEncryptionReady()).resolves.not.toThrow()
    })
  })

  describe('setStoredSalt', () => {
    it('should store normalized salt', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt('test-salt')

      expect(mockSetItem).toHaveBeenCalledWith(
        ENCRYPTION_SALT_STORAGE_KEY,
        expect.any(String)
      )
    })

    it('should handle quoted salt input', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt('"test-salt"')

      expect(mockSetItem).toHaveBeenCalled()
    })

    it('should normalize salt with wrong length', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.crypto_generichash.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt('test-salt')

      expect(mockSodium.crypto_generichash).toHaveBeenCalled()
    })

    it('should fallback to storing as-is when decoding fails', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('decode failed')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('decode failed')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(20))

      const testSalt = 'invalid-salt'
      await (await import('../encryption-utils')).setStoredSalt(testSalt)

      expect(mockSetItem).toHaveBeenCalledWith(
        ENCRYPTION_SALT_STORAGE_KEY,
        expect.any(String)
      )
    })

    it('should handle hex salt format', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('not base64')
      })
      mockSodium.from_hex.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (
        await import('../encryption-utils')
      ).setStoredSalt('0123456789abcdef0123456789abcdef')

      expect(mockSodium.from_hex).toHaveBeenCalled()
    })
  })

  describe('decryptTextWithKey - edge cases', () => {
    it('should handle fallback for double-base64 encoding', async () => {
      const encryptedBase64 = 'ZG91YmxlLWJhc2U2NA==' // "double-base64" in base64
      const keyBase64 = 'base64key=='

      mockSodium.from_base64
        .mockReturnValueOnce(new Uint8Array(10))
        .mockReturnValueOnce(new Uint8Array(32))
      mockSodium.crypto_aead_xchacha20poly1305_ietf_decrypt.mockImplementation(
        () => {
          throw new Error('decryption failed')
        }
      )

      const decrypted = await decryptTextWithKey(encryptedBase64, keyBase64)

      expect(decrypted).toBeTruthy()
    })

    it('should return plaintext as last resort fallback', async () => {
      const plaintext = 'plaintext-content'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('invalid base64')
      })

      const result = await decryptTextWithKey(plaintext, keyBase64)

      expect(result).toBe(plaintext)
    })
  })

  describe('ENCRYPTION_VERSION constant', () => {
    it('should export ENCRYPTION_VERSION', () => {
      const { ENCRYPTION_VERSION } = require('../encryption-utils')
      expect(ENCRYPTION_VERSION).toBeDefined()
      expect(typeof ENCRYPTION_VERSION).toBe('number')
    })
  })
})
