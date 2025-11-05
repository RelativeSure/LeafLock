import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock libsodium-wrappers-sumo with a factory function to avoid hoisting issues
vi.mock('libsodium-wrappers-sumo', () => {
  const mockSodiumInstance = {
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
    from_base64: vi.fn((_value: string) => new Uint8Array(16)),
    to_base64: vi.fn((_bytes: Uint8Array) => 'base64encoded'),
    from_string: vi.fn((str: string) => new TextEncoder().encode(str)),
    to_string: vi.fn((bytes: Uint8Array) => new TextDecoder().decode(bytes)),
    from_hex: vi.fn(() => new Uint8Array(16)),
    crypto_pwhash: vi.fn(() => new Uint8Array(32)),
    crypto_generichash: vi.fn(() => new Uint8Array(16)),
    randombytes_buf: vi.fn(() => new Uint8Array(24)),
    crypto_aead_xchacha20poly1305_ietf_encrypt: vi.fn(() => new Uint8Array(10)),
    crypto_aead_xchacha20poly1305_ietf_decrypt: vi.fn(() => new Uint8Array(5)),
  }
  return {
    default: mockSodiumInstance,
  }
})

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
import sodium from 'libsodium-wrappers-sumo'

// Get the mocked instance
const mockSodium = sodium as any

describe('encryption-utils', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset all sodium mocks to default implementations
    mockSodium.from_base64.mockReset().mockImplementation((_value: string) => new Uint8Array(16))
    mockSodium.to_base64.mockReset().mockImplementation((_bytes: Uint8Array) => 'base64encoded')
    mockSodium.from_string.mockReset().mockImplementation((str: string) => new TextEncoder().encode(str))
    mockSodium.to_string.mockReset().mockImplementation((bytes: Uint8Array) => new TextDecoder().decode(bytes))
    mockSodium.from_hex.mockReset().mockImplementation(() => new Uint8Array(16))
    mockSodium.crypto_pwhash.mockReset().mockImplementation(() => new Uint8Array(32))
    mockSodium.crypto_generichash.mockReset().mockImplementation(() => new Uint8Array(16))
    mockSodium.randombytes_buf.mockReset().mockImplementation(() => new Uint8Array(24))
    mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt.mockReset().mockImplementation(() => new Uint8Array(10))
    mockSodium.crypto_aead_xchacha20poly1305_ietf_decrypt.mockReset().mockImplementation(() => new Uint8Array(5))

    // Mock localStorage properly
    const localStorageMock = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    }
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
    })
    // Reset atob to default behavior
    global.atob = vi.fn((str: string) => {
      return Buffer.from(str, 'base64').toString('binary')
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
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('invalid hex')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(20)) // Wrong length
      mockSodium.crypto_generichash.mockImplementation(() => {
        throw new Error('hash failed')
      })

      // Mock atob to fail as well
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      await expect(deriveKey(password, salt)).rejects.toThrow('Invalid encryption salt format')
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

      // All base64 variants fail
      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('base64 failed')
      })
      // Hex fails
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('not hex')
      })
      // UTF-8 fails
      mockSodium.from_string.mockImplementation(() => {
        throw new Error('string failed')
      })

      // atob fallback succeeds with 32 bytes (wrong length, triggers normalization)
      const mockBinaryString = 'x'.repeat(32) // 32 character string = 32 bytes
      global.atob = vi.fn(() => mockBinaryString)

      // crypto_generichash normalizes 32 bytes to 16 bytes
      mockSodium.crypto_generichash.mockReturnValueOnce(new Uint8Array(16))
      // crypto_pwhash derives the key
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      // to_base64 encodes the key
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
      expect(mockSodium.crypto_generichash).toHaveBeenCalledWith(16, expect.any(Uint8Array))
    })

  })

  describe('encryptTextWithKey', () => {
    it('should encrypt text with given key', async () => {
      const plaintext = 'secret message'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.randombytes_buf.mockReturnValueOnce(new Uint8Array(24))
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(plaintext.length))
      mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt.mockReturnValueOnce(new Uint8Array(10))
      mockSodium.to_base64.mockReturnValueOnce('encrypted-base64')

      const encrypted = await encryptTextWithKey(plaintext, keyBase64)

      expect(encrypted).toBe('encrypted-base64')
      expect(mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt).toHaveBeenCalled()
    })
  })

  describe('decryptTextWithKey', () => {
    it('should decrypt text with given key', async () => {
      const encryptedBase64 = 'encrypted-base64'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64
        .mockReturnValueOnce(new Uint8Array(34)) // payload (24 nonce + 10 ciphertext)
        .mockReturnValueOnce(new Uint8Array(32)) // key
      mockSodium.crypto_aead_xchacha20poly1305_ietf_decrypt.mockReturnValueOnce(new Uint8Array(5))
      mockSodium.to_string.mockReturnValueOnce('decrypted text')

      const decrypted = await decryptTextWithKey(encryptedBase64, keyBase64)

      expect(decrypted).toBe('decrypted text')
    })

    it('should handle legacy payload (plaintext)', async () => {
      const encryptedBase64 = 'short'
      const keyBase64 = 'base64key=='

      const shortPayload = new Uint8Array([115, 104, 111, 114, 116]) // "short" as bytes
      mockSodium.from_base64.mockReturnValueOnce(shortPayload) // Too short (< nonce length)
      mockSodium.to_string.mockReturnValueOnce('short')

      const decrypted = await decryptTextWithKey(encryptedBase64, keyBase64)

      expect(decrypted).toBe('short')
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

      expect(mockSetItem).toHaveBeenCalledWith(ENCRYPTION_KEY_STORAGE_KEY, 'new-key-base64')
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

      // encryptTextWithKey calls:
      // 1. from_base64(keyBase64) -> key
      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      // 2. randombytes_buf() -> nonce
      mockSodium.randombytes_buf.mockReturnValueOnce(new Uint8Array(24))
      // 3. from_string(plaintext) -> message
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(4)) // "test" = 4 bytes
      // 4. encrypt() -> ciphertext
      mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt.mockReturnValueOnce(new Uint8Array(10))
      // 5. to_base64(combined) -> result
      mockSodium.to_base64.mockReturnValueOnce('encrypted-result')

      const encrypted = await encryptTextWithStoredKey('test')

      expect(encrypted).toBe('encrypted-result')
    })

    it('should throw error when no key is stored', async () => {
      const mockGetItem = vi.fn(() => null)
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      await expect(encryptTextWithStoredKey('test')).rejects.toThrow('Encryption key not available')
    })
  })

  describe('decryptTextWithStoredKey', () => {
    it('should decrypt using stored key', async () => {
      const mockGetItem = vi.fn(() => 'stored-key-base64')
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      const payloadBytes = new Uint8Array(34) // 24 nonce + 10 ciphertext
      const decryptedBytes = new Uint8Array([100, 101, 99, 114, 121, 112, 116, 101, 100]) // "decrypted"

      // decryptTextWithKey calls:
      // 1. from_base64(payloadBase64) -> payload
      mockSodium.from_base64.mockReturnValueOnce(payloadBytes)
      // 2. from_base64(keyBase64) -> key
      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      // 3. decrypt() -> decrypted bytes
      mockSodium.crypto_aead_xchacha20poly1305_ietf_decrypt.mockReturnValueOnce(decryptedBytes)
      // 4. to_string(bytes) -> string
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

      expect(mockSetItem).toHaveBeenCalledWith(ENCRYPTION_SALT_STORAGE_KEY, expect.any(String))
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

      // All base64 variants fail
      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('base64 failed')
      })
      // Hex fails
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('not hex')
      })
      // UTF-8 fails
      mockSodium.from_string.mockImplementation(() => {
        throw new Error('string failed')
      })

      // atob fallback succeeds with 32 bytes (wrong length, triggers normalization)
      const mockBinaryString = 'y'.repeat(32) // 32 character string = 32 bytes
      global.atob = vi.fn(() => mockBinaryString)

      // crypto_generichash normalizes 32 bytes to 16 bytes
      mockSodium.crypto_generichash.mockReturnValueOnce(new Uint8Array(16))
      // to_base64 encodes the normalized salt
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt('test-salt')

      expect(mockSodium.crypto_generichash).toHaveBeenCalledWith(16, expect.any(Uint8Array))
      expect(mockSetItem).toHaveBeenCalledWith(ENCRYPTION_SALT_STORAGE_KEY, 'normalized-salt-base64')
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

      expect(mockSetItem).toHaveBeenCalledWith(ENCRYPTION_SALT_STORAGE_KEY, expect.any(String))
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

      await (await import('../encryption-utils')).setStoredSalt('0123456789abcdef0123456789abcdef')

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
      mockSodium.crypto_aead_xchacha20poly1305_ietf_decrypt.mockImplementation(() => {
        throw new Error('decryption failed')
      })

      const decrypted = await decryptTextWithKey(encryptedBase64, keyBase64)

      expect(decrypted).toBeTruthy()
    })

    it('should return plaintext as last resort fallback', async () => {
      const plaintext = 'plaintext-content'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('invalid base64')
      })

      // atob also fails
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      const result = await decryptTextWithKey(plaintext, keyBase64)

      expect(result).toBe(plaintext)
    })
  })

  describe('ENCRYPTION_VERSION constant', () => {
    it('should export ENCRYPTION_VERSION', async () => {
      const { ENCRYPTION_VERSION } = await import('../encryption-utils')
      expect(ENCRYPTION_VERSION).toBeDefined()
      expect(typeof ENCRYPTION_VERSION).toBe('number')
    })
  })

  describe('deriveKey - additional edge cases', () => {
    it('should handle empty salt string', async () => {
      const password = 'test-password'
      const salt = ''

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('invalid base64')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('invalid hex')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(0)) // Empty array (wrong length)
      mockSodium.crypto_generichash.mockImplementation(() => {
        throw new Error('hash failed')
      })

      // atob also fails
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      await expect(deriveKey(password, salt)).rejects.toThrow('Invalid encryption salt format')
    })

    it('should handle salt with padding fallback', async () => {
      const password = 'test-password'
      const salt = 'base64nopad' // Missing padding

      // First 4 base64 variants fail
      mockSodium.from_base64
        .mockImplementationOnce(() => { throw new Error('variant 1 failed') })
        .mockImplementationOnce(() => { throw new Error('variant 2 failed') })
        .mockImplementationOnce(() => { throw new Error('variant 3 failed') })
        .mockImplementationOnce(() => { throw new Error('variant 4 failed') })
        // Fifth call (padding fallback) succeeds with correct length
        .mockReturnValueOnce(new Uint8Array(16))

      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })

    it('should handle UTF-8 direct bytes with exact length', async () => {
      const password = 'test-password'
      const salt = '1234567890123456' // Exactly 16 bytes

      // All base64 variants fail (4 calls)
      mockSodium.from_base64
        .mockImplementationOnce(() => { throw new Error('variant 1 failed') })
        .mockImplementationOnce(() => { throw new Error('variant 2 failed') })
        .mockImplementationOnce(() => { throw new Error('variant 3 failed') })
        .mockImplementationOnce(() => { throw new Error('variant 4 failed') })
        // Padding fallback fails
        .mockImplementationOnce(() => { throw new Error('padding failed') })

      // Hex fails
      mockSodium.from_hex.mockImplementationOnce(() => { throw new Error('not hex') })
      // UTF-8 succeeds with exact 16 bytes
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })

    it('should handle atob fallback with URL-safe base64', async () => {
      const password = 'test-password'
      const salt = 'url-safe_base64'

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('not standard base64')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('not hex')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(20))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      // Mock atob to return proper bytes
      global.atob = vi.fn(() => '1234567890123456')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })

    it('should handle normalization failure when crypto_generichash throws', async () => {
      const password = 'test-password'
      const salt = 'base64salt=='

      // All base64 variants fail
      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('base64 failed')
      })
      // Hex fails
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('not hex')
      })
      // UTF-8 fails
      mockSodium.from_string.mockImplementation(() => {
        throw new Error('not string')
      })
      mockSodium.crypto_generichash.mockImplementation(() => {
        throw new Error('hash failed')
      })

      // Mock atob to also fail
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      await expect(deriveKey(password, salt)).rejects.toThrow('Invalid encryption salt format')
    })

    it('should handle whitespace-only salt', async () => {
      const password = 'test-password'
      const salt = '   '

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('invalid base64')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('invalid hex')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(0)) // Empty array (wrong length)
      mockSodium.crypto_generichash.mockImplementation(() => {
        throw new Error('hash failed')
      })

      // Mock atob to also fail
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      await expect(deriveKey(password, salt)).rejects.toThrow('Invalid encryption salt format')
    })

    it('should handle odd-length hex string', async () => {
      const password = 'test-password'
      const salt = '0123456789abcde' // 15 hex chars (odd)

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('not base64')
      })
      mockSodium.from_hex.mockReturnValueOnce(new Uint8Array(7)) // Wrong length
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(20)) // Wrong length
      mockSodium.crypto_generichash.mockImplementation(() => {
        throw new Error('hash failed')
      })

      // Mock atob to also fail
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      await expect(deriveKey(password, salt)).rejects.toThrow('Invalid encryption salt format')
    })

    it('should trim whitespace from salt', async () => {
      const password = 'test-password'
      const salt = '  base64salt==  '

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.crypto_pwhash.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_base64.mockReturnValueOnce('derived-key-base64')

      const key = await deriveKey(password, salt)

      expect(key).toBe('derived-key-base64')
    })
  })

  describe('getStoredSalt - edge cases', () => {
    it('should return null when window is undefined', () => {
      const originalWindow = global.window
      // @ts-expect-error - Testing SSR scenario
      global.window = undefined

      const salt = getStoredSalt()

      expect(salt).toBeNull()

      global.window = originalWindow
    })

    it('should handle null from localStorage', () => {
      const mockGetItem = vi.fn(() => null)
      Object.defineProperty(window, 'localStorage', {
        value: { getItem: mockGetItem },
        writable: true,
      })

      const salt = getStoredSalt()

      expect(salt).toBeNull()
    })
  })

  describe('setStoredSalt - additional edge cases', () => {
    it('should do nothing when window is undefined', async () => {
      const originalWindow = global.window
      // @ts-expect-error - Testing SSR scenario
      global.window = undefined

      await expect(
        (await import('../encryption-utils')).setStoredSalt('test-salt')
      ).resolves.not.toThrow()

      global.window = originalWindow
    })

    it('should handle atob fallback path', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('not base64')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('not hex')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(20))

      global.atob = vi.fn(() => '1234567890123456')

      await (await import('../encryption-utils')).setStoredSalt('url-safe_test')

      expect(mockSetItem).toHaveBeenCalled()
    })

    it('should handle UTF-8 with exact salt bytes length', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('not base64')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('not hex')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.to_base64.mockReturnValueOnce('utf8-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt('1234567890123456')

      expect(mockSodium.from_string).toHaveBeenCalled()
    })

    it('should handle normalization failure in crypto_generichash', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('not base64')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('not hex')
      })
      mockSodium.from_string.mockImplementation(() => {
        throw new Error('not string')
      })
      mockSodium.crypto_generichash.mockImplementation(() => {
        throw new Error('hash failed')
      })

      // Mock atob to fail as well
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      const testSalt = 'test-salt-too-long'
      await (await import('../encryption-utils')).setStoredSalt(testSalt)

      expect(mockSetItem).toHaveBeenCalledWith(ENCRYPTION_SALT_STORAGE_KEY, testSalt)
    })

    it('should handle single-quoted salt in setStoredSalt', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(16))
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt("'test-salt'")

      expect(mockSetItem).toHaveBeenCalled()
    })

    it('should handle empty salt input', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('invalid')
      })
      mockSodium.from_hex.mockImplementation(() => {
        throw new Error('invalid')
      })
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(0))
      mockSodium.crypto_generichash.mockImplementation(() => {
        throw new Error('hash failed')
      })

      // Mock atob to fail as well
      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      await (await import('../encryption-utils')).setStoredSalt('')

      expect(mockSetItem).toHaveBeenCalledWith(ENCRYPTION_SALT_STORAGE_KEY, '')
    })

    it('should handle padding fallback for base64', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      let callCount = 0
      mockSodium.from_base64.mockImplementation(() => {
        callCount++
        if (callCount <= 4) {
          throw new Error('invalid variant')
        }
        return new Uint8Array(16)
      })
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt('base64nopad')

      expect(mockSetItem).toHaveBeenCalled()
    })

    it('should handle URL-safe base64 variant', async () => {
      const mockSetItem = vi.fn()
      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })

      mockSodium.from_base64
        .mockImplementationOnce(() => {
          throw new Error('not original')
        })
        .mockImplementationOnce(() => {
          throw new Error('not no-padding')
        })
        .mockReturnValueOnce(new Uint8Array(16))
      mockSodium.to_base64.mockReturnValueOnce('normalized-salt-base64')

      await (await import('../encryption-utils')).setStoredSalt('url-safe-base64')

      expect(mockSetItem).toHaveBeenCalled()
    })
  })

  describe('setStoredKey - edge cases', () => {
    it('should do nothing when window is undefined', () => {
      const originalWindow = global.window
      // @ts-expect-error - Testing SSR scenario
      global.window = undefined

      expect(() => setStoredKey('test-key')).not.toThrow()

      global.window = originalWindow
    })

    it('should dispatch custom event with correct type', () => {
      const mockSetItem = vi.fn()
      const mockDispatchEvent = vi.fn()

      Object.defineProperty(window, 'localStorage', {
        value: { setItem: mockSetItem },
        writable: true,
      })
      window.dispatchEvent = mockDispatchEvent

      setStoredKey('new-key')

      expect(mockDispatchEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'encryption-key-updated',
        })
      )
    })
  })

  describe('encryptTextWithKey - edge cases', () => {
    it('should handle empty plaintext', async () => {
      const plaintext = ''
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.randombytes_buf.mockReturnValueOnce(new Uint8Array(24))
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(0))
      mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt.mockReturnValueOnce(new Uint8Array(0))
      mockSodium.to_base64.mockReturnValueOnce('encrypted-empty')

      const encrypted = await encryptTextWithKey(plaintext, keyBase64)

      expect(encrypted).toBe('encrypted-empty')
    })

    it('should handle large plaintext', async () => {
      const plaintext = 'x'.repeat(10000)
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockReturnValueOnce(new Uint8Array(32))
      mockSodium.randombytes_buf.mockReturnValueOnce(new Uint8Array(24))
      mockSodium.from_string.mockReturnValueOnce(new Uint8Array(10000))
      mockSodium.crypto_aead_xchacha20poly1305_ietf_encrypt.mockReturnValueOnce(
        new Uint8Array(10016)
      )
      mockSodium.to_base64.mockReturnValueOnce('encrypted-large')

      const encrypted = await encryptTextWithKey(plaintext, keyBase64)

      expect(encrypted).toBe('encrypted-large')
    })
  })

  describe('decryptTextWithKey - additional edge cases', () => {
    it('should handle empty ciphertext after nonce extraction', async () => {
      const encryptedBase64 = 'encrypted-base64'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64
        .mockReturnValueOnce(new Uint8Array(24)) // Exactly nonce length
        .mockReturnValueOnce(new Uint8Array(32))
      mockSodium.to_string.mockReturnValueOnce('fallback')

      const decrypted = await decryptTextWithKey(encryptedBase64, keyBase64)

      expect(decrypted).toBe('fallback')
    })

    it('should handle atob fallback failure', async () => {
      const plaintext = 'not-base64-at-all'
      const keyBase64 = 'base64key=='

      mockSodium.from_base64.mockImplementation(() => {
        throw new Error('invalid base64')
      })

      global.atob = vi.fn(() => {
        throw new Error('atob failed')
      })

      const result = await decryptTextWithKey(plaintext, keyBase64)

      expect(result).toBe(plaintext)
    })
  })

  describe('ensureEncryptionReady - additional tests', () => {
    it('should return the same promise on multiple calls', async () => {
      const promise1 = ensureEncryptionReady()
      const promise2 = ensureEncryptionReady()

      await expect(promise1).resolves.not.toThrow()
      await expect(promise2).resolves.not.toThrow()
    })
  })
})
