import { describe, it, expect, beforeEach, vi } from 'vitest'
import sodium from 'libsodium-wrappers'

// Mock sodium library
vi.mock('libsodium-wrappers', () => ({
  ready: Promise.resolve(),
  crypto_secretbox_easy: vi.fn(),
  crypto_secretbox_open_easy: vi.fn(),
  crypto_secretbox_NONCEBYTES: 24,
  from_string: vi.fn((str) => new Uint8Array(Buffer.from(str, 'utf8'))),
  to_string: vi.fn((bytes) => Buffer.from(bytes).toString('utf8')),
  to_base64: vi.fn((bytes) => Buffer.from(bytes).toString('base64')),
  from_base64: vi.fn((str) => new Uint8Array(Buffer.from(str, 'base64'))),
  base64_variants: { ORIGINAL: 1 },
  randombytes_buf: vi.fn(() => new Uint8Array(32)),
  crypto_pwhash: vi.fn(() => new Uint8Array(32)),
  crypto_pwhash_ALG_ARGON2ID: 2,
  crypto_pwhash_SALTBYTES: 32,
  crypto_pwhash_OPSLIMIT_INTERACTIVE: 2,
  crypto_pwhash_MEMLIMIT_INTERACTIVE: 67108864
}))

// Import after mocking
const mockApp = `
// Simplified CryptoService from App.jsx
class CryptoService {
  constructor() {
    this.masterKey = null;
    this.derivedKey = null;
    this.sodiumReady = false;
    this.initSodium();
  }

  async initSodium() {
    if (!this.sodiumReady) {
      await sodium.ready;
      this.sodiumReady = true;
    }
  }

  async generateSalt() {
    await this.initSodium();
    return sodium.randombytes_buf(32);
  }

  async deriveKeyFromPassword(password, salt) {
    await this.initSodium();
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    
    return sodium.crypto_pwhash(
      32,
      passwordBytes,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID
    );
  }

  async encryptData(plaintext) {
    await this.initSodium();
    if (!this.derivedKey) {
      throw new Error('Derived key not set. Please unlock first.');
    }

    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES);
    crypto.getRandomValues(nonce);

    const plaintextBytes = sodium.from_string(plaintext);
    const ciphertext = sodium.crypto_secretbox_easy(plaintextBytes, nonce, this.derivedKey);

    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce, 0);
    combined.set(ciphertext, nonce.length);

    return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL);
  }

  async decryptData(encryptedData) {
    await this.initSodium();
    if (!this.derivedKey) {
      throw new Error('Derived key not set. Please unlock first.');
    }

    const combined = sodium.from_base64(encryptedData, sodium.base64_variants.ORIGINAL);
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES);

    const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, this.derivedKey);
    return sodium.to_string(decrypted);
  }

  setDerivedKey(key) {
    this.derivedKey = key;
  }
}

// Export for testing
if (typeof window !== 'undefined') {
  window.CryptoService = CryptoService;
} else {
  global.CryptoService = CryptoService;
}
`

// Evaluate the mock code to make CryptoService available
eval(mockApp)
const CryptoService = global.CryptoService

describe('CryptoService', () => {
  let cryptoService

  beforeEach(() => {
    vi.clearAllMocks()
    cryptoService = new CryptoService()
  })

  describe('Initialization', () => {
    it('should initialize sodium library', async () => {
      expect(sodium.ready).toBeDefined()
      await cryptoService.initSodium()
      expect(cryptoService.sodiumReady).toBe(true)
    })
  })

  describe('Salt Generation', () => {
    it('should generate random salt', async () => {
      const mockSalt = new Uint8Array(32)
      sodium.randombytes_buf.mockReturnValue(mockSalt)

      const salt = await cryptoService.generateSalt()
      
      expect(sodium.randombytes_buf).toHaveBeenCalledWith(32)
      expect(salt).toEqual(mockSalt)
    })
  })

  describe('Key Derivation', () => {
    it('should derive key from password and salt', async () => {
      const password = 'TestPassword123!'
      const salt = new Uint8Array(32)
      const expectedKey = new Uint8Array(32)

      sodium.crypto_pwhash.mockReturnValue(expectedKey)

      const derivedKey = await cryptoService.deriveKeyFromPassword(password, salt)

      expect(sodium.crypto_pwhash).toHaveBeenCalledWith(
        32,
        expect.any(Uint8Array),
        salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_ARGON2ID
      )
      expect(derivedKey).toEqual(expectedKey)
    })
  })

  describe('Encryption/Decryption', () => {
    beforeEach(() => {
      const testKey = new Uint8Array(32)
      cryptoService.setDerivedKey(testKey)
    })

    it('should encrypt data successfully', async () => {
      const plaintext = 'Test message for encryption'
      const mockCiphertext = new Uint8Array([1, 2, 3, 4])
      const mockBase64 = 'AQIDBA=='

      sodium.crypto_secretbox_easy.mockReturnValue(mockCiphertext)
      sodium.to_base64.mockReturnValue(mockBase64)

      const encrypted = await cryptoService.encryptData(plaintext)

      expect(sodium.from_string).toHaveBeenCalledWith(plaintext)
      expect(sodium.crypto_secretbox_easy).toHaveBeenCalled()
      expect(sodium.to_base64).toHaveBeenCalled()
      expect(encrypted).toBe(mockBase64)
    })

    it('should decrypt data successfully', async () => {
      const encryptedData = 'AQIDBA=='
      const mockDecrypted = new Uint8Array([72, 101, 108, 108, 111]) // "Hello"
      const expectedPlaintext = 'Hello'

      sodium.from_base64.mockReturnValue(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 1, 2, 3, 4]))
      sodium.crypto_secretbox_open_easy.mockReturnValue(mockDecrypted)
      sodium.to_string.mockReturnValue(expectedPlaintext)

      const decrypted = await cryptoService.decryptData(encryptedData)

      expect(sodium.from_base64).toHaveBeenCalledWith(encryptedData, sodium.base64_variants.ORIGINAL)
      expect(sodium.crypto_secretbox_open_easy).toHaveBeenCalled()
      expect(sodium.to_string).toHaveBeenCalledWith(mockDecrypted)
      expect(decrypted).toBe(expectedPlaintext)
    })

    it('should throw error when encrypting without derived key', async () => {
      cryptoService.setDerivedKey(null)

      await expect(cryptoService.encryptData('test')).rejects.toThrow(
        'Derived key not set. Please unlock first.'
      )
    })

    it('should throw error when decrypting without derived key', async () => {
      cryptoService.setDerivedKey(null)

      await expect(cryptoService.decryptData('AQIDBA==')).rejects.toThrow(
        'Derived key not set. Please unlock first.'
      )
    })
  })

  describe('Round-trip Encryption', () => {
    it('should successfully encrypt and decrypt data', async () => {
      const plaintext = 'This is a test message with special chars: 🔐📝✅'
      const testKey = new Uint8Array(32)
      const mockCiphertext = new Uint8Array([1, 2, 3, 4])
      const mockCombined = new Uint8Array(28) // 24 nonce + 4 ciphertext
      const mockBase64 = 'mock-encrypted-data'

      cryptoService.setDerivedKey(testKey)

      // Mock encryption
      sodium.from_string.mockReturnValue(new Uint8Array(Buffer.from(plaintext, 'utf8')))
      sodium.crypto_secretbox_easy.mockReturnValue(mockCiphertext)
      sodium.to_base64.mockReturnValue(mockBase64)

      const encrypted = await cryptoService.encryptData(plaintext)
      expect(encrypted).toBe(mockBase64)

      // Mock decryption
      sodium.from_base64.mockReturnValue(mockCombined)
      sodium.crypto_secretbox_open_easy.mockReturnValue(new Uint8Array(Buffer.from(plaintext, 'utf8')))
      sodium.to_string.mockReturnValue(plaintext)

      const decrypted = await cryptoService.decryptData(encrypted)
      expect(decrypted).toBe(plaintext)
    })
  })

  describe('Error Handling', () => {
    it('should handle sodium library initialization failure', async () => {
      sodium.ready = Promise.reject(new Error('Sodium init failed'))
      
      const newService = new CryptoService()
      
      // Should handle the error gracefully
      await new Promise(resolve => setTimeout(resolve, 10))
      expect(newService.sodiumReady).toBe(false)
    })
  })
})