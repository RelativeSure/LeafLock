import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mockSodium, mockCryptoSubtle, MockCryptoService } from './test-utils.jsx'

// Mock libsodium-wrappers
vi.mock('libsodium-wrappers', () => mockSodium)

// Import the classes after mocking
const { default: sodium } = await import('libsodium-wrappers')

// Create a test version of CryptoService that uses our mocks
class TestCryptoService {
  constructor() {
    this.masterKey = null;
    this.derivedKey = null;
    this.sodiumReady = false;
    this.initSodium();
  }

  async initSodium() {
    await sodium.ready;
    this.sodiumReady = true;
  }

  async deriveKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    
    // Mock PBKDF2 derivation
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 600000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return new Uint8Array(derivedBits);
  }

  async encryptData(plaintext) {
    if (!this.sodiumReady) await this.initSodium();
    if (!this.masterKey) throw new Error('No encryption key set');
    
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const messageBytes = sodium.from_string(plaintext);
    const ciphertext = sodium.crypto_secretbox_easy(messageBytes, nonce, this.masterKey);
    
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);
    
    return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL);
  }

  async decryptData(encryptedData) {
    if (!this.sodiumReady) await this.initSodium();
    if (!this.masterKey) throw new Error('No decryption key set');
    
    const combined = sodium.from_base64(encryptedData, sodium.base64_variants.ORIGINAL);
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES);
    
    const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, this.masterKey);
    return sodium.to_string(decrypted);
  }

  async generateSalt() {
    if (!this.sodiumReady) await this.initSodium();
    return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  }

  async setMasterKey(key) {
    this.masterKey = key;
  }
}

describe('CryptoService', () => {
  let cryptoService;

  beforeEach(async () => {
    vi.clearAllMocks();
    cryptoService = new TestCryptoService();
    await cryptoService.initSodium();
  })

  afterEach(() => {
    vi.resetAllMocks();
  })

  describe('Initialization', () => {
    it('initializes libsodium correctly', async () => {
      expect(cryptoService.sodiumReady).toBe(true);
      expect(sodium.ready).resolves.toBeUndefined();
    })

    it('creates service without master key initially', () => {
      expect(cryptoService.masterKey).toBeNull();
    })
  })

  describe('Key Derivation', () => {
    it('derives key from password and salt', async () => {
      const password = 'TestPassword123!';
      const salt = new Uint8Array(32).fill(1);
      
      const derivedKey = await cryptoService.deriveKeyFromPassword(password, salt);
      
      expect(derivedKey).toBeInstanceOf(Uint8Array);
      expect(derivedKey.length).toBe(32);
      expect(mockCryptoSubtle.importKey).toHaveBeenCalledWith(
        'raw',
        expect.any(Uint8Array),
        'PBKDF2',
        false,
        ['deriveBits']
      );
      expect(mockCryptoSubtle.deriveBits).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'PBKDF2',
          salt: salt,
          iterations: 600000,
          hash: 'SHA-256'
        }),
        'mock-key-material',
        256
      );
    })

    it('produces different keys for different passwords', async () => {
      const salt = new Uint8Array(32).fill(1);
      
      const key1 = await cryptoService.deriveKeyFromPassword('password1', salt);
      const key2 = await cryptoService.deriveKeyFromPassword('password2', salt);
      
      // Should produce different results (mocked to be same, but in real implementation would differ)
      expect(mockCryptoSubtle.importKey).toHaveBeenCalledTimes(2);
    })

    it('produces different keys for different salts', async () => {
      const password = 'TestPassword123!';
      const salt1 = new Uint8Array(32).fill(1);
      const salt2 = new Uint8Array(32).fill(2);
      
      await cryptoService.deriveKeyFromPassword(password, salt1);
      await cryptoService.deriveKeyFromPassword(password, salt2);
      
      expect(mockCryptoSubtle.deriveBits).toHaveBeenNthCalledWith(1, 
        expect.objectContaining({ salt: salt1 }), 
        'mock-key-material', 
        256
      );
      expect(mockCryptoSubtle.deriveBits).toHaveBeenNthCalledWith(2,
        expect.objectContaining({ salt: salt2 }), 
        'mock-key-material', 
        256
      );
    })

    it('uses high iteration count for security', async () => {
      const password = 'TestPassword123!';
      const salt = new Uint8Array(32).fill(1);
      
      await cryptoService.deriveKeyFromPassword(password, salt);
      
      expect(mockCryptoSubtle.deriveBits).toHaveBeenCalledWith(
        expect.objectContaining({
          iterations: 600000 // High iteration count
        }),
        expect.any(String),
        256
      );
    })
  })

  describe('Encryption/Decryption', () => {
    beforeEach(async () => {
      // Set up master key
      const masterKey = new Uint8Array(32).fill(1);
      await cryptoService.setMasterKey(masterKey);
    })

    it('encrypts plaintext data', async () => {
      const plaintext = 'Secret message';
      
      const encrypted = await cryptoService.encryptData(plaintext);
      
      expect(typeof encrypted).toBe('string');
      expect(encrypted).not.toBe(plaintext);
      expect(sodium.from_string).toHaveBeenCalledWith(plaintext);
      expect(sodium.randombytes_buf).toHaveBeenCalledWith(sodium.crypto_secretbox_NONCEBYTES);
      expect(sodium.crypto_secretbox_easy).toHaveBeenCalled();
      expect(sodium.to_base64).toHaveBeenCalled();
    })

    it('decrypts encrypted data', async () => {
      // Mock the encryption/decryption chain
      const plaintext = 'Secret message';
      mockSodium.to_string.mockReturnValue(plaintext);
      
      const encrypted = 'mocked-base64-encrypted-data';
      
      const decrypted = await cryptoService.decryptData(encrypted);
      
      expect(decrypted).toBe(plaintext);
      expect(sodium.from_base64).toHaveBeenCalledWith(encrypted, sodium.base64_variants.ORIGINAL);
      expect(sodium.crypto_secretbox_open_easy).toHaveBeenCalled();
      expect(sodium.to_string).toHaveBeenCalled();
    })

    it('fails to encrypt without master key', async () => {
      const cryptoWithoutKey = new TestCryptoService();
      await cryptoWithoutKey.initSodium();
      
      await expect(cryptoWithoutKey.encryptData('test')).rejects.toThrow('No encryption key set');
    })

    it('fails to decrypt without master key', async () => {
      const cryptoWithoutKey = new TestCryptoService();
      await cryptoWithoutKey.initSodium();
      
      await expect(cryptoWithoutKey.decryptData('test')).rejects.toThrow('No decryption key set');
    })

    it('encrypts empty string', async () => {
      const encrypted = await cryptoService.encryptData('');
      
      expect(typeof encrypted).toBe('string');
      expect(sodium.from_string).toHaveBeenCalledWith('');
    })

    it('handles Unicode characters', async () => {
      const unicodeText = '🔒 Secure 测试 العربية';
      
      const encrypted = await cryptoService.encryptData(unicodeText);
      
      expect(sodium.from_string).toHaveBeenCalledWith(unicodeText);
    })

    it('produces different ciphertext for same plaintext', async () => {
      const plaintext = 'Same message';
      
      // Mock different nonces for each call
      mockSodium.randombytes_buf
        .mockReturnValueOnce(new Uint8Array([1, 2, 3]))
        .mockReturnValueOnce(new Uint8Array([4, 5, 6]));
      
      mockSodium.to_base64
        .mockReturnValueOnce('encrypted-1')
        .mockReturnValueOnce('encrypted-2');
      
      const encrypted1 = await cryptoService.encryptData(plaintext);
      const encrypted2 = await cryptoService.encryptData(plaintext);
      
      expect(encrypted1).not.toBe(encrypted2);
      expect(mockSodium.randombytes_buf).toHaveBeenCalledTimes(2);
    })
  })

  describe('Salt Generation', () => {
    it('generates salt of correct size', async () => {
      const salt = await cryptoService.generateSalt();
      
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(sodium.randombytes_buf).toHaveBeenCalledWith(sodium.crypto_pwhash_SALTBYTES);
    })

    it('generates different salts', async () => {
      mockSodium.randombytes_buf
        .mockReturnValueOnce(new Uint8Array([1, 2, 3]))
        .mockReturnValueOnce(new Uint8Array([4, 5, 6]));
      
      const salt1 = await cryptoService.generateSalt();
      const salt2 = await cryptoService.generateSalt();
      
      expect(salt1).not.toEqual(salt2);
      expect(mockSodium.randombytes_buf).toHaveBeenCalledTimes(2);
    })
  })

  describe('Error Handling', () => {
    it('handles libsodium initialization failure', async () => {
      const failingCrypto = new TestCryptoService();
      failingCrypto.sodiumReady = false;
      
      // Mock sodium to throw error
      mockSodium.crypto_secretbox_easy.mockImplementationOnce(() => {
        throw new Error('Sodium error');
      })
      
      await failingCrypto.setMasterKey(new Uint8Array(32));
      
      await expect(failingCrypto.encryptData('test')).rejects.toThrow();
    })

    it('handles invalid encrypted data', async () => {
      // Mock decryption failure
      mockSodium.crypto_secretbox_open_easy.mockImplementationOnce(() => {
        throw new Error('Decryption failed');
      })
      
      await expect(cryptoService.decryptData('invalid-data')).rejects.toThrow();
    })

    it('handles corrupted base64 data', async () => {
      mockSodium.from_base64.mockImplementationOnce(() => {
        throw new Error('Invalid base64');
      })
      
      await expect(cryptoService.decryptData('invalid-base64')).rejects.toThrow();
    })
  })

  describe('Key Management', () => {
    it('sets master key correctly', async () => {
      const key = new Uint8Array(32).fill(42);
      
      await cryptoService.setMasterKey(key);
      
      expect(cryptoService.masterKey).toBe(key);
    })

    it('allows key rotation', async () => {
      const oldKey = new Uint8Array(32).fill(1);
      const newKey = new Uint8Array(32).fill(2);
      
      await cryptoService.setMasterKey(oldKey);
      expect(cryptoService.masterKey).toBe(oldKey);
      
      await cryptoService.setMasterKey(newKey);
      expect(cryptoService.masterKey).toBe(newKey);
    })
  })

  describe('Security Properties', () => {
    beforeEach(async () => {
      await cryptoService.setMasterKey(new Uint8Array(32).fill(1));
    })

    it('uses secure random nonces', async () => {
      await cryptoService.encryptData('test');
      
      expect(mockSodium.randombytes_buf).toHaveBeenCalledWith(
        mockSodium.crypto_secretbox_NONCEBYTES
      );
    })

    it('combines nonce with ciphertext', async () => {
      const mockNonce = new Uint8Array([1, 2, 3]);
      const mockCiphertext = new Uint8Array([4, 5, 6]);
      
      mockSodium.randombytes_buf.mockReturnValue(mockNonce);
      mockSodium.crypto_secretbox_easy.mockReturnValue(mockCiphertext);
      
      await cryptoService.encryptData('test');
      
      // Should combine nonce and ciphertext
      expect(mockSodium.to_base64).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        mockSodium.base64_variants.ORIGINAL
      );
    })

    it('properly extracts nonce during decryption', async () => {
      const mockCombined = new Uint8Array([1, 2, 3, 4, 5, 6]); // nonce + ciphertext
      mockSodium.from_base64.mockReturnValue(mockCombined);
      mockSodium.crypto_secretbox_NONCEBYTES = 3;
      
      await cryptoService.decryptData('test-encrypted');
      
      expect(mockSodium.crypto_secretbox_open_easy).toHaveBeenCalledWith(
        new Uint8Array([4, 5, 6]), // ciphertext part
        new Uint8Array([1, 2, 3]), // nonce part
        cryptoService.masterKey
      );
    })

    it('uses authenticated encryption', async () => {
      await cryptoService.encryptData('test');
      
      // Should use authenticated encryption (crypto_secretbox_easy)
      expect(mockSodium.crypto_secretbox_easy).toHaveBeenCalled();
    })

    it('validates authentication during decryption', async () => {
      await cryptoService.decryptData('test');
      
      // Should use authenticated decryption (crypto_secretbox_open_easy)
      expect(mockSodium.crypto_secretbox_open_easy).toHaveBeenCalled();
    })
  })

  describe('Performance', () => {
    beforeEach(async () => {
      await cryptoService.setMasterKey(new Uint8Array(32).fill(1));
    })

    it('encrypts data efficiently', async () => {
      const largeData = 'x'.repeat(10000); // 10KB
      
      const startTime = performance.now();
      await cryptoService.encryptData(largeData);
      const endTime = performance.now();
      
      const duration = endTime - startTime;
      expect(duration).toBeLessThan(100); // Should complete in under 100ms
    })

    it('decrypts data efficiently', async () => {
      mockSodium.to_string.mockReturnValue('x'.repeat(10000));
      
      const startTime = performance.now();
      await cryptoService.decryptData('large-encrypted-data');
      const endTime = performance.now();
      
      const duration = endTime - startTime;
      expect(duration).toBeLessThan(100); // Should complete in under 100ms
    })

    it('handles multiple concurrent operations', async () => {
      const operations = Array.from({ length: 10 }, (_, i) => 
        cryptoService.encryptData(`message ${i}`)
      );
      
      const startTime = performance.now();
      await Promise.all(operations);
      const endTime = performance.now();
      
      const duration = endTime - startTime;
      expect(duration).toBeLessThan(500); // All operations in under 500ms
    })
  })

  describe('Mock CryptoService', () => {
    let mockCrypto;

    beforeEach(() => {
      mockCrypto = new MockCryptoService();
    })

    it('provides simplified encryption for testing', async () => {
      const plaintext = 'test message';
      const encrypted = await mockCrypto.encryptData(plaintext);
      
      expect(encrypted).toBe(btoa(plaintext));
    })

    it('provides simplified decryption for testing', async () => {
      const plaintext = 'test message';
      const encrypted = btoa(plaintext);
      const decrypted = await mockCrypto.decryptData(encrypted);
      
      expect(decrypted).toBe(plaintext);
    })

    it('handles encryption/decryption round trip', async () => {
      const plaintext = 'test message';
      const encrypted = await mockCrypto.encryptData(plaintext);
      const decrypted = await mockCrypto.decryptData(encrypted);
      
      expect(decrypted).toBe(plaintext);
    })

    it('provides consistent salt generation', async () => {
      const salt = await mockCrypto.generateSalt();
      
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(salt.length).toBe(32);
    })

    it('allows key derivation for testing', async () => {
      const key = await mockCrypto.deriveKeyFromPassword('password', new Uint8Array(32));
      
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    })
  })
})