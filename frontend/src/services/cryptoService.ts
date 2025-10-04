import { loadSodium, type SodiumModule } from './sodiumLoader'

export class CryptoService {
  public masterKey: Uint8Array | null = null
  public derivedKey: Uint8Array | null = null
  public sodiumReady = false
  private sodiumLib: SodiumModule | null = null

  private async ensureSodium(): Promise<SodiumModule> {
    if (this.sodiumLib && this.sodiumReady) {
      return this.sodiumLib
    }

    console.log('🧪 Initializing sodium library...')
    try {
      const sodium = await loadSodium()

      const requiredFunctions = [
        'crypto_secretbox_easy',
        'crypto_secretbox_open_easy',
        'crypto_secretbox_NONCEBYTES',
        'from_string',
        'to_string',
        'to_base64',
        'from_base64',
        'base64_variants',
      ]

      for (const func of requiredFunctions) {
        if (typeof (sodium as any)[func] === 'undefined') {
          throw new Error(`Sodium function ${func} is not available`)
        }
      }

      this.sodiumLib = sodium
      this.sodiumReady = true
      console.log('🧪 Sodium library initialized successfully with all functions')
      return sodium
    } catch (err) {
      console.error('💥 Failed to initialize sodium:', err)
      this.sodiumLib = null
      this.sodiumReady = false
      throw err
    }
  }

  async initSodium(): Promise<void> {
    await this.ensureSodium()
  }

  async deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const encoder = new TextEncoder()
    const passwordBytes = encoder.encode(password)

    const keyMaterial = await window.crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits'])

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: 600000,
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    )

    return new Uint8Array(derivedBits)
  }

  async encryptData(plaintext: string): Promise<string> {
    const sodium = (await this.ensureSodium()) as any
    if (!this.masterKey) throw new Error('No encryption key set')

    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES)
    crypto.getRandomValues(nonce)

    const messageBytes = sodium.from_string(plaintext)
    const ciphertext = sodium.crypto_secretbox_easy(messageBytes, nonce, this.masterKey)

    const combined = new Uint8Array(nonce.length + ciphertext.length)
    combined.set(nonce)
    combined.set(ciphertext, nonce.length)

    const base64Variants = sodium.base64_variants ?? {}
    const originalVariant = base64Variants.ORIGINAL ?? base64Variants.ORIGINAL_NO_PADDING
    return originalVariant ? sodium.to_base64(combined, originalVariant) : sodium.to_base64(combined)
  }

  async decryptData(encryptedData: string): Promise<string> {
    const sodium = (await this.ensureSodium()) as any
    if (!this.masterKey) throw new Error('No decryption key set')

    const base64Variants = sodium.base64_variants ?? {}
    const originalVariant = base64Variants.ORIGINAL ?? base64Variants.ORIGINAL_NO_PADDING
    const combined = originalVariant
      ? sodium.from_base64(encryptedData, originalVariant)
      : sodium.from_base64(encryptedData)
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES)
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES)

    const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, this.masterKey)
    return sodium.to_string(decrypted)
  }

  async generateSalt(): Promise<Uint8Array> {
    const saltBytes = new Uint8Array(32)
    crypto.getRandomValues(saltBytes)
    console.log('🧂 Generated salt using Web Crypto API')
    return saltBytes
  }

  async setMasterKey(key: Uint8Array): Promise<void> {
    this.masterKey = key
  }

  isSodiumReady(): boolean {
    return this.sodiumReady && this.sodiumLib !== null
  }
}

export const cryptoService = new CryptoService()
