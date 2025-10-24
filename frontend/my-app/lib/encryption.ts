export class EncryptionService {
  private static readonly ALGORITHM = "AES-GCM"
  private static readonly KEY_LENGTH = 256
  private static readonly IV_LENGTH = 12
  private static readonly SALT_LENGTH = 16

  /**
   * Derives a cryptographic key from a password using PBKDF2
   */
  private static async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password)

    const keyMaterial = await crypto.subtle.importKey("raw", passwordBuffer, "PBKDF2", false, [
      "deriveBits",
      "deriveKey",
    ])

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: this.ALGORITHM, length: this.KEY_LENGTH },
      false,
      ["encrypt", "decrypt"],
    )
  }

  /**
   * Encrypts text using AES-GCM
   */
  static async encrypt(plaintext: string, password: string): Promise<string> {
    try {
      const encoder = new TextEncoder()
      const data = encoder.encode(plaintext)

      // Generate random salt and IV
      const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH))
      const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH))

      // Derive key from password
      const key = await this.deriveKey(password, salt)

      // Encrypt the data
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: this.ALGORITHM,
          iv: iv,
        },
        key,
        data,
      )

      // Combine salt + iv + encrypted data
      const combined = new Uint8Array(salt.length + iv.length + encryptedData.byteLength)
      combined.set(salt, 0)
      combined.set(iv, salt.length)
      combined.set(new Uint8Array(encryptedData), salt.length + iv.length)

      // Convert to base64 for storage
      return this.arrayBufferToBase64(combined)
    } catch (error) {
      console.error("[v0] Encryption error:", error)
      throw new Error("Failed to encrypt data")
    }
  }

  /**
   * Decrypts text using AES-GCM
   */
  static async decrypt(encryptedText: string, password: string): Promise<string> {
    try {
      // Convert from base64
      const combined = this.base64ToArrayBuffer(encryptedText)

      // Extract salt, iv, and encrypted data
      const salt = combined.slice(0, this.SALT_LENGTH)
      const iv = combined.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH)
      const encryptedData = combined.slice(this.SALT_LENGTH + this.IV_LENGTH)

      // Derive key from password
      const key = await this.deriveKey(password, salt)

      // Decrypt the data
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: this.ALGORITHM,
          iv: iv,
        },
        key,
        encryptedData,
      )

      // Convert back to string
      const decoder = new TextDecoder()
      return decoder.decode(decryptedData)
    } catch (error) {
      console.error("[v0] Decryption error:", error)
      throw new Error("Failed to decrypt data - incorrect password or corrupted data")
    }
  }

  /**
   * Generates a secure random encryption key
   */
  static generateEncryptionKey(): string {
    const array = new Uint8Array(32)
    crypto.getRandomValues(array)
    return this.arrayBufferToBase64(array)
  }

  /**
   * Converts ArrayBuffer to base64 string
   */
  private static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    let binary = ""
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
  }

  /**
   * Converts base64 string to Uint8Array
   */
  private static base64ToArrayBuffer(base64: string): Uint8Array {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes
  }

  /**
   * Hashes a password for verification
   */
  static async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(password)
    const hashBuffer = await crypto.subtle.digest("SHA-256", data)
    return this.arrayBufferToBase64(hashBuffer)
  }
}
