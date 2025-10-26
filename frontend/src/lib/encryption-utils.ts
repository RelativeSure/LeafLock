import sodium from 'libsodium-wrappers-sumo'

export const ENCRYPTION_VERSION = 1
export const ENCRYPTION_KEY_STORAGE_KEY = 'encryptionKey'
export const ENCRYPTION_SALT_STORAGE_KEY = 'encryptionSalt'

let sodiumReadyPromise: Promise<typeof sodium> | null = null

async function getSodium(): Promise<typeof sodium> {
  if (!sodiumReadyPromise) {
    sodiumReadyPromise = sodium.ready.then(() => sodium)
  }
  return sodiumReadyPromise
}

export async function deriveKey(password: string, saltBase64: string): Promise<string> {
  const s = await getSodium()
  const salt = s.from_base64(saltBase64, s.base64_variants.ORIGINAL)
  const keyBytes = s.crypto_pwhash(
    s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    password,
    salt,
    s.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    s.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    s.crypto_pwhash_ALG_DEFAULT
  )
  return s.to_base64(keyBytes, s.base64_variants.ORIGINAL)
}

export async function encryptTextWithKey(plaintext: string, keyBase64: string): Promise<string> {
  const s = await getSodium()
  const key = s.from_base64(keyBase64, s.base64_variants.ORIGINAL)
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const message = s.from_string(plaintext)
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(message, null, null, nonce, key)

  const combined = new Uint8Array(nonce.length + ciphertext.length)
  combined.set(nonce)
  combined.set(ciphertext, nonce.length)

  return s.to_base64(combined, s.base64_variants.ORIGINAL)
}

export async function decryptTextWithKey(
  payloadBase64: string,
  keyBase64: string
): Promise<string> {
  const s = await getSodium()
  try {
    const payload = s.from_base64(payloadBase64, s.base64_variants.ORIGINAL)
    const nonceLength = s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    const key = s.from_base64(keyBase64, s.base64_variants.ORIGINAL)

    if (payload.length <= nonceLength) {
      // Legacy fallback: payload is the plaintext bytes
      return s.to_string(payload)
    }

    const nonce = payload.slice(0, nonceLength)
    const ciphertext = payload.slice(nonceLength)
    const message = s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key)
    return s.to_string(message)
  } catch (error) {
    // Fallback for legacy double-base64 or plaintext storage
    try {
      const binary = atob(payloadBase64)
      const bytes = new Uint8Array(binary.length)
      for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i)
      }
      return new TextDecoder().decode(bytes)
    } catch {
      return payloadBase64
    }
  }
}

export function getStoredKey(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(ENCRYPTION_KEY_STORAGE_KEY)
}

export function setStoredKey(keyBase64: string | null) {
  if (typeof window === 'undefined') return
  if (keyBase64) {
    window.localStorage.setItem(ENCRYPTION_KEY_STORAGE_KEY, keyBase64)
  } else {
    window.localStorage.removeItem(ENCRYPTION_KEY_STORAGE_KEY)
  }
  window.dispatchEvent(new Event('encryption-key-updated'))
}

export function getStoredSalt(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(ENCRYPTION_SALT_STORAGE_KEY)
}

export function setStoredSalt(saltBase64: string) {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(ENCRYPTION_SALT_STORAGE_KEY, saltBase64)
}

export async function encryptTextWithStoredKey(plaintext: string): Promise<string> {
  const key = getStoredKey()
  if (!key) {
    throw new Error('Encryption key not available')
  }
  return encryptTextWithKey(plaintext, key)
}

export async function decryptTextWithStoredKey(payloadBase64: string): Promise<string> {
  const key = getStoredKey()
  if (!key) {
    throw new Error('Encryption key not available')
  }
  return decryptTextWithKey(payloadBase64, key)
}

export async function ensureEncryptionReady() {
  await getSodium()
}
