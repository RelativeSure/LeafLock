// Placeholder encryption context - to be implemented later
export function useEncryption() {
  return {
    isUnlocked: true,
    encryptText: (text: string) => Promise.resolve(text),
    decryptText: (text: string) => Promise.resolve(text),
    setEncryptionKey: (_key: string) => {
      // TODO: Implement encryption key setting
      console.log('Setting encryption key')
    },
  }
}
