export const testUsers = {
  user1: {
    email: 'test1@example.com',
    password: 'VerySecurePassword123!',
  },
  user2: {
    email: 'test2@example.com',
    password: 'AnotherSecurePassword456!',
  },
}

export const testNotes = {
  simple: 'This is a simple test note',
  markdown: '# Test Note\n\nThis is a **markdown** note with *formatting*.',
  long: 'This is a very long note that contains a lot of text to test scrolling and rendering of large content. '.repeat(10),
  withSpecialChars: 'Test note with special characters: @#$%^&*()_+-=[]{}|;:,.<>?',
}

export function generateUniqueEmail(): string {
  const timestamp = Date.now()
  return `test${timestamp}@example.com`
}

export function generateTestNote(prefix = 'Test note'): string {
  const timestamp = Date.now()
  return `${prefix} created at ${timestamp}`
}