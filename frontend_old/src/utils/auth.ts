const TOKEN_KEY = 'secure_token' as const

export const getStoredAuthToken = (): string | null => {
  return localStorage.getItem(TOKEN_KEY)
}

export const persistAuthToken = (token: string): void => {
  localStorage.setItem(TOKEN_KEY, token)
}

export const clearStoredAuthToken = (): void => {
  localStorage.removeItem(TOKEN_KEY)
}
