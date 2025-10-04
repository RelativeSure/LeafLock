const TOKEN_KEYS = ['secure_token', 'auth_token'] as const

export const getStoredAuthToken = (): string | null => {
	for (const key of TOKEN_KEYS) {
		const token = localStorage.getItem(key)
		if (token) {
			if (key !== 'secure_token') {
				persistAuthToken(token)
			}
			return token
		}
	}
	return null
}

export const persistAuthToken = (token: string): void => {
	localStorage.setItem('secure_token', token)
	localStorage.removeItem('auth_token')
}

export const clearStoredAuthToken = (): void => {
	localStorage.removeItem('secure_token')
	localStorage.removeItem('auth_token')
}
