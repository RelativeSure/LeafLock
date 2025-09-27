const ORIGIN_SENTINELS = new Set(['__ORIGIN__', 'origin', 'same-origin'])
const DEFAULT_FALLBACK = 'http://localhost:8080'

const stripTrailingSlash = (value: string) => value.replace(/\/+$/, '')

export const getApiBaseUrl = (): string => {
  const raw = (import.meta as any)?.env?.VITE_API_URL
  const value = typeof raw === 'string' ? raw.trim() : ''

  if (!value || ORIGIN_SENTINELS.has(value)) {
    if (typeof window !== 'undefined' && window.location) {
      return stripTrailingSlash(window.location.origin)
    }
    return DEFAULT_FALLBACK
  }

  if (/^https?:\/\//i.test(value)) {
    return stripTrailingSlash(value)
  }

  if (value.startsWith('//')) {
    const protocol = typeof window !== 'undefined' && window.location ? window.location.protocol : 'https:'
    return stripTrailingSlash(`${protocol}${value}`)
  }

  console.warn('[LeafLock] VITE_API_URL should be a full URL or __ORIGIN__; falling back to default when possible.', value)

  if (typeof window !== 'undefined' && window.location) {
    return stripTrailingSlash(`${window.location.origin}/${value.replace(/^\/+/, '')}`)
  }

  return stripTrailingSlash(DEFAULT_FALLBACK)
}

export default getApiBaseUrl
