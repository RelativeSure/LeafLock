const DEFAULT_BACKEND_PORT = '8080'

const normalizeHost = (host: string): string => {
  if (host.includes(':') && !host.startsWith('[')) {
    return `[${host}]`
  }
  return host
}

const sanitizeEnvUrl = (value: string | undefined): string | undefined => {
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed) return undefined
  return trimmed.replace(/\/$/, '')
}

export const resolveApiBaseUrl = (): string => {
  const envOverride = sanitizeEnvUrl(import.meta.env.VITE_API_URL)
  if (envOverride) {
    return `${envOverride}/api/v1`
  }

  if (typeof window !== 'undefined' && window.location?.hostname) {
    const protocol = window.location.protocol === 'https:' ? 'https' : 'http'
    const host = normalizeHost(window.location.hostname)
    return `${protocol}://${host}:${DEFAULT_BACKEND_PORT}/api/v1`
  }

  return `http://localhost:${DEFAULT_BACKEND_PORT}/api/v1`
}

export const resolveWsBaseUrl = (): string => {
  const envOverride = sanitizeEnvUrl(import.meta.env.VITE_WS_URL)
  if (envOverride) {
    return envOverride
  }

  if (typeof window !== 'undefined' && window.location?.hostname) {
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const host = normalizeHost(window.location.hostname)
    return `${protocol}://${host}:${DEFAULT_BACKEND_PORT}`
  }

  return `ws://localhost:${DEFAULT_BACKEND_PORT}`
}

export const resolveHttpUrl = (path: string): string => {
  const base = resolveApiBaseUrl()
  return `${base}${path.startsWith('/') ? path : `/${path}`}`
}
