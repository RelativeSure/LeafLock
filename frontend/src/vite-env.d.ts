/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string
  readonly VITE_DEV_HOST: string
  readonly VITE_DEV_PORT: string
  readonly VITE_DEV_BACKEND_PROTOCOL: string
  readonly VITE_DEV_BACKEND_HOST: string
  readonly VITE_DEV_BACKEND_PORT: string
  readonly VITE_DEV_PROXY_TARGET: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
