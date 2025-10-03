import { create } from 'zustand'

interface MfaStatus {
  enabled: boolean
  has_secret: boolean
}

interface MfaSetup {
  secret: string
  otpauth_url: string
  issuer?: string
  account?: string
}

interface AuthState {
  // Authentication state
  isAuthenticated: boolean
  token: string | null
  userId: string | null
  workspaceId: string | null
  isAdmin: boolean

  // MFA state
  mfaStatus: MfaStatus | null
  mfaSetup: MfaSetup | null
  mfaBackupCodes: string[] | null
  mfaVerificationPending: boolean
  mfaSessionToken: string | null

  // Actions
  setAuthenticated: (token: string, userId: string, workspaceId?: string) => void
  setMfaRequired: (sessionToken: string) => void
  setMfaStatus: (status: MfaStatus) => void
  setMfaSetup: (setup: MfaSetup | null) => void
  setBackupCodes: (codes: string[] | null) => void
  completeMfaVerification: (token: string, userId: string, workspaceId?: string) => void
  setAdmin: (isAdmin: boolean) => void
  logout: () => void
  reset: () => void
}

const initialState = {
  isAuthenticated: false,
  token: null,
  userId: null,
  workspaceId: null,
  isAdmin: false,
  mfaStatus: null,
  mfaSetup: null,
  mfaBackupCodes: null,
  mfaVerificationPending: false,
  mfaSessionToken: null,
}

export const useAuthStore = create<AuthState>((set) => ({
  ...initialState,

  setAuthenticated: (token, userId, workspaceId) =>
    set({
      isAuthenticated: true,
      token,
      userId,
      workspaceId: workspaceId || null,
      mfaVerificationPending: false,
      mfaSessionToken: null,
    }),

  setMfaRequired: (sessionToken) =>
    set({
      mfaVerificationPending: true,
      mfaSessionToken: sessionToken,
      isAuthenticated: false,
    }),

  setMfaStatus: (status) =>
    set({
      mfaStatus: status,
    }),

  setMfaSetup: (setup) =>
    set({
      mfaSetup: setup,
    }),

  setBackupCodes: (codes) =>
    set({
      mfaBackupCodes: codes,
    }),

  completeMfaVerification: (token, userId, workspaceId) =>
    set({
      isAuthenticated: true,
      token,
      userId,
      workspaceId: workspaceId || null,
      mfaVerificationPending: false,
      mfaSessionToken: null,
    }),

  setAdmin: (isAdmin) =>
    set({
      isAdmin,
    }),

  logout: () =>
    set({
      isAuthenticated: false,
      token: null,
      userId: null,
      workspaceId: null,
      mfaVerificationPending: false,
      mfaSessionToken: null,
    }),

  reset: () => set(initialState),
}))

// Selectors
export const selectIsAuthenticated = (state: AuthState) => state.isAuthenticated
export const selectToken = (state: AuthState) => state.token
export const selectUserId = (state: AuthState) => state.userId
export const selectMfaStatus = (state: AuthState) => state.mfaStatus
export const selectMfaVerificationPending = (state: AuthState) =>
  state.mfaVerificationPending
export const selectMfaSessionToken = (state: AuthState) => state.mfaSessionToken
