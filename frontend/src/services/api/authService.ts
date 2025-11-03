import { ApiClient } from './apiClient'
import { LoginResponse, RegisterResponse, MFAStatusResponse } from './types'

class AuthService extends ApiClient {
  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await this.request<any>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })

    // Handle MFA-required response (no token yet)
    if (response.mfa_required && !response.token) {
      return {
        token: '',
        user: {
          id: response.user_id || '',
          email: email,
          name: '',
          role: response.is_admin ? 'admin' : 'user',
          mfaEnabled: true,
          createdAt: new Date().toISOString(),
        },
        requiresMFA: true,
        mfaSession: response.session_token,
        encryptionSalt: response.encryption_salt,
        encryptionVersion: response.encryption_version,
      }
    }

    // Handle successful login with token
    if (response.token) {
      this.setToken(response.token)

      // Transform backend response to frontend format
      const transformedResponse: LoginResponse = {
        token: response.token,
        user: {
          id: response.user_id || '',
          email: email, // Store the email we used for login
          name: '', // We'll get the name from other endpoints or registration
          role: response.is_admin ? 'admin' : 'user',
          mfaEnabled: response.mfa_required || false,
          createdAt: new Date().toISOString(),
        },
        requiresMFA: response.mfa_required,
        encryptionSalt: response.encryption_salt,
        encryptionVersion: response.encryption_version,
      }

      if (typeof window !== 'undefined') {
        localStorage.setItem('user', JSON.stringify(transformedResponse.user))
      }

      return transformedResponse
    }

    // Fallback for unexpected response format
    return response
  }

  async register(email: string, password: string, name: string): Promise<RegisterResponse> {
    const response = await this.request<any>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    })

    return {
      message:
        response?.message ??
        'Registration request accepted. If this email is eligible, you will receive further instructions shortly.',
    }
  }

  async verifyMFA(code: string, sessionToken?: string): Promise<LoginResponse> {
    const response = await this.request<any>('/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ 
        code,
        session_token: sessionToken 
      }),
    })

    if (response.token) {
      this.setToken(response.token)

      // Get the stored user data to preserve email and name
      let storedUser: any = {}
      if (typeof window !== 'undefined') {
        const userStr = localStorage.getItem('user')
        if (userStr) {
          storedUser = JSON.parse(userStr)
        }
      }

      // Transform backend response to frontend format
      const transformedResponse: LoginResponse = {
        token: response.token,
        user: {
          id: response.user_id || storedUser.id || '',
          email: storedUser.email || '',
          name: storedUser.name || '',
          role: response.is_admin ? 'admin' : 'user',
          mfaEnabled: true,
          createdAt: storedUser.createdAt || new Date().toISOString(),
        },
        requiresMFA: false,
        encryptionSalt: response.encryption_salt,
        encryptionVersion: response.encryption_version,
      }

      if (typeof window !== 'undefined') {
        localStorage.setItem('user', JSON.stringify(transformedResponse.user))
      }

      return transformedResponse
    }

    return response
  }

  async logout(): Promise<void> {
    this.clearToken()
  }

  async getMFAStatus(): Promise<MFAStatusResponse> {
    return this.request<MFAStatusResponse>('/auth/mfa/status')
  }

  async beginMFASetup(): Promise<{ secret: string; qrCode: string }> {
    return this.request<{ secret: string; qrCode: string }>('/auth/mfa/begin', {
      method: 'POST',
    })
  }

  async enableMFA(code: string): Promise<void> {
    await this.request('/auth/mfa/enable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
  }

  async disableMFA(): Promise<void> {
    await this.request('/auth/mfa/disable', {
      method: 'POST',
    })
  }

  async getBackupCodes(): Promise<string[]> {
    const response = await this.request<{ backupCodes: string[] }>('/auth/mfa/backup-codes')
    return response.backupCodes
  }

  async regenerateBackupCodes(): Promise<string[]> {
    const response = await this.request<{ backupCodes: string[] }>(
      '/auth/mfa/backup-codes/regenerate',
      {
        method: 'POST',
      }
    )
    return response.backupCodes
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.request('/auth/password/reset-request', {
      method: 'POST',
      body: JSON.stringify({ email }),
    })
  }

  async isRegistrationEnabled(): Promise<boolean> {
    const response = await this.request<{ enabled: boolean }>('/auth/registration')
    return response.enabled
  }
}

export const authService = new AuthService()
