import { ApiClient } from './apiClient'
import { RegisterResponse, MFAStatusResponse } from './types'

class AuthService extends ApiClient {
  // Registration is handled through Clerk, but backend still processes registration requests
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
