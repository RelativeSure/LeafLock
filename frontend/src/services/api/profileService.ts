import { apiClient } from './apiClient'

export interface Profile {
  id: string
  email: string
  display_name?: string | null
  bio?: string | null
  avatar_url?: string | null
  profile_picture_type: string
  gravatar_url: string
  created_at: string
  last_login?: string | null
}

export interface UpdateProfileRequest {
  display_name?: string | null
  bio?: string | null
  avatar_url?: string | null
}

export const profileService = {
  /**
   * Get current user's profile
   */
  getProfile: async (): Promise<Profile> => {
    const response = await apiClient.get('/profile')
    return response.data
  },

  /**
   * Update current user's profile
   */
  updateProfile: async (data: UpdateProfileRequest): Promise<Profile> => {
    const response = await apiClient.put('/profile', data)
    return response.data
  },

  /**
   * Set avatar type (gravatar or custom)
   */
  setAvatarType: async (type: 'gravatar' | 'custom'): Promise<void> => {
    await apiClient.post('/profile/avatar-type', { type })
  },
}
