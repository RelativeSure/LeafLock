/**
 * Clerk User Management Service
 *
 * Provides user profile management using Clerk's built-in functionality
 */

import { useUser } from '@clerk/clerk-react'
import { useCallback } from 'react'

export interface UserProfileUpdate {
  firstName?: string
  lastName?: string
  email?: string
  avatar?: File
  publicMetadata?: Record<string, any>
  privateMetadata?: Record<string, any>
}

export interface UserProfile {
  id: string
  email: string
  firstName: string | null
  lastName: string | null
  fullName: string | null
  avatarUrl: string | null
  isAdmin: boolean
  publicMetadata: Record<string, any>
  privateMetadata: Record<string, any>
  createdAt: Date
  updatedAt: Date
}

export const useClerkUserService = (): {
  user: any
  isLoaded: boolean
  updateProfile: (data: UserProfileUpdate) => Promise<void>
  updateEmail: (newEmail: string) => Promise<void>
  updateAvatar: (file: File) => Promise<void>
  getUserProfile: () => UserProfile | null
  verifyEmail: (emailAddressId: string, code: string) => Promise<void>
  resendVerificationEmail: (emailAddressId: string) => Promise<void>
  deleteEmail: (emailAddressId: string) => Promise<void>
  getEmailAddresses: () => any[]
  refreshUserData: () => Promise<void>
  setAdminStatus: (isAdmin: boolean) => Promise<void>
} => {
  const { user, isLoaded } = useUser()

  const updateProfile = useCallback(
    async (data: UserProfileUpdate): Promise<void> => {
      if (!user) {
        throw new Error('No user logged in')
      }

      try {
        const updates: any = {}

        // Update basic profile information
        if (data.firstName !== undefined) updates.firstName = data.firstName
        if (data.lastName !== undefined) updates.lastName = data.lastName
        if (data.publicMetadata !== undefined) updates.publicMetadata = data.publicMetadata
        if (data.privateMetadata !== undefined) updates.privateMetadata = data.privateMetadata

        if (Object.keys(updates).length > 0) {
          await user.update(updates)
        }

        // Update email if provided
        if (data.email) {
          const emailAddress = user.emailAddresses.find((ea) => ea.emailAddress === data.email)
          if (!emailAddress) {
            // Create new email address
            const newEmail = await user.createEmailAddress({ email: data.email })
            await newEmail.prepareVerification({ strategy: 'email_code' })

            // Set as primary email
            await user.update({ primaryEmailAddressId: newEmail.id })
          }
        }

        // Update avatar if provided
        if (data.avatar) {
          await user.setProfileImage({ file: data.avatar })
        }
      } catch (error) {
        console.error('Failed to update user profile:', error)
        throw new Error('Failed to update profile. Please try again.')
      }
    },
    [user]
  )

  const updateEmail = useCallback(
    async (newEmail: string): Promise<void> => {
      if (!user) {
        throw new Error('No user logged in')
      }

      try {
        // Check if email already exists
        const existingEmail = user.emailAddresses.find((ea) => ea.emailAddress === newEmail)
        if (existingEmail) {
          throw new Error('Email address already exists')
        }

        // Create new email address
        const emailAddress = await user.createEmailAddress({ email: newEmail })

        // Send verification code
        await emailAddress.prepareVerification({ strategy: 'email_code' })

        // Note: User needs to verify the email before it becomes primary
        return Promise.resolve()
      } catch (error) {
        console.error('Failed to update email:', error)
        throw error
      }
    },
    [user]
  )

  const updateAvatar = useCallback(
    async (file: File): Promise<void> => {
      if (!user) {
        throw new Error('No user logged in')
      }

      try {
        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
        if (!allowedTypes.includes(file.type)) {
          throw new Error('Invalid file type. Please use JPG, PNG, GIF, or WebP.')
        }

        // Validate file size (max 10MB)
        const maxSize = 10 * 1024 * 1024 // 10MB
        if (file.size > maxSize) {
          throw new Error('File size too large. Maximum size is 10MB.')
        }

        await user.setProfileImage({ file })
      } catch (error) {
        console.error('Failed to update avatar:', error)
        throw error
      }
    },
    [user]
  )

  const getUserProfile = useCallback((): UserProfile | null => {
    if (!user || !isLoaded) {
      return null
    }

    return {
      id: user.id,
      email: user.primaryEmailAddress?.emailAddress || '',
      firstName: user.firstName,
      lastName: user.lastName,
      fullName: user.fullName,
      avatarUrl: user.imageUrl,
      isAdmin: user.publicMetadata?.isAdmin === true || user.publicMetadata?.role === 'admin',
      publicMetadata: user.publicMetadata || {},
      privateMetadata: (user as any).privateMetadata || {},
      createdAt: user.createdAt ? new Date(user.createdAt) : new Date(),
      updatedAt: user.updatedAt ? new Date(user.updatedAt) : new Date(),
    }
  }, [user, isLoaded])

  const verifyEmail = useCallback(
    async (emailAddressId: string, code: string): Promise<void> => {
      if (!user) {
        throw new Error('No user logged in')
      }

      try {
        const emailAddress = user.emailAddresses.find((ea) => ea.id === emailAddressId)
        if (!emailAddress) {
          throw new Error('Email address not found')
        }

        const result = await emailAddress.attemptVerification({ code })

        // Check verification result - adjust based on your Clerk version
        if (!result || (result as any).error) {
          throw new Error('Invalid verification code')
        }

        // Set as primary email if verification successful
        await user.update({ primaryEmailAddressId: emailAddressId })
      } catch (error) {
        console.error('Email verification failed:', error)
        throw error
      }
    },
    [user]
  )

  const resendVerificationEmail = useCallback(
    async (emailAddressId: string): Promise<void> => {
      if (!user) {
        throw new Error('No user logged in')
      }

      try {
        const emailAddress = user.emailAddresses.find((ea) => ea.id === emailAddressId)
        if (!emailAddress) {
          throw new Error('Email address not found')
        }

        await emailAddress.prepareVerification({ strategy: 'email_code' })
      } catch (error) {
        console.error('Failed to resend verification email:', error)
        throw error
      }
    },
    [user]
  )

  const deleteEmail = useCallback(
    async (emailAddressId: string): Promise<void> => {
      if (!user) {
        throw new Error('No user logged in')
      }

      try {
        const emailAddress = user.emailAddresses.find((ea) => ea.id === emailAddressId)
        if (!emailAddress) {
          throw new Error('Email address not found')
        }

        // Cannot delete primary email
        if (emailAddress.id === user.primaryEmailAddressId) {
          throw new Error('Cannot delete primary email address')
        }

        await emailAddress.destroy()
      } catch (error) {
        console.error('Failed to delete email:', error)
        throw error
      }
    },
    [user]
  )

  const getEmailAddresses = useCallback(() => {
    if (!user || !isLoaded) {
      return []
    }

    return user.emailAddresses.map((ea) => ({
      id: ea.id,
      emailAddress: ea.emailAddress,
      verificationStatus: ea.verification.status,
      isPrimary: ea.id === user.primaryEmailAddressId,
    }))
  }, [user, isLoaded])

  const refreshUserData = useCallback(async (): Promise<void> => {
    if (!user) {
      throw new Error('No user logged in')
    }

    try {
      await user.reload()
    } catch (error) {
      console.error('Failed to refresh user data:', error)
      throw error
    }
  }, [user])

  const setAdminStatus = useCallback(
    async (isAdmin: boolean): Promise<void> => {
      if (!user) {
        throw new Error('No user logged in')
      }

      try {
        // Update user metadata - adjust based on your Clerk version
        const updateData: any = {
          unsafeMetadata: {
            ...(user as any).unsafeMetadata,
            isAdmin: isAdmin,
          },
        }

        // Some Clerk versions use publicMetadata instead
        if ('publicMetadata' in user) {
          updateData.publicMetadata = {
            ...user.publicMetadata,
            isAdmin: isAdmin,
          }
        }

        await user.update(updateData)
      } catch (error) {
        console.error('Failed to update admin status:', error)
        throw error
      }
    },
    [user]
  )

  return {
    user: user || null,
    isLoaded,
    updateProfile,
    updateEmail,
    updateAvatar,
    getUserProfile,
    verifyEmail,
    resendVerificationEmail,
    deleteEmail,
    getEmailAddresses,
    refreshUserData,
    setAdminStatus,
  }
}
