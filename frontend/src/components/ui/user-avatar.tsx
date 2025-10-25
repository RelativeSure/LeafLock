'use client'

import { Avatar, AvatarImage, AvatarFallback } from '@/components/ui/avatar'
import { getGravatarUrl, getUserInitials } from '@/lib/gravatar-utils'
import { useSettingsStore } from '@/stores/settingsStore'
import type { User } from '@/types'

interface UserAvatarProps {
  user: User | null
  size?: number
  className?: string
}

export function UserAvatar({ user, size = 32, className }: UserAvatarProps) {
  const { settings } = useSettingsStore()

  if (!user) {
    return (
      <Avatar className={className} style={{ width: size, height: size }}>
        <AvatarFallback>?</AvatarFallback>
      </Avatar>
    )
  }

  const getAvatarContent = () => {
    switch (settings.profilePicture.type) {
      case 'custom': {
        if (settings.profilePicture.customUrl) {
          return (
            <>
              <AvatarImage src={settings.profilePicture.customUrl} alt={user.name} />
              <AvatarFallback>{getUserInitials(user.name)}</AvatarFallback>
            </>
          )
        }
        // Fall through to initials if no custom URL
        return <AvatarFallback>{getUserInitials(user.name)}</AvatarFallback>
      }

      case 'initials':
        return <AvatarFallback>{getUserInitials(user.name)}</AvatarFallback>

      case 'gravatar':
      default: {
        const gravatarUrl = getGravatarUrl(user.email, size)
        return (
          <>
            <AvatarImage src={gravatarUrl} alt={user.name} />
            <AvatarFallback>{getUserInitials(user.name)}</AvatarFallback>
          </>
        )
      }
    }
  }

  return (
    <Avatar className={className} style={{ width: size, height: size }}>
      {getAvatarContent()}
    </Avatar>
  )
}
