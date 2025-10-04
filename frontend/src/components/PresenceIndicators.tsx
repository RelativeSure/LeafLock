import { Badge } from './ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip'
import { Users, Circle } from 'lucide-react'
import { useCollaborationStore, PresenceUser } from '../stores/collaborationStore'

interface PresenceIndicatorsProps {
  className?: string
}

interface UserAvatarProps {
  user: PresenceUser
  size?: 'sm' | 'md' | 'lg'
}

function UserAvatar({ user, size = 'md' }: UserAvatarProps) {
  const sizeClasses = {
    sm: 'w-6 h-6 text-xs',
    md: 'w-8 h-8 text-sm',
    lg: 'w-10 h-10 text-base',
  }

  const statusColors = {
    online: 'border-green-500',
    typing: 'border-blue-500',
    offline: 'border-gray-300',
  }

  const statusIndicatorColors = {
    online: 'bg-green-500',
    typing: 'bg-blue-500',
    offline: 'bg-gray-400',
  }

  return (
    <div className={`relative ${sizeClasses[size]} flex items-center justify-center rounded-full bg-gradient-to-r from-purple-500 to-pink-600 text-white font-medium border-2 ${statusColors[user.status]}`}>
      {user.user_email.charAt(0).toUpperCase()}

      {/* Status indicator */}
      <div className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-white ${statusIndicatorColors[user.status]}`}>
        {user.status === 'typing' && (
          <div className="w-full h-full rounded-full bg-blue-500 animate-pulse" />
        )}
      </div>
    </div>
  )
}

interface UserListProps {
  users: PresenceUser[]
}

function UserList({ users }: UserListProps) {
  if (users.length === 0) {
    return (
      <div className="flex items-center text-sm text-gray-500">
        <Users className="w-4 h-4 mr-2" />
        No active collaborators
      </div>
    )
  }

  const activeUsers = users.filter(user => user.status !== 'offline')
  const typingUsers = users.filter(user => user.status === 'typing')

  return (
    <div className="flex items-center space-x-2">
      {/* Avatar stack */}
      <div className="flex -space-x-2">
        {activeUsers.slice(0, 3).map((user, index) => (
          <TooltipProvider key={user.user_id}>
            <Tooltip>
              <TooltipTrigger asChild>
                <div style={{ zIndex: activeUsers.length - index }}>
                  <UserAvatar user={user} size="sm" />
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <div className="text-sm">
                  <div className="font-medium">{user.user_email}</div>
                  <div className="text-xs text-gray-400 capitalize">
                    {user.status === 'typing' ? 'Typing...' : 'Online'}
                  </div>
                </div>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ))}

        {/* Show count if more than 3 users */}
        {activeUsers.length > 3 && (
          <div className="w-6 h-6 text-xs flex items-center justify-center rounded-full bg-gray-200 text-gray-600 border-2 border-white">
            +{activeUsers.length - 3}
          </div>
        )}
      </div>

      {/* Status text */}
      <div className="flex items-center space-x-2 text-sm text-gray-600">
        {typingUsers.length > 0 && (
          <div className="flex items-center space-x-1">
            <div className="flex space-x-1">
              <Circle className="w-2 h-2 fill-blue-500 text-blue-500 animate-pulse" />
              <Circle className="w-2 h-2 fill-blue-500 text-blue-500 animate-pulse" style={{ animationDelay: '0.2s' }} />
              <Circle className="w-2 h-2 fill-blue-500 text-blue-500 animate-pulse" style={{ animationDelay: '0.4s' }} />
            </div>
            <span className="text-blue-600">
              {typingUsers.length === 1
                ? `${typingUsers[0].user_email.split('@')[0]} is typing...`
                : `${typingUsers.length} people are typing...`
              }
            </span>
          </div>
        )}

        {activeUsers.length > 0 && typingUsers.length === 0 && (
          <Badge variant="secondary" className="bg-green-100 text-green-800">
            {activeUsers.length} active
          </Badge>
        )}
      </div>
    </div>
  )
}

export function PresenceIndicators({ className }: PresenceIndicatorsProps) {
  const { presenceUsers, isConnected } = useCollaborationStore()

  if (!isConnected) {
    return (
      <div className={`flex items-center text-sm text-gray-500 ${className}`}>
        <Circle className="w-3 h-3 mr-2 text-gray-400" />
        Disconnected
      </div>
    )
  }

  return (
    <div className={`flex items-center space-x-4 ${className}`}>
      <UserList users={presenceUsers} />
    </div>
  )
}

// Compact version for toolbar
export function CompactPresenceIndicators({ className }: PresenceIndicatorsProps) {
  const { presenceUsers, isConnected } = useCollaborationStore()

  if (!isConnected) {
    return (
      <Badge variant="outline" className={`text-red-600 border-red-200 ${className}`}>
        <Circle className="w-2 h-2 mr-1 fill-red-500" />
        Offline
      </Badge>
    )
  }

  const activeUsers = presenceUsers.filter(user => user.status !== 'offline')

  if (activeUsers.length === 0) {
    return (
      <Badge variant="outline" className={`text-gray-600 border-gray-200 ${className}`}>
        <Circle className="w-2 h-2 mr-1 fill-gray-400" />
        Solo
      </Badge>
    )
  }

  return (
    <Badge variant="outline" className={`text-green-600 border-green-200 ${className}`}>
      <Circle className="w-2 h-2 mr-1 fill-green-500" />
      {activeUsers.length} online
    </Badge>
  )
}

// Cursor component for showing other users' cursor positions
interface CollaborativeCursorProps {
  user: PresenceUser
  position: { top: number; left: number }
}

export function CollaborativeCursor({ user, position }: CollaborativeCursorProps) {
  return (
    <div
      className="absolute pointer-events-none z-50 transition-all duration-150"
      style={{
        top: position.top,
        left: position.left,
      }}
    >
      {/* Cursor line */}
      <div className="w-0.5 h-5 bg-blue-500 relative">
        {/* User label */}
        <div className="absolute -top-6 left-0 bg-blue-500 text-white text-xs px-2 py-1 rounded whitespace-nowrap">
          {user.user_email.split('@')[0]}
        </div>
        {/* Cursor tip */}
        <div className="absolute -left-1 -bottom-1 w-2 h-2 bg-blue-500 rotate-45" />
      </div>
    </div>
  )
}
