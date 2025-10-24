'use client'

import { useCollaboration } from '@/lib/collaboration-context'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Users } from 'lucide-react'

interface CollaborationBarProps {
  noteId: string
}

export function CollaborationBar({ noteId }: CollaborationBarProps) {
  const { getSessionUsers } = useCollaboration()
  const activeUsers = getSessionUsers(noteId)

  if (activeUsers.length <= 1) {
    return null
  }

  return (
    <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-surface/50 animate-slide-in">
      <Users className="h-4 w-4 text-muted" />
      <span className="text-sm text-muted-foreground">{activeUsers.length} people editing</span>

      <TooltipProvider>
        <div className="flex items-center -space-x-2 ml-2">
          {activeUsers.slice(0, 5).map((user) => (
            <Tooltip key={user.id}>
              <TooltipTrigger>
                <Avatar
                  className="h-7 w-7 border-2 border-background"
                  style={{ backgroundColor: user.color }}
                >
                  <AvatarFallback className="text-white text-xs">
                    {user.name.charAt(0).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
              </TooltipTrigger>
              <TooltipContent>
                <p>{user.name}</p>
              </TooltipContent>
            </Tooltip>
          ))}
          {activeUsers.length > 5 && (
            <Avatar className="h-7 w-7 border-2 border-background bg-muted">
              <AvatarFallback className="text-xs">+{activeUsers.length - 5}</AvatarFallback>
            </Avatar>
          )}
        </div>
      </TooltipProvider>
    </div>
  )
}
