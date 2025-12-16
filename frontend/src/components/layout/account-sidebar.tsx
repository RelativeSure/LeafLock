import * as React from 'react'
import { User, Download, Lock, Bell, ArrowLeft, Shield, Settings } from 'lucide-react'
import { useNavigate } from '@tanstack/react-router'

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarGroup,
  SidebarGroupLabel,
} from '@/components/ui/sidebar'
import { Button } from '@/components/ui/button'
import { UserAvatar } from '@/components/ui/user-avatar'

import { useClerkAuthStore } from '@/stores/clerkAuthStore'

interface AccountSidebarProps extends React.ComponentProps<typeof Sidebar> {
  onClose: () => void
}

export function AccountSidebar({ onClose, ...props }: AccountSidebarProps) {
  const navigate = useNavigate()
  const { user } = useClerkAuthStore()

  const handleNavigation = (path: string) => {
    navigate({ to: path })
    onClose()
  }

  return (
    <Sidebar collapsible="none" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <Button
              onClick={onClose}
              variant="ghost"
              size="sm"
              className="w-full justify-start gap-2"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Notes
            </Button>
          </SidebarMenuItem>
        </SidebarMenu>
        <SidebarMenu className="mt-4">
          <SidebarMenuItem>
            <div className="flex items-center gap-3 p-2">
              <UserAvatar user={user} size={40} />
              <div className="flex-1 min-w-0">
                <p className="font-semibold truncate">{user?.name || 'User'}</p>
                <p className="text-sm text-muted-foreground truncate">{user?.email || ''}</p>
              </div>
            </div>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent className="mt-4">
        <SidebarGroup>
          <SidebarGroupLabel>Account Settings</SidebarGroupLabel>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                onClick={() => handleNavigation('/settings?tab=profile')}
                className="justify-start gap-2 w-full"
              >
                <User className="w-4 h-4" />
                Profile
              </SidebarMenuButton>
            </SidebarMenuItem>

            <SidebarMenuItem>
              <SidebarMenuButton
                onClick={() => handleNavigation('/settings?tab=backup')}
                className="justify-start gap-2 w-full"
              >
                <Download className="w-4 h-4" />
                Backup & Restore
              </SidebarMenuButton>
            </SidebarMenuItem>

            <SidebarMenuItem>
              <SidebarMenuButton
                onClick={() => handleNavigation('/settings?tab=security')}
                className="justify-start gap-2 w-full"
              >
                <Lock className="w-4 h-4" />
                Security
              </SidebarMenuButton>
            </SidebarMenuItem>

            <SidebarMenuItem>
              <SidebarMenuButton
                onClick={() => handleNavigation('/settings?tab=preferences')}
                className="justify-start gap-2 w-full"
              >
                <Bell className="w-4 h-4" />
                Preferences
              </SidebarMenuButton>
            </SidebarMenuItem>

            {user?.isAdmin && (
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => handleNavigation('/admin')}
                  className="justify-start gap-2 w-full"
                >
                  <Shield className="w-4 h-4" />
                  Admin Console
                </SidebarMenuButton>
              </SidebarMenuItem>
            )}
          </SidebarMenu>
        </SidebarGroup>

        <SidebarGroup className="mt-8">
          <SidebarGroupLabel>General</SidebarGroupLabel>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                onClick={() => handleNavigation('/settings')}
                className="justify-start gap-2 w-full"
              >
                <Settings className="w-4 h-4" />
                All Settings
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <Button onClick={() => handleNavigation('/settings?tab=profile')} className="w-full">
              Manage Account
            </Button>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  )
}
