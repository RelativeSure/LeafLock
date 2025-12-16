/**
 * SettingsLayout Component
 *
 * Purpose: Provides a consistent layout for settings and account pages with
 * collapsible sidebar navigation. Mirrors the main app sidebar behavior
 * but with settings-specific navigation items.
 *
 * Architecture:
 * - Collapsible sidebar with settings navigation
 * - Main content area for tabbed interface
 * - Responsive design matching main app sidebar
 * - URL-based navigation state management
 */

import * as React from 'react'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { ArrowLeft, ChevronRight, User, Download, Lock, Bell, Settings } from 'lucide-react'

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
import { Separator } from '@/components/ui/separator'

interface SettingsLayoutProps {
  children: React.ReactNode
  title: string
  description?: string
  onBack?: () => void
}

export function SettingsLayout({ children, title, description, onBack }: SettingsLayoutProps) {
  const navigate = useNavigate()
  const search = useSearch({ strict: false }) as { tab?: string }
  const activeTab = search.tab || 'profile'

  const handleNavigation = (path: string, tab?: string) => {
    if (tab) {
      navigate({ to: path, search: { tab } })
    } else {
      navigate({ to: path })
    }
  }

  const handleBackToApp = () => {
    if (onBack) {
      onBack()
    } else {
      navigate({ to: '/' })
    }
  }

  return (
    <div className="flex h-screen bg-background">
      {/* Settings Sidebar */}
      <Sidebar collapsible="icon" className="border-r">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton onClick={handleBackToApp} className="w-full justify-start gap-2">
                <ArrowLeft className="w-4 h-4" />
                <span className="group-data-[collapsible=icon]:hidden">Back to Notes</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
          <Separator className="my-2" />
          <SidebarMenu>
            <SidebarMenuItem>
              <div className="flex items-center gap-2 p-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                  <Settings className="h-4 w-4 text-primary" />
                </div>
                <div className="flex flex-col group-data-[collapsible=icon]:hidden">
                  <span className="text-sm font-semibold">{title}</span>
                  {description && (
                    <span className="text-xs text-muted-foreground">{description}</span>
                  )}
                </div>
              </div>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>

        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel className="group-data-[collapsible=icon]:hidden">
              Account Settings
            </SidebarGroupLabel>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => handleNavigation('/account', 'profile')}
                  isActive={activeTab === 'profile'}
                  className="justify-start gap-2 w-full"
                  tooltip="Profile"
                >
                  <User className="w-4 h-4" />
                  <span className="group-data-[collapsible=icon]:hidden">Profile</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => handleNavigation('/account', 'backup')}
                  isActive={activeTab === 'backup'}
                  className="justify-start gap-2 w-full"
                  tooltip="Backup & Restore"
                >
                  <Download className="w-4 h-4" />
                  <span className="group-data-[collapsible=icon]:hidden">Backup</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => handleNavigation('/account', 'security')}
                  isActive={activeTab === 'security'}
                  className="justify-start gap-2 w-full"
                  tooltip="Security"
                >
                  <Lock className="w-4 h-4" />
                  <span className="group-data-[collapsible=icon]:hidden">Security</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => handleNavigation('/account', 'preferences')}
                  isActive={activeTab === 'preferences'}
                  className="justify-start gap-2 w-full"
                  tooltip="Preferences"
                >
                  <Bell className="w-4 h-4" />
                  <span className="group-data-[collapsible=icon]:hidden">Preferences</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroup>

          <SidebarGroup>
            <SidebarGroupLabel className="group-data-[collapsible=icon]:hidden">
              General
            </SidebarGroupLabel>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => handleNavigation('/settings')}
                  className="justify-start gap-2 w-full"
                  tooltip="All Settings"
                >
                  <Settings className="w-4 h-4" />
                  <span className="group-data-[collapsible=icon]:hidden">All Settings</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroup>
        </SidebarContent>

        <SidebarFooter className="group-data-[collapsible=icon]:px-1">
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton asChild tooltip="Collapse Sidebar" className="justify-center">
                <div>
                  <ChevronRight className="h-4 w-4 transition-transform group-data-[state=collapsed]:rotate-180" />
                  <span className="group-data-[collapsible=icon]:hidden ml-2">Collapse</span>
                </div>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>

        <SidebarRail />
      </Sidebar>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <div className="flex h-14 items-center px-4">
            <h1 className="text-xl font-semibold">{title}</h1>
            {description && (
              <span className="ml-2 text-sm text-muted-foreground">{description}</span>
            )}
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-4xl">{children}</div>
        </main>
      </div>
    </div>
  )
}
