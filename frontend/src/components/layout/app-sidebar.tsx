import * as React from 'react'
import { Home, Settings, Shield, Tag, Plus, LogOut, Leaf, ChevronRight, Trash2 } from 'lucide-react'
import { Link, useNavigate, useLocation } from '@tanstack/react-router'
import { useClerk } from '@clerk/clerk-react'

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarSeparator,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
  SidebarGroupAction,
} from '@/components/ui/sidebar'
import { SidebarNoteList } from './sidebar-note-list'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { UserAvatar } from '@/components/ui/user-avatar'

import { useClerkAuthStore } from '@/stores/clerkAuthStore'
import { useNotesStore } from '@/stores/notesStore'

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const navigate = useNavigate()
  const location = useLocation()
  const { user } = useClerkAuthStore()
  const clerk = useClerk()
  const {
    folders,
    tags,
    selectFolder,
    selectTag,
    createFolder,
    createNote,
    selectedFolder,
    isLoading,
  } = useNotesStore()
  const [isCreateFolderOpen, setIsCreateFolderOpen] = React.useState(false)
  const [newFolderName, setNewFolderName] = React.useState('')
  const [newFolderColor, setNewFolderColor] = React.useState('#3b82f6')

  const handleCreateFolder = async () => {
    if (newFolderName.trim()) {
      await createFolder({ name: newFolderName, color: newFolderColor })
      setNewFolderName('')
      setNewFolderColor('#3b82f6')
      setIsCreateFolderOpen(false)
    }
  }

  const handleLogout = async () => {
    await clerk.signOut()
    navigate({ to: '/login' })
  }

  const handleCreateNote = async () => {
    try {
      const note = await createNote({})
      if (note?.id) {
        navigate({ to: '/' })
      }
    } catch (error) {
      console.error('Failed to create note:', error)
    }
  }

  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader className="group-data-[collapsible=icon]:px-1">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              asChild
              className="group-data-[collapsible=icon]:!p-2 group-data-[collapsible=icon]:justify-center"
            >
              <Link to="/">
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                  <Leaf className="size-4" />
                </div>
                <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
                  <span className="truncate font-semibold">LeafLock</span>
                  <span className="truncate text-xs">Secure Notes</span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Platform</SidebarGroupLabel>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                tooltip="All Notes"
                isActive={location.pathname === '/' && selectedFolder === null}
                onClick={() => {
                  selectFolder(null)
                  navigate({ to: '/' })
                }}
                className="group-data-[collapsible=icon]:justify-center"
              >
                <Home />
                <span className="group-data-[collapsible=icon]:hidden">All Notes</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
            <SidebarMenuItem>
              <SidebarMenuButton
                tooltip="Trash"
                onClick={() => {
                  // Placeholder for trash
                }}
                className="group-data-[collapsible=icon]:justify-center"
              >
                <Trash2 />
                <span className="group-data-[collapsible=icon]:hidden">Trash</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroup>

        <SidebarSeparator />

        <SidebarGroup>
          <SidebarGroupLabel>Notes</SidebarGroupLabel>
          <SidebarGroupAction title="New Note" onClick={handleCreateNote} disabled={isLoading}>
            <Plus /> <span className="sr-only">New Note</span>
          </SidebarGroupAction>
          <SidebarGroupContent>
            <SidebarNoteList />
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarSeparator />

        <Collapsible defaultOpen className="group/collapsible">
          <SidebarGroup className="group-data-[collapsible=icon]:px-1">
            <SidebarGroupLabel asChild>
              <CollapsibleTrigger className="group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-2">
                <span className="group-data-[collapsible=icon]:hidden">Folders</span>
                <span className="hidden group-data-[collapsible=icon]:block text-xs">F</span>
                <ChevronRight className="ml-auto transition-transform group-data-[state=open]/collapsible:rotate-90 group-data-[collapsible=icon]:hidden" />
              </CollapsibleTrigger>
            </SidebarGroupLabel>

            <Dialog open={isCreateFolderOpen} onOpenChange={setIsCreateFolderOpen}>
              <DialogTrigger asChild>
                <SidebarGroupAction title="Add Folder">
                  <Plus /> <span className="sr-only">Add Folder</span>
                </SidebarGroupAction>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create Folder</DialogTitle>
                  <DialogDescription>Organize your notes into folders.</DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid gap-2">
                    <Label htmlFor="folder-name">Name</Label>
                    <Input
                      id="folder-name"
                      value={newFolderName}
                      onChange={(e) => setNewFolderName(e.target.value)}
                      placeholder="Project X"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label>Color</Label>
                    <div className="flex gap-2">
                      {['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#6366f1'].map(
                        (color) => (
                          <button
                            key={color}
                            type="button"
                            onClick={() => setNewFolderColor(color)}
                            className={`w-6 h-6 rounded-full border-2 transition-all ${
                              newFolderColor === color
                                ? 'border-primary scale-110'
                                : 'border-transparent'
                            }`}
                            style={{ backgroundColor: color }}
                          />
                        )
                      )}
                    </div>
                  </div>
                </div>
                <DialogFooter>
                  <Button onClick={handleCreateFolder}>Create Folder</Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>

            <CollapsibleContent>
              <SidebarGroupContent>
                <SidebarMenu>
                  {folders.map((folder) => (
                    <SidebarMenuItem key={folder.id}>
                      <SidebarMenuButton
                        onClick={() => {
                          selectFolder(folder.id)
                          navigate({ to: '/' })
                        }}
                        isActive={selectedFolder === folder.id}
                        className="group-data-[collapsible=icon]:justify-center"
                      >
                        <div
                          className="h-2 w-2 rounded-full"
                          style={{ backgroundColor: folder.color }}
                        />
                        <span className="group-data-[collapsible=icon]:hidden">{folder.name}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                  {folders.length === 0 && (
                    <SidebarMenuItem>
                      <span className="px-2 text-xs text-muted-foreground">No folders</span>
                    </SidebarMenuItem>
                  )}
                </SidebarMenu>
              </SidebarGroupContent>
            </CollapsibleContent>
          </SidebarGroup>
        </Collapsible>

        <Collapsible defaultOpen className="group/collapsible">
          <SidebarGroup className="group-data-[collapsible=icon]:px-1">
            <SidebarGroupLabel asChild>
              <CollapsibleTrigger className="group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-2">
                <span className="group-data-[collapsible=icon]:hidden">Tags</span>
                <span className="hidden group-data-[collapsible=icon]:block text-xs">T</span>
                <ChevronRight className="ml-auto transition-transform group-data-[state=open]/collapsible:rotate-90 group-data-[collapsible=icon]:hidden" />
              </CollapsibleTrigger>
            </SidebarGroupLabel>
            <CollapsibleContent>
              <SidebarGroupContent>
                <SidebarMenu>
                  {tags.map((tag) => (
                    <SidebarMenuItem key={tag.id}>
                      <SidebarMenuButton
                        onClick={() => {
                          selectTag(tag.name)
                          navigate({ to: '/' })
                        }}
                        className="group-data-[collapsible=icon]:justify-center"
                      >
                        <Tag />
                        <span className="group-data-[collapsible=icon]:hidden">{tag.name}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                  {tags.length === 0 && (
                    <SidebarMenuItem>
                      <span className="px-2 text-xs text-muted-foreground">No tags</span>
                    </SidebarMenuItem>
                  )}
                </SidebarMenu>
              </SidebarGroupContent>
            </CollapsibleContent>
          </SidebarGroup>
        </Collapsible>

        <SidebarGroup className="mt-auto">
          <SidebarGroupLabel>Settings</SidebarGroupLabel>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                asChild
                tooltip="Settings"
                className="group-data-[collapsible=icon]:justify-center"
              >
                <Link to="/settings">
                  <Settings />
                  <span className="group-data-[collapsible=icon]:hidden">Settings</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
            {user?.isAdmin && (
              <SidebarMenuItem>
                <SidebarMenuButton
                  asChild
                  tooltip="Admin Console"
                  className="group-data-[collapsible=icon]:justify-center"
                >
                  <Link to="/admin">
                    <Shield />
                    <span className="group-data-[collapsible=icon]:hidden">Admin Console</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            )}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="group-data-[collapsible=icon]:px-1">
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton
                  size="lg"
                  className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground group-data-[collapsible=icon]:!p-2 group-data-[collapsible=icon]:justify-center"
                >
                  <UserAvatar user={user} size={32} />
                  <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
                    <span className="truncate font-semibold">{user?.name || 'User'}</span>
                    <span className="truncate text-xs">{user?.email || ''}</span>
                  </div>
                  <ChevronRight className="ml-auto size-4 group-data-[collapsible=icon]:hidden" />
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                className="w-[--radix-dropdown-menu-trigger-width] min-w-56 rounded-lg"
                side="bottom"
                align="end"
                sideOffset={4}
              >
                <DropdownMenuItem onClick={() => navigate({ to: '/settings' })}>
                  <Settings className="mr-2 h-4 w-4" />
                  Account
                </DropdownMenuItem>
                <DropdownMenuItem onClick={handleLogout}>
                  <LogOut className="mr-2 h-4 w-4" />
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}
