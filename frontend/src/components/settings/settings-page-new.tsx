/**
 * SettingsPage Component with Collapsible Sidebar
 *
 * Purpose: Comprehensive settings interface with collapsible sidebar navigation.
 * Provides centralized location for managing user account, security, data backup/restore,
 * application preferences, and folder/tag management.
 *
 * Architecture:
 * - Collapsible sidebar with all settings navigation
 * - Main content area with tabbed interface
 * - URL-based tab state management
 * - Consistent with main app and account page sidebar behavior
 */

import * as React from 'react'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { SettingsLayout } from '@/components/layout/settings-layout'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { UserAvatar } from '@/components/ui/user-avatar'
import { useClerkAuthStore } from '@/stores/clerkAuthStore'
import { useSettingsStore } from '@/stores/settingsStore'
import { useNotesStore } from '@/stores/notesStore'
import { useTemplatesStore } from '@/stores/templatesStore'
import { useToast } from '@/hooks/use-toast'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Database, Download, FolderPlus, TagIcon, Lock, Bell } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface SettingsSearchParams {
  tab?: string
}

export function SettingsPage() {
  const navigate = useNavigate()
  const { user } = useClerkAuthStore()
  const { settings, updateSettings } = useSettingsStore()
  const { notes, folders, tags, createNote, createFolder, createTag } = useNotesStore()
  const { templates, createTemplate } = useTemplatesStore()
  const { toast } = useToast()
  const search = useSearch({ strict: false }) as SettingsSearchParams
  const activeTab = search.tab || 'profile'
  const [isUpdatingProfile, setIsUpdatingProfile] = React.useState(false)

  const handleBackToApp = () => {
    navigate({ to: '/' })
  }

  const handleProfilePictureChange = (type: 'gravatar' | 'initials') => {
    setIsUpdatingProfile(true)
    updateSettings({
      profilePicture: { type },
    })
    setTimeout(() => {
      setIsUpdatingProfile(false)
      toast.success('Profile picture updated successfully.')
    }, 300)
  }

  const handleExportNotes = () => {
    const data = {
      version: '1.0',
      exportedAt: new Date().toISOString(),
      user: {
        id: user?.id,
        email: user?.email,
        name: user?.name,
      },
      notes: (notes || []).map((note) => ({
        ...note,
        encrypted: note.encrypted || false,
      })),
      folders: folders || [],
      tags: tags || [],
      templates: templates || [],
    }

    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `leaflock-backup-${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    toast.success('Your data has been exported successfully.')
  }

  const handleImportNotes = async (file: File) => {
    try {
      const text = await file.text()
      const data = JSON.parse(text)

      if (!data.version || !data.notes) {
        throw new Error('Invalid backup file format')
      }

      // Import folders
      if (data.folders) {
        for (const folder of data.folders) {
          await createFolder({
            name: folder.name,
            color: folder.color,
          })
        }
      }

      // Import tags
      if (data.tags) {
        for (const tag of data.tags) {
          await createTag({
            name: tag.name,
            color: tag.color,
          })
        }
      }

      // Import notes
      for (const note of data.notes) {
        await createNote({
          title: note.title,
          content: note.content,
          folderId: note.folderId,
          tags: note.tags || [],
          encrypted: note.encrypted || false,
        })
      }

      // Import templates
      if (data.templates) {
        for (const template of data.templates) {
          await createTemplate({
            name: template.name,
            content: template.content,
            description: template.description,
          })
        }
      }

      toast.success('Your data has been imported successfully.')
    } catch (error) {
      console.error('Import error:', error)
      toast.error('Failed to import backup file. Please check the file format.')
    }
  }

  const renderProfileTab = () => (
    <TabsContent value="profile" className="space-y-6 mt-0">
      <Card>
        <CardHeader>
          <CardTitle>Profile Information</CardTitle>
          <CardDescription>Manage your profile picture and account details.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Profile Picture */}
          <div className="space-y-4">
            <Label>Profile Picture</Label>
            <div className="flex items-center gap-4">
              <UserAvatar user={user} size={80} />
              <div className="space-y-2">
                <div className="flex gap-2">
                  <Button
                    variant={settings.profilePicture.type === 'gravatar' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => handleProfilePictureChange('gravatar')}
                    disabled={isUpdatingProfile}
                  >
                    Gravatar
                  </Button>
                  <Button
                    variant={settings.profilePicture.type === 'initials' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => handleProfilePictureChange('initials')}
                    disabled={isUpdatingProfile}
                  >
                    Initials
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground">
                  {settings.profilePicture.type === 'gravatar'
                    ? 'Using Gravatar based on your email address'
                    : 'Using your name initials'}
                </p>
              </div>
            </div>
          </div>

          <Separator />

          {/* Account Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <Label htmlFor="name">Name</Label>
              <Input id="name" value={user?.name || ''} disabled />
            </div>
            <div>
              <Label htmlFor="email">Email</Label>
              <Input id="email" value={user?.email || ''} disabled />
            </div>
          </div>
        </CardContent>
      </Card>
    </TabsContent>
  )

  const renderBackupTab = () => (
    <TabsContent value="backup" className="space-y-6 mt-0">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Data Backup & Restore
          </CardTitle>
          <CardDescription>
            Export your notes, folders, tags, and templates to a backup file, or restore from a
            previous backup.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Export Data</h3>
              <p className="text-sm text-muted-foreground">
                Download a complete backup of your data including notes, folders, tags, and
                templates.
              </p>
              <Button onClick={handleExportNotes} className="w-full">
                <Download className="h-4 w-4 mr-2" />
                Export Backup
              </Button>
            </div>

            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Import Data</h3>
              <p className="text-sm text-muted-foreground">
                Restore your data from a previous backup file.
              </p>
              <Input
                type="file"
                accept=".json"
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  if (file) handleImportNotes(file)
                }}
                className="w-full"
              />
            </div>
          </div>
        </CardContent>
      </Card>
    </TabsContent>
  )

  const renderSecurityTab = () => (
    <TabsContent value="security" className="space-y-6 mt-0">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" />
            Security Settings
          </CardTitle>
          <CardDescription>
            Manage your security preferences and encryption settings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Encryption Status</Label>
                <p className="text-sm text-muted-foreground">Your data is encrypted at rest</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-green-500" />
                <span className="text-sm font-medium">Enabled</span>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Auto-save</Label>
                <p className="text-sm text-muted-foreground">
                  Automatically save your notes while editing
                </p>
              </div>
              <Switch
                checked={settings.autoSave}
                onCheckedChange={(checked) => updateSettings({ autoSave: checked })}
              />
            </div>
          </div>
        </CardContent>
      </Card>
    </TabsContent>
  )

  const renderPreferencesTab = () => (
    <TabsContent value="preferences" className="space-y-6 mt-0">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Preferences
          </CardTitle>
          <CardDescription>
            Customize your application preferences and notification settings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Email Notifications</Label>
                <p className="text-sm text-muted-foreground">
                  Receive email notifications for important updates
                </p>
              </div>
              <Switch
                checked={settings.emailNotifications}
                onCheckedChange={(checked) => updateSettings({ emailNotifications: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Default Note Behavior</Label>
                <p className="text-sm text-muted-foreground">
                  Control how new notes are created and where they appear
                </p>
              </div>
              <Select
                value={settings.defaultNoteBehavior}
                onValueChange={(value: 'last-seen' | 'new-note') =>
                  updateSettings({ defaultNoteBehavior: value })
                }
              >
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="Select behavior" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="last-seen">Last seen folder</SelectItem>
                  <SelectItem value="new-note">New note folder</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>
    </TabsContent>
  )

  const renderFoldersTab = () => (
    <TabsContent value="folders" className="space-y-6 mt-0">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FolderPlus className="h-5 w-5" />
            Manage Folders & Tags
          </CardTitle>
          <CardDescription>
            Organize your notes with folders and tags for better categorization.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Folders</h3>
              <p className="text-sm text-muted-foreground">
                Create and manage folders to organize your notes.
              </p>
              <Button onClick={() => navigate({ to: '/manage' })} className="w-full">
                <FolderPlus className="h-4 w-4 mr-2" />
                Manage Folders
              </Button>
            </div>

            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Tags</h3>
              <p className="text-sm text-muted-foreground">
                Use tags to categorize and filter your notes.
              </p>
              <Button onClick={() => navigate({ to: '/manage' })} className="w-full">
                <TagIcon className="h-4 w-4 mr-2" />
                Manage Tags
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </TabsContent>
  )

  return (
    <SettingsLayout
      title="Settings"
      description="Configure your LeafLock experience"
      onBack={handleBackToApp}
    >
      <Tabs
        value={activeTab}
        onValueChange={(value) => navigate({ to: '/settings', search: { tab: value } })}
      >
        <TabsList className="grid w-full grid-cols-5 mb-6">
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="backup">Backup</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="preferences">Preferences</TabsTrigger>
          <TabsTrigger value="folders">Folders & Tags</TabsTrigger>
        </TabsList>

        {renderProfileTab()}
        {renderBackupTab()}
        {renderSecurityTab()}
        {renderPreferencesTab()}
        {renderFoldersTab()}
      </Tabs>
    </SettingsLayout>
  )
}
