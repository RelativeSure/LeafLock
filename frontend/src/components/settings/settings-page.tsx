'use client'

import { useNotesStore, useTemplatesStore, useSettingsStore, useAuthStore } from '@/stores'
import { Button } from '@/components/ui/button'
import { Download } from 'lucide-react'
import { Label } from '@/components/ui/label'
import { useToast } from '@/hooks/use-toast'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'

export function SettingsPage() {
  const { notes, folders, tags, createNote, createFolder, createTag } = useNotesStore()
  const { templates, createTemplate } = useTemplatesStore()
  const { settings } = useSettingsStore()
  const { user } = useAuthStore()
  const { toast } = useToast()

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
      settings: settings || {},
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

    toast({
      title: 'Export successful',
      description: 'Your data has been exported successfully.',
    })

    // Log the export activity
    console.log('Export activity:', { userId: user?.id, action: 'export_data' })
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
            tags: template.tags || [],
            isPublic: template.isPublic || false,
          })
        }
      }

      toast({
        title: 'Import successful',
        description: 'Your data has been imported successfully.',
      })

      // Log the import activity
      console.log('Import activity:', { userId: user?.id, action: 'import_data' })
    } catch (error) {
      toast({
        title: 'Import failed',
        description: error instanceof Error ? error.message : 'Failed to import data',
        variant: 'destructive',
      })
    }
  }

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      handleImportNotes(file)
    }
  }

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground mt-2">
          Manage your account settings and data backup options.
        </p>
      </div>

      <Tabs defaultValue="backup" className="space-y-6">
        <TabsList>
          <TabsTrigger value="backup">Backup & Restore</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        <TabsContent value="backup" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                Data Backup & Restore
              </CardTitle>
              <CardDescription>
                Export your notes, folders, tags, and templates to a backup file, or restore from a previous backup.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Export Data</h3>
                  <p className="text-sm text-muted-foreground">
                    Download a complete backup of your data including notes, folders, tags, and templates.
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
                  <div className="space-y-2">
                    <Input
                      type="file"
                      accept=".json"
                      onChange={handleFileUpload}
                      className="w-full"
                    />
                    <p className="text-xs text-muted-foreground">
                      Select a .json backup file to restore
                    </p>
                  </div>
                </div>
              </div>

              <Separator />

              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Data Summary</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 border rounded-lg">
                    <div className="text-2xl font-bold text-primary">{notes?.length || 0}</div>
                    <div className="text-sm text-muted-foreground">Notes</div>
                  </div>
                  <div className="text-center p-4 border rounded-lg">
                    <div className="text-2xl font-bold text-primary">{folders?.length || 0}</div>
                    <div className="text-sm text-muted-foreground">Folders</div>
                  </div>
                  <div className="text-center p-4 border rounded-lg">
                    <div className="text-2xl font-bold text-primary">{tags?.length || 0}</div>
                    <div className="text-sm text-muted-foreground">Tags</div>
                  </div>
                  <div className="text-center p-4 border rounded-lg">
                    <div className="text-2xl font-bold text-primary">{templates?.length || 0}</div>
                    <div className="text-sm text-muted-foreground">Templates</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="account" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Account Information</CardTitle>
              <CardDescription>
                Manage your account details and preferences.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
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

        <TabsContent value="security" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Security Settings
              </CardTitle>
              <CardDescription>
                Manage your security preferences and encryption settings.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Encryption Status</Label>
                <p className="text-sm text-muted-foreground">
                  Your notes are encrypted using AES-256 encryption for maximum security.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
