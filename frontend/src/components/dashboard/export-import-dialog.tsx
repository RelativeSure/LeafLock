'use client'

import { useState } from 'react'
import { useNotesStore, useTemplatesStore, useSettingsStore, useAuthStore } from '@/stores'
import { ActivityLogger } from '@/lib/activity-logger'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Download, Upload, FileJson, Database, Shield } from 'lucide-react'
import { Label } from '@/components/ui/label'
import { useToast } from '@/hooks/use-toast'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'

export function ExportImportDialog() {
  const { notes, folders, tags, createNote, createFolder, createTag } = useNotesStore()
  const { templates, createTemplate } = useTemplatesStore()
  const { settings } = useSettingsStore()
  const { user } = useAuthStore()
  const { toast } = useToast()
  const [isOpen, setIsOpen] = useState(false)

  const handleExportNotes = () => {
    const data = {
      notes: notes.filter((n) => !n.isTrashed),
      folders,
      tags,
      exportedAt: new Date().toISOString(),
      version: '1.0',
      type: 'notes',
    }

    downloadJSON(data, `leaflock-notes-${new Date().toISOString().split('T')[0]}.json`)

    toast({
      title: 'Notes exported',
      description: `Exported ${data.notes.length} notes, ${folders.length} folders, and ${tags.length} tags.`,
    })
  }

  const handleExportTemplates = () => {
    const data = {
      templates,
      exportedAt: new Date().toISOString(),
      version: '1.0',
      type: 'templates',
    }

    downloadJSON(data, `leaflock-templates-${new Date().toISOString().split('T')[0]}.json`)

    toast({
      title: 'Templates exported',
      description: `Exported ${templates.length} templates.`,
    })
  }

  const handleExportAccountData = () => {
    if (!user) return

    const activityLogs = ActivityLogger.getLogsByUser(user.id)

    const accountData = {
      // Personal Information
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
        mfaEnabled: user.mfaEnabled,
      },
      // Content Data
      notes: notes.map((note) => ({
        ...note,
        // Include encryption status
        encrypted: note.encrypted || false,
      })),
      folders,
      tags,
      templates,
      // Settings and Preferences
      settings,
      // Activity and Security Logs
      activityLogs,
      // Metadata
      export: {
        exportedAt: new Date().toISOString(),
        version: '1.0',
        type: 'gdpr-full-export',
        dataRetentionPolicy:
          'Notes and data are stored locally in your browser. Trashed notes are deleted after 30 days.',
        privacyPolicy: 'https://docs.leaflock.app/privacy',
        termsOfService: 'https://docs.leaflock.app/terms',
      },
    }

    downloadJSON(
      accountData,
      `leaflock-account-data-${new Date().toISOString().split('T')[0]}.json`
    )

    // Log the export action
    ActivityLogger.log(user.id, user.name, user.email, 'data_export')

    toast({
      title: 'Account data exported',
      description: 'Your complete account data has been exported in compliance with GDPR.',
    })
  }

  const downloadJSON = (data: any, filename: string) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target?.result as string)

        const importedCount = { notes: 0, folders: 0, tags: 0, templates: 0 }

        // Import based on type
        if (data.type === 'notes' || !data.type) {
          // Import folders first
          if (data.folders) {
            data.folders.forEach((folder: any) => {
              createFolder(folder)
              importedCount.folders++
            })
          }

          // Import tags
          if (data.tags) {
            data.tags.forEach((tag: any) => {
              createTag(tag)
              importedCount.tags++
            })
          }

          // Import notes
          if (data.notes) {
            data.notes.forEach((note: any) => {
              createNote(note)
              importedCount.notes++
            })
          }
        }

        // Import templates
        if (data.type === 'templates' || data.templates) {
          const templatesToImport = data.templates || []
          templatesToImport.forEach((template: any) => {
            createTemplate(template)
            importedCount.templates++
          })
        }

        toast({
          title: 'Import successful',
          description: `Imported ${importedCount.notes} notes, ${importedCount.folders} folders, ${importedCount.tags} tags, and ${importedCount.templates} templates.`,
        })

        setIsOpen(false)
      } catch (error) {
        toast({
          title: 'Import failed',
          description: 'The file format is invalid. Please select a valid LeafLock backup file.',
          variant: 'destructive',
        })
      }
    }
    reader.readAsText(file)
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" className="gap-2 bg-transparent">
          <FileJson className="h-4 w-4" />
          Backup & Restore
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Backup & Restore</DialogTitle>
          <DialogDescription>Export your data or import from a previous backup</DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="export" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="export">Export Data</TabsTrigger>
            <TabsTrigger value="import">Import Data</TabsTrigger>
          </TabsList>

          <TabsContent value="export" className="space-y-4 mt-4">
            {/* Notes Export */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-muted-foreground" />
                <Label>Notes & Organization</Label>
              </div>
              <Button
                onClick={handleExportNotes}
                variant="outline"
                className="w-full gap-2 justify-start bg-transparent"
              >
                <Download className="h-4 w-4" />
                Export Notes, Folders & Tags ({notes.filter((n) => !n.isTrashed).length} notes)
              </Button>
              <p className="text-xs text-muted-foreground">
                Download all your notes, folders, and tags as a JSON file.
              </p>
            </div>

            <Separator />

            {/* Templates Export */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <FileJson className="h-4 w-4 text-muted-foreground" />
                <Label>Templates</Label>
              </div>
              <Button
                onClick={handleExportTemplates}
                variant="outline"
                className="w-full gap-2 justify-start bg-transparent"
              >
                <Download className="h-4 w-4" />
                Export Templates ({templates.length} templates)
              </Button>
              <p className="text-xs text-muted-foreground">Download all your saved templates.</p>
            </div>

            <Separator />

            {/* GDPR Full Export */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <Label>Complete Account Data (GDPR)</Label>
              </div>
              <Button
                onClick={handleExportAccountData}
                variant="outline"
                className="w-full gap-2 justify-start bg-transparent"
              >
                <Download className="h-4 w-4" />
                Export All Account Data
              </Button>
              <p className="text-xs text-muted-foreground">
                Download your complete account data including notes, templates, settings, and
                activity logs. This export complies with GDPR data portability requirements.
              </p>
            </div>
          </TabsContent>

          <TabsContent value="import" className="space-y-4 mt-4">
            <div className="space-y-2">
              <Label htmlFor="import-file">Import from Backup</Label>
              <div className="flex gap-2">
                <Button variant="outline" className="w-full gap-2 bg-transparent" asChild>
                  <label htmlFor="import-file" className="cursor-pointer">
                    <Upload className="h-4 w-4" />
                    Choose File to Import
                  </label>
                </Button>
              </div>
              <input
                id="import-file"
                type="file"
                accept=".json"
                onChange={handleImport}
                className="hidden"
              />
              <p className="text-xs text-muted-foreground">
                Import notes, templates, folders, and tags from a LeafLock backup file. This will
                add to your existing data without overwriting.
              </p>
            </div>

            <div className="p-4 bg-muted rounded-lg space-y-2">
              <p className="text-sm font-medium">Supported Import Formats:</p>
              <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                <li>Notes backup files (notes, folders, tags)</li>
                <li>Templates backup files</li>
                <li>Full account data exports</li>
              </ul>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
