'use client'

import { useState, useEffect } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { useToast } from '../../hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Slider } from '@/components/ui/slider'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { HoverCard, HoverCardContent, HoverCardTrigger } from '@/components/ui/hover-card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  History,
  RotateCcw,
  Trash2,
  Clock,
  User,
  FileText,
  Calendar,
  Settings,
  GitCompare,
} from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import { diffWords, Change } from 'diff'
import type { NoteVersion } from '@/types'

interface VersionHistoryDialogProps {
  noteId: string
  noteTitle: string
  children: React.ReactNode
}

export function VersionHistoryDialog({ noteId, noteTitle, children }: VersionHistoryDialogProps) {
  const [open, setOpen] = useState(false)
  const [versions, setVersions] = useState<NoteVersion[]>([])
  const [loading, setLoading] = useState(false)
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [changeDescription, setChangeDescription] = useState('')
  const [showRestoreDialog, setShowRestoreDialog] = useState(false)
  const [versionToRestore, setVersionToRestore] = useState<NoteVersion | null>(null)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [versionToDelete, setVersionToDelete] = useState<NoteVersion | null>(null)
  const [activeTab, setActiveTab] = useState('timeline')
  const [compareV1, setCompareV1] = useState<string>('')
  const [compareV2, setCompareV2] = useState<string>('')
  const [comparisonData, setComparisonData] = useState<{ v1: NoteVersion; v2: NoteVersion } | null>(
    null
  )
  const [retentionPolicy, setRetentionPolicy] = useState(20)
  const [isSavingRetention, setIsSavingRetention] = useState(false)

  const {
    createNoteVersion,
    getNoteVersions,
    restoreNoteVersion,
    deleteNoteVersion,
    compareNoteVersions,
    updateRetentionPolicy,
  } = useNotesStore()
  const { toast } = useToast()

  const loadVersions = async () => {
    setLoading(true)
    try {
      const versionList = await getNoteVersions(noteId)
      setVersions(
        versionList.sort(
          (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
        )
      )

      // Set default comparison values
      if (versionList.length >= 2) {
        setCompareV1(versionList[0].versionNumber.toString())
        setCompareV2(versionList[1].versionNumber.toString())
      }
    } catch (error) {
      toast.error('Failed to load version history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (open) {
      loadVersions()
    }
  }, [open, noteId])

  const handleCreateVersion = async () => {
    if (!changeDescription.trim()) {
      toast.error('Please enter a description for this version.')
      return
    }

    try {
      await createNoteVersion(noteId, changeDescription)
      toast.success('Version saved', {
        description: 'A new version has been saved successfully.',
      })
      setChangeDescription('')
      setShowCreateDialog(false)
      loadVersions()
    } catch (error) {
      toast.error('Failed to create version.')
    }
  }

  const handleRestoreVersion = async () => {
    if (!versionToRestore) return

    try {
      await restoreNoteVersion(versionToRestore.id)
      toast.success('Version restored', {
        description: `Restored to version from ${format(new Date(versionToRestore.createdAt), 'MMM d, yyyy')}.`,
      })
      setShowRestoreDialog(false)
      setVersionToRestore(null)
      setOpen(false)
    } catch (error) {
      toast.error('Failed to restore version.')
    }
  }

  const handleDeleteVersion = async () => {
    if (!versionToDelete) return

    try {
      await deleteNoteVersion(versionToDelete.id)
      toast.success('Version deleted', {
        description: 'Version has been permanently deleted.',
      })
      setShowDeleteDialog(false)
      setVersionToDelete(null)
      loadVersions()
    } catch (error) {
      toast.error('Failed to delete version.')
    }
  }

  const handleCompare = async () => {
    if (!compareV1 || !compareV2) {
      toast.error('Please select two versions to compare.')
      return
    }

    try {
      const result = await compareNoteVersions(noteId, parseInt(compareV1), parseInt(compareV2))
      setComparisonData(result)
    } catch (error) {
      toast.error('Failed to compare versions.')
    }
  }

  const handleSaveRetention = async () => {
    setIsSavingRetention(true)
    try {
      await updateRetentionPolicy(noteId, retentionPolicy)
      toast.success('Retention policy updated', {
        description: `Retention policy updated to ${retentionPolicy} versions.`,
      })
    } catch (error) {
      toast.error('Failed to update retention policy.')
    } finally {
      setIsSavingRetention(false)
    }
  }

  const openRestoreDialog = (version: NoteVersion) => {
    setVersionToRestore(version)
    setShowRestoreDialog(true)
  }

  const openDeleteDialog = (version: NoteVersion) => {
    setVersionToDelete(version)
    setShowDeleteDialog(true)
  }

  const renderDiff = (text1: string, text2: string) => {
    const changes = diffWords(text1, text2)

    return (
      <div className="font-mono text-sm">
        {changes.map((change: Change, index: number) => {
          if (change.added) {
            return (
              <span
                key={index}
                className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200"
              >
                {change.value}
              </span>
            )
          }
          if (change.removed) {
            return (
              <span
                key={index}
                className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 line-through"
              >
                {change.value}
              </span>
            )
          }
          return <span key={index}>{change.value}</span>
        })}
      </div>
    )
  }

  return (
    <>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTrigger asChild>{children}</DialogTrigger>
        <DialogContent className="max-w-5xl max-h-[85vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              Version History
            </DialogTitle>
            <DialogDescription>View and manage versions for "{noteTitle}"</DialogDescription>
          </DialogHeader>

          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="timeline">
                <History className="h-4 w-4 mr-2" />
                Timeline
              </TabsTrigger>
              <TabsTrigger value="compare">
                <GitCompare className="h-4 w-4 mr-2" />
                Compare
              </TabsTrigger>
              <TabsTrigger value="settings">
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </TabsTrigger>
            </TabsList>

            {/* Timeline Tab */}
            <TabsContent value="timeline" className="space-y-4 mt-4">
              <div className="flex justify-between items-center">
                <div className="text-sm text-muted-foreground">
                  {versions.length} version{versions.length !== 1 ? 's' : ''} available
                </div>
                <Button onClick={() => setShowCreateDialog(true)} size="sm">
                  <FileText className="h-4 w-4 mr-2" />
                  Create Version
                </Button>
              </div>

              <ScrollArea className="h-[450px]">
                {loading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                  </div>
                ) : versions.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No versions available</p>
                    <p className="text-sm">Create your first version to start tracking changes</p>
                  </div>
                ) : (
                  <div className="space-y-3 pr-4">
                    {versions.map((version, index) => (
                      <HoverCard key={version.id}>
                        <HoverCardTrigger asChild>
                          <Card className="transition-all hover:shadow-md cursor-pointer">
                            <CardHeader className="pb-3">
                              <div className="flex items-start justify-between">
                                <div className="space-y-1 flex-1">
                                  <div className="flex items-center gap-2">
                                    <Badge variant="outline" className="text-xs">
                                      v{version.versionNumber}
                                    </Badge>
                                    {index === 0 && (
                                      <Badge variant="default" className="text-xs">
                                        Current
                                      </Badge>
                                    )}
                                  </div>
                                  <CardTitle className="text-sm">
                                    {version.changeDescription || 'No description'}
                                  </CardTitle>
                                  <CardDescription className="text-xs">
                                    <div className="flex items-center gap-4">
                                      <span className="flex items-center gap-1">
                                        <Calendar className="h-3 w-3" />
                                        {format(new Date(version.createdAt), 'MMM d, yyyy')}
                                      </span>
                                      <span className="flex items-center gap-1">
                                        <Clock className="h-3 w-3" />
                                        {formatDistanceToNow(new Date(version.createdAt), {
                                          addSuffix: true,
                                        })}
                                      </span>
                                      <span className="flex items-center gap-1">
                                        <User className="h-3 w-3" />
                                        {version.createdBy}
                                      </span>
                                    </div>
                                  </CardDescription>
                                </div>
                                <div className="flex items-center gap-1">
                                  {index > 0 && (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => openRestoreDialog(version)}
                                      className="h-8 w-8 p-0"
                                    >
                                      <RotateCcw className="h-4 w-4" />
                                    </Button>
                                  )}
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => openDeleteDialog(version)}
                                    className="h-8 w-8 p-0 text-destructive hover:text-destructive"
                                  >
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </div>
                              </div>
                            </CardHeader>
                          </Card>
                        </HoverCardTrigger>
                        <HoverCardContent className="w-96">
                          <div className="space-y-2">
                            <h4 className="text-sm font-semibold">{version.title || 'Untitled'}</h4>
                            <p className="text-xs text-muted-foreground line-clamp-4">
                              {version.content.replace(/<[^>]*>/g, '')}
                            </p>
                          </div>
                        </HoverCardContent>
                      </HoverCard>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </TabsContent>

            {/* Compare Tab */}
            <TabsContent value="compare" className="space-y-4 mt-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Version 1</Label>
                  <Select value={compareV1} onValueChange={setCompareV1}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select version" />
                    </SelectTrigger>
                    <SelectContent>
                      {versions.map((v) => (
                        <SelectItem key={v.id} value={v.versionNumber.toString()}>
                          v{v.versionNumber} - {format(new Date(v.createdAt), 'MMM d, yyyy')}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Version 2</Label>
                  <Select value={compareV2} onValueChange={setCompareV2}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select version" />
                    </SelectTrigger>
                    <SelectContent>
                      {versions.map((v) => (
                        <SelectItem key={v.id} value={v.versionNumber.toString()}>
                          v{v.versionNumber} - {format(new Date(v.createdAt), 'MMM d, yyyy')}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Button onClick={handleCompare} className="w-full">
                <GitCompare className="h-4 w-4 mr-2" />
                Compare Versions
              </Button>

              {comparisonData && (
                <ScrollArea className="h-[400px]">
                  <div className="space-y-4 pr-4">
                    <div>
                      <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                        <Badge variant="outline">v{comparisonData.v1.versionNumber}</Badge>
                        Title Comparison
                      </h3>
                      <Card>
                        <CardContent className="pt-4">
                          {renderDiff(comparisonData.v2.title || '', comparisonData.v1.title || '')}
                        </CardContent>
                      </Card>
                    </div>

                    <div>
                      <h3 className="text-sm font-semibold mb-2">Content Comparison</h3>
                      <Card>
                        <CardContent className="pt-4 max-h-[300px] overflow-auto">
                          {renderDiff(
                            comparisonData.v2.content.replace(/<[^>]*>/g, ''),
                            comparisonData.v1.content.replace(/<[^>]*>/g, '')
                          )}
                        </CardContent>
                      </Card>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">
                            Version {comparisonData.v1.versionNumber}
                          </CardTitle>
                          <CardDescription className="text-xs">
                            {format(new Date(comparisonData.v1.createdAt), 'PPpp')}
                          </CardDescription>
                        </CardHeader>
                      </Card>
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">
                            Version {comparisonData.v2.versionNumber}
                          </CardTitle>
                          <CardDescription className="text-xs">
                            {format(new Date(comparisonData.v2.createdAt), 'PPpp')}
                          </CardDescription>
                        </CardHeader>
                      </Card>
                    </div>
                  </div>
                </ScrollArea>
              )}
            </TabsContent>

            {/* Settings Tab */}
            <TabsContent value="settings" className="space-y-6 mt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Version Retention Policy</CardTitle>
                  <CardDescription>
                    Control how many versions are kept for this note
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <Label>Keep last {retentionPolicy} versions</Label>
                      <Badge variant="outline">{retentionPolicy} versions</Badge>
                    </div>
                    <Slider
                      value={[retentionPolicy]}
                      onValueChange={(value) => setRetentionPolicy(value[0])}
                      min={10}
                      max={50}
                      step={10}
                      className="w-full"
                    />
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>10 (Minimal)</span>
                      <span>20 (Balanced)</span>
                      <span>50 (Maximum)</span>
                    </div>
                  </div>

                  <Button
                    onClick={handleSaveRetention}
                    disabled={isSavingRetention}
                    className="w-full"
                  >
                    {isSavingRetention ? 'Saving...' : 'Save Retention Policy'}
                  </Button>

                  <div className="text-xs text-muted-foreground space-y-1">
                    <p>• Older versions beyond the limit will be automatically deleted</p>
                    <p>• Current version is always kept regardless of the policy</p>
                    <p>• Lower values save storage space but keep less history</p>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Version Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Version</DialogTitle>
            <DialogDescription>
              Save the current state of this note as a new version.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="changeDescription">Change Description</Label>
              <Input
                id="changeDescription"
                value={changeDescription}
                onChange={(e) => setChangeDescription(e.target.value)}
                placeholder="Describe what changed in this version..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateVersion}>Create Version</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Restore Version Dialog */}
      <AlertDialog open={showRestoreDialog} onOpenChange={setShowRestoreDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Restore Version</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to restore this version? This will replace the current content
              of the note.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleRestoreVersion}>Restore Version</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Version Dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Version</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to permanently delete this version? This action cannot be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteVersion}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete Version
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
