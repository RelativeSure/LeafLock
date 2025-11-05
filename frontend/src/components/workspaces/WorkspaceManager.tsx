import { useState } from 'react'
import { Plus, Edit2, Trash2, Folder } from 'lucide-react'
import { useWorkspaceStore } from '@/stores/workspaceStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { useToast } from '@/hooks/use-toast'

export function WorkspaceManager() {
  const { workspaces, createWorkspace, updateWorkspace, deleteWorkspace } =
    useWorkspaceStore()
  const { toast } = useToast()

  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [isEditOpen, setIsEditOpen] = useState(false)
  const [isDeleteOpen, setIsDeleteOpen] = useState(false)

  const [newWorkspaceName, setNewWorkspaceName] = useState('')
  const [editingWorkspace, setEditingWorkspace] = useState<{
    id: string
    name: string
  } | null>(null)
  const [deletingWorkspaceId, setDeletingWorkspaceId] = useState<string | null>(null)

  const handleCreate = async () => {
    if (!newWorkspaceName.trim()) return

    try {
      await createWorkspace(newWorkspaceName)
      setNewWorkspaceName('')
      setIsCreateOpen(false)
      toast({
        title: 'Success',
        description: 'Workspace created successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to create workspace',
        variant: 'destructive',
      })
    }
  }

  const handleEdit = async () => {
    if (!editingWorkspace || !editingWorkspace.name.trim()) return

    try {
      await updateWorkspace(editingWorkspace.id, editingWorkspace.name)
      setEditingWorkspace(null)
      setIsEditOpen(false)
      toast({
        title: 'Success',
        description: 'Workspace updated successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update workspace',
        variant: 'destructive',
      })
    }
  }

  const handleDelete = async () => {
    if (!deletingWorkspaceId) return

    try {
      await deleteWorkspace(deletingWorkspaceId)
      setDeletingWorkspaceId(null)
      setIsDeleteOpen(false)
      toast({
        title: 'Success',
        description: 'Workspace deleted successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to delete workspace',
        variant: 'destructive',
      })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Workspaces</h2>
          <p className="text-muted-foreground">
            Organize your notes into separate workspaces
          </p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              New Workspace
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Workspace</DialogTitle>
              <DialogDescription>
                Create a new workspace to organize your notes
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="workspace-name">Name</Label>
                <Input
                  id="workspace-name"
                  value={newWorkspaceName}
                  onChange={(e) => setNewWorkspaceName(e.target.value)}
                  placeholder="My Workspace"
                  onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreate}>Create</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {workspaces.map((workspace) => (
          <Card key={workspace.id}>
            <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
              <div className="flex items-center gap-2">
                <Folder className="h-5 w-5 text-primary" />
                <CardTitle className="text-lg">{workspace.name}</CardTitle>
              </div>
              <div className="flex gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setEditingWorkspace({ id: workspace.id, name: workspace.name })
                    setIsEditOpen(true)
                  }}
                >
                  <Edit2 className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setDeletingWorkspaceId(workspace.id)
                    setIsDeleteOpen(true)
                  }}
                >
                  <Trash2 className="h-4 w-4 text-destructive" />
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Created {new Date(workspace.created_at).toLocaleDateString()}
              </CardDescription>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Edit Dialog */}
      <Dialog open={isEditOpen} onOpenChange={setIsEditOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Workspace</DialogTitle>
            <DialogDescription>Update the workspace name</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-workspace-name">Name</Label>
              <Input
                id="edit-workspace-name"
                value={editingWorkspace?.name || ''}
                onChange={(e) =>
                  setEditingWorkspace(
                    editingWorkspace
                      ? { ...editingWorkspace, name: e.target.value }
                      : null
                  )
                }
                onKeyDown={(e) => e.key === 'Enter' && handleEdit()}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsEditOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleEdit}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={isDeleteOpen} onOpenChange={setIsDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Workspace?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the workspace and all its contents. This
              action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className="bg-destructive">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
