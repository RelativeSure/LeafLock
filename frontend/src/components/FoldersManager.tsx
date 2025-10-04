import React, { useState, useEffect } from 'react'
import { Plus, X, Folder, FolderOpen, Edit3, Trash2, ChevronRight, ChevronDown } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Label } from './ui/label'
import { foldersService, Folder as FolderType, FolderTreeNode, CreateFolderRequest } from '../services/foldersService'
import { Spinner } from '@/components/ui/spinner'

interface FoldersManagerProps {
  onClose?: () => void
  onFoldersChange?: (folders: FolderType[]) => void
}

const defaultColors = [
  '#3b82f6', // blue
  '#ef4444', // red
  '#10b981', // green
  '#f59e0b', // yellow
  '#8b5cf6', // purple
  '#f97316', // orange
  '#06b6d4', // cyan
  '#84cc16', // lime
  '#ec4899', // pink
  '#6b7280', // gray
]

export const FoldersManager: React.FC<FoldersManagerProps> = ({ onClose, onFoldersChange }) => {
  const [folders, setFolders] = useState<FolderType[]>([])
  const [folderTree, setFolderTree] = useState<FolderTreeNode[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set())
  const [newFolder, setNewFolder] = useState<CreateFolderRequest>({
    name: '',
    color: defaultColors[0],
    parent_id: undefined
  })

  const loadFolders = async () => {
    try {
      setError(null)
      const fetchedFolders = await foldersService.getFolders()
      setFolders(fetchedFolders)
      setFolderTree(foldersService.buildFolderTree(fetchedFolders))
      onFoldersChange?.(fetchedFolders)
    } catch (err) {
      console.error('Failed to load folders:', err)
      setError(err instanceof Error ? err.message : 'Failed to load folders')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadFolders()
  }, [])

  const handleCreateFolder = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newFolder.name.trim()) return

    try {
      setError(null)
      setIsCreating(true)
      await foldersService.createFolder(newFolder)
      setNewFolder({ name: '', color: defaultColors[0], parent_id: undefined })
      await loadFolders()
    } catch (err) {
      console.error('Failed to create folder:', err)
      setError(err instanceof Error ? err.message : 'Failed to create folder')
    } finally {
      setIsCreating(false)
    }
  }

  const handleDeleteFolder = async (folderId: string) => {
    if (!confirm('Are you sure you want to delete this folder? Notes will be moved to the parent folder.')) {
      return
    }

    try {
      setError(null)
      await foldersService.deleteFolder(folderId)
      await loadFolders()
    } catch (err) {
      console.error('Failed to delete folder:', err)
      setError(err instanceof Error ? err.message : 'Failed to delete folder')
    }
  }

  const toggleExpanded = (folderId: string) => {
    const newExpanded = new Set(expandedFolders)
    if (newExpanded.has(folderId)) {
      newExpanded.delete(folderId)
    } else {
      newExpanded.add(folderId)
    }
    setExpandedFolders(newExpanded)
  }

  const handleRenameFolder = async (node: FolderTreeNode) => {
    const newName = window.prompt('Rename folder', node.name)
    if (!newName || !newName.trim() || newName.trim() === node.name) {
      return
    }

    try {
      setError(null)
      await foldersService.updateFolder(node.id, {
        name: newName.trim(),
        color: node.color,
        parent_id: node.parent_id || undefined,
        position: node.position,
      })
      await loadFolders()
    } catch (err) {
      console.error('Failed to rename folder:', err)
      setError(err instanceof Error ? err.message : 'Failed to rename folder')
    }
  }

  const renderFolderNode = (node: FolderTreeNode, depth = 0) => {
    const isExpanded = expandedFolders.has(node.id)
    const hasChildren = node.children.length > 0

    return (
      <div key={node.id}>
        <div
          className="flex items-center gap-2 p-2 hover:bg-gray-50 rounded group"
          style={{ marginLeft: `${depth * 20}px` }}
        >
          {hasChildren ? (
            <button
              onClick={() => toggleExpanded(node.id)}
              className="w-4 h-4 flex items-center justify-center hover:bg-gray-200 rounded"
            >
              {isExpanded ? (
                <ChevronDown className="w-3 h-3" />
              ) : (
                <ChevronRight className="w-3 h-3" />
              )}
            </button>
          ) : (
            <div className="w-4 h-4" />
          )}

          <div className="flex items-center gap-2 flex-1">
            {hasChildren && isExpanded ? (
              <FolderOpen className="w-4 h-4" style={{ color: node.color }} />
            ) : (
              <Folder className="w-4 h-4" style={{ color: node.color }} />
            )}
            <span className="text-sm font-medium">{node.name}</span>
          </div>

          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setNewFolder({ ...newFolder, parent_id: node.id })}
              className="h-6 w-6 p-0"
              title="Add subfolder"
            >
              <Plus className="w-3 h-3" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleRenameFolder(node)}
              className="h-6 w-6 p-0"
              title="Rename folder"
            >
              <Edit3 className="w-3 h-3" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleDeleteFolder(node.id)}
              className="h-6 w-6 p-0 text-red-600 hover:text-red-700 hover:bg-red-50"
              title="Delete folder"
            >
              <Trash2 className="w-3 h-3" />
            </Button>
          </div>
        </div>

        {hasChildren && isExpanded && (
          <div>
            {node.children.map(child => renderFolderNode(child, depth + 1))}
          </div>
        )}
      </div>
    )
  }

  if (loading) {
    return (
      <Card className="w-full max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Folder className="w-5 h-5" />
            Folders Manager
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <Spinner className="h-6 w-6 text-primary" />
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full max-w-2xl">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <CardTitle className="flex items-center gap-2">
          <Folder className="w-5 h-5" />
          Folders Manager
        </CardTitle>
        {onClose && (
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="w-4 h-4" />
          </Button>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-red-600 text-sm">
            {error}
          </div>
        )}

        {/* Create New Folder Form */}
        <form onSubmit={handleCreateFolder} className="space-y-3 p-3 bg-gray-50 rounded">
          <div>
            <Label htmlFor="folder-name">Folder Name</Label>
            <Input
              id="folder-name"
              type="text"
              value={newFolder.name}
              onChange={(e) => setNewFolder({ ...newFolder, name: e.target.value })}
              placeholder="Enter folder name..."
              maxLength={100}
              disabled={isCreating}
            />
          </div>

          <div>
            <Label>Color</Label>
            <div className="flex gap-2 mt-2">
              {defaultColors.map((color) => (
                <button
                  key={color}
                  type="button"
                  className={`w-6 h-6 rounded-full border-2 ${
                    newFolder.color === color ? 'border-gray-900' : 'border-gray-300'
                  }`}
                  style={{ backgroundColor: color }}
                  onClick={() => setNewFolder({ ...newFolder, color })}
                  disabled={isCreating}
                />
              ))}
            </div>
          </div>

          {newFolder.parent_id && (
            <div className="text-sm text-gray-600">
              Parent: {folders.find(f => f.id === newFolder.parent_id)?.name}
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setNewFolder({ ...newFolder, parent_id: undefined })}
                className="ml-2 h-5 w-5 p-0"
              >
                <X className="w-3 h-3" />
              </Button>
            </div>
          )}

          <Button
            type="submit"
            disabled={!newFolder.name.trim() || isCreating}
            className="w-full"
          >
            {isCreating ? (
              <div className="flex items-center gap-2">
                <Spinner className="h-4 w-4 text-white" aria-hidden="true" />
                Creating...
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Plus className="w-4 h-4" />
                Create Folder
              </div>
            )}
          </Button>
        </form>

        {/* Folder Tree */}
        <div>
          <Label>Your Folders ({folders.length})</Label>
          {folderTree.length === 0 ? (
            <div className="text-center py-6 text-gray-500">
              <Folder className="w-8 h-8 mx-auto mb-2 text-gray-300" />
              <p>No folders yet</p>
              <p className="text-sm">Create your first folder above</p>
            </div>
          ) : (
            <div className="mt-2 border rounded bg-white">
              {folderTree.map(node => renderFolderNode(node))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export default FoldersManager
