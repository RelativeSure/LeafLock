import { useState } from 'react'
import { ChevronRight, ChevronDown, Folder, FolderOpen } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import type { Folder as FolderType } from '@/services/api'

interface FolderTreeProps {
  folders: FolderType[]
  selectedFolderId: string | null
  onSelectFolder: (folderId: string | null) => void
  onMoveFolderToParent?: (folderId: string, parentId: string | null) => void
  className?: string
}

interface FolderNodeProps {
  folder: FolderType
  level: number
  selectedFolderId: string | null
  onSelectFolder: (folderId: string | null) => void
  onMoveFolderToParent?: (folderId: string, parentId: string | null) => void
}

function FolderNode({
  folder,
  level,
  selectedFolderId,
  onSelectFolder,
  onMoveFolderToParent,
}: FolderNodeProps) {
  const [isExpanded, setIsExpanded] = useState(true)
  const [isDragOver, setIsDragOver] = useState(false)
  const hasChildren = folder.children && folder.children.length > 0
  const isSelected = selectedFolderId === folder.id

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation()
    setIsExpanded(!isExpanded)
  }

  const handleSelect = () => {
    onSelectFolder(folder.id)
  }

  const handleDragStart = (e: React.DragEvent) => {
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('folderId', folder.id)
    e.dataTransfer.setData('folderName', folder.name)
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setIsDragOver(true)
  }

  const handleDragLeave = () => {
    setIsDragOver(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragOver(false)

    const draggedFolderId = e.dataTransfer.getData('folderId')

    // Prevent dropping folder on itself
    if (draggedFolderId === folder.id) {
      return
    }

    // Prevent dropping folder on its own descendant
    const isDescendant = (parent: FolderType, targetId: string): boolean => {
      if (parent.id === targetId) return true
      if (!parent.children) return false
      return parent.children.some((child) => isDescendant(child, targetId))
    }

    if (isDescendant(folder, draggedFolderId)) {
      return
    }

    if (onMoveFolderToParent) {
      onMoveFolderToParent(draggedFolderId, folder.id)
    }
  }

  return (
    <div>
      <div
        draggable
        onDragStart={handleDragStart}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleSelect}
        className={cn(
          'flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer',
          'hover:bg-accent transition-colors',
          isSelected && 'bg-accent font-medium',
          isDragOver && 'bg-primary/10 border-2 border-primary border-dashed'
        )}
        style={{ paddingLeft: `${level * 1.5}rem` }}
      >
        {hasChildren && (
          <Button onClick={handleToggle} variant="ghost" size="sm" className="p-0.5 h-auto">
            {isExpanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </Button>
        )}
        {!hasChildren && <div className="w-5" />}

        {isExpanded || !hasChildren ? (
          <FolderOpen className="h-4 w-4" style={{ color: folder.color }} />
        ) : (
          <Folder className="h-4 w-4" style={{ color: folder.color }} />
        )}

        <span className="flex-1 truncate text-sm">{folder.name}</span>

        {hasChildren && (
          <span className="text-xs text-muted-foreground">{folder.children?.length}</span>
        )}
      </div>

      {hasChildren && isExpanded && (
        <div>
          {folder.children?.map((child) => (
            <FolderNode
              key={child.id}
              folder={child}
              level={level + 1}
              selectedFolderId={selectedFolderId}
              onSelectFolder={onSelectFolder}
              onMoveFolderToParent={onMoveFolderToParent}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export function FolderTree({
  folders,
  selectedFolderId,
  onSelectFolder,
  onMoveFolderToParent,
  className,
}: FolderTreeProps) {
  const handleDropOnRoot = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()

    const draggedFolderId = e.dataTransfer.getData('folderId')

    if (onMoveFolderToParent) {
      onMoveFolderToParent(draggedFolderId, null)
    }
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
  }

  return (
    <div
      className={cn('space-y-1', className)}
      onDragOver={handleDragOver}
      onDrop={handleDropOnRoot}
    >
      {folders.length === 0 ? (
        <div className="px-2 py-4 text-center text-sm text-muted-foreground">No folders yet</div>
      ) : (
        folders.map((folder) => (
          <FolderNode
            key={folder.id}
            folder={folder}
            level={0}
            selectedFolderId={selectedFolderId}
            onSelectFolder={onSelectFolder}
            onMoveFolderToParent={onMoveFolderToParent}
          />
        ))
      )}
    </div>
  )
}
