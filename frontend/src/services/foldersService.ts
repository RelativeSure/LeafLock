/**
 * Folders service for managing folder hierarchy
 */

export interface Folder {
  id: string
  parent_id?: string
  name: string
  color: string
  position: number
  created_at: string
  updated_at: string
}

export interface CreateFolderRequest {
  name: string
  parent_id?: string
  color?: string
  position?: number
}

export interface UpdateFolderRequest {
  name: string
  parent_id?: string
  color?: string
  position?: number
}

export interface MoveNoteToFolderRequest {
  folder_id?: string
}

export interface FoldersResponse {
  folders: Folder[]
}

class FoldersService {
  private baseUrl: string

  constructor() {
    this.baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8080'
  }

  private getAuthHeaders(): Record<string, string> {
    const token = localStorage.getItem('auth_token')
    const csrfToken = localStorage.getItem('csrf_token')

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken
    }

    return headers
  }

  /**
   * Get all folders for the current user
   */
  async getFolders(): Promise<Folder[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/folders`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to fetch folders')
    }

    const data: FoldersResponse = await response.json()
    return data.folders
  }

  /**
   * Create a new folder
   */
  async createFolder(folder: CreateFolderRequest): Promise<Folder> {
    const response = await fetch(`${this.baseUrl}/api/v1/folders`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(folder),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to create folder')
    }

    return response.json()
  }

  /**
   * Update a folder
   */
  async updateFolder(folderId: string, folder: UpdateFolderRequest): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v1/folders/${folderId}`, {
      method: 'PUT',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(folder),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to update folder')
    }
  }

  /**
   * Delete a folder
   */
  async deleteFolder(folderId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v1/folders/${folderId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to delete folder')
    }
  }

  /**
   * Move a note to a different folder
   */
  async moveNoteToFolder(noteId: string, folderId?: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v1/notes/${noteId}/folder`, {
      method: 'PUT',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ folder_id: folderId }),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to move note')
    }
  }

  /**
   * Build a hierarchical folder tree from flat array
   */
  buildFolderTree(folders: Folder[]): FolderTreeNode[] {
    const folderMap = new Map<string, FolderTreeNode>()
    const rootFolders: FolderTreeNode[] = []

    // Create folder nodes
    folders.forEach(folder => {
      folderMap.set(folder.id, {
        ...folder,
        children: []
      })
    })

    // Build hierarchy
    folders.forEach(folder => {
      const node = folderMap.get(folder.id)!

      if (folder.parent_id) {
        const parent = folderMap.get(folder.parent_id)
        if (parent) {
          parent.children.push(node)
        } else {
          // Parent not found, treat as root
          rootFolders.push(node)
        }
      } else {
        rootFolders.push(node)
      }
    })

    // Sort by position
    const sortByPosition = (nodes: FolderTreeNode[]) => {
      nodes.sort((a, b) => a.position - b.position)
      nodes.forEach(node => sortByPosition(node.children))
    }

    sortByPosition(rootFolders)
    return rootFolders
  }

  /**
   * Get all descendant folder IDs for a given folder
   */
  getDescendantIds(folderId: string, folders: Folder[]): string[] {
    const descendants: string[] = []
    const children = folders.filter(f => f.parent_id === folderId)

    children.forEach(child => {
      descendants.push(child.id)
      descendants.push(...this.getDescendantIds(child.id, folders))
    })

    return descendants
  }

  /**
   * Check if moving a folder would create a circular reference
   */
  wouldCreateCircularReference(folderId: string, newParentId: string, folders: Folder[]): boolean {
    if (folderId === newParentId) return true

    const descendants = this.getDescendantIds(folderId, folders)
    return descendants.includes(newParentId)
  }
}

export interface FolderTreeNode extends Folder {
  children: FolderTreeNode[]
}

export const foldersService = new FoldersService()