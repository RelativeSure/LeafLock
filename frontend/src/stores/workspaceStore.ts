import { create } from 'zustand'
import { workspaceService, type Workspace } from '@/services/api/workspaceService'

interface WorkspaceState {
  workspaces: Workspace[]
  currentWorkspace: Workspace | null
  isLoading: boolean
  error: string | null

  fetchWorkspaces: () => Promise<void>
  setCurrentWorkspace: (workspace: Workspace) => void
  createWorkspace: (name: string) => Promise<Workspace>
  updateWorkspace: (id: string, name: string) => Promise<void>
  deleteWorkspace: (id: string) => Promise<void>
}

export const useWorkspaceStore = create<WorkspaceState>((set, get) => ({
  workspaces: [],
  currentWorkspace: null,
  isLoading: false,
  error: null,

  fetchWorkspaces: async () => {
    set({ isLoading: true, error: null })
    try {
      const workspaces = await workspaceService.getWorkspaces()

      // If no current workspace is set, set the first one
      const currentWorkspace = get().currentWorkspace || (workspaces.length > 0 ? workspaces[0] : null)

      set({ workspaces, currentWorkspace, isLoading: false })
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to fetch workspaces',
        isLoading: false,
      })
    }
  },

  setCurrentWorkspace: (workspace: Workspace) => {
    set({ currentWorkspace: workspace })
    // Store in localStorage for persistence
    localStorage.setItem('currentWorkspaceId', workspace.id)
  },

  createWorkspace: async (name: string) => {
    try {
      const workspace = await workspaceService.createWorkspace({ name })
      set((state) => ({
        workspaces: [...state.workspaces, workspace],
      }))
      return workspace
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Failed to create workspace' })
      throw error
    }
  },

  updateWorkspace: async (id: string, name: string) => {
    try {
      const updated = await workspaceService.updateWorkspace(id, { name })
      set((state) => ({
        workspaces: state.workspaces.map((w) => (w.id === id ? updated : w)),
        currentWorkspace:
          state.currentWorkspace?.id === id ? updated : state.currentWorkspace,
      }))
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Failed to update workspace' })
      throw error
    }
  },

  deleteWorkspace: async (id: string) => {
    try {
      await workspaceService.deleteWorkspace(id)

      set((state) => {
        const newWorkspaces = state.workspaces.filter((w) => w.id !== id)
        const newCurrentWorkspace =
          state.currentWorkspace?.id === id
            ? newWorkspaces.length > 0
              ? newWorkspaces[0]
              : null
            : state.currentWorkspace

        return {
          workspaces: newWorkspaces,
          currentWorkspace: newCurrentWorkspace,
        }
      })

      // Update localStorage
      const newCurrent = get().currentWorkspace
      if (newCurrent) {
        localStorage.setItem('currentWorkspaceId', newCurrent.id)
      } else {
        localStorage.removeItem('currentWorkspaceId')
      }
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Failed to delete workspace' })
      throw error
    }
  },
}))
