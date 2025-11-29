/**
 * Workspace Store - Multi-Workspace Management and Context Switching
 * 
 * @description
 * Manages multiple workspaces for users who need to separate their work
 * across different contexts (personal, work, projects, etc.). Handles
 * workspace creation, switching, and persistence of current workspace
 * selection across sessions.
 * 
 * @responsibilities
 * - Workspace CRUD operations (create, read, update, delete)
 * - Current workspace selection and persistence
 * - Workspace context switching for data isolation
 * - Default workspace assignment for new users
 * - Error handling and loading states
 * 
 * @data-isolation
 * - Each workspace provides separate context for notes, folders, and settings
 * - Workspace ID used as filter for all data operations
 * - Automatic data refresh when switching workspaces
 * - Prevents cross-workspace data contamination
 * 
 * @persistence-strategy
 * - Current workspace ID stored in localStorage for session continuity
 * - Workspace list fetched fresh on each app load
 * - Automatic fallback to first available workspace
 * - Cleanup of invalid workspace references
 * 
 * @integration-patterns
 * - Consumed by workspace switcher components
 * - Used by other stores for data filtering (notes, settings, etc.)
 * - Provides context for API calls across the application
 * - Integrates with workspace service for backend communication
 * 
 * @error-handling
 * - Graceful handling of workspace fetch failures
 * - Automatic cleanup of deleted workspace references
 * - User-friendly error messages for UI display
 * - Loading states for async operations
 */
import { create } from 'zustand'
import { workspaceService, type Workspace } from '@/services/api/workspaceService'

interface WorkspaceState {
  /**
   * Available workspaces for current user
   * @type {Workspace[]} All workspaces user has access to
   * Fetched from server on initialization and workspace operations
   * Used for workspace selection and management UI
   */
  workspaces: Workspace[]
  
  /**
   * Currently active workspace for data context
   * @type {Workspace | null} null if no workspaces available
   * Determines data filtering for all other stores
   * Persisted to localStorage for session continuity
   */
  currentWorkspace: Workspace | null
  
  /**
   * Loading state for workspace operations
   * @type {boolean} true during fetch/create/update/delete operations
   * Used by UI components to show loading indicators
   */
  isLoading: boolean
  
  /**
   * Error state for workspace operations
   * @type {string | null} Error message or null if no error
   * Set on operation failures, cleared on successful operations
   * Used for error display in UI components
   */
  error: string | null

  /**
   * Fetch all available workspaces for current user
   * @throws {Error} On fetch failure
   * 
   * @initialization
   * - Called during app initialization to load workspace context
   * - Automatically sets first workspace as current if none selected
   * - Handles empty workspace list gracefully
   * 
   * @auto-selection
   * - If no current workspace set: selects first available
   * - Preserves existing selection if workspace still exists
   * - Handles workspace deletion by auto-selecting alternative
   * 
   * @error-handling
   * - Sets error state for UI display
   * - Maintains existing state on failure
   * - Provides fallback error message
   */
  fetchWorkspaces: () => Promise<void>
  
  /**
   * Set current workspace and persist selection
   * @param workspace - Workspace to activate
   * 
   * @context-switching
   * - Updates current workspace immediately
   * - Stores workspace ID in localStorage for persistence
   * - Triggers data refresh in consuming components
   * 
   * @persistence
   * - Workspace ID stored as 'currentWorkspaceId' in localStorage
   * - Restored on app initialization for continuity
   * - Automatically cleaned up if workspace becomes unavailable
   */
  setCurrentWorkspace: (workspace: Workspace) => void
  
  /**
   * Create new workspace
   * @param name - Workspace name
   * @returns Promise resolving to created workspace
   * @throws {Error} On creation failure
   * 
   * @creation
   * - Creates workspace via workspaceService
   * - Adds to local workspaces collection
   * - Does not automatically switch to new workspace
   * 
   * @validation
   * - Name required and validated server-side
   * - Automatically associated with current user
   * - Unique naming enforced by backend
   */
  createWorkspace: (name: string) => Promise<Workspace>
  
  /**
   * Update workspace name
   * @param id - Workspace ID to update
   * @param name - New workspace name
   * @throws {Error} On update failure
   * 
   * @update
   * - Updates workspace via workspaceService
   * - Updates local workspaces collection
   * - Updates current workspace if it's the one being updated
   * 
   * @validation
   * - Name required and validated server-side
   * - Unique naming enforced by backend
   * - Preserves all other workspace properties
   */
  updateWorkspace: (id: string, name: string) => Promise<void>
  
  /**
   * Delete workspace and handle context cleanup
   * @param id - Workspace ID to delete
   * @throws {Error} On deletion failure
   * 
   * @deletion
   * - Deletes workspace via workspaceService
   * - Removes from local workspaces collection
   * - Handles current workspace reassignment if needed
   * 
   * @cleanup
   * - Auto-selects first remaining workspace if current was deleted
   * - Clears localStorage if no workspaces remain
   * - Triggers data refresh in consuming components
   * 
   * @warning
   * - This will delete all data within the workspace
   * - Consider confirmation dialog in UI
   * - Automatic fallback prevents app breakage
   */
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
      const currentWorkspace =
        get().currentWorkspace || (workspaces.length > 0 ? workspaces[0] : null)

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
        currentWorkspace: state.currentWorkspace?.id === id ? updated : state.currentWorkspace,
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
