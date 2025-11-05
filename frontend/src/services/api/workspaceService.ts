import { apiClient } from './apiClient'

export interface Workspace {
  id: string
  name: string
  owner_id: string
  created_at: string
  updated_at: string
}

export interface CreateWorkspaceRequest {
  name: string
}

export interface UpdateWorkspaceRequest {
  name: string
}

export const workspaceService = {
  /**
   * Get all workspaces for the current user
   */
  getWorkspaces: async (): Promise<Workspace[]> => {
    const response = await apiClient.get('/workspaces')
    return response.data.workspaces || []
  },

  /**
   * Get a specific workspace
   */
  getWorkspace: async (id: string): Promise<Workspace> => {
    const response = await apiClient.get(`/workspaces/${id}`)
    return response.data
  },

  /**
   * Create a new workspace
   */
  createWorkspace: async (data: CreateWorkspaceRequest): Promise<Workspace> => {
    const response = await apiClient.post('/workspaces', data)
    return response.data
  },

  /**
   * Update a workspace
   */
  updateWorkspace: async (id: string, data: UpdateWorkspaceRequest): Promise<Workspace> => {
    const response = await apiClient.put(`/workspaces/${id}`, data)
    return response.data
  },

  /**
   * Delete a workspace
   */
  deleteWorkspace: async (id: string): Promise<void> => {
    await apiClient.delete(`/workspaces/${id}`)
  },
}
