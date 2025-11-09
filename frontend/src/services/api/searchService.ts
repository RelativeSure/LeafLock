import { apiClient } from './apiClient'

export interface SearchFilters {
  tags?: string[]
  folder_ids?: string[]
  start_date?: string
  end_date?: string
  is_pinned?: boolean
  is_locked?: boolean
  is_trashed?: boolean
  sort_by?: 'created_at' | 'updated_at'
  sort_order?: 'asc' | 'desc'
  limit?: number
  offset?: number
}

export interface NoteMetadata {
  id: string
  folder_id?: string | null
  tags: string[]
  is_pinned: boolean
  is_locked: boolean
  created_at: string
  updated_at: string
}

export interface SearchResponse {
  notes: NoteMetadata[]
  total: number
  limit: number
  offset: number
}

export const searchService = {
  /**
   * Search notes by metadata filters
   * Note: Content search is performed client-side after decryption
   */
  searchNotes: async (filters: SearchFilters = {}): Promise<SearchResponse> => {
    return await apiClient.post<SearchResponse>('/search', filters)
  },
}
