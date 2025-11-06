import { apiClient } from './apiClient'

export interface UserStats {
  total_notes: number
  total_folders: number
  total_tags: number
  total_collaborations: number
  notes_created_today: number
  notes_created_week: number
  notes_created_month: number
  activity_by_day: ActivityData[]
  notes_by_folder: CountData[]
  notes_by_tag: CountData[]
  recent_activity: RecentActivityEntry[]
}

export interface ActivityData {
  date: string
  count: number
}

export interface CountData {
  name: string
  count: number
}

export interface RecentActivityEntry {
  type: string
  message: string
  timestamp: string
}

export interface AdminStats {
  total_users: number
  total_notes: number
  total_workspaces: number
  active_users: number
  user_growth: ActivityData[]
  note_growth: ActivityData[]
}

export const analyticsService = {
  async getUserAnalytics(): Promise<UserStats> {
    const response = await apiClient.get('/analytics')
    return response.data
  },

  async getAdminAnalytics(): Promise<AdminStats> {
    const response = await apiClient.get('/admin/analytics')
    return response.data
  },
}
