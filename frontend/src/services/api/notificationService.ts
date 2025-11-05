import { apiClient } from './apiClient'

export interface Notification {
  id: string
  user_id: string
  type:
    | 'note_shared'
    | 'note_commented'
    | 'folder_shared'
    | 'mention'
    | 'system'
    | 'collaboration_invite'
  title: string
  message: string
  action_url?: string | null
  metadata: Record<string, unknown>
  is_read: boolean
  created_at: string
  read_at?: string | null
}

export interface NotificationsResponse {
  notifications: Notification[]
  unread_count: number
  limit: number
  offset: number
}

export interface CreateNotificationRequest {
  type: string
  title: string
  message: string
  action_url?: string | null
  metadata?: Record<string, unknown>
}

export const notificationService = {
  /**
   * Get all notifications for the current user
   */
  getNotifications: async (
    limit = 50,
    offset = 0,
    unreadOnly = false
  ): Promise<NotificationsResponse> => {
    const response = await apiClient.get('/notifications', {
      params: { limit, offset, unread_only: unreadOnly },
    })
    return response.data
  },

  /**
   * Get unread notification count
   */
  getUnreadCount: async (): Promise<number> => {
    const response = await apiClient.get('/notifications/unread-count')
    return response.data.unread_count
  },

  /**
   * Create a notification for a specific user
   */
  createNotification: async (
    userId: string,
    notification: CreateNotificationRequest
  ): Promise<Notification> => {
    const response = await apiClient.post(`/notifications/${userId}`, notification)
    return response.data
  },

  /**
   * Mark a notification as read
   */
  markAsRead: async (notificationId: string): Promise<void> => {
    await apiClient.post(`/notifications/${notificationId}/read`)
  },

  /**
   * Mark all notifications as read
   */
  markAllAsRead: async (): Promise<void> => {
    await apiClient.post('/notifications/read-all')
  },

  /**
   * Delete a notification
   */
  deleteNotification: async (notificationId: string): Promise<void> => {
    await apiClient.delete(`/notifications/${notificationId}`)
  },
}
