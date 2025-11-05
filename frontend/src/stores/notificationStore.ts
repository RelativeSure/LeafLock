import { create } from 'zustand'
import { notificationService, type Notification } from '@/services/api/notificationService'

interface NotificationState {
  notifications: Notification[]
  unreadCount: number
  isLoading: boolean
  error: string | null

  fetchNotifications: (limit?: number, offset?: number, unreadOnly?: boolean) => Promise<void>
  fetchUnreadCount: () => Promise<void>
  markAsRead: (notificationId: string) => Promise<void>
  markAllAsRead: () => Promise<void>
  deleteNotification: (notificationId: string) => Promise<void>
  addNotification: (notification: Notification) => void
}

export const useNotificationStore = create<NotificationState>((set, _get) => ({
  notifications: [],
  unreadCount: 0,
  isLoading: false,
  error: null,

  fetchNotifications: async (limit = 50, offset = 0, unreadOnly = false) => {
    set({ isLoading: true, error: null })
    try {
      const response = await notificationService.getNotifications(limit, offset, unreadOnly)
      set({
        notifications: response.notifications,
        unreadCount: response.unread_count,
        isLoading: false,
      })
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to fetch notifications',
        isLoading: false,
      })
    }
  },

  fetchUnreadCount: async () => {
    try {
      const count = await notificationService.getUnreadCount()
      set({ unreadCount: count })
    } catch (error) {
      console.error('Failed to fetch unread count:', error)
    }
  },

  markAsRead: async (notificationId: string) => {
    try {
      await notificationService.markAsRead(notificationId)

      set((state) => ({
        notifications: state.notifications.map((n) =>
          n.id === notificationId ? { ...n, is_read: true, read_at: new Date().toISOString() } : n
        ),
        unreadCount: Math.max(0, state.unreadCount - 1),
      }))
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Failed to mark as read' })
    }
  },

  markAllAsRead: async () => {
    try {
      await notificationService.markAllAsRead()

      set((state) => ({
        notifications: state.notifications.map((n) => ({
          ...n,
          is_read: true,
          read_at: new Date().toISOString(),
        })),
        unreadCount: 0,
      }))
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Failed to mark all as read' })
    }
  },

  deleteNotification: async (notificationId: string) => {
    try {
      await notificationService.deleteNotification(notificationId)

      set((state) => {
        const notification = state.notifications.find((n) => n.id === notificationId)
        const wasUnread = notification && !notification.is_read

        return {
          notifications: state.notifications.filter((n) => n.id !== notificationId),
          unreadCount: wasUnread ? Math.max(0, state.unreadCount - 1) : state.unreadCount,
        }
      })
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Failed to delete notification' })
    }
  },

  addNotification: (notification: Notification) => {
    set((state) => ({
      notifications: [notification, ...state.notifications],
      unreadCount: state.unreadCount + 1,
    }))
  },
}))
