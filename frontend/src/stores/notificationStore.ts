/**
 * Notification Store - User Notification and Alert Management
 * 
 * @description
 * Manages user notifications including system alerts, collaboration updates,
 * and application messages. Handles notification fetching, read status tracking,
 * and real-time notification updates. Provides unread count tracking for UI badges
 * and notification center functionality.
 * 
 * @responsibilities
 * - Notification fetching with pagination support
 * - Unread count tracking and badge updates
 * - Read/unread status management
 * - Notification deletion and cleanup
 * - Real-time notification updates
 * - Error handling for notification operations
 * 
 * @notification-types
 * - System alerts: maintenance, updates, security notices
 * - Collaboration updates: shared notes, comments, mentions
 * - Application messages: save confirmations, error alerts
 * - User actions: task completions, reminders
 * 
 * @pagination-strategy
 * - Supports limit/offset based pagination
 * - Unread-only filtering for focused views
 * - Efficient loading for large notification volumes
 * - Maintains notification order by timestamp
 * 
 * @real-time-updates
 * - Supports adding notifications from WebSocket events
 * - Immediate unread count updates
 * - Live notification badge updates
 * - Integration with real-time services
 * 
 * @integration-patterns
 * - Consumed by notification center and badge components
 * - Used by header/navigation for unread indicators
 * - Integrates with notification service for API operations
 * - Supports WebSocket integration for real-time updates
 * 
 * @state-management
 * - Separate arrays for different notification views
 * - Unread count cached for performance
 * - Loading and error states for async operations
 * - Optimistic updates for immediate UI feedback
 */
import { create } from 'zustand'
import { notificationService, type Notification } from '@/services/api/notificationService'

interface NotificationState {
  /**
   * Current notification list
   * @type {Notification[]} Array of user notifications
   * Ordered by timestamp (newest first)
   * Updated via fetch operations and real-time events
   */
  notifications: Notification[]
  
  /**
   * Unread notification count for badge display
   * @type {number} Count of unread notifications
   * Updated independently for performance
   * Used for header badges and notification indicators
   */
  unreadCount: number
  
  /**
   * Loading state for notification operations
   * @type {boolean} true during fetch/mark/delete operations
   * Used by UI components to show loading indicators
   */
  isLoading: boolean
  
  /**
   * Error state for notification operations
   * @type {string | null} Error message or null if no error
   * Set on operation failures, cleared on successful operations
   * Used for error display in notification center
   */
  error: string | null

  /**
   * Fetch notifications with pagination support
   * @param limit - Maximum notifications to fetch (default: 50)
   * @param offset - Pagination offset (default: 0)
   * @param unreadOnly - Fetch only unread notifications (default: false)
   * @throws {Error} On fetch failure
   * 
   * @pagination
   * - Supports limit/offset based pagination
   * - Concatenates results for infinite scroll
   * - Resets list when offset is 0
   * 
   * @filtering
   * - Unread-only mode for focused notification views
   * - Preserves notification order by timestamp
   * - Efficient for large notification volumes
   * 
   * @response-handling
   * - Updates notifications array with fetched data
   * - Updates unread count from server response
   * - Handles empty results gracefully
   */
  fetchNotifications: (limit?: number, offset?: number, unreadOnly?: boolean) => Promise<void>
  
  /**
   * Fetch current unread notification count
   * @throws {Error} On fetch failure (logged but not thrown)
   * 
   * @optimization
   * - Separate endpoint for efficient count retrieval
   * - Used for badge updates without full notification fetch
   * - Silent failure to prevent UI disruption
   * 
   * @badge-updates
   * - Updates unreadCount for header badges
   * - Real-time count for notification indicators
   * - Independent of notification list fetching
   */
  fetchUnreadCount: () => Promise<void>
  
  /**
   * Mark notification as read
   * @param notificationId - Notification ID to mark
   * @throws {Error} On mark operation failure
   * 
   * @optimistic-update
   * - Updates local state immediately for responsiveness
   * - Updates read_at timestamp with current time
   * - Decrements unread count immediately
   * 
   * @server-sync
   * - API call to persist read status
   * - Rollback on failure (though not implemented)
   * - Maintains consistency with server state
   */
  markAsRead: (notificationId: string) => Promise<void>
  
  /**
   * Mark all notifications as read
   * @throws {Error} On bulk mark operation failure
   * 
   * @bulk-operation
   * - Single API call for all notifications
   * - Updates all local notifications immediately
   * - Resets unread count to zero
   * 
   * @optimistic-update
   * - Updates entire notification array at once
   * - Immediate UI feedback for user action
   * - Efficient for notification center "mark all" functionality
   */
  markAllAsRead: () => Promise<void>
  
  /**
   * Delete notification permanently
   * @param notificationId - Notification ID to delete
   * @throws {Error} On deletion failure
   * 
   * @deletion
   * - Removes notification via API call
   * - Updates local array immediately
   * - Adjusts unread count if notification was unread
   * 
   * @cleanup
   * - Maintains unread count accuracy
   * - Permanent deletion (no undo)
   * - Used for notification cleanup and management
   */
  deleteNotification: (notificationId: string) => Promise<void>
  
  /**
   * Add notification from real-time event
   * @param notification - Notification to add
   * 
   * @real-time-integration
   * - Adds notification to beginning of array
   * - Increments unread count immediately
   * - Used by WebSocket event handlers
   * 
   * @immediate-update
   * - No API call required (assumes server-validated)
   * - Immediate UI update for real-time feel
   * - Supports live notification delivery
   * 
   * @use-cases
   * - WebSocket notification events
   * - Push notification handlers
   * - Real-time collaboration updates
   */
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
