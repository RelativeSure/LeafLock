/**
 * Audit Log Store - Security Audit Trail and Activity Monitoring
 * 
 * @description
 * Manages audit logs for security monitoring, compliance tracking, and
 * activity analysis. Provides separate views for user activity and admin-level
   system monitoring. Supports filtering, pagination, and detailed log analysis
   for security investigations and compliance reporting.
 * 
 * @responsibilities
 * - User activity log fetching and display
 * - Admin system log monitoring (for administrators)
 * - Audit log filtering and search capabilities
 * - Pagination for large log volumes
 * - Error handling for audit operations
 * - Filter state management for persistent views
 * 
 * @security-considerations
 * - Audit logs contain sensitive system activity data
 * - Admin access restricted to authorized users
 * - Immutable log entries for compliance integrity
 * - Timestamp and user attribution for all activities
 * - Secure API access with proper authentication
 * 
 * @compliance-features
 * - Complete activity trail with timestamps
 * - User attribution for all actions
 * - Filterable by date, user, action type
 * - Export capabilities for compliance reporting
 * - Tamper-evident log structure
 * 
 * @data-separation
 * - User logs: Activity for current user only
 * - Admin logs: System-wide activity (admin only)
 * - Separate loading states and error handling
 * - Independent pagination for each view
 * 
 * @integration-patterns
 * - Consumed by audit log viewer components
 * - Used by admin dashboards for system monitoring
 * - Integrates with audit log service for API operations
 * - Provides data for security analysis tools
 * 
 * @filtering-capabilities
 * - Date range filtering for time-based analysis
 * - User filtering for specific user activity
 * - Action type filtering for categorization
 * - Combined filters for detailed analysis
 */
import { create } from 'zustand'
import { auditLogService, AuditLogEntry, GetAuditLogsParams } from '@/services/api/auditLogService'

interface AuditLogState {
  /**
   * User's personal activity logs
   * @type {AuditLogEntry[]} Activity history for current user
   * Personal view of all user actions
   * Used for personal activity review
   */
  userLogs: AuditLogEntry[]

  /**
   * Total count of user logs available
   * @type {number} Total logs for pagination
   * Used for pagination calculations
   * May exceed loaded logs count
   */
  userTotal: number

  /**
   * Pagination indicator for user logs
   * @type {boolean} true if more logs available
   * Used for infinite scroll implementation
   * Indicates whether to show "load more" option
   */
  userHasMore: boolean

  /**
   * Loading state for user logs
   * @type {boolean} true during user log fetch
   * Used by UI components for loading indicators
   * Separate from admin log loading state
   */
  userLoading: boolean

  /**
   * Error state for user logs
   * @type {string | null} Error message or null
   * Set on user log fetch failures
   * Separate from admin log errors
   */
  userError: string | null

  /**
   * Admin system-wide audit logs
   * @type {AuditLogEntry[]} All system activity logs
   * Admin-only view of system activity
   * Used for security monitoring and analysis
   */
  adminLogs: AuditLogEntry[]

  /**
   * Total count of admin logs available
   * @type {number} Total system logs for pagination
   * Used for pagination calculations
   * May be larger than user logs count
   */
  adminTotal: number

  /**
   * Pagination indicator for admin logs
   * @type {boolean} true if more admin logs available
   * Used for infinite scroll implementation
   * Indicates whether to show "load more" option
   */
  adminHasMore: boolean

  /**
   * Loading state for admin logs
   * @type {boolean} true during admin log fetch
   * Used by UI components for loading indicators
   * Separate from user log loading state
   */
  adminLoading: boolean

  /**
   * Error state for admin logs
   * @type {string | null} Error message or null
   * Set on admin log fetch failures
   * May indicate permission issues for non-admins
   */
  adminError: string | null

  /**
   * Current filters for admin log viewing
   * @type {GetAuditLogsParams} Active filter parameters
   * Applied to admin log fetching
   * Persisted during session for consistent views
   */
  filters: GetAuditLogsParams

  /**
   * Fetch user's personal activity logs
   * @param limit - Maximum logs to fetch (default: 50)
   * @param offset - Pagination offset (default: 0)
   * @throws {Error} On fetch failure
   *
   * @pagination
   * - Supports limit/offset based pagination
   * - Concatenates results for infinite scroll
   * - Resets list when offset is 0
   *
   * @user-scope
   * - Returns only current user's activity
   * - Personal activity history and review
   * - Privacy-respecting user-only view
   *
   * @data-integrity
   * - Maintains log immutability
   * - Preserves complete activity trail
   * - Timestamp-based ordering
   */
  fetchUserLogs: (limit?: number, offset?: number) => Promise<void>

  /**
   * Fetch system-wide audit logs (admin only)
   * @param params - Optional filter parameters
   * @throws {Error} On fetch failure or permission denied
   *
   * @admin-access
   * - Requires administrative privileges
   * - Returns all user activities system-wide
   * - Used for security monitoring and analysis
   *
   * @filtering
   * - Applies current filters if not overridden
   * - Supports date, user, and action filtering
   * - Merges custom parameters with stored filters
   *
   * @security
   * - May fail with permission errors for non-admins
   * - Comprehensive system activity view
   * - Compliance and security analysis support
   */
  fetchAdminLogs: (params?: GetAuditLogsParams) => Promise<void>

  /**
   * Set filters for admin log viewing
   * @param filters - Filter parameters to apply
   *
   * @filter-management
   * - Merges with existing filters
   * - Applied to subsequent admin log fetches
   * - Persistent during session
   *
   * @use-cases
   * - Date range filtering for time analysis
   * - User filtering for specific activity
   * - Action type filtering for categorization
   * - Combined filters for detailed analysis
   */
  setFilters: (filters: GetAuditLogsParams) => void

  /**
   * Clear all filters to default state
   * @returns {void} Resets to default filter parameters
   *
   * @reset
   * - Returns to default filter settings
   * - Applied to subsequent fetches
   * - Does not trigger automatic refetch
   *
   * @defaults
   * - limit: 50 (default page size)
   * - offset: 0 (first page)
   * - No date, user, or action filters
   */
  clearFilters: () => void
}

const defaultFilters: GetAuditLogsParams = {
  limit: 50,
  offset: 0,
}

export const useAuditLogStore = create<AuditLogState>((set, get) => ({
  // Initial state
  userLogs: [],
  userTotal: 0,
  userHasMore: false,
  userLoading: false,
  userError: null,

  adminLogs: [],
  adminTotal: 0,
  adminHasMore: false,
  adminLoading: false,
  adminError: null,

  filters: defaultFilters,

  // Fetch user's own audit logs
  fetchUserLogs: async (limit = 50, offset = 0) => {
    set({ userLoading: true, userError: null })

    try {
      const response = await auditLogService.getUserAuditLogs(limit, offset)

      set({
        userLogs: offset === 0 ? response.logs : [...get().userLogs, ...response.logs],
        userTotal: response.total,
        userHasMore: response.has_more,
        userLoading: false,
      })
    } catch (error) {
      set({
        userError: error instanceof Error ? error.message : 'Failed to fetch audit logs',
        userLoading: false,
      })
    }
  },

  // Fetch all audit logs (admin)
  fetchAdminLogs: async (params = {}) => {
    set({ adminLoading: true, adminError: null })

    try {
      const mergedParams = { ...get().filters, ...params }
      const response = await auditLogService.getAllAuditLogs(mergedParams)

      set({
        adminLogs:
          mergedParams.offset === 0 ? response.logs : [...get().adminLogs, ...response.logs],
        adminTotal: response.total,
        adminHasMore: response.has_more,
        adminLoading: false,
        filters: mergedParams,
      })
    } catch (error) {
      set({
        adminError: error instanceof Error ? error.message : 'Failed to fetch audit logs',
        adminLoading: false,
      })
    }
  },

  // Set filters for admin view
  setFilters: (filters: GetAuditLogsParams) => {
    set({ filters: { ...get().filters, ...filters } })
  },

  // Clear filters
  clearFilters: () => {
    set({ filters: defaultFilters })
  },
}))
