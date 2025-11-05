import { create } from 'zustand'
import {
  auditLogService,
  AuditLogEntry,
  GetAuditLogsParams,
} from '@/services/api/auditLogService'

interface AuditLogState {
  // User's own logs
  userLogs: AuditLogEntry[]
  userTotal: number
  userHasMore: boolean
  userLoading: boolean
  userError: string | null

  // Admin view (all logs)
  adminLogs: AuditLogEntry[]
  adminTotal: number
  adminHasMore: boolean
  adminLoading: boolean
  adminError: string | null

  // Filters for admin view
  filters: GetAuditLogsParams

  // Actions
  fetchUserLogs: (limit?: number, offset?: number) => Promise<void>
  fetchAdminLogs: (params?: GetAuditLogsParams) => Promise<void>
  setFilters: (filters: GetAuditLogsParams) => void
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
          mergedParams.offset === 0
            ? response.logs
            : [...get().adminLogs, ...response.logs],
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
