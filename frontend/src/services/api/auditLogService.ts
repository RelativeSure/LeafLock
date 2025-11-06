import { apiClient } from './apiClient'

export interface AuditLogEntry {
  id: string
  user_id?: string
  user_email?: string
  action: string
  resource_type?: string
  resource_id?: string
  metadata?: Record<string, unknown>
  created_at: string
}

export interface AuditLogsResponse {
  logs: AuditLogEntry[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

export interface GetAuditLogsParams {
  user_id?: string
  action?: string
  resource_type?: string
  start_date?: string
  end_date?: string
  limit?: number
  offset?: number
}

export const auditLogService = {
  /**
   * Get current user's audit logs
   */
  getUserAuditLogs: async (limit: number = 50, offset: number = 0): Promise<AuditLogsResponse> => {
    const response = await apiClient.get('/audit-logs', {
      params: { limit, offset },
    })
    return response.data
  },

  /**
   * Get all audit logs (admin only)
   */
  getAllAuditLogs: async (params: GetAuditLogsParams = {}): Promise<AuditLogsResponse> => {
    const response = await apiClient.get('/admin/audit-logs', { params })
    return response.data
  },
}
