import { useEffect, useState } from 'react'
import { useAuditLogStore } from '@/stores/auditLogStore'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { Loader2, Filter, X } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const ACTION_COLORS: Record<string, string> = {
  login: 'bg-green-500',
  logout: 'bg-gray-500',
  'note.created': 'bg-blue-500',
  'note.updated': 'bg-yellow-500',
  'note.deleted': 'bg-red-500',
  'note.shared': 'bg-purple-500',
  'mfa.enabled': 'bg-green-600',
  'mfa.disabled': 'bg-orange-500',
  'password.changed': 'bg-red-600',
}

const ACTION_LABELS: Record<string, string> = {
  login: 'Logged In',
  logout: 'Logged Out',
  'note.created': 'Created Note',
  'note.updated': 'Updated Note',
  'note.deleted': 'Deleted Note',
  'note.restored': 'Restored Note',
  'note.shared': 'Shared Note',
  'mfa.enabled': 'Enabled MFA',
  'mfa.disabled': 'Disabled MFA',
  'password.changed': 'Changed Password',
  'password.reset': 'Reset Password',
}

export function AdminAuditLogViewer() {
  const {
    adminLogs,
    adminTotal,
    adminHasMore,
    adminLoading,
    adminError,
    filters,
    fetchAdminLogs,
    setFilters,
    clearFilters,
  } = useAuditLogStore()

  const [showFilters, setShowFilters] = useState(false)
  const [localFilters, setLocalFilters] = useState(filters)

  useEffect(() => {
    fetchAdminLogs({ limit: 50, offset: 0 })
  }, [fetchAdminLogs])

  const handleApplyFilters = () => {
    setFilters(localFilters)
    fetchAdminLogs({ ...localFilters, offset: 0 })
  }

  const handleClearFilters = () => {
    const defaultFilters = { limit: 50, offset: 0 }
    setLocalFilters(defaultFilters)
    clearFilters()
    fetchAdminLogs(defaultFilters)
  }

  const handleLoadMore = () => {
    const newOffset = (filters.offset || 0) + (filters.limit || 50)
    fetchAdminLogs({ ...filters, offset: newOffset })
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(date)
  }

  if (adminLoading && adminLogs.length === 0) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (adminError) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
        Error: {adminError}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">System Audit Logs</h2>
          <p className="text-sm text-muted-foreground">
            All user activity across the system ({adminTotal} total events)
          </p>
        </div>
        <Button onClick={() => setShowFilters(!showFilters)} variant="outline" size="sm">
          <Filter className="mr-2 h-4 w-4" />
          {showFilters ? 'Hide' : 'Show'} Filters
        </Button>
      </div>

      {showFilters && (
        <Card className="p-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="user-filter">User Email</Label>
              <Input
                id="user-filter"
                placeholder="Filter by email..."
                value={localFilters.user_id || ''}
                onChange={(e) => setLocalFilters({ ...localFilters, user_id: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="action-filter">Action</Label>
              <Select
                value={localFilters.action || 'all'}
                onValueChange={(value) =>
                  setLocalFilters({
                    ...localFilters,
                    action: value === 'all' ? undefined : value,
                  })
                }
              >
                <SelectTrigger id="action-filter">
                  <SelectValue placeholder="All actions" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Actions</SelectItem>
                  <SelectItem value="login">Login</SelectItem>
                  <SelectItem value="logout">Logout</SelectItem>
                  <SelectItem value="note.created">Note Created</SelectItem>
                  <SelectItem value="note.updated">Note Updated</SelectItem>
                  <SelectItem value="note.deleted">Note Deleted</SelectItem>
                  <SelectItem value="note.shared">Note Shared</SelectItem>
                  <SelectItem value="mfa.enabled">MFA Enabled</SelectItem>
                  <SelectItem value="password.changed">Password Changed</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="resource-filter">Resource Type</Label>
              <Select
                value={localFilters.resource_type || 'all'}
                onValueChange={(value) =>
                  setLocalFilters({
                    ...localFilters,
                    resource_type: value === 'all' ? undefined : value,
                  })
                }
              >
                <SelectTrigger id="resource-filter">
                  <SelectValue placeholder="All resources" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Resources</SelectItem>
                  <SelectItem value="note">Notes</SelectItem>
                  <SelectItem value="user">Users</SelectItem>
                  <SelectItem value="folder">Folders</SelectItem>
                  <SelectItem value="tag">Tags</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="start-date">Start Date</Label>
              <Input
                id="start-date"
                type="datetime-local"
                value={localFilters.start_date || ''}
                onChange={(e) => setLocalFilters({ ...localFilters, start_date: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="end-date">End Date</Label>
              <Input
                id="end-date"
                type="datetime-local"
                value={localFilters.end_date || ''}
                onChange={(e) => setLocalFilters({ ...localFilters, end_date: e.target.value })}
              />
            </div>

            <div className="flex items-end gap-2">
              <Button onClick={handleApplyFilters} className="flex-1">
                Apply Filters
              </Button>
              <Button onClick={handleClearFilters} variant="outline" size="icon">
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </Card>
      )}

      <div className="space-y-2">
        {adminLogs.length === 0 ? (
          <Card className="p-8 text-center text-muted-foreground">No audit logs found</Card>
        ) : (
          adminLogs.map((log) => (
            <Card key={log.id} className="p-4">
              <div className="flex items-start gap-4">
                <Badge className={`${ACTION_COLORS[log.action] || 'bg-gray-500'} text-white`}>
                  {ACTION_LABELS[log.action] || log.action}
                </Badge>

                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      {log.user_email && (
                        <div className="font-medium text-sm">{log.user_email}</div>
                      )}
                      {log.resource_type && (
                        <div className="text-sm text-muted-foreground">
                          {log.resource_type}
                          {log.resource_id && ` (${log.resource_id.slice(0, 8)}...)`}
                        </div>
                      )}
                    </div>
                    <time className="text-sm text-muted-foreground">
                      {formatDate(log.created_at)}
                    </time>
                  </div>

                  {log.metadata && Object.keys(log.metadata).length > 0 && (
                    <div className="rounded bg-muted p-2 text-xs">
                      {Object.entries(log.metadata).map(([key, value]) => (
                        <div key={key} className="flex gap-2">
                          <span className="font-medium">{key}:</span>
                          <span className="text-muted-foreground">{JSON.stringify(value)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </Card>
          ))
        )}
      </div>

      {adminHasMore && (
        <div className="flex justify-center">
          <Button onClick={handleLoadMore} disabled={adminLoading} variant="outline">
            {adminLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Loading...
              </>
            ) : (
              'Load More'
            )}
          </Button>
        </div>
      )}
    </div>
  )
}
