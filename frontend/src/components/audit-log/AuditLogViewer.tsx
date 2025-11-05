import { useEffect, useState } from 'react'
import { useAuditLogStore } from '@/stores/auditLogStore'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Loader2 } from 'lucide-react'

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

export function AuditLogViewer() {
  const { userLogs, userTotal, userHasMore, userLoading, userError, fetchUserLogs } =
    useAuditLogStore()

  const [offset, setOffset] = useState(0)
  const limit = 50

  useEffect(() => {
    fetchUserLogs(limit, 0)
  }, [fetchUserLogs])

  const handleLoadMore = () => {
    const newOffset = offset + limit
    setOffset(newOffset)
    fetchUserLogs(limit, newOffset)
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

  if (userLoading && userLogs.length === 0) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (userError) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
        Error: {userError}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Activity Log</h2>
          <p className="text-sm text-muted-foreground">
            Your account activity history ({userTotal} total events)
          </p>
        </div>
      </div>

      <div className="space-y-2">
        {userLogs.length === 0 ? (
          <Card className="p-8 text-center text-muted-foreground">
            No activity recorded yet
          </Card>
        ) : (
          userLogs.map((log) => (
            <Card key={log.id} className="p-4">
              <div className="flex items-start gap-4">
                <Badge
                  className={`${
                    ACTION_COLORS[log.action] || 'bg-gray-500'
                  } text-white`}
                >
                  {ACTION_LABELS[log.action] || log.action}
                </Badge>

                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="font-medium">
                      {log.resource_type && (
                        <span className="text-sm text-muted-foreground">
                          {log.resource_type}
                          {log.resource_id && ` (${log.resource_id.slice(0, 8)}...)`}
                        </span>
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
                          <span className="text-muted-foreground">
                            {JSON.stringify(value)}
                          </span>
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

      {userHasMore && (
        <div className="flex justify-center">
          <Button onClick={handleLoadMore} disabled={userLoading} variant="outline">
            {userLoading ? (
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
