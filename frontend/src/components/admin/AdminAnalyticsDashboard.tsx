import { useEffect, useState } from 'react'
import { Users, FileText, Folder, TrendingUp } from 'lucide-react'
import { analyticsService, type AdminStats } from '@/services/api/analyticsService'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useToast } from '@/hooks/use-toast'

export function AdminAnalyticsDashboard() {
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const { toast } = useToast()

  useEffect(() => {
    loadAnalytics()
  }, [])

  const loadAnalytics = async () => {
    try {
      setIsLoading(true)
      const data = await analyticsService.getAdminAnalytics()
      setStats(data)
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load admin analytics',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="flex items-center justify-center h-96">
        <p className="text-muted-foreground">No analytics data available</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Admin Analytics</h2>
        <p className="text-muted-foreground">
          System-wide statistics and insights
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_users}</div>
            <p className="text-xs text-muted-foreground">
              {stats.active_users} active (30d)
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Notes</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_notes}</div>
            <p className="text-xs text-muted-foreground">Across all users</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Workspaces</CardTitle>
            <Folder className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_workspaces}</div>
            <p className="text-xs text-muted-foreground">Total workspaces</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Users</CardTitle>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.active_users}</div>
            <p className="text-xs text-muted-foreground">
              {Math.round((stats.active_users / stats.total_users) * 100)}% of total
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Growth Trends */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* User Growth */}
        <Card>
          <CardHeader>
            <CardTitle>User Growth</CardTitle>
            <CardDescription>New users in the last 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            {stats.user_growth && stats.user_growth.length > 0 ? (
              <ScrollArea className="h-[300px]">
                <div className="space-y-2">
                  {stats.user_growth.slice().reverse().map((growth, index) => {
                    const maxCount = Math.max(...stats.user_growth.map((g) => g.count), 1)
                    const percentage = (growth.count / maxCount) * 100
                    const date = new Date(growth.date)

                    return (
                      <div key={index} className="space-y-1">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">
                            {date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                          </span>
                          <Badge variant="secondary" className="bg-green-100 text-green-800">
                            {growth.count}
                          </Badge>
                        </div>
                        <Progress value={percentage} className="h-2" />
                      </div>
                    )
                  })}
                </div>
              </ScrollArea>
            ) : (
              <div className="flex items-center justify-center h-[300px]">
                <p className="text-muted-foreground">No user growth data</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Note Growth */}
        <Card>
          <CardHeader>
            <CardTitle>Note Creation</CardTitle>
            <CardDescription>Notes created in the last 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            {stats.note_growth && stats.note_growth.length > 0 ? (
              <ScrollArea className="h-[300px]">
                <div className="space-y-2">
                  {stats.note_growth.slice().reverse().map((growth, index) => {
                    const maxCount = Math.max(...stats.note_growth.map((g) => g.count), 1)
                    const percentage = (growth.count / maxCount) * 100
                    const date = new Date(growth.date)

                    return (
                      <div key={index} className="space-y-1">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">
                            {date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                          </span>
                          <Badge variant="secondary" className="bg-blue-100 text-blue-800">
                            {growth.count}
                          </Badge>
                        </div>
                        <Progress value={percentage} className="h-2" />
                      </div>
                    )
                  })}
                </div>
              </ScrollArea>
            ) : (
              <div className="flex items-center justify-center h-[300px]">
                <p className="text-muted-foreground">No note growth data</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* System Health Metrics */}
      <Card>
        <CardHeader>
          <CardTitle>System Metrics</CardTitle>
          <CardDescription>Key performance indicators</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2">
              <p className="text-sm font-medium text-muted-foreground">User Engagement</p>
              <p className="text-2xl font-bold">
                {Math.round((stats.active_users / stats.total_users) * 100)}%
              </p>
              <p className="text-xs text-muted-foreground">
                Active users / Total users
              </p>
            </div>

            <div className="space-y-2">
              <p className="text-sm font-medium text-muted-foreground">Avg Notes per User</p>
              <p className="text-2xl font-bold">
                {Math.round(stats.total_notes / stats.total_users)}
              </p>
              <p className="text-xs text-muted-foreground">
                Total notes / Total users
              </p>
            </div>

            <div className="space-y-2">
              <p className="text-sm font-medium text-muted-foreground">Avg Workspaces per User</p>
              <p className="text-2xl font-bold">
                {(stats.total_workspaces / stats.total_users).toFixed(1)}
              </p>
              <p className="text-xs text-muted-foreground">
                Total workspaces / Total users
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
