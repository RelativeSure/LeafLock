import { useEffect, useState } from 'react'
import { FileText, Folder, Tag, Users, TrendingUp, Activity } from 'lucide-react'
import { analyticsService, type UserStats } from '@/services/api/analyticsService'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useToast } from '@/hooks/use-toast'

export function AnalyticsDashboard() {
  const [stats, setStats] = useState<UserStats | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const { toast } = useToast()

  useEffect(() => {
    loadAnalytics()
  }, [])

  const loadAnalytics = async () => {
    try {
      setIsLoading(true)
      const data = await analyticsService.getUserAnalytics()
      setStats(data)
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load analytics',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const formatTimeAgo = (timestamp: string) => {
    const date = new Date(timestamp)
    const now = new Date()
    const seconds = Math.floor((now.getTime() - date.getTime()) / 1000)

    if (seconds < 60) return 'Just now'
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`
    return date.toLocaleDateString()
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
        <h2 className="text-2xl font-bold">Analytics Dashboard</h2>
        <p className="text-muted-foreground">
          View your notes statistics and activity insights
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Notes</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_notes}</div>
            <p className="text-xs text-muted-foreground">
              {stats.notes_created_today} created today
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Folders</CardTitle>
            <Folder className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_folders}</div>
            <p className="text-xs text-muted-foreground">Organizing your notes</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Tags</CardTitle>
            <Tag className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_tags}</div>
            <p className="text-xs text-muted-foreground">For categorization</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Collaborations</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_collaborations}</div>
            <p className="text-xs text-muted-foreground">Shared notes</p>
          </CardContent>
        </Card>
      </div>

      {/* Time-based Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Today</CardTitle>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.notes_created_today}</div>
            <p className="text-xs text-muted-foreground">Notes created</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">This Week</CardTitle>
            <Activity className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.notes_created_week}</div>
            <p className="text-xs text-muted-foreground">Notes created</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">This Month</CardTitle>
            <Activity className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.notes_created_month}</div>
            <p className="text-xs text-muted-foreground">Notes created</p>
          </CardContent>
        </Card>
      </div>

      {/* Activity Trend (Last 30 Days) */}
      <Card>
        <CardHeader>
          <CardTitle>Activity Trend</CardTitle>
          <CardDescription>Notes created in the last 30 days</CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[300px]">
            <div className="space-y-2">
              {stats.activity_by_day.slice().reverse().map((activity, index) => {
                const maxCount = Math.max(...stats.activity_by_day.map((a) => a.count), 1)
                const percentage = (activity.count / maxCount) * 100
                const date = new Date(activity.date)

                return (
                  <div key={index} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">
                        {date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      </span>
                      <Badge variant="secondary">{activity.count}</Badge>
                    </div>
                    <Progress value={percentage} className="h-2" />
                  </div>
                )
              })}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Distribution Tabs */}
      <Tabs defaultValue="folders" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="folders">By Folder</TabsTrigger>
          <TabsTrigger value="tags">By Tag</TabsTrigger>
        </TabsList>

        <TabsContent value="folders">
          <Card>
            <CardHeader>
              <CardTitle>Notes by Folder</CardTitle>
              <CardDescription>Top 10 folders with most notes</CardDescription>
            </CardHeader>
            <CardContent>
              {stats.notes_by_folder.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Folder</TableHead>
                      <TableHead className="text-right">Count</TableHead>
                      <TableHead className="w-[40%]">Distribution</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {stats.notes_by_folder.map((folder, index) => {
                      const maxCount = stats.notes_by_folder[0].count
                      const percentage = (folder.count / maxCount) * 100

                      return (
                        <TableRow key={index}>
                          <TableCell className="font-medium">{folder.name}</TableCell>
                          <TableCell className="text-right">
                            <Badge variant="secondary">{folder.count}</Badge>
                          </TableCell>
                          <TableCell>
                            <Progress value={percentage} className="h-2" />
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              ) : (
                <div className="flex items-center justify-center h-32">
                  <p className="text-muted-foreground">No folders yet</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="tags">
          <Card>
            <CardHeader>
              <CardTitle>Notes by Tag</CardTitle>
              <CardDescription>Top 10 tags with most notes</CardDescription>
            </CardHeader>
            <CardContent>
              {stats.notes_by_tag.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Tag</TableHead>
                      <TableHead className="text-right">Count</TableHead>
                      <TableHead className="w-[40%]">Distribution</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {stats.notes_by_tag.map((tag, index) => {
                      const maxCount = stats.notes_by_tag[0].count
                      const percentage = (tag.count / maxCount) * 100

                      return (
                        <TableRow key={index}>
                          <TableCell className="font-medium">{tag.name}</TableCell>
                          <TableCell className="text-right">
                            <Badge variant="secondary">{tag.count}</Badge>
                          </TableCell>
                          <TableCell>
                            <Progress value={percentage} className="h-2" />
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              ) : (
                <div className="flex items-center justify-center h-32">
                  <p className="text-muted-foreground">No tags yet</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
          <CardDescription>Your latest actions</CardDescription>
        </CardHeader>
        <CardContent>
          {stats.recent_activity.length > 0 ? (
            <ScrollArea className="h-[300px]">
              <div className="space-y-4">
                {stats.recent_activity.map((activity, index) => (
                  <div key={index} className="flex items-start gap-3 pb-3 border-b last:border-0">
                    <div className="mt-1">
                      <Activity className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-medium">{activity.message}</p>
                      <p className="text-xs text-muted-foreground">
                        {formatTimeAgo(activity.timestamp)}
                      </p>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {activity.type}
                    </Badge>
                  </div>
                ))}
              </div>
            </ScrollArea>
          ) : (
            <div className="flex items-center justify-center h-32">
              <p className="text-muted-foreground">No recent activity</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
