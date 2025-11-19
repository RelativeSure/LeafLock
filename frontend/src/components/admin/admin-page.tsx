import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Shield,
  Users,
  Database,
  Activity,
  AlertTriangle,
  Globe,
  Lock,
  Eye,
  Trash2,
  Edit,
  Search,
  Filter,
  Download,
  RefreshCw,
  BarChart3,
  Server,
  MemoryStick,
} from 'lucide-react'
import { toast } from 'sonner'

interface User {
  id: string
  name: string
  email: string
  role: 'admin' | 'user'
  status: 'active' | 'suspended' | 'pending'
  createdAt: string
  lastLogin: string
  notesCount: number
}

interface SystemStats {
  totalUsers: number
  activeUsers: number
  totalNotes: number
  totalTemplates: number
  totalTags: number
  systemUptime: string
  memoryUsage: number
  cpuUsage: number
  diskUsage: number
}

interface Announcement {
  id: string
  title: string
  content: string
  type: 'info' | 'warning' | 'success' | 'error'
  isActive: boolean
  createdAt: string
}

export function AdminPage() {
  const [isLoading, setIsLoading] = useState(true)
  const [users, setUsers] = useState<User[]>([])
  const [systemStats, setSystemStats] = useState<SystemStats>({
    totalUsers: 0,
    activeUsers: 0,
    totalNotes: 0,
    totalTemplates: 0,
    totalTags: 0,
    systemUptime: '0d 0h 0m',
    memoryUsage: 0,
    cpuUsage: 0,
    diskUsage: 0,
  })
  const [announcements, setAnnouncements] = useState<Announcement[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [isUserDialogOpen, setIsUserDialogOpen] = useState(false)
  const [isAnnouncementDialogOpen, setIsAnnouncementDialogOpen] = useState(false)

  useEffect(() => {
    const loadAdminData = async () => {
      setIsLoading(true)
      try {
        // Simulate API calls
        await new Promise((resolve) => setTimeout(resolve, 1000))

        setUsers([
          {
            id: '1',
            name: 'John Doe',
            email: 'john@example.com',
            role: 'admin',
            status: 'active',
            createdAt: '2024-01-15',
            lastLogin: '2024-10-24',
            notesCount: 25,
          },
          {
            id: '2',
            name: 'Jane Smith',
            email: 'jane@example.com',
            role: 'user',
            status: 'active',
            createdAt: '2024-02-20',
            lastLogin: '2024-10-23',
            notesCount: 12,
          },
          {
            id: '3',
            name: 'Bob Johnson',
            email: 'bob@example.com',
            role: 'user',
            status: 'suspended',
            createdAt: '2024-03-10',
            lastLogin: '2024-10-20',
            notesCount: 8,
          },
        ])

        setSystemStats({
          totalUsers: 3,
          activeUsers: 2,
          totalNotes: 45,
          totalTemplates: 6,
          totalTags: 15,
          systemUptime: '15d 8h 32m',
          memoryUsage: 68,
          cpuUsage: 23,
          diskUsage: 45,
        })

        setAnnouncements([
          {
            id: '1',
            title: 'System Maintenance',
            content: 'Scheduled maintenance will occur on Sunday at 2 AM UTC.',
            type: 'info',
            isActive: true,
            createdAt: '2024-10-20',
          },
          {
            id: '2',
            title: 'New Features Available',
            content: 'Check out the new collaboration features and improved encryption.',
            type: 'success',
            isActive: true,
            createdAt: '2024-10-18',
          },
        ])
      } catch (error) {
        toast.error('Failed to load admin data')
        console.error('Admin data load error:', error)
      } finally {
        setIsLoading(false)
      }
    }

    loadAdminData()
  }, [])

  const handleUserStatusChange = async (userId: string, newStatus: string) => {
    try {
      const apiUrl = import.meta.env.VITE_API_URL || window.location.origin
      const token = localStorage.getItem('token')

      if (newStatus === 'active') {
        await fetch(`${apiUrl}/api/v1/admin/users/${userId}/unlock`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        })
      }

      setUsers((prev) =>
        prev.map((user) => (user.id === userId ? { ...user, status: newStatus as any } : user))
      )
      toast.success(`User status updated to ${newStatus}`)
    } catch (error) {
      toast.error('Failed to update user status')
    }
  }

  const handleUserRoleChange = async (userId: string, newRole: string) => {
    try {
      const apiUrl = import.meta.env.VITE_API_URL || window.location.origin
      const token = localStorage.getItem('token')

      await fetch(`${apiUrl}/api/v1/admin/users/${userId}/role`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ isAdmin: newRole === 'admin' }),
      })

      setUsers((prev) =>
        prev.map((user) => (user.id === userId ? { ...user, role: newRole as any } : user))
      )
      toast.success(`User role updated to ${newRole}`)
    } catch (error) {
      toast.error('Failed to update user role')
    }
  }

  const handleDeleteUser = async (userId: string) => {
    try {
      const apiUrl = import.meta.env.VITE_API_URL || window.location.origin
      const token = localStorage.getItem('token')

      await fetch(`${apiUrl}/api/v1/admin/users/${userId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })

      setUsers((prev) => prev.filter((user) => user.id !== userId))
      toast.success('User deleted successfully')
    } catch (error) {
      toast.error('Failed to delete user')
    }
  }

  const filteredUsers = users.filter(
    (user) =>
      user.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase())
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Admin Dashboard</h1>
            <p className="text-muted-foreground">Manage your LeafLock instance</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export Data
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{systemStats.totalUsers}</div>
            <p className="text-xs text-muted-foreground">{systemStats.activeUsers} active users</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Notes</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{systemStats.totalNotes}</div>
            <p className="text-xs text-muted-foreground">Across all users</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Uptime</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{systemStats.systemUptime}</div>
            <p className="text-xs text-muted-foreground">Since last restart</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Memory Usage</CardTitle>
            <MemoryStick className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{systemStats.memoryUsage}%</div>
            <p className="text-xs text-muted-foreground">Current usage</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="users" className="space-y-6 flex-1 overflow-hidden flex flex-col">
        <TabsList className="grid w-full grid-cols-5 shrink-0">
          <TabsTrigger value="users" className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            Users
          </TabsTrigger>
          <TabsTrigger value="system" className="flex items-center gap-2">
            <Server className="h-4 w-4" />
            System
          </TabsTrigger>
          <TabsTrigger value="announcements" className="flex items-center gap-2">
            <Globe className="h-4 w-4" />
            Announcements
          </TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-2">
            <Lock className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="analytics" className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4" />
            Analytics
          </TabsTrigger>
        </TabsList>

        <div className="flex-1 overflow-auto min-h-0">
            <TabsContent value="users" className="h-full space-y-6 mt-0">
            <Card className="h-full flex flex-col">
                <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Users className="h-5 w-5" />
                    User Management
                </CardTitle>
                <CardDescription>Manage user accounts, roles, and permissions</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 flex-1 flex flex-col overflow-hidden">
                <div className="flex items-center gap-4 shrink-0">
                    <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search users..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-10"
                    />
                    </div>
                    <Button variant="outline">
                    <Filter className="h-4 w-4 mr-2" />
                    Filter
                    </Button>
                </div>

                <div className="flex-1 overflow-auto border rounded-md">
                    <Table>
                    <TableHeader className="sticky top-0 bg-card z-10">
                        <TableRow>
                        <TableHead>User</TableHead>
                        <TableHead>Role</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Notes</TableHead>
                        <TableHead>Last Login</TableHead>
                        <TableHead>Actions</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {filteredUsers.map((user) => (
                        <TableRow key={user.id}>
                            <TableCell>
                            <div>
                                <div className="font-medium">{user.name}</div>
                                <div className="text-sm text-muted-foreground">{user.email}</div>
                            </div>
                            </TableCell>
                            <TableCell>
                            <Select
                                value={user.role}
                                onValueChange={(value) => handleUserRoleChange(user.id, value)}
                            >
                                <SelectTrigger className="w-32">
                                <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                <SelectItem value="user">User</SelectItem>
                                <SelectItem value="admin">Admin</SelectItem>
                                </SelectContent>
                            </Select>
                            </TableCell>
                            <TableCell>
                            <Select
                                value={user.status}
                                onValueChange={(value) => handleUserStatusChange(user.id, value)}
                            >
                                <SelectTrigger className="w-32">
                                <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                <SelectItem value="active">Active</SelectItem>
                                <SelectItem value="suspended">Suspended</SelectItem>
                                <SelectItem value="pending">Pending</SelectItem>
                                </SelectContent>
                            </Select>
                            </TableCell>
                            <TableCell>{user.notesCount}</TableCell>
                            <TableCell>{user.lastLogin}</TableCell>
                            <TableCell>
                            <div className="flex items-center gap-2">
                                <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                    setSelectedUser(user)
                                    setIsUserDialogOpen(true)
                                }}
                                >
                                <Eye className="h-4 w-4" />
                                </Button>
                                <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDeleteUser(user.id)}
                                >
                                <Trash2 className="h-4 w-4" />
                                </Button>
                            </div>
                            </TableCell>
                        </TableRow>
                        ))}
                    </TableBody>
                    </Table>
                </div>
                </CardContent>
            </Card>
            </TabsContent>

            <TabsContent value="system" className="space-y-6 mt-0">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                    <Server className="h-5 w-5" />
                    System Resources
                    </CardTitle>
                    <CardDescription>Monitor system performance and resource usage</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                        <span>CPU Usage</span>
                        <span>{systemStats.cpuUsage}%</span>
                    </div>
                    <div className="w-full bg-secondary rounded-full h-2">
                        <div
                        className="bg-primary h-2 rounded-full transition-all duration-300"
                        style={{ width: `${systemStats.cpuUsage}%` }}
                        />
                    </div>
                    </div>

                    <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                        <span>Memory Usage</span>
                        <span>{systemStats.memoryUsage}%</span>
                    </div>
                    <div className="w-full bg-secondary rounded-full h-2">
                        <div
                        className="bg-primary h-2 rounded-full transition-all duration-300"
                        style={{ width: `${systemStats.memoryUsage}%` }}
                        />
                    </div>
                    </div>

                    <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                        <span>Disk Usage</span>
                        <span>{systemStats.diskUsage}%</span>
                    </div>
                    <div className="w-full bg-secondary rounded-full h-2">
                        <div
                        className="bg-primary h-2 rounded-full transition-all duration-300"
                        style={{ width: `${systemStats.diskUsage}%` }}
                        />
                    </div>
                    </div>
                </CardContent>
                </Card>

                <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    Database Statistics
                    </CardTitle>
                    <CardDescription>Overview of data storage and usage</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-4 border rounded-lg">
                        <div className="text-2xl font-bold">{systemStats.totalNotes}</div>
                        <div className="text-sm text-muted-foreground">Total Notes</div>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                        <div className="text-2xl font-bold">{systemStats.totalTemplates}</div>
                        <div className="text-sm text-muted-foreground">Templates</div>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                        <div className="text-2xl font-bold">{systemStats.totalTags}</div>
                        <div className="text-sm text-muted-foreground">Tags</div>
                    </div>
                    <div className="text-center p-4 border rounded-lg">
                        <div className="text-2xl font-bold">{systemStats.totalUsers}</div>
                        <div className="text-sm text-muted-foreground">Users</div>
                    </div>
                    </div>
                </CardContent>
                </Card>
            </div>
            </TabsContent>

            <TabsContent value="announcements" className="space-y-6 mt-0">
            <Card>
                <CardHeader>
                <div className="flex items-center justify-between">
                    <div>
                    <CardTitle className="flex items-center gap-2">
                        <Globe className="h-5 w-5" />
                        System Announcements
                    </CardTitle>
                    <CardDescription>
                        Manage system-wide announcements and notifications
                    </CardDescription>
                    </div>
                    <Button onClick={() => setIsAnnouncementDialogOpen(true)}>
                    <Edit className="h-4 w-4 mr-2" />
                    New Announcement
                    </Button>
                </div>
                </CardHeader>
                <CardContent>
                <div className="space-y-4">
                    {announcements.map((announcement) => (
                    <div key={announcement.id} className="p-4 border rounded-lg">
                        <div className="flex items-start justify-between">
                        <div className="space-y-2">
                            <div className="flex items-center gap-2">
                            <h3 className="font-medium">{announcement.title}</h3>
                            <Badge variant={announcement.isActive ? 'default' : 'secondary'}>
                                {announcement.isActive ? 'Active' : 'Inactive'}
                            </Badge>
                            <Badge variant="outline">{announcement.type}</Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">{announcement.content}</p>
                            <p className="text-xs text-muted-foreground">
                            Created: {announcement.createdAt}
                            </p>
                        </div>
                        <div className="flex items-center gap-2">
                            <Switch
                            checked={announcement.isActive}
                            onCheckedChange={async (checked) => {
                                try {
                                const apiUrl = import.meta.env.VITE_API_URL || window.location.origin
                                const token = localStorage.getItem('token')

                                await fetch(
                                    `${apiUrl}/api/v1/admin/announcements/${announcement.id}`,
                                    {
                                    method: 'PUT',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        Authorization: `Bearer ${token}`,
                                    },
                                    body: JSON.stringify({
                                        ...announcement,
                                        isActive: checked,
                                    }),
                                    }
                                )

                                setAnnouncements((prev) =>
                                    prev.map((a) =>
                                    a.id === announcement.id ? { ...a, isActive: checked } : a
                                    )
                                )
                                toast.success('Announcement status updated')
                                } catch (error) {
                                toast.error('Failed to update announcement')
                                }
                            }}
                            />
                            <Button variant="ghost" size="sm">
                            <Edit className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                            <Trash2 className="h-4 w-4" />
                            </Button>
                        </div>
                        </div>
                    </div>
                    ))}
                </div>
                </CardContent>
            </Card>
            </TabsContent>

            <TabsContent value="security" className="space-y-6 mt-0">
            <Card>
                <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Security Settings
                </CardTitle>
                <CardDescription>Configure security policies and access controls</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                        <Label htmlFor="registration">User Registration</Label>
                        <p className="text-sm text-muted-foreground">
                        Allow new users to register accounts
                        </p>
                    </div>
                    <Switch id="registration" defaultChecked />
                    </div>

                    <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                        <Label htmlFor="mfa">Require MFA</Label>
                        <p className="text-sm text-muted-foreground">
                        Force all users to enable two-factor authentication
                        </p>
                    </div>
                    <Switch id="mfa" />
                    </div>

                    <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                        <Label htmlFor="encryption">Force Encryption</Label>
                        <p className="text-sm text-muted-foreground">
                        Require all notes to be encrypted
                        </p>
                    </div>
                    <Switch id="encryption" defaultChecked />
                    </div>
                </div>

                <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                    Security settings changes take effect immediately and may affect user experience.
                    </AlertDescription>
                </Alert>
                </CardContent>
            </Card>
            </TabsContent>

            <TabsContent value="analytics" className="space-y-6 mt-0">
            <Card>
                <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <BarChart3 className="h-5 w-5" />
                    Usage Analytics
                </CardTitle>
                <CardDescription>View usage statistics and trends</CardDescription>
                </CardHeader>
                <CardContent>
                <div className="text-center py-8 text-muted-foreground">
                    <BarChart3 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Analytics dashboard coming soon...</p>
                    <p className="text-sm">
                    Track user engagement, feature usage, and system performance metrics.
                    </p>
                </div>
                </CardContent>
            </Card>
            </TabsContent>
        </div>
      </Tabs>

      <Dialog open={isUserDialogOpen} onOpenChange={setIsUserDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>User Details</DialogTitle>
            <DialogDescription>View and manage user account information</DialogDescription>
          </DialogHeader>
          {selectedUser && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Name</Label>
                  <p className="text-sm font-medium">{selectedUser.name}</p>
                </div>
                <div>
                  <Label>Email</Label>
                  <p className="text-sm font-medium">{selectedUser.email}</p>
                </div>
                <div>
                  <Label>Role</Label>
                  <p className="text-sm font-medium">{selectedUser.role}</p>
                </div>
                <div>
                  <Label>Status</Label>
                  <p className="text-sm font-medium">{selectedUser.status}</p>
                </div>
                <div>
                  <Label>Notes Count</Label>
                  <p className="text-sm font-medium">{selectedUser.notesCount}</p>
                </div>
                <div>
                  <Label>Last Login</Label>
                  <p className="text-sm font-medium">{selectedUser.lastLogin}</p>
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsUserDialogOpen(false)}>
              Close
            </Button>
            <Button onClick={() => setIsUserDialogOpen(false)}>Save Changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isAnnouncementDialogOpen} onOpenChange={setIsAnnouncementDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Announcement</DialogTitle>
            <DialogDescription>Create a new system-wide announcement</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="announcement-title">Title</Label>
              <Input id="announcement-title" placeholder="Announcement title" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="announcement-content">Content</Label>
              <Input id="announcement-content" placeholder="Announcement content" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="announcement-type">Type</Label>
              <Select>
                <SelectTrigger>
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="info">Info</SelectItem>
                  <SelectItem value="warning">Warning</SelectItem>
                  <SelectItem value="success">Success</SelectItem>
                  <SelectItem value="error">Error</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsAnnouncementDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                setIsAnnouncementDialogOpen(false)
                toast.success('Announcement created successfully')
              }}
            >
              Create Announcement
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
