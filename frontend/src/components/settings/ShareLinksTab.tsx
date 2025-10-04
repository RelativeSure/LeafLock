import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Button } from '../ui/button'
import { Input } from '../ui/input'
import { Badge } from '../ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../ui/select'
import { Link as LinkIcon, Copy, Trash2, Clock, Eye, Edit, Shield, Search } from 'lucide-react'
import { useShareLinksStore, ShareLink } from '../../stores/shareLinksStore'
import { toast } from 'sonner'

export function ShareLinksTab() {
  const { shareLinks, fetchAllUserLinks, revokeShareLink, copyLinkToClipboard } = useShareLinksStore()

  const [searchQuery, setSearchQuery] = useState('')
  const [filterStatus, setFilterStatus] = useState<'all' | 'active' | 'expired'>('all')
  const [filterPermission, setFilterPermission] = useState<'all' | 'read' | 'write'>('all')
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const loadLinks = async () => {
      try {
        await fetchAllUserLinks()
      } catch (error) {
        toast.error('Failed to load share links')
      } finally {
        setIsLoading(false)
      }
    }
    loadLinks()
  }, [fetchAllUserLinks])

  const handleCopyLink = async (url: string) => {
    try {
      await copyLinkToClipboard(url)
      toast.success('Link copied to clipboard!')
    } catch (err) {
      toast.error('Failed to copy link')
    }
  }

  const handleRevokeLink = async (token: string) => {
    if (!confirm('Are you sure you want to revoke this share link? This action cannot be undone.')) {
      return
    }

    try {
      await revokeShareLink(token)
      toast.success('Share link revoked')
    } catch (err) {
      toast.error('Failed to revoke link')
    }
  }

  // Filter links
  const filteredLinks = shareLinks.filter((link) => {
    // Search filter
    if (searchQuery && !link.note_title?.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false
    }

    // Status filter
    if (filterStatus === 'active' && !link.is_active) return false
    if (filterStatus === 'expired') {
      const isExpired = link.expires_at && new Date(link.expires_at) < new Date()
      if (!isExpired) return false
    }

    // Permission filter
    if (filterPermission !== 'all' && link.permission !== filterPermission) {
      return false
    }

    return true
  })

  // Calculate stats
  const stats = {
    total: shareLinks.length,
    active: shareLinks.filter((l) => l.is_active).length,
    expired: shareLinks.filter((l) => l.expires_at && new Date(l.expires_at) < new Date()).length,
    totalAccesses: shareLinks.reduce((sum, l) => sum + l.use_count, 0),
  }

  const getPermissionBadge = (permission: string) => {
    if (permission === 'write') {
      return (
        <Badge variant="outline" className="bg-blue-100 text-blue-800 border-blue-200">
          <Edit className="h-3 w-3 mr-1" />
          Write
        </Badge>
      )
    }
    return (
      <Badge variant="outline" className="bg-green-100 text-green-800 border-green-200">
        <Eye className="h-3 w-3 mr-1" />
        Read
      </Badge>
    )
  }

  const getStatusBadge = (link: ShareLink) => {
    if (!link.is_active) {
      return <Badge variant="outline" className="bg-gray-100 text-gray-800">Revoked</Badge>
    }

    if (link.expires_at && new Date(link.expires_at) < new Date()) {
      return <Badge variant="outline" className="bg-red-100 text-red-800">Expired</Badge>
    }

    if (link.max_uses && link.use_count >= link.max_uses) {
      return <Badge variant="outline" className="bg-orange-100 text-orange-800">Limit Reached</Badge>
    }

    return <Badge variant="outline" className="bg-green-100 text-green-800">Active</Badge>
  }

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold">{stats.total}</div>
            <div className="text-sm text-muted-foreground">Total Links</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-green-600">{stats.active}</div>
            <div className="text-sm text-muted-foreground">Active</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-red-600">{stats.expired}</div>
            <div className="text-sm text-muted-foreground">Expired</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-blue-600">{stats.totalAccesses}</div>
            <div className="text-sm text-muted-foreground">Total Accesses</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <LinkIcon className="h-5 w-5" />
            Share Links
          </CardTitle>
          <CardDescription>
            Manage all your shareable links across all notes
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by note title..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>

            <Select value={filterStatus} onValueChange={(value: any) => setFilterStatus(value)}>
              <SelectTrigger className="w-full md:w-[160px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="expired">Expired</SelectItem>
              </SelectContent>
            </Select>

            <Select value={filterPermission} onValueChange={(value: any) => setFilterPermission(value)}>
              <SelectTrigger className="w-full md:w-[160px]">
                <SelectValue placeholder="Permission" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Permissions</SelectItem>
                <SelectItem value="read">Read Only</SelectItem>
                <SelectItem value="write">Read & Write</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Links Table */}
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">
              Loading share links...
            </div>
          ) : filteredLinks.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              {searchQuery || filterStatus !== 'all' || filterPermission !== 'all'
                ? 'No share links match your filters'
                : 'No share links created yet'}
            </div>
          ) : (
            <div className="border rounded-lg">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Note</TableHead>
                    <TableHead>Permission</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Uses</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredLinks.map((link) => (
                    <TableRow key={link.id}>
                      <TableCell className="font-medium max-w-[200px] truncate">
                        {link.note_title || 'Untitled Note'}
                        {link.has_password && (
                          <Shield className="inline h-3 w-3 ml-2 text-yellow-600" title="Password protected" />
                        )}
                      </TableCell>
                      <TableCell>{getPermissionBadge(link.permission)}</TableCell>
                      <TableCell>{getStatusBadge(link)}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(link.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {link.expires_at ? (
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {new Date(link.expires_at).toLocaleDateString()}
                          </div>
                        ) : (
                          'Never'
                        )}
                      </TableCell>
                      <TableCell className="text-sm">
                        {link.use_count}
                        {link.max_uses ? ` / ${link.max_uses}` : ''}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleCopyLink(link.share_url)}
                            title="Copy link"
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                          {link.is_active && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleRevokeLink(link.token)}
                              className="text-red-600 hover:text-red-700 hover:bg-red-50"
                              title="Revoke link"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
