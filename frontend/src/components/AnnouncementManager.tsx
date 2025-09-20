import React, { useState, useEffect } from 'react'
import {
  Megaphone,
  Plus,
  Edit3,
  Trash2,
  Eye,
  EyeOff,
  Loader2,
  Save,
  Palette,
  Calendar,
  Users,
  Globe
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import AnnouncementBanner, { Announcement } from './AnnouncementBanner'

type StatusState = {
  variant: 'default' | 'destructive'
  message: string
} | null

interface AnnouncementFormData {
  title: string
  content: string
  visibility: 'all' | 'logged_in'
  style: {
    backgroundColor?: string
    textColor?: string
    borderColor?: string
    icon?: 'info' | 'warning' | 'success' | 'error'
    fontSize?: 'small' | 'normal' | 'large'
    animation?: 'none' | 'fade' | 'slide' | 'pulse'
  }
  active: boolean
  dismissible: boolean
  priority: number
  start_date?: string
  end_date?: string
}

const defaultFormData: AnnouncementFormData = {
  title: '',
  content: '',
  visibility: 'logged_in',
  style: {
    backgroundColor: '#f0f9ff',
    textColor: '#0c4a6e',
    borderColor: '#0ea5e9',
    icon: 'info',
    fontSize: 'normal',
    animation: 'none',
  },
  active: true,
  dismissible: true,
  priority: 0,
}

interface AnnouncementManagerProps {
  api: any
}

const AnnouncementManager: React.FC<AnnouncementManagerProps> = ({ api }) => {
  const [announcements, setAnnouncements] = useState<Announcement[]>([])
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState<StatusState>(null)
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<AnnouncementFormData>(defaultFormData)
  const [previewData, setPreviewData] = useState<Announcement | null>(null)

  const setSuccess = (message: string) => setStatus({ variant: 'default', message })
  const setFailure = (message: string) => setStatus({ variant: 'destructive', message })

  const fetchAnnouncements = async () => {
    try {
      setLoading(true)
      const response = await api.adminGetAnnouncements()
      setAnnouncements(response.announcements || [])
    } catch (error: any) {
      setFailure(error?.message || 'Failed to fetch announcements')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAnnouncements()
  }, [])

  // Update preview when form data changes
  useEffect(() => {
    if (formData.title || formData.content) {
      setPreviewData({
        id: 'preview',
        title: formData.title || 'Preview Title',
        content: formData.content || 'Preview content...',
        visibility: formData.visibility,
        style: formData.style,
        dismissible: formData.dismissible,
        priority: formData.priority,
        created_at: new Date().toISOString(),
      })
    } else {
      setPreviewData(null)
    }
  }, [formData])

  const openDialog = (announcement?: Announcement) => {
    if (announcement) {
      setEditingId(announcement.id)
      setFormData({
        title: announcement.title,
        content: announcement.content,
        visibility: announcement.visibility,
        style: announcement.style || defaultFormData.style,
        active: announcement.active || true,
        dismissible: announcement.dismissible,
        priority: announcement.priority,
        start_date: announcement.start_date?.slice(0, 16) || '',
        end_date: announcement.end_date?.slice(0, 16) || '',
      })
    } else {
      setEditingId(null)
      setFormData(defaultFormData)
    }
    setIsDialogOpen(true)
  }

  const closeDialog = () => {
    setIsDialogOpen(false)
    setEditingId(null)
    setFormData(defaultFormData)
    setPreviewData(null)
  }

  const handleSubmit = async () => {
    if (!formData.title.trim() || !formData.content.trim()) {
      setFailure('Title and content are required')
      return
    }

    try {
      setLoading(true)
      const payload = {
        ...formData,
        start_date: formData.start_date ? new Date(formData.start_date).toISOString() : undefined,
        end_date: formData.end_date ? new Date(formData.end_date).toISOString() : undefined,
      }

      if (editingId) {
        await api.adminUpdateAnnouncement(editingId, payload)
        setSuccess('Announcement updated successfully')
      } else {
        await api.adminCreateAnnouncement(payload)
        setSuccess('Announcement created successfully')
      }

      closeDialog()
      await fetchAnnouncements()
    } catch (error: any) {
      setFailure(error?.message || 'Failed to save announcement')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this announcement?')) {
      return
    }

    try {
      setLoading(true)
      await api.adminDeleteAnnouncement(id)
      setSuccess('Announcement deleted successfully')
      await fetchAnnouncements()
    } catch (error: any) {
      setFailure(error?.message || 'Failed to delete announcement')
    } finally {
      setLoading(false)
    }
  }

  const toggleActive = async (id: string, currentActive: boolean) => {
    try {
      setLoading(true)
      await api.adminUpdateAnnouncement(id, { active: !currentActive })
      setSuccess(`Announcement ${!currentActive ? 'activated' : 'deactivated'}`)
      await fetchAnnouncements()
    } catch (error: any) {
      setFailure(error?.message || 'Failed to update announcement')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Megaphone className="h-4 w-4" /> Announcement Manager
        </CardTitle>
        <CardDescription>
          Create and manage system-wide announcements with rich formatting and styling options.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {status && status.message && (
          <Alert variant={status.variant}>
            <AlertDescription>{status.message}</AlertDescription>
          </Alert>
        )}

        <div className="flex justify-between items-center">
          <h3 className="text-sm font-medium">Active Announcements ({announcements.filter(a => a.active).length})</h3>
          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button onClick={() => openDialog()}>
                <Plus className="h-4 w-4 mr-2" />
                Create Announcement
              </Button>
            </DialogTrigger>

            <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>
                  {editingId ? 'Edit Announcement' : 'Create New Announcement'}
                </DialogTitle>
                <DialogDescription>
                  Create rich announcements with markdown support and custom styling.
                </DialogDescription>
              </DialogHeader>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Form */}
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="title">Title</Label>
                    <Input
                      id="title"
                      placeholder="Announcement title"
                      value={formData.title}
                      onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="content">Content (Markdown supported)</Label>
                    <textarea
                      id="content"
                      className="w-full h-32 px-3 py-2 border border-input bg-background rounded-md text-sm resize-y"
                      placeholder="Announcement content with **markdown** support..."
                      value={formData.content}
                      onChange={(e) => setFormData({ ...formData, content: e.target.value })}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="visibility">Visibility</Label>
                      <Select
                        value={formData.visibility}
                        onValueChange={(value: 'all' | 'logged_in') =>
                          setFormData({ ...formData, visibility: value })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">
                            <div className="flex items-center gap-2">
                              <Globe className="h-4 w-4" />
                              All visitors
                            </div>
                          </SelectItem>
                          <SelectItem value="logged_in">
                            <div className="flex items-center gap-2">
                              <Users className="h-4 w-4" />
                              Logged in users only
                            </div>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="priority">Priority</Label>
                      <Input
                        id="priority"
                        type="number"
                        min="0"
                        max="10"
                        value={formData.priority}
                        onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 0 })}
                      />
                    </div>
                  </div>

                  {/* Style Controls */}
                  <div className="space-y-3 border-t pt-4">
                    <Label className="flex items-center gap-2">
                      <Palette className="h-4 w-4" />
                      Styling Options
                    </Label>

                    <div className="grid grid-cols-3 gap-2">
                      <div className="space-y-1">
                        <Label className="text-xs">Background</Label>
                        <input
                          type="color"
                          className="w-full h-8 rounded border"
                          value={formData.style.backgroundColor}
                          onChange={(e) => setFormData({
                            ...formData,
                            style: { ...formData.style, backgroundColor: e.target.value }
                          })}
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">Text Color</Label>
                        <input
                          type="color"
                          className="w-full h-8 rounded border"
                          value={formData.style.textColor}
                          onChange={(e) => setFormData({
                            ...formData,
                            style: { ...formData.style, textColor: e.target.value }
                          })}
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">Border Color</Label>
                        <input
                          type="color"
                          className="w-full h-8 rounded border"
                          value={formData.style.borderColor}
                          onChange={(e) => setFormData({
                            ...formData,
                            style: { ...formData.style, borderColor: e.target.value }
                          })}
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="icon">Icon</Label>
                        <Select
                          value={formData.style.icon}
                          onValueChange={(value: 'info' | 'warning' | 'success' | 'error') =>
                            setFormData({ ...formData, style: { ...formData.style, icon: value } })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="info">Info</SelectItem>
                            <SelectItem value="warning">Warning</SelectItem>
                            <SelectItem value="success">Success</SelectItem>
                            <SelectItem value="error">Error</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="fontSize">Font Size</Label>
                        <Select
                          value={formData.style.fontSize}
                          onValueChange={(value: 'small' | 'normal' | 'large') =>
                            setFormData({ ...formData, style: { ...formData.style, fontSize: value } })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="small">Small</SelectItem>
                            <SelectItem value="normal">Normal</SelectItem>
                            <SelectItem value="large">Large</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>

                  {/* Schedule */}
                  <div className="space-y-3 border-t pt-4">
                    <Label className="flex items-center gap-2">
                      <Calendar className="h-4 w-4" />
                      Schedule (Optional)
                    </Label>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="start_date">Start Date</Label>
                        <Input
                          id="start_date"
                          type="datetime-local"
                          value={formData.start_date}
                          onChange={(e) => setFormData({ ...formData, start_date: e.target.value })}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="end_date">End Date</Label>
                        <Input
                          id="end_date"
                          type="datetime-local"
                          value={formData.end_date}
                          onChange={(e) => setFormData({ ...formData, end_date: e.target.value })}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Preview */}
                <div className="space-y-4">
                  <Label>Preview</Label>
                  <div className="border rounded-lg p-4 min-h-[200px] bg-muted/30">
                    {previewData ? (
                      <AnnouncementBanner
                        announcements={[previewData]}
                        className="mb-0"
                      />
                    ) : (
                      <div className="text-center text-muted-foreground py-8">
                        Enter title and content to see preview
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={closeDialog}>
                  Cancel
                </Button>
                <Button onClick={handleSubmit} disabled={loading}>
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  <Save className="mr-2 h-4 w-4" />
                  {editingId ? 'Update' : 'Create'} Announcement
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {/* Announcements List */}
        <div className="space-y-3">
          {loading && announcements.length === 0 ? (
            <div className="text-center py-8">
              <Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />
              Loading announcements...
            </div>
          ) : announcements.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No announcements yet. Create your first one above.
            </div>
          ) : (
            announcements.map((announcement) => (
              <Card key={announcement.id} className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h4 className="font-semibold">{announcement.title}</h4>
                      <Badge variant={announcement.active ? 'default' : 'secondary'}>
                        {announcement.active ? 'Active' : 'Inactive'}
                      </Badge>
                      <Badge variant="outline">
                        {announcement.visibility === 'all' ? 'Public' : 'Logged in'}
                      </Badge>
                      {announcement.priority > 0 && (
                        <Badge variant="outline">Priority: {announcement.priority}</Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {announcement.content}
                    </p>
                    <div className="text-xs text-muted-foreground mt-2">
                      Created: {new Date(announcement.created_at).toLocaleDateString()}
                      {announcement.start_date && (
                        <> • Starts: {new Date(announcement.start_date).toLocaleDateString()}</>
                      )}
                      {announcement.end_date && (
                        <> • Ends: {new Date(announcement.end_date).toLocaleDateString()}</>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => toggleActive(announcement.id, announcement.active || false)}
                      disabled={loading}
                    >
                      {announcement.active ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => openDialog(announcement)}
                      disabled={loading}
                    >
                      <Edit3 className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(announcement.id)}
                      disabled={loading}
                      className="text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export default AnnouncementManager