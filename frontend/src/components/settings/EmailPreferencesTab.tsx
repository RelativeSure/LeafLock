import { useState, useEffect } from 'react'
import { Mail, Bell, MessageSquare, Users, Zap } from 'lucide-react'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/hooks/use-toast'
import { apiClient } from '@/services/api/apiClient'

interface EmailPreferences {
  email_notifications: boolean
  email_on_note_shared: boolean
  email_on_collaboration: boolean
  email_on_mention: boolean
  email_digest_frequency: 'never' | 'daily' | 'weekly'
}

export function EmailPreferencesTab() {
  const { toast } = useToast()
  const [preferences, setPreferences] = useState<EmailPreferences>({
    email_notifications: false,
    email_on_note_shared: true,
    email_on_collaboration: true,
    email_on_mention: true,
    email_digest_frequency: 'never',
  })
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    fetchPreferences()
  }, [])

  const fetchPreferences = async () => {
    try {
      setIsLoading(true)
      const response = await apiClient.get('/settings')
      const data = response.data

      setPreferences({
        email_notifications: data.emailNotifications || false,
        email_on_note_shared: data.email_on_note_shared ?? true,
        email_on_collaboration: data.email_on_collaboration ?? true,
        email_on_mention: data.email_on_mention ?? true,
        email_digest_frequency: data.email_digest_frequency || 'never',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load email preferences',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const updatePreference = async (key: keyof EmailPreferences, value: boolean | string) => {
    try {
      await apiClient.put('/settings', {
        [key]: value,
      })

      setPreferences((prev) => ({
        ...prev,
        [key]: value,
      }))

      toast({
        title: 'Success',
        description: 'Email preference updated',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update preference',
        variant: 'destructive',
      })
    }
  }

  if (isLoading) {
    return <div className="flex items-center justify-center p-8">Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Email Preferences</h2>
        <p className="text-muted-foreground">Configure when you receive email notifications</p>
      </div>

      {/* Master Toggle */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            Email Notifications
          </CardTitle>
          <CardDescription>Master toggle for all email notifications</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="email-notifications">Enable Email Notifications</Label>
              <div className="text-sm text-muted-foreground">
                Receive emails for important events
              </div>
            </div>
            <Switch
              id="email-notifications"
              checked={preferences.email_notifications}
              onCheckedChange={(checked) => updatePreference('email_notifications', checked)}
            />
          </div>
        </CardContent>
      </Card>

      {/* Event-specific Notifications */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Event Notifications
          </CardTitle>
          <CardDescription>Choose which events trigger email notifications</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5 flex items-center gap-2">
              <Zap className="h-4 w-4 text-muted-foreground" />
              <div>
                <Label htmlFor="email-note-shared">Note Shared</Label>
                <div className="text-sm text-muted-foreground">
                  When someone shares a note with you
                </div>
              </div>
            </div>
            <Switch
              id="email-note-shared"
              checked={preferences.email_on_note_shared}
              onCheckedChange={(checked) => updatePreference('email_on_note_shared', checked)}
              disabled={!preferences.email_notifications}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5 flex items-center gap-2">
              <Users className="h-4 w-4 text-muted-foreground" />
              <div>
                <Label htmlFor="email-collaboration">Collaboration Invites</Label>
                <div className="text-sm text-muted-foreground">
                  When you're invited to collaborate
                </div>
              </div>
            </div>
            <Switch
              id="email-collaboration"
              checked={preferences.email_on_collaboration}
              onCheckedChange={(checked) => updatePreference('email_on_collaboration', checked)}
              disabled={!preferences.email_notifications}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5 flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-muted-foreground" />
              <div>
                <Label htmlFor="email-mention">Mentions</Label>
                <div className="text-sm text-muted-foreground">
                  When someone mentions you in a note
                </div>
              </div>
            </div>
            <Switch
              id="email-mention"
              checked={preferences.email_on_mention}
              onCheckedChange={(checked) => updatePreference('email_on_mention', checked)}
              disabled={!preferences.email_notifications}
            />
          </div>
        </CardContent>
      </Card>

      {/* Digest Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Email Digest</CardTitle>
          <CardDescription>Receive periodic summaries of activity</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <Label htmlFor="digest-frequency">Digest Frequency</Label>
            <Select
              value={preferences.email_digest_frequency}
              onValueChange={(value) => updatePreference('email_digest_frequency', value)}
              disabled={!preferences.email_notifications}
            >
              <SelectTrigger id="digest-frequency">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="never">Never</SelectItem>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
