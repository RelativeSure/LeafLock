import { useState, useEffect } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { useToast } from '@/hooks/use-toast'
import { apiClient } from '@/services/api/apiClient'

interface AppSettings {
  [key: string]: string
}

export function AdminSettingsPanel() {
  const [settings, setSettings] = useState<AppSettings>({})
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const { toast } = useToast()

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      setIsLoading(true)
      const response = await apiClient.get('/admin/settings')
      setSettings(response.data.settings || {})
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load settings',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const updateSetting = async (key: string, value: string) => {
    try {
      setIsSaving(true)
      await apiClient.put('/admin/settings', { key, value })
      setSettings({ ...settings, [key]: value })
      toast({
        title: 'Success',
        description: 'Setting updated successfully',
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update setting',
        variant: 'destructive',
      })
    } finally {
      setIsSaving(false)
    }
  }

  const getSettingValue = (key: string, defaultValue: string = ''): string => {
    return settings[key] || defaultValue
  }

  const getBooleanSetting = (key: string, defaultValue: boolean = false): boolean => {
    const value = settings[key]
    if (value === undefined) return defaultValue
    return value === 'true'
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <RefreshCw className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Application Settings</h2>
        <p className="text-muted-foreground">
          Configure system-wide settings for your LeafLock instance
        </p>
      </div>

      {/* Security Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Security</CardTitle>
          <CardDescription>Security and access control settings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="registration">Allow User Registration</Label>
              <div className="text-sm text-muted-foreground">
                Enable or disable new user signups
              </div>
            </div>
            <Switch
              id="registration"
              checked={getBooleanSetting('registration_enabled', true)}
              onCheckedChange={(checked) => updateSetting('registration_enabled', String(checked))}
              disabled={isSaving}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="session_timeout">Session Timeout (hours)</Label>
            <Input
              id="session_timeout"
              type="number"
              value={getSettingValue('session_timeout', '24')}
              onChange={(e) => updateSetting('session_timeout', e.target.value)}
              onBlur={() => {}}
              disabled={isSaving}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="password_min_length">Minimum Password Length</Label>
            <Input
              id="password_min_length"
              type="number"
              value={getSettingValue('password_min_length', '12')}
              onChange={(e) => updateSetting('password_min_length', e.target.value)}
              disabled={isSaving}
            />
          </div>
        </CardContent>
      </Card>

      {/* Storage Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Storage</CardTitle>
          <CardDescription>Storage limits and file upload settings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="max_file_size">Max File Upload Size (MB)</Label>
            <Input
              id="max_file_size"
              type="number"
              value={getSettingValue('max_file_size', '10')}
              onChange={(e) => updateSetting('max_file_size', e.target.value)}
              disabled={isSaving}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="storage_limit_per_user">Storage Limit Per User (GB)</Label>
            <Input
              id="storage_limit_per_user"
              type="number"
              value={getSettingValue('storage_limit_per_user', '5')}
              onChange={(e) => updateSetting('storage_limit_per_user', e.target.value)}
              disabled={isSaving}
            />
          </div>
        </CardContent>
      </Card>

      {/* Email Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Email</CardTitle>
          <CardDescription>Email notification settings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="email_enabled">Enable Email Notifications</Label>
              <div className="text-sm text-muted-foreground">
                Send email notifications for important events
              </div>
            </div>
            <Switch
              id="email_enabled"
              checked={getBooleanSetting('email_notifications_enabled', false)}
              onCheckedChange={(checked) =>
                updateSetting('email_notifications_enabled', String(checked))
              }
              disabled={isSaving}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="smtp_host">SMTP Host</Label>
            <Input
              id="smtp_host"
              value={getSettingValue('smtp_host', '')}
              onChange={(e) => updateSetting('smtp_host', e.target.value)}
              placeholder="smtp.example.com"
              disabled={isSaving}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="smtp_port">SMTP Port</Label>
            <Input
              id="smtp_port"
              type="number"
              value={getSettingValue('smtp_port', '587')}
              onChange={(e) => updateSetting('smtp_port', e.target.value)}
              disabled={isSaving}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="smtp_from">From Email Address</Label>
            <Input
              id="smtp_from"
              type="email"
              value={getSettingValue('smtp_from', '')}
              onChange={(e) => updateSetting('smtp_from', e.target.value)}
              placeholder="noreply@example.com"
              disabled={isSaving}
            />
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={fetchSettings} variant="outline" disabled={isSaving}>
          <RefreshCw className={`mr-2 h-4 w-4 ${isSaving ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>
    </div>
  )
}
