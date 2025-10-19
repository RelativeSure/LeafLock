import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Mail, Server, Key, Shield, CheckCircle2, XCircle, Info, ExternalLink } from 'lucide-react'

export function AdminSettingsTab() {
  // SMTP configuration is currently environment-only
  // This tab displays the current status and provides documentation
  // Runtime configuration will require backend changes (future enhancement)

  const smtpEnabled = import.meta.env.VITE_SMTP_ENABLED === 'true'

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Mail className="h-5 w-5" />
                SMTP Configuration
              </CardTitle>
              <CardDescription>
                Email server settings for password resets and notifications
              </CardDescription>
            </div>
            <Badge variant={smtpEnabled ? 'default' : 'secondary'} className="h-fit">
              {smtpEnabled ? (
                <span className="flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" />
                  Enabled
                </span>
              ) : (
                <span className="flex items-center gap-1">
                  <XCircle className="h-3 w-3" />
                  Disabled
                </span>
              )}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              SMTP settings are currently configured via environment variables and require a
              container restart to change. Runtime configuration will be added in a future update.
            </AlertDescription>
          </Alert>

          {smtpEnabled ? (
            <div className="space-y-4">
              <div className="rounded-lg border border-border bg-muted/30 p-4 space-y-3">
                <div className="flex items-start gap-3">
                  <Server className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div className="flex-1 space-y-1">
                    <p className="text-sm font-medium">SMTP Server</p>
                    <p className="text-sm text-muted-foreground">
                      Configured via{' '}
                      <code className="bg-muted px-1.5 py-0.5 rounded text-xs">SMTP_HOST</code> and{' '}
                      <code className="bg-muted px-1.5 py-0.5 rounded text-xs">SMTP_PORT</code>
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Key className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div className="flex-1 space-y-1">
                    <p className="text-sm font-medium">Authentication</p>
                    <p className="text-sm text-muted-foreground">
                      Configured via{' '}
                      <code className="bg-muted px-1.5 py-0.5 rounded text-xs">SMTP_USER</code> and{' '}
                      <code className="bg-muted px-1.5 py-0.5 rounded text-xs">SMTP_PASSWORD</code>
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Shield className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div className="flex-1 space-y-1">
                    <p className="text-sm font-medium">Security</p>
                    <p className="text-sm text-muted-foreground">
                      TLS encryption configured via{' '}
                      <code className="bg-muted px-1.5 py-0.5 rounded text-xs">SMTP_USE_TLS</code>
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Mail className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div className="flex-1 space-y-1">
                    <p className="text-sm font-medium">Sender Address</p>
                    <p className="text-sm text-muted-foreground">
                      Configured via{' '}
                      <code className="bg-muted px-1.5 py-0.5 rounded text-xs">SMTP_FROM</code>
                    </p>
                  </div>
                </div>
              </div>

              <div className="pt-2">
                <h4 className="text-sm font-medium mb-2">Features Enabled</h4>
                <ul className="space-y-1.5 text-sm text-muted-foreground">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-green-600 dark:text-green-500" />
                    Welcome emails on registration
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-green-600 dark:text-green-500" />
                    Password reset emails
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-green-600 dark:text-green-500" />
                    Password changed notifications
                  </li>
                </ul>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-dashed border-border bg-muted/20 p-8 text-center space-y-3">
              <XCircle className="h-12 w-12 text-muted-foreground/50 mx-auto" />
              <div className="space-y-1">
                <p className="text-sm font-medium">SMTP Not Configured</p>
                <p className="text-sm text-muted-foreground max-w-md mx-auto">
                  Email features are currently disabled. Configure SMTP environment variables and
                  restart the container to enable email functionality.
                </p>
              </div>
            </div>
          )}

          <div className="pt-2 border-t">
            <a
              href="https://docs.leaflock.app/configuration/smtp"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
            >
              <Info className="h-4 w-4" />
              View SMTP Configuration Guide
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            System Settings
          </CardTitle>
          <CardDescription>Global system configuration and security settings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              Registration and other system settings are managed via the Admin page. Additional
              runtime configuration options will be added in future updates.
            </AlertDescription>
          </Alert>

          <div className="pt-2">
            <a
              href="/admin"
              className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
            >
              <Shield className="h-4 w-4" />
              Manage User Accounts & Registration
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
