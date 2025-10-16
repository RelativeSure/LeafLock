import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Alert, AlertDescription } from '../ui/alert'
import { Mail, Download, Eye, Info } from 'lucide-react'

export function PrivacySettingsTab() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            Email Notifications
          </CardTitle>
          <CardDescription>Manage which emails you receive from LeafLock</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              Email notification preferences will be available in a future update. Currently, you
              receive essential security emails only (password resets, account security alerts).
            </AlertDescription>
          </Alert>

          <div className="space-y-3 pt-2">
            <h4 className="text-sm font-medium">Current Email Types</h4>
            <div className="space-y-2">
              <div className="flex items-start gap-3 rounded-lg border border-border bg-muted/30 p-3">
                <div className="flex-1">
                  <p className="text-sm font-medium">Security Alerts</p>
                  <p className="text-xs text-muted-foreground">
                    Password resets, account changes, and security notifications (always enabled)
                  </p>
                </div>
                <span className="text-xs text-muted-foreground">Required</span>
              </div>

              <div className="flex items-start gap-3 rounded-lg border border-border bg-muted/30 p-3">
                <div className="flex-1">
                  <p className="text-sm font-medium">Welcome Emails</p>
                  <p className="text-xs text-muted-foreground">
                    New account welcome message with getting started tips
                  </p>
                </div>
                <span className="text-xs text-muted-foreground">Enabled</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Data Export
          </CardTitle>
          <CardDescription>Download your data or manage your account</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            You can export all your notes and data from the <strong>Account</strong> tab in
            Settings. This includes all notes, tags, folders, and templates in an encrypted format.
          </p>

          <div className="pt-2">
            <a
              href="#account"
              onClick={(e) => {
                e.preventDefault()
                const accountTab = document.querySelector('[value="account"]') as HTMLElement
                accountTab?.click()
              }}
              className="text-sm text-primary hover:underline inline-flex items-center gap-1.5"
            >
              <Download className="h-4 w-4" />
              Go to Account Tab to Export Data
            </a>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5" />
            Privacy & Security
          </CardTitle>
          <CardDescription>Understand how your data is protected</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div className="flex items-start gap-3">
              <div className="rounded-full bg-primary/10 p-2">
                <Eye className="h-4 w-4 text-primary" />
              </div>
              <div className="flex-1 space-y-1">
                <p className="text-sm font-medium">Zero-Knowledge Encryption</p>
                <p className="text-xs text-muted-foreground">
                  All your notes are encrypted on your device before being sent to the server. The
                  server never sees your plaintext data - only you have the encryption keys.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="rounded-full bg-primary/10 p-2">
                <Mail className="h-4 w-4 text-primary" />
              </div>
              <div className="flex-1 space-y-1">
                <p className="text-sm font-medium">Email Privacy</p>
                <p className="text-xs text-muted-foreground">
                  Your email address is encrypted in the database using GDPR-compliant encryption.
                  We only decrypt it when absolutely necessary for account recovery.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="rounded-full bg-primary/10 p-2">
                <Download className="h-4 w-4 text-primary" />
              </div>
              <div className="flex-1 space-y-1">
                <p className="text-sm font-medium">Data Portability</p>
                <p className="text-xs text-muted-foreground">
                  You can export all your data at any time. Your exported data remains encrypted and
                  can be imported into another LeafLock instance.
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t">
            <a
              href="https://docs.leaflock.app/privacy-policy"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-primary hover:underline inline-flex items-center gap-1.5"
            >
              <Info className="h-4 w-4" />
              Read Full Privacy Policy
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
