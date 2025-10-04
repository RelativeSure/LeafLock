import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs'
import { Button } from '../ui/button'
import { MfaSettings } from './MfaSettings'
import { DeleteAccount } from './DeleteAccount'
import { ExportDataComponent } from './ExportData'
import { ShareLinksTab } from './ShareLinksTab'
import { Shield, Eye, User, ArrowLeft, Link as LinkIcon } from 'lucide-react'
import { ThemeToggle } from '@/components/ThemeToggle'
import type { MfaSetup, MfaStatus } from '@/lib/schemas'

// SecureAPI interface (for type checking)
interface SecureAPI {
  getMfaStatus: () => Promise<MfaStatus>
  startMfaSetup: () => Promise<MfaSetup>
  enableMfa: (code: string) => Promise<MfaStatus>
  disableMfa: (code: string) => Promise<MfaStatus>
  deleteAccount: (password: string) => Promise<{ success: boolean; message: string }>
  exportAccountData: () => Promise<any>
  // TODO: Implement these methods in SecureAPI
  // getBackupCodes: () => Promise<{ total: number; remaining: number }>
  // regenerateBackupCodes: (password: string) => Promise<{ codes: string[] }>
}

interface SettingsPageProps {
  api: SecureAPI
  onBack: () => void
  onLogout: () => void
}

export function SettingsPage({ api, onBack, onLogout }: SettingsPageProps) {
  // Placeholder functions for backup codes (to be implemented in SecureAPI)
  const handleGetBackupCodes = async () => {
    // TODO: Implement in SecureAPI
    console.warn('getBackupCodes not yet implemented')
    return { total: 10, remaining: 10 }
  }

  const handleRegenerateBackupCodes = async (_password: string) => {
    // TODO: Implement in SecureAPI
    console.warn('regenerateBackupCodes not yet implemented')
    return { codes: [] }
  }

  const handleDeleteAccount = async (password: string) => {
    await api.deleteAccount(password)
    onLogout()
  }

  const handleExportData = async () => {
    return await api.exportAccountData()
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col items-center p-6">
      <div className="w-full max-w-4xl space-y-6">
        {/* Header with back button and theme toggle */}
        <div className="flex items-center justify-between">
          <Button variant="ghost" onClick={onBack} className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to notes
          </Button>
          <ThemeToggle />
        </div>

        {/* Page title */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground mt-2">
            Manage your account security, privacy, and preferences
          </p>
        </div>

        {/* Tabbed content */}
        <Tabs defaultValue="security" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="security" className="gap-2">
              <Shield className="h-4 w-4" />
              Security
            </TabsTrigger>
            <TabsTrigger value="sharing" className="gap-2">
              <LinkIcon className="h-4 w-4" />
              Sharing
            </TabsTrigger>
            <TabsTrigger value="privacy" className="gap-2">
              <Eye className="h-4 w-4" />
              Privacy
            </TabsTrigger>
            <TabsTrigger value="account" className="gap-2">
              <User className="h-4 w-4" />
              Account
            </TabsTrigger>
          </TabsList>

          {/* Security Tab */}
          <TabsContent value="security" className="mt-6">
            <MfaSettings
              onGetMfaStatus={() => api.getMfaStatus()}
              onBeginMfaSetup={() => api.startMfaSetup()}
              onEnableMfa={async (code): Promise<MfaStatus & { backup_codes?: string[] }> => {
                const status = await api.enableMfa(code)
                return { ...status }
              }}
              onDisableMfa={(code): Promise<MfaStatus> => api.disableMfa(code)}
              onGetBackupCodes={handleGetBackupCodes}
              onRegenerateBackupCodes={handleRegenerateBackupCodes}
            />
          </TabsContent>

          {/* Sharing Tab */}
          <TabsContent value="sharing" className="mt-6">
            <ShareLinksTab />
          </TabsContent>

          {/* Privacy Tab */}
          <TabsContent value="privacy" className="mt-6">
            <Card>
              <CardHeader>
                <CardTitle>Privacy Settings</CardTitle>
                <CardDescription>
                  Control your data visibility and sharing preferences
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-center py-12">
                  <p className="text-muted-foreground text-center">
                    Privacy settings coming soon
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Account Tab */}
          <TabsContent value="account" className="mt-6 space-y-6">
            {/* Export Data Section */}
            <ExportDataComponent onExport={handleExportData} />

            {/* Delete Account Section */}
            <DeleteAccount onDelete={handleDeleteAccount} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
