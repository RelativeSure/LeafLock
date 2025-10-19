import { useState, useEffect } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs'
import { Button } from '../ui/button'
import { MfaSettings } from './MfaSettings'
import { DeleteAccount } from './DeleteAccount'
import { ExportDataComponent } from './ExportData'
import { ShareLinksTab } from './ShareLinksTab'
import { AdminSettingsTab } from './AdminSettingsTab'
import { PrivacySettingsTab } from './PrivacySettingsTab'
import { Shield, Eye, User, ArrowLeft, Link as LinkIcon, Settings } from 'lucide-react'
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
  getBackupCodes: () => Promise<{ total: number; remaining: number }>
  regenerateBackupCodes: (password: string) => Promise<{ codes: string[] }>
}

interface SettingsPageProps {
  api: SecureAPI
  onBack: () => void
  onLogout: () => void
}

function SettingsPage({ api, onBack, onLogout }: SettingsPageProps) {
  const [isAdmin, setIsAdmin] = useState(false)
  const [isStoreReady, setIsStoreReady] = useState(false)

  useEffect(() => {
    // Dynamically import the auth store to avoid initialization issues
    import('@/stores/authStore').then(({ useAuthStore }) => {
      setIsAdmin(useAuthStore.getState().isAdmin)
      const unsubscribe = useAuthStore.subscribe((state) => {
        setIsAdmin(state.isAdmin)
      })
      setIsStoreReady(true)
      return () => unsubscribe()
    })
  }, [])

  const handleGetBackupCodes = async () => {
    return await api.getBackupCodes()
  }

  const handleRegenerateBackupCodes = async (password: string) => {
    return await api.regenerateBackupCodes(password)
  }

  const handleDeleteAccount = async (password: string) => {
    await api.deleteAccount(password)
    onLogout()
  }

  const handleExportData = async () => {
    return await api.exportAccountData()
  }

  if (!isStoreReady) {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
        <div className="text-muted-foreground">Loading settings...</div>
      </div>
    )
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
          <TabsList className={`grid w-full ${isAdmin ? 'grid-cols-5' : 'grid-cols-4'}`}>
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
            {isAdmin && (
              <TabsTrigger value="admin" className="gap-2">
                <Settings className="h-4 w-4" />
                Admin
              </TabsTrigger>
            )}
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
            <PrivacySettingsTab />
          </TabsContent>

          {/* Account Tab */}
          <TabsContent value="account" className="mt-6 space-y-6">
            {/* Export Data Section */}
            <ExportDataComponent onExport={handleExportData} />

            {/* Delete Account Section */}
            <DeleteAccount onDelete={handleDeleteAccount} />
          </TabsContent>

          {/* Admin Tab - Only visible to admins */}
          {isAdmin && (
            <TabsContent value="admin" className="mt-6">
              <AdminSettingsTab />
            </TabsContent>
          )}
        </Tabs>
      </div>
    </div>
  )
}

export default SettingsPage
