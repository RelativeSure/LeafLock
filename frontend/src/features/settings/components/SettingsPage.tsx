import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { MfaSettings } from './MfaSettings'
import { DeleteAccount } from './DeleteAccount'
import { ExportDataComponent } from './ExportData'
import { ShareLinksTab } from './ShareLinksTab'
import { AdminSettingsTab } from './AdminSettingsTab'
import { PrivacySettingsTab } from './PrivacySettingsTab'
import { Shield, Eye, User, ArrowLeft, Link as LinkIcon, Settings } from 'lucide-react'
import { ThemeToggle } from '@/components/common'
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
  const [activeTab, setActiveTab] = useState('security')

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
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card flex flex-col">
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-2 mb-4">
            <Button variant="ghost" onClick={onBack} className="gap-2">
              <ArrowLeft className="h-4 w-4" />
              Back to notes
            </Button>
          </div>
          <h1 className="text-2xl font-serif font-semibold text-foreground">Settings</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage your account security, privacy, and preferences
          </p>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          <Button
            variant={activeTab === 'security' ? 'default' : 'ghost'}
            className="w-full justify-start gap-3 text-foreground/80 hover:text-foreground"
            onClick={() => setActiveTab('security')}
          >
            <Shield className="h-4 w-4" />
            Security
          </Button>
          <Button
            variant={activeTab === 'privacy' ? 'default' : 'ghost'}
            className="w-full justify-start gap-3 text-foreground/60 hover:text-foreground"
            onClick={() => setActiveTab('privacy')}
          >
            <Eye className="h-4 w-4" />
            Privacy
          </Button>
          <Button
            variant={activeTab === 'account' ? 'default' : 'ghost'}
            className="w-full justify-start gap-3 text-foreground/60 hover:text-foreground"
            onClick={() => setActiveTab('account')}
          >
            <User className="h-4 w-4" />
            Account
          </Button>
          <Button
            variant={activeTab === 'sharing' ? 'default' : 'ghost'}
            className="w-full justify-start gap-3 text-foreground/60 hover:text-foreground"
            onClick={() => setActiveTab('sharing')}
          >
            <LinkIcon className="h-4 w-4" />
            Sharing
          </Button>
          {isAdmin && (
            <Button
              variant={activeTab === 'admin' ? 'default' : 'ghost'}
              className="w-full justify-start gap-3 text-foreground/60 hover:text-foreground"
              onClick={() => setActiveTab('admin')}
            >
              <Settings className="h-4 w-4" />
              Admin
            </Button>
          )}
        </nav>

        <div className="p-4 border-t border-border">
          <ThemeToggle />
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <main className="flex-1 overflow-auto p-8">
          {activeTab === 'security' && (
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
          )}

          {activeTab === 'privacy' && <PrivacySettingsTab />}

          {activeTab === 'account' && (
            <div className="space-y-6">
              <ExportDataComponent onExport={handleExportData} />
              <DeleteAccount onDelete={handleDeleteAccount} />
            </div>
          )}

          {activeTab === 'sharing' && <ShareLinksTab />}

          {activeTab === 'admin' && isAdmin && <AdminSettingsTab />}
        </main>
      </div>
    </div>
  )
}

export default SettingsPage
