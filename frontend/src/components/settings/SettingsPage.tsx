import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs'
import { Button } from '../ui/button'
import { MfaSettings } from './MfaSettings'
import { DeleteAccount } from './DeleteAccount'
import { ExportData } from './ExportData'
import { Shield, Eye, User, ArrowLeft } from 'lucide-react'
import { Alert, AlertDescription } from '../ui/alert'

// ThemeToggle component (inline to match App.tsx pattern)
import { useState } from 'react'
import { useTheme } from '../../ThemeContext'
import type { ThemeType } from '../../ThemeContext'

const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useTheme()
  const [isOpen, setIsOpen] = useState(false)

  const themeOptions = [
    {
      value: 'system' as ThemeType,
      label: 'System',
      icon: (
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
          />
        </svg>
      ),
    },
    {
      value: 'light' as ThemeType,
      label: 'Light',
      icon: (
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
          />
        </svg>
      ),
    },
    {
      value: 'dark' as ThemeType,
      label: 'Dark',
      icon: (
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
          />
        </svg>
      ),
    },
  ]

  return (
    <div className="relative">
      <Button
        variant="outline"
        size="icon"
        onClick={() => setIsOpen(!isOpen)}
        className="rounded-full"
        aria-label="Toggle theme"
      >
        {themeOptions.find((opt) => opt.value === theme)?.icon}
      </Button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setIsOpen(false)}
            aria-hidden="true"
          />
          <div className="absolute right-0 top-12 z-50 w-48 rounded-md border bg-popover p-1 shadow-md">
            <div className="space-y-1">
              {themeOptions.map((option) => (
                <button
                  key={option.value}
                  onClick={() => {
                    setTheme(option.value)
                    setIsOpen(false)
                  }}
                  className={`w-full flex items-center gap-3 px-3 py-2 text-sm rounded-sm transition-colors ${
                    theme === option.value
                      ? 'bg-accent text-accent-foreground'
                      : 'hover:bg-accent hover:text-accent-foreground'
                  }`}
                >
                  {option.icon}
                  <span>{option.label}</span>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// SecureAPI interface (for type checking)
interface SecureAPI {
  getMfaStatus: () => Promise<{ enabled: boolean; has_secret: boolean }>
  startMfaSetup: () => Promise<{
    secret: string
    otpauth_url: string
    issuer?: string
    account?: string
  }>
  enableMfa: (code: string) => Promise<{ backup_codes?: string[] }>
  disableMfa: (code: string) => Promise<{ enabled: boolean }>
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

  const handleRegenerateBackupCodes = async (password: string) => {
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
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="security" className="gap-2">
              <Shield className="h-4 w-4" />
              Security
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
              onGetMfaStatus={api.getMfaStatus.bind(api)}
              onBeginMfaSetup={api.startMfaSetup.bind(api)}
              onEnableMfa={api.enableMfa.bind(api)}
              onDisableMfa={api.disableMfa.bind(api)}
              onGetBackupCodes={handleGetBackupCodes}
              onRegenerateBackupCodes={handleRegenerateBackupCodes}
            />
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
            <ExportData onExport={handleExportData} />

            {/* Delete Account Section */}
            <DeleteAccount onDelete={handleDeleteAccount} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
