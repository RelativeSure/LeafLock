"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/lib/auth-context"
import { useSettings } from "@/lib/settings-context"
import { useTheme } from "next-themes"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { Shield, ArrowLeft, User, Bell, Lock, Palette, Globe, AlertTriangle, ExternalLink } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { toast } from "sonner"
import { ActivityLogger } from "@/lib/activity-logger"

export default function SettingsPage() {
  const { user, isLoading, enableMFA, disableMFA, logout } = useAuth()
  const { settings, updateSettings } = useSettings()
  const { theme, setTheme } = useTheme()
  const router = useRouter()
  const [activeTab, setActiveTab] = useState("profile")
  const [mfaSecret, setMfaSecret] = useState("")
  const [showMfaDialog, setShowMfaDialog] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [deleteConfirmation, setDeleteConfirmation] = useState("")

  useEffect(() => {
    if (!isLoading && !user) {
      router.push("/auth")
    }
  }, [user, isLoading, router])

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  const handleEnableMFA = async () => {
    const secret = await enableMFA()
    setMfaSecret(secret)
    setShowMfaDialog(true)
    toast.success("MFA enabled successfully")
  }

  const handleDisableMFA = async () => {
    await disableMFA()
    toast.success("MFA disabled successfully")
  }

  const handleDeleteAccount = () => {
    if (deleteConfirmation !== "DELETE") {
      toast.error("Please type DELETE to confirm")
      return
    }

    if (user) {
      ActivityLogger.log(user.id, user.name, user.email, "account_deleted")
    }

    localStorage.clear()

    toast.success("Account deleted successfully")
    logout()
    router.push("/auth")
  }

  const tabs = [
    { id: "profile", label: "Profile", icon: User },
    { id: "security", label: "Security", icon: Lock },
    { id: "appearance", label: "Appearance", icon: Palette },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "preferences", label: "Preferences", icon: Globe },
    { id: "privacy", label: "Privacy & Data", icon: Shield },
  ]

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border bg-card px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => router.push("/dashboard")}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>
          <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary-foreground" />
          </div>
          <h1 className="text-xl font-bold">Settings</h1>
        </div>
      </header>

      <div className="flex h-[calc(100vh-57px)]">
        <aside className="w-64 border-r border-border bg-card p-4">
          <nav className="space-y-1">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 ${
                    activeTab === tab.id
                      ? "bg-primary text-primary-foreground shadow-sm"
                      : "text-foreground hover:bg-accent hover:text-accent-foreground"
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  {tab.label}
                </button>
              )
            })}
          </nav>
        </aside>

        <main className="flex-1 overflow-y-auto p-8">
          <div className="max-w-2xl">
            {activeTab === "profile" && (
              <div className="space-y-6 animate-in fade-in-50 duration-300">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Profile Settings</h2>
                  <p className="text-muted-foreground">Manage your account information</p>
                </div>

                <Card className="p-6 space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="name">Full Name</Label>
                    <Input id="name" defaultValue={user.name} />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="email">Email Address</Label>
                    <Input id="email" type="email" defaultValue={user.email} disabled />
                    <p className="text-xs text-muted-foreground">Email cannot be changed</p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="joined">Member Since</Label>
                    <Input id="joined" defaultValue={new Date(user.createdAt).toLocaleDateString()} disabled />
                  </div>

                  <Separator />

                  <div className="flex justify-end gap-3">
                    <Button variant="outline">Cancel</Button>
                    <Button>Save Changes</Button>
                  </div>
                </Card>
              </div>
            )}

            {activeTab === "security" && (
              <div className="space-y-6 animate-in fade-in-50 duration-300">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Security Settings</h2>
                  <p className="text-muted-foreground">Manage your security preferences</p>
                </div>

                <Card className="p-6 space-y-6">
                  <div>
                    <h3 className="font-semibold mb-4">Two-Factor Authentication</h3>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium">MFA Status</p>
                        <p className="text-xs text-muted-foreground">{user.mfaEnabled ? "Enabled" : "Disabled"}</p>
                      </div>
                      {user.mfaEnabled ? (
                        <Button variant="destructive" onClick={handleDisableMFA}>
                          Disable MFA
                        </Button>
                      ) : (
                        <Button onClick={handleEnableMFA}>Enable MFA</Button>
                      )}
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="font-semibold mb-4">Change Password</h3>
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="current-password">Current Password</Label>
                        <Input id="current-password" type="password" />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="new-password">New Password</Label>
                        <Input id="new-password" type="password" />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="confirm-password">Confirm New Password</Label>
                        <Input id="confirm-password" type="password" />
                      </div>
                      <Button>Update Password</Button>
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="font-semibold mb-4">End-to-End Encryption</h3>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium">Encryption Status</p>
                        <p className="text-xs text-muted-foreground">
                          {settings.encryptionEnabled ? "All notes are encrypted" : "Encryption disabled"}
                        </p>
                      </div>
                      <Switch
                        checked={settings.encryptionEnabled}
                        onCheckedChange={(checked) => updateSettings({ encryptionEnabled: checked })}
                      />
                    </div>
                  </div>
                </Card>
              </div>
            )}

            {activeTab === "appearance" && (
              <div className="space-y-6 animate-in fade-in-50 duration-300">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Appearance Settings</h2>
                  <p className="text-muted-foreground">Customize how the app looks</p>
                </div>

                <Card className="p-6 space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="theme">Theme</Label>
                    <Select value={theme} onValueChange={setTheme}>
                      <SelectTrigger id="theme">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="light">Light</SelectItem>
                        <SelectItem value="dark">Dark</SelectItem>
                        <SelectItem value="system">System</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">Choose your preferred color scheme</p>
                  </div>

                  <Separator />

                  <div className="space-y-2">
                    <Label htmlFor="view">Default View</Label>
                    <Select
                      value={settings.defaultView}
                      onValueChange={(value: any) => updateSettings({ defaultView: value })}
                    >
                      <SelectTrigger id="view">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="list">List View</SelectItem>
                        <SelectItem value="grid">Grid View</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <Separator />

                  <div className="space-y-2">
                    <Label htmlFor="language">Language</Label>
                    <Select value={settings.language} onValueChange={(value) => updateSettings({ language: value })}>
                      <SelectTrigger id="language">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="en">English</SelectItem>
                        <SelectItem value="es">Spanish</SelectItem>
                        <SelectItem value="fr">French</SelectItem>
                        <SelectItem value="de">German</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </Card>
              </div>
            )}

            {activeTab === "notifications" && (
              <div className="space-y-6 animate-in fade-in-50 duration-300">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Notification Settings</h2>
                  <p className="text-muted-foreground">Manage how you receive notifications</p>
                </div>

                <Card className="p-6 space-y-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">Push Notifications</p>
                      <p className="text-xs text-muted-foreground">Receive notifications in your browser</p>
                    </div>
                    <Switch
                      checked={settings.notificationsEnabled}
                      onCheckedChange={(checked) => updateSettings({ notificationsEnabled: checked })}
                    />
                  </div>

                  <Separator />

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">Email Notifications</p>
                      <p className="text-xs text-muted-foreground">Receive updates via email</p>
                    </div>
                    <Switch
                      checked={settings.emailNotifications}
                      onCheckedChange={(checked) => updateSettings({ emailNotifications: checked })}
                    />
                  </div>
                </Card>
              </div>
            )}

            {activeTab === "preferences" && (
              <div className="space-y-6 animate-in fade-in-50 duration-300">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Preferences</h2>
                  <p className="text-muted-foreground">Customize your editing experience</p>
                </div>

                <Card className="p-6 space-y-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">Auto-Save</p>
                      <p className="text-xs text-muted-foreground">Automatically save notes while editing</p>
                    </div>
                    <Switch
                      checked={settings.autoSave}
                      onCheckedChange={(checked) => updateSettings({ autoSave: checked })}
                    />
                  </div>

                  {settings.autoSave && (
                    <div className="space-y-2">
                      <Label htmlFor="interval">Auto-Save Interval (seconds)</Label>
                      <Input
                        id="interval"
                        type="number"
                        value={settings.autoSaveInterval}
                        onChange={(e) => updateSettings({ autoSaveInterval: Number.parseInt(e.target.value) })}
                        min={10}
                        max={300}
                      />
                    </div>
                  )}
                </Card>
              </div>
            )}

            {activeTab === "privacy" && (
              <div className="space-y-6 animate-in fade-in-50 duration-300">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Privacy & Data</h2>
                  <p className="text-muted-foreground">Manage your data and privacy settings</p>
                </div>

                <Card className="p-6 space-y-6">
                  <div>
                    <h3 className="font-semibold mb-2">Data Storage</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      All your data is stored locally in your browser. LeafLock does not store your notes on external
                      servers.
                    </p>
                    <div className="p-3 bg-muted rounded-lg text-xs space-y-1">
                      <p>
                        <span className="font-medium">Location:</span> Browser Local Storage
                      </p>
                      <p>
                        <span className="font-medium">Encryption:</span>{" "}
                        {settings.encryptionEnabled ? "Enabled (AES-GCM)" : "Disabled"}
                      </p>
                      <p>
                        <span className="font-medium">Retention:</span> Until you delete your account or clear browser
                        data
                      </p>
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="font-semibold mb-2">Data Collection</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      We collect minimal data to provide our services:
                    </p>
                    <ul className="text-sm space-y-2 list-disc list-inside text-muted-foreground">
                      <li>Account information (name, email)</li>
                      <li>Activity logs (login times, security events)</li>
                      <li>Settings and preferences</li>
                      <li>Notes, folders, tags, and templates (stored locally)</li>
                    </ul>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="font-semibold mb-2">Your Rights (GDPR)</h3>
                    <div className="space-y-3">
                      <div className="flex items-start gap-2">
                        <Shield className="h-4 w-4 mt-0.5 text-muted-foreground" />
                        <div className="text-sm">
                          <p className="font-medium">Right to Access</p>
                          <p className="text-muted-foreground">Export all your data at any time</p>
                        </div>
                      </div>
                      <div className="flex items-start gap-2">
                        <Shield className="h-4 w-4 mt-0.5 text-muted-foreground" />
                        <div className="text-sm">
                          <p className="font-medium">Right to Portability</p>
                          <p className="text-muted-foreground">Download your data in machine-readable format (JSON)</p>
                        </div>
                      </div>
                      <div className="flex items-start gap-2">
                        <Shield className="h-4 w-4 mt-0.5 text-muted-foreground" />
                        <div className="text-sm">
                          <p className="font-medium">Right to Erasure</p>
                          <p className="text-muted-foreground">Delete your account and all associated data</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="font-semibold mb-2">Documentation</h3>
                    <div className="space-y-2">
                      <Button variant="outline" className="w-full justify-between bg-transparent" asChild>
                        <a href="https://docs.leaflock.app/privacy" target="_blank" rel="noopener noreferrer">
                          Privacy Policy
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </Button>
                      <Button variant="outline" className="w-full justify-between bg-transparent" asChild>
                        <a href="https://docs.leaflock.app/terms" target="_blank" rel="noopener noreferrer">
                          Terms of Service
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </Button>
                      <Button variant="outline" className="w-full justify-between bg-transparent" asChild>
                        <a href="https://docs.leaflock.app/gdpr" target="_blank" rel="noopener noreferrer">
                          GDPR Compliance
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </Button>
                    </div>
                  </div>
                </Card>

                <Card className="p-6 space-y-4 border-destructive">
                  <div className="flex items-center gap-2 text-destructive">
                    <AlertTriangle className="h-5 w-5" />
                    <h3 className="font-semibold">Danger Zone</h3>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Once you delete your account, there is no going back. All your data will be permanently deleted.
                  </p>
                  <Button variant="destructive" onClick={() => setShowDeleteDialog(true)} className="w-full">
                    Delete Account
                  </Button>
                </Card>
              </div>
            )}
          </div>
        </main>
      </div>

      <Dialog open={showMfaDialog} onOpenChange={setShowMfaDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Two-Factor Authentication Enabled</DialogTitle>
            <DialogDescription>Save this secret key in your authenticator app</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="p-4 bg-muted rounded-lg">
              <p className="text-sm font-mono break-all">{mfaSecret}</p>
            </div>
            <p className="text-sm text-muted-foreground">
              Use this key with apps like Google Authenticator or Authy to generate verification codes.
            </p>
            <Button onClick={() => setShowMfaDialog(false)} className="w-full">
              Done
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete your account and remove all your data from our
              systems.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="delete-confirm">Type DELETE to confirm</Label>
              <Input
                id="delete-confirm"
                value={deleteConfirmation}
                onChange={(e) => setDeleteConfirmation(e.target.value)}
                placeholder="DELETE"
              />
            </div>
            <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
              <p className="text-sm text-destructive">
                <strong>Warning:</strong> All your notes, folders, tags, templates, and settings will be permanently
                deleted.
              </p>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteConfirmation("")}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteAccount}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete Account
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
