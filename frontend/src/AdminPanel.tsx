import React, { useEffect, useState } from 'react'
import { Shield, Loader2, Mail, Crown } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import type { AdminUser } from '@/lib/schemas'

const roles = ['admin', 'moderator', 'auditor']

type AdminPanelProps = {
  api: any
}

type StatusState = {
  variant: 'default' | 'destructive'
  message: string
} | null

const AdminPanel: React.FC<AdminPanelProps> = ({ api }) => {
  const [userId, setUserId] = useState('')
  const [role, setRole] = useState('moderator')
  const [status, setStatus] = useState<StatusState>(null)
  const [userRoles, setUserRoles] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [quickOpen, setQuickOpen] = useState(false)
  const [quickQuery, setQuickQuery] = useState('')
  const [quickLoading, setQuickLoading] = useState(false)
  const [quickResults, setQuickResults] = useState<AdminPanelQuickUser[]>([])
  const quickDebounceRef = React.useRef<number | null>(null)

  type AdminPanelQuickUser = Pick<AdminUser, 'user_id' | 'email' | 'is_admin' | 'admin_via_allowlist'>

  const maskEmail = (email: string): string => {
    const [localPart, domain] = email.split('@')
    if (localPart.length <= 2) return `${localPart[0]}***@${domain}`
    return `${localPart.slice(0, 2)}***@${domain}`
  }

  useEffect(() => {
    try {
      const me = localStorage.getItem('current_user_id') || ''
      if (me) {
        setUserId(me)
      }
    } catch {
      // ignore localStorage failures (e.g., disabled storage)
    }
  }, [])

  const ensureUserId = () => {
    if (!userId.trim()) {
      setStatus({
        variant: 'destructive',
        message: 'Enter a user ID before performing admin actions.',
      })
      return false
    }
    return true
  }

  const setSuccess = (message: string) => setStatus({ variant: 'default', message })
  const setFailure = (message: string) => setStatus({ variant: 'destructive', message })

  const fetchRoles = async (quiet = false) => {
    if (!ensureUserId()) return
    try {
      const res = await api.adminGetUserRoles(userId)
      setUserRoles(res.roles || [])
      if (!quiet) setSuccess('Roles refreshed.')
    } catch (e: any) {
      if (!quiet) setFailure(e?.message || 'Failed to load roles')
    }
  }

  const handleLoadRoles = async () => {
    if (!ensureUserId()) return
    setStatus(null)
    setLoading(true)
    await fetchRoles()
    setLoading(false)
  }

  const toggleAdmin = async (val: boolean) => {
    if (!ensureUserId()) return
    setStatus(null)
    setLoading(true)
    try {
      await api.adminSetAdmin(userId, val)
      setSuccess(`Admin ${val ? 'granted' : 'revoked'}.`)
      await fetchRoles(true)
    } catch (e: any) {
      setFailure(e?.message || 'Failed to update admin status')
    } finally {
      setLoading(false)
    }
  }

  const assignRole = async () => {
    if (!ensureUserId()) return
    setStatus(null)
    setLoading(true)
    try {
      await api.adminAssignRole(userId, role)
      setSuccess(`Assigned ${role}.`)
      await fetchRoles(true)
    } catch (e: any) {
      setFailure(e?.message || 'Failed to assign role')
    } finally {
      setLoading(false)
    }
  }

  const removeRole = async () => {
    if (!ensureUserId()) return
    setStatus(null)
    setLoading(true)
    try {
      await api.adminRemoveRole(userId, role)
      setSuccess(`Removed ${role}.`)
      await fetchRoles(true)
    } catch (e: any) {
      setFailure(e?.message || 'Failed to remove role')
    } finally {
      setLoading(false)
    }
  }

  const useMyId = () => {
    try {
      const me = localStorage.getItem('current_user_id') || ''
      if (me) {
        setUserId(me)
        setStatus({ variant: 'default', message: 'Loaded your user ID.' })
      } else {
        setFailure('No stored user ID found.')
      }
    } catch {
      setFailure('Unable to access stored user ID.')
    }
  }

  const loadUsers = async (query = quickQuery.trim()) => {
    const trimmed = query.trim()
    if (!trimmed) {
      setQuickResults([])
      return
    }
    try {
      const res = await api.adminListUsers({ q: trimmed, limit: 8, offset: 0 })
      setQuickResults(res.users || [])
    } catch (e: any) {
      setFailure(e?.message || 'Lookup failed')
      setQuickResults([])
      throw e
    }
  }

  const resetQuickState = () => {
    setQuickQuery('')
    setQuickResults([])
    setQuickLoading(false)
    if (quickDebounceRef.current) {
      window.clearTimeout(quickDebounceRef.current)
      quickDebounceRef.current = null
    }
  }

  const ensureQuickResults = (query: string) => {
    if (!quickOpen) return
    if (quickDebounceRef.current) {
      window.clearTimeout(quickDebounceRef.current)
    }
    if (!query.trim()) {
      setQuickResults([])
      setQuickLoading(false)
      return
    }
    quickDebounceRef.current = window.setTimeout(async () => {
      setQuickLoading(true)
      try {
        await loadUsers(query)
      } catch {
        // loadUsers already sets failure state
      } finally {
        setQuickLoading(false)
      }
    }, 250)
  }

  const handleQuickSelect = async (user: AdminPanelQuickUser) => {
    setQuickLoading(true)
    setStatus(null)
    try {
      await api.adminSetAdmin(user.user_id, true)
      setSuccess(`Granted admin to ${maskEmail(user.email)}.`)
      await loadUsers()
      setQuickOpen(false)
      resetQuickState()
    } catch (e: any) {
      setFailure(e?.message || 'Failed to grant admin')
    } finally {
      setQuickLoading(false)
    }
  }

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Shield className="h-4 w-4" /> Admin Panel
        </CardTitle>
        <CardDescription>
          Manage administrator privileges and roles for individual users.
          <br />
          <span className="text-amber-600 dark:text-amber-400 text-sm font-medium">
            ⚠️ Handle user data with care - emails are masked for privacy.
          </span>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {status && status.message && (
          <Alert variant={status.variant}>
            <AlertDescription>{status.message}</AlertDescription>
          </Alert>
        )}

        <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_auto]">
          <div className="space-y-2">
            <Label htmlFor="admin-user-id">User ID</Label>
            <Input
              id="admin-user-id"
              placeholder="User ID (UUID)"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="flex items-end">
            <Button variant="outline" type="button" onClick={useMyId} disabled={loading}>
              Use my ID
            </Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_auto]">
          <div className="space-y-2">
            <Label htmlFor="admin-role">Role</Label>
            <Select value={role} onValueChange={(value) => setRole(value)}>
              <SelectTrigger id="admin-role">
                <SelectValue placeholder="Select a role" />
              </SelectTrigger>
              <SelectContent>
                {roles.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button onClick={handleLoadRoles} disabled={loading || !userId.trim()}>
            {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            Load Roles
          </Button>
          <Button
            variant="secondary"
            onClick={() => toggleAdmin(true)}
            disabled={loading || !userId.trim()}
          >
            Make Admin
          </Button>
          <Button
            variant="outline"
            onClick={() => toggleAdmin(false)}
            disabled={loading || !userId.trim()}
          >
            Revoke Admin
          </Button>
          <Button variant="secondary" onClick={assignRole} disabled={loading || !userId.trim()}>
            Assign Role
          </Button>
          <Button variant="destructive" onClick={removeRole} disabled={loading || !userId.trim()}>
            Remove Role
          </Button>
        </div>

        <div className="space-y-2">
          <Label className="text-sm font-medium">Current roles</Label>
          <div className="flex flex-wrap gap-2">
            {userRoles.length > 0 ? (
              userRoles.map((r) => (
                <Badge key={r} variant="secondary">
                  {r}
                </Badge>
              ))
            ) : (
              <span className="text-sm text-muted-foreground">(none)</span>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <Label>Quick grant</Label>
          <Button
            type="button"
            variant="secondary"
            className="w-full md:w-auto"
            onClick={() => {
              setQuickOpen(true)
              resetQuickState()
            }}
          >
            <Crown className="mr-2 h-4 w-4" /> Grant admin by email
          </Button>
          <p className="text-sm text-muted-foreground">
            Opens a command palette to search users and instantly promote them.
            <br />
            <span className="text-amber-600 dark:text-amber-400 text-xs">
              Note: Emails are masked for privacy protection.
            </span>
          </p>
        </div>
      </CardContent>

      <CommandDialog
        open={quickOpen}
        onOpenChange={(open) => {
          setQuickOpen(open)
          if (!open) {
            resetQuickState()
          }
        }}
      >
        <div className="p-3">
          <CommandInput
            placeholder="Search users by email..."
            value={quickQuery}
            onValueChange={(value) => {
              setQuickQuery(value)
              ensureQuickResults(value)
            }}
          />
        </div>
        <CommandList>
          <CommandEmpty>
            {quickQuery.trim()
              ? 'No matching users. Double-check the email.'
              : 'Start typing an email address.'}
          </CommandEmpty>
          {quickLoading && (
            <CommandGroup heading="Searching">
              <CommandItem disabled>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Looking up users…
              </CommandItem>
            </CommandGroup>
          )}
          {!quickLoading && quickResults.length > 0 && (
            <CommandGroup heading="Users">
              {quickResults.map((user) => (
                <CommandItem
                  key={user.user_id}
                  value={user.email}
                  onSelect={() => handleQuickSelect(user)}
                  className="justify-between"
                >
                  <div className="flex items-center gap-2">
                    <Mail className="h-4 w-4 text-muted-foreground" />
                    <span>{maskEmail(user.email)}</span>
                  </div>
                  {user.is_admin ? (
                    <Badge variant="outline">admin</Badge>
                  ) : user.admin_via_allowlist ? (
                    <Badge variant="secondary">allowlist</Badge>
                  ) : null}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
        </CommandList>
      </CommandDialog>
    </Card>
  )
}

export default AdminPanel
