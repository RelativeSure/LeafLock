import React, { useEffect, useState } from 'react'
import { Shield, Loader2 } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'

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
      setStatus({ variant: 'destructive', message: 'Enter a user ID before performing admin actions.' })
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

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Shield className="h-4 w-4" /> Admin Panel
        </CardTitle>
        <CardDescription>Manage administrator privileges and roles for individual users.</CardDescription>
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
          <Button variant="secondary" onClick={() => toggleAdmin(true)} disabled={loading || !userId.trim()}>
            Make Admin
          </Button>
          <Button variant="outline" onClick={() => toggleAdmin(false)} disabled={loading || !userId.trim()}>
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
      </CardContent>
    </Card>
  )
}

export default AdminPanel
