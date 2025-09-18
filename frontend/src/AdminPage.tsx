import React, { useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Shield, Crown } from 'lucide-react'
import AdminUserPicker from '@/components/admin/AdminUserPicker'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { MultiCombobox } from '@/components/ui/multi-combobox'
import { Switch } from '@/components/ui/switch'

type AdminPageProps = { api: any; onBack: () => void }

const availableRoles = ['moderator', 'auditor']

type AdminUser = {
  user_id: string
  email: string
  is_admin: boolean
  admin_via_allowlist?: boolean
  roles: string[]
  created_at?: string
  last_login?: string | null
  registration_ip?: string
  last_ip?: string
}

const AdminPage: React.FC<AdminPageProps> = ({ api, onBack }) => {
  const [users, setUsers] = useState<AdminUser[]>([])
  const [total, setTotal] = useState(0)
  const [selectedUserId, setSelectedUserId] = useState<string>('')
  const [selected, setSelected] = useState<AdminUser | null>(null)
  const [selectedRole, setSelectedRole] = useState('moderator')
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const [limit] = useState(25)
  const [offset, setOffset] = useState(0)
  const [rolesFilter, setRolesFilter] = useState<string[]>([])
  const [adminFilter, setAdminFilter] = useState<'any' | 'true' | 'false'>('any')
  const [regFrom, setRegFrom] = useState('')
  const [regTo, setRegTo] = useState('')
  const [lastFrom, setLastFrom] = useState('')
  const [lastTo, setLastTo] = useState('')
  const [hasLogin, setHasLogin] = useState(false)
  const [hasIp, setHasIp] = useState(false)
  const [sort, setSort] = useState<'created_at'|'last_login'|'email'|'is_admin'>('created_at')
  const [order, setOrder] = useState<'ASC'|'DESC'>('DESC')
  const searchDebounceRef = React.useRef<number | null>(null)
  const [bulkRole, setBulkRole] = useState('moderator')
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkAction, setBulkAction] = useState<'assign'|'remove'>('assign')
  const [busy, setBusy] = useState(false)
  const [regEnabled, setRegEnabled] = useState<boolean>(true)
  const [regBusy, setRegBusy] = useState<boolean>(false)
  const [bulkAdminOpen, setBulkAdminOpen] = useState(false)
  const [adminAction, setAdminAction] = useState<'grant'|'revoke'>('grant')
  const [confirmRoleText, setConfirmRoleText] = useState('')
  const [confirmAdminText, setConfirmAdminText] = useState('')
  // no-op: using Combobox component

  const loadUsers = async () => {
    setError(null)
    try {
      const res = await api.adminListUsers({
        q,
        limit,
        offset,
        ...(rolesFilter.length ? { roles: rolesFilter.join(',') } : {}),
        // future: roles multi-select: join and send as roles
        ...(adminFilter !== 'any' ? { admin: adminFilter } : {}),
        ...(regFrom ? { reg_from: regFrom } : {}),
        ...(regTo ? { reg_to: regTo } : {}),
        ...(lastFrom ? { last_from: lastFrom } : {}),
        ...(lastTo ? { last_to: lastTo } : {}),
        ...(hasLogin ? { has_login: 'true' } : {}),
        ...(hasIp ? { has_ip: 'true' } : {}),
        sort,
        order,
      } as any)
      const list: AdminUser[] = res.users || []
      setUsers(list)
      setTotal(res.total || 0)
      if (list.length > 0) {
        setSelectedUserId(list[0].user_id)
        setSelected(list[0])
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to load users')
    }
  }

  useEffect(() => {
    loadUsers()
    // load registration setting
    ;(async () => {
      try {
        const r = await api.adminGetRegistration()
        if (typeof r?.enabled === 'boolean') setRegEnabled(!!r.enabled)
      } catch {}
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, limit, offset, rolesFilter, adminFilter, regFrom, regTo, lastFrom, lastTo, hasLogin, hasIp, sort, order])

  // Debounce search input updates
  const handleSearchChange = (value: string) => {
    setQ(value)
    if (searchDebounceRef.current) window.clearTimeout(searchDebounceRef.current)
    searchDebounceRef.current = window.setTimeout(() => {
      setOffset(0)
      loadUsers()
    }, 300)
  }

  useEffect(() => {
    const u = users.find((u) => u.user_id === selectedUserId) || null
    setSelected(u)
  }, [selectedUserId, users])

  const refreshSelectedRoles = async () => {
    if (!selected) return
    try {
      const res = await api.adminGetUserRoles(selected.user_id)
      setSelected({ ...selected, roles: res.roles || [] })
    } catch {}
  }

  const toggleAdmin = async (val: boolean) => {
    if (!selected) return
    setError(null)
    setStatus(null)
    try {
      await api.adminSetAdmin(selected.user_id, val)
      setStatus(`Admin ${val ? 'granted' : 'revoked'}`)
      await loadUsers()
    } catch (e: any) {
      setError(e?.message || 'Failed to toggle admin')
    }
  }

  const assignRole = async () => {
    if (!selected) return
    setError(null)
    setStatus(null)
    try {
      await api.adminAssignRole(selected.user_id, selectedRole)
      setStatus(`Assigned role: ${selectedRole}`)
      await refreshSelectedRoles()
    } catch (e: any) {
      setError(e?.message || 'Failed to assign role')
    }
  }

  const removeRole = async () => {
    if (!selected) return
    setError(null)
    setStatus(null)
    try {
      await api.adminRemoveRole(selected.user_id, selectedRole)
      setStatus(`Removed role: ${selectedRole}`)
      await refreshSelectedRoles()
    } catch (e: any) {
      setError(e?.message || 'Failed to remove role')
    }
  }

  return (
    <>
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-5xl mx-auto space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <h1 className="text-2xl font-semibold">Admin Dashboard</h1>
          </div>
          <Button variant="ghost" onClick={onBack}>Back to Notes</Button>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {status && (
          <Alert>
            <AlertDescription>{status}</AlertDescription>
          </Alert>
        )}

        <Card>
          <CardHeader>
            <CardTitle>User Management</CardTitle>
            <CardDescription>Search, view, and manage users</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between rounded-md border p-3">
              <div>
                <div className="font-medium">User Registration</div>
                <div className="text-sm text-muted-foreground">Toggle public sign-ups for new users</div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-sm text-muted-foreground">{regEnabled ? 'Enabled' : 'Disabled'}</span>
                <Switch
                  checked={regEnabled}
                  disabled={regBusy}
                  onCheckedChange={async (val) => {
                    setRegBusy(true)
                    setStatus(null)
                    setError(null)
                    try {
                      const r = await api.adminSetRegistration(!!val)
                      setRegEnabled(!!r.enabled)
                      setStatus(`Registration ${r.enabled ? 'enabled' : 'disabled'}`)
                    } catch (e:any) {
                      setError(e?.message || 'Failed to update registration setting')
                    } finally {
                      setRegBusy(false)
                    }
                  }}
                />
              </div>
            </div>
            <div className="flex items-end justify-between gap-4">
              <div className="w-full md:w-1/2 space-y-2">
                <Label htmlFor="search">Search</Label>
                <input
                  id="search"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                  placeholder="Email contains…"
                  value={q}
                  onChange={(e) => handleSearchChange(e.target.value)}
                />
              </div>
              <div className="flex items-center gap-2">
                <Button variant="secondary" onClick={() => setOffset((o) => Math.max(0, o - limit))} disabled={offset === 0}>
                  Prev
                </Button>
                <Button variant="secondary" onClick={() => setOffset((o) => (o + limit < total ? o + limit : o))} disabled={offset + limit >= total}>
                  Next
                </Button>
                <span className="text-sm text-muted-foreground">{Math.min(offset + 1, total)}-{Math.min(offset + limit, total)} of {total}</span>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-1">
                <Label>Sort</Label>
                <div className="flex gap-2">
                  <Select value={sort} onValueChange={(v) => { setSort(v as any); setOffset(0) }}>
                    <SelectTrigger className="w-[180px]"><SelectValue placeholder="Sort by" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="created_at">Registered</SelectItem>
                      <SelectItem value="last_login">Last login</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                      <SelectItem value="is_admin">Is admin</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={order} onValueChange={(v) => { setOrder(v as any); setOffset(0) }}>
                    <SelectTrigger className="w-[140px]"><SelectValue placeholder="Order" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="DESC">Desc</SelectItem>
                      <SelectItem value="ASC">Asc</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-1">
                <Label>Roles</Label>
                <MultiCombobox
                  items={availableRoles.map((r) => ({ label: r, value: r }))}
                  values={rolesFilter}
                  onChange={(vals) => { setRolesFilter(vals); setOffset(0) }}
                  placeholder="Filter by roles…"
                />
              </div>
              <div className="space-y-1">
                <Label>Admin</Label>
                <Select value={adminFilter} onValueChange={(v) => { setAdminFilter(v as any); setOffset(0) }}>
                  <SelectTrigger className="w-full"><SelectValue placeholder="Any" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="any">Any</SelectItem>
                    <SelectItem value="true">Admin only</SelectItem>
                    <SelectItem value="false">Non-admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>Activity</Label>
                <div className="flex items-center gap-2 text-sm">
                  <label className="inline-flex items-center gap-2">
                    <input type="checkbox" className="accent-primary" checked={hasLogin} onChange={(e) => { setHasLogin(e.target.checked); setOffset(0) }} />
                    Has login
                  </label>
                  <label className="inline-flex items-center gap-2">
                    <input type="checkbox" className="accent-primary" checked={hasIp} onChange={(e) => { setHasIp(e.target.checked); setOffset(0) }} />
                    Has IP
                  </label>
                </div>
              </div>
              <div className="space-y-1">
                <Label>Registered from</Label>
                <input type="date" className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring" value={regFrom} onChange={(e) => { setRegFrom(e.target.value); setOffset(0) }} />
              </div>
              <div className="space-y-1">
                <Label>Registered to</Label>
                <input type="date" className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring" value={regTo} onChange={(e) => { setRegTo(e.target.value); setOffset(0) }} />
              </div>
              <div className="space-y-1">
                <Label>Last login from</Label>
                <input type="date" className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring" value={lastFrom} onChange={(e) => { setLastFrom(e.target.value); setOffset(0) }} />
              </div>
              <div className="space-y-1">
                <Label>Last login to</Label>
                <input type="date" className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring" value={lastTo} onChange={(e) => { setLastTo(e.target.value); setOffset(0) }} />
              </div>
              <div className="flex items-end gap-2">
                <Button variant="outline" onClick={() => { setQ(''); setRolesFilter([]); setAdminFilter('any'); setRegFrom(''); setRegTo(''); setLastFrom(''); setLastTo(''); setHasLogin(false); setHasIp(false); setOffset(0); }}>Reset</Button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-1">
                <Label>Bulk role</Label>
                <Select value={bulkRole} onValueChange={(v) => setBulkRole(v)}>
                  <SelectTrigger className="w-full"><SelectValue placeholder="Select role" /></SelectTrigger>
                  <SelectContent>
                    {availableRoles.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-end gap-2">
                <Button variant="secondary" onClick={() => { setBulkAction('assign'); setBulkOpen(true) }}>Assign to all filtered</Button>
                <Button variant="destructive" onClick={() => { setBulkAction('remove'); setBulkOpen(true) }}>Remove from all filtered</Button>
              </div>
              <div className="flex items-end gap-2">
                <Button variant="secondary" onClick={() => { setAdminAction('grant'); setBulkAdminOpen(true) }}>Grant admin to all filtered</Button>
                <Button variant="destructive" onClick={() => { setAdminAction('revoke'); setBulkAdminOpen(true) }}>Revoke admin for all filtered</Button>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-2">
                <Label>User</Label>
                <div className="flex gap-2 items-center">
                  <AdminUserPicker users={users} value={selectedUserId} onChange={setSelectedUserId} />
                  <Button variant="outline" onClick={() => toggleAdmin(true)} disabled={!selected}>
                    <Crown className="mr-2 h-4 w-4" /> Make Admin
                  </Button>
                  <Button variant="outline" onClick={() => toggleAdmin(false)} disabled={!selected}>Revoke</Button>
                </div>
              </div>
              <div className="flex items-end gap-2">
                <Button variant="secondary" onClick={loadUsers}>Refresh</Button>
                <Button variant="outline" onClick={async () => {
                  try {
                    const blob = await api.adminExportUsersCsv({
                      q, limit, offset,
                      ...(rolesFilter.length ? { roles: rolesFilter.join(',') } : {}),
                      ...(adminFilter !== 'any' ? { admin: adminFilter } : {}),
                      ...(regFrom ? { reg_from: regFrom } : {}),
                      ...(regTo ? { reg_to: regTo } : {}),
                      ...(lastFrom ? { last_from: lastFrom } : {}),
                      ...(lastTo ? { last_to: lastTo } : {}),
                      ...(hasLogin ? { has_login: 'true' } : {}),
                      ...(hasIp ? { has_ip: 'true' } : {}),
                      sort, order,
                    } as any)
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = 'users.csv'
                    document.body.appendChild(a)
                    a.click()
                    a.remove()
                    URL.revokeObjectURL(url)
                  } catch (e:any) {
                    setError(e?.message || 'Export failed')
                  }
                }}>Export CSV</Button>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="role">Role</Label>
              <div className="flex gap-2 items-center">
                <Select value={selectedRole} onValueChange={(v) => setSelectedRole(v)}>
                  <SelectTrigger className="w-[220px]" id="role">
                    <SelectValue placeholder="Select a role" />
                  </SelectTrigger>
                  <SelectContent>
                    {availableRoles.map((r) => (
                      <SelectItem key={r} value={r}>{r}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button variant="secondary" onClick={assignRole} disabled={!selected}>Assign</Button>
                <Button variant="secondary" onClick={removeRole} disabled={!selected}>Remove</Button>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Current Roles</Label>
              <div className="flex gap-2 flex-wrap">
                {selected?.roles?.length ? (
                  selected.roles.map((r) => <Badge key={r} variant="secondary">{r}</Badge>)
                ) : (
                  <span className="text-sm text-muted-foreground">(none)</span>
                )}
              </div>
            </div>

            {selected && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">User Info</CardTitle>
                    <CardDescription>{selected.email}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-1 text-sm text-muted-foreground">
                    <div>
                      Admin: {selected.is_admin ? 'Yes' : 'No'}
                      {selected.admin_via_allowlist ? ' (allowlist override)' : ''}
                    </div>
                    <div>Registered: {selected.created_at ? new Date(selected.created_at).toLocaleString() : '-'}</div>
                    <div>Last login: {selected.last_login ? new Date(selected.last_login).toLocaleString() : '-'}</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">IP Addresses</CardTitle>
                    <CardDescription>Registration and last used</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-1 text-sm text-muted-foreground">
                    <div>Registration IP: {selected.registration_ip || '-'}</div>
                    <div>Last used IP: {selected.last_ip || '-'}</div>
                  </CardContent>
                </Card>
              </div>
            )}

            <div className="space-y-2">
              <Label>All Users</Label>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Email</TableHead>
                    <TableHead>Admin</TableHead>
                    <TableHead>Roles</TableHead>
                    <TableHead>Last Login</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((u) => (
                    <TableRow key={u.user_id} className={u.user_id === selectedUserId ? 'bg-accent/30' : ''} onClick={() => setSelectedUserId(u.user_id)}>
                      <TableCell>{u.email}</TableCell>
                      <TableCell>
                        {u.is_admin ? (
                          <Badge variant={u.admin_via_allowlist ? 'secondary' : 'default'}>
                            admin{u.admin_via_allowlist ? ' • allowlist' : ''}
                          </Badge>
                        ) : (
                          '-'
                        )}
                      </TableCell>
                      <TableCell className="space-x-1">
                        {u.roles?.length ? u.roles.map((r) => <Badge key={r} variant="secondary">{r}</Badge>) : <span className="text-muted-foreground">(none)</span>}
                      </TableCell>
                      <TableCell>{u.last_login ? new Date(u.last_login).toLocaleString() : '-'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>

    <Dialog open={bulkOpen} onOpenChange={(v) => { setBulkOpen(v); if (!v) setConfirmRoleText('') }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{bulkAction === 'assign' ? 'Assign role to all filtered users' : 'Remove role from all filtered users'}</DialogTitle>
          <DialogDescription>
            This will {bulkAction} the role “{bulkRole}” for all users matching current filters ({total} users). Proceed?
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="confirm-bulk-role" className="text-sm">Type CONFIRM to continue</Label>
          <Input id="confirm-bulk-role" value={confirmRoleText} onChange={(e) => setConfirmRoleText(e.target.value)} placeholder="CONFIRM" />
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setBulkOpen(false)} disabled={busy}>Cancel</Button>
          <Button
            variant={bulkAction === 'assign' ? 'secondary' : 'destructive'}
            disabled={busy || confirmRoleText !== 'CONFIRM'}
            onClick={async () => {
              setBusy(true)
              setStatus(null)
              setError(null)
              try {
                const filters: any = {
                  q,
                  ...(rolesFilter.length ? { roles: rolesFilter.join(',') } : {}),
                  ...(adminFilter !== 'any' ? { admin: adminFilter } : {}),
                  ...(regFrom ? { reg_from: regFrom } : {}),
                  ...(regTo ? { reg_to: regTo } : {}),
                  ...(lastFrom ? { last_from: lastFrom } : {}),
                  ...(lastTo ? { last_to: lastTo } : {}),
                  ...(hasLogin ? { has_login: true } : {}),
                  ...(hasIp ? { has_ip: true } : {}),
                }
                const res = await api.adminBulkRole(bulkAction, bulkRole, filters)
                setStatus(`${bulkAction === 'assign' ? 'Assigned' : 'Removed'} for ${res.affected ?? 'selected'} users`)
                setBulkOpen(false)
                await loadUsers()
              } catch (e:any) {
                setError(e?.message || 'Bulk operation failed')
              } finally {
                setBusy(false)
              }
            }}
          >
            {busy ? 'Working…' : (bulkAction === 'assign' ? 'Assign' : 'Remove')}
          </Button>
        </div>
      </DialogContent>
    </Dialog>

    <Dialog open={bulkAdminOpen} onOpenChange={(v) => { setBulkAdminOpen(v); if (!v) setConfirmAdminText('') }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{adminAction === 'grant' ? 'Grant admin to all filtered users' : 'Revoke admin for all filtered users'}</DialogTitle>
          <DialogDescription>
            This will {adminAction} admin for all users matching current filters ({total} users). Proceed?
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="confirm-bulk-admin" className="text-sm">Type CONFIRM to continue</Label>
          <Input id="confirm-bulk-admin" value={confirmAdminText} onChange={(e) => setConfirmAdminText(e.target.value)} placeholder="CONFIRM" />
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setBulkAdminOpen(false)} disabled={busy}>Cancel</Button>
          <Button
            variant={adminAction === 'grant' ? 'secondary' : 'destructive'}
            disabled={busy || confirmAdminText !== 'CONFIRM'}
            onClick={async () => {
              setBusy(true)
              setStatus(null)
              setError(null)
              try {
                const filters: any = {
                  q,
                  ...(rolesFilter.length ? { roles: rolesFilter.join(',') } : {}),
                  ...(adminFilter !== 'any' ? { admin: adminFilter } : {}),
                  ...(regFrom ? { reg_from: regFrom } : {}),
                  ...(regTo ? { reg_to: regTo } : {}),
                  ...(lastFrom ? { last_from: lastFrom } : {}),
                  ...(lastTo ? { last_to: lastTo } : {}),
                  ...(hasLogin ? { has_login: true } : {}),
                  ...(hasIp ? { has_ip: true } : {}),
                }
                const res = await api.adminBulkAdmin(adminAction, filters)
                setStatus(`${adminAction === 'grant' ? 'Granted' : 'Revoked'} admin for ${res.affected ?? 'selected'} users`)
                setBulkAdminOpen(false)
                await loadUsers()
              } catch (e:any) {
                setError(e?.message || 'Bulk admin update failed')
              } finally {
                setBusy(false)
              }
            }}
          >
            {busy ? 'Working…' : (adminAction === 'grant' ? 'Grant' : 'Revoke')}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
    </>
  )
}

export default AdminPage
