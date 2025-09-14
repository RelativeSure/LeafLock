import React, { useEffect, useState } from 'react'

type AdminPanelProps = {
  api: any
}

const roles = ['admin', 'moderator', 'auditor']

const AdminPanel: React.FC<AdminPanelProps> = ({ api }) => {
  const [userId, setUserId] = useState('')
  const [role, setRole] = useState('moderator')
  const [result, setResult] = useState<string>('')
  const [userRoles, setUserRoles] = useState<string[]>([])

  const loadRoles = async () => {
    try {
      const res = await api.adminGetUserRoles(userId)
      setUserRoles(res.roles || [])
      setResult('Loaded roles')
    } catch (e: any) {
      setResult(`Error: ${e.message}`)
    }
  }

  const toggleAdmin = async (val: boolean) => {
    try {
      await api.adminSetAdmin(userId, val)
      setResult(`Admin set to ${val}`)
      await loadRoles()
    } catch (e: any) {
      setResult(`Error: ${e.message}`)
    }
  }

  const assignRole = async () => {
    try {
      await api.adminAssignRole(userId, role)
      setResult(`Assigned ${role}`)
      await loadRoles()
    } catch (e: any) {
      setResult(`Error: ${e.message}`)
    }
  }

  const removeRole = async () => {
    try {
      await api.adminRemoveRole(userId, role)
      setResult(`Removed ${role}`)
      await loadRoles()
    } catch (e: any) {
      setResult(`Error: ${e.message}`)
    }
  }

  return (
    <div style={{ border: '1px solid #444', padding: 12, borderRadius: 8, marginTop: 12 }}>
      <h3>Admin Panel</h3>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <input
          placeholder="User ID (UUID)"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          style={{ width: '420px' }}
        />
        <button onClick={() => {
          try { const me = localStorage.getItem('current_user_id') || ''; if (me) setUserId(me) } catch {}
        }}>Use my ID</button>
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {roles.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button onClick={loadRoles}>Load Roles</button>
        <button onClick={() => toggleAdmin(true)}>Make Admin</button>
        <button onClick={() => toggleAdmin(false)}>Revoke Admin</button>
        <button onClick={assignRole}>Assign Role</button>
        <button onClick={removeRole}>Remove Role</button>
      </div>
      <div style={{ marginTop: 8, fontSize: 12, color: '#aaa' }}>{result}</div>
      <div style={{ marginTop: 8 }}>
        <strong>Current roles:</strong> {userRoles.join(', ') || '(none)'}
      </div>
    </div>
  )
  useEffect(() => {
    try {
      const me = localStorage.getItem('current_user_id') || ''
      if (me) setUserId(me)
    } catch {}
  }, [])
}

export default AdminPanel
