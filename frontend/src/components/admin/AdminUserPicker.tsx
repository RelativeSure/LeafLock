import React from 'react'
import { Combobox } from '@/components/ui/combobox'
import { Badge } from '@/components/ui/badge'

export type AdminUserOption = {
  user_id: string
  email: string
  is_admin?: boolean
  admin_via_allowlist?: boolean
}

type AdminUserPickerProps = {
  users: AdminUserOption[]
  value?: string
  onChange: (userId: string) => void
  className?: string
}

const AdminUserPicker: React.FC<AdminUserPickerProps> = ({ users, value, onChange, className }) => {
  return (
    <Combobox
      items={users.map((u) => ({
        label: u.email,
        value: u.user_id,
        rightSlot: u.is_admin ? (
          <Badge variant="secondary">admin{u.admin_via_allowlist ? ' • allowlist' : ''}</Badge>
        ) : undefined,
      }))}
      value={value}
      onChange={onChange}
      placeholder="Search users by email..."
      triggerText={users.find((u) => u.user_id === value)?.email || 'Choose a user'}
      className={className}
    />
  )
}

export default AdminUserPicker
