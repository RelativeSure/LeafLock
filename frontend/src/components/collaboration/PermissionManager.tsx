import { useState } from 'react'
import { Shield, Clock, Edit3, Trash2, Share2, MessageSquare } from 'lucide-react'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface PermissionSettings {
  permission: 'read' | 'write' | 'admin'
  can_edit?: boolean
  can_delete?: boolean
  can_share?: boolean
  can_comment?: boolean
  expires_at?: string
}

interface PermissionManagerProps {
  initialPermissions?: PermissionSettings
  onChange: (permissions: PermissionSettings) => void
}

export function PermissionManager({ initialPermissions, onChange }: PermissionManagerProps) {
  const [permission, setPermission] = useState<'read' | 'write' | 'admin'>(
    initialPermissions?.permission || 'read'
  )
  const [canEdit, setCanEdit] = useState(initialPermissions?.can_edit ?? true)
  const [canDelete, setCanDelete] = useState(initialPermissions?.can_delete ?? false)
  const [canShare, setCanShare] = useState(initialPermissions?.can_share ?? false)
  const [canComment, setCanComment] = useState(initialPermissions?.can_comment ?? true)
  const [expiresAt, setExpiresAt] = useState(initialPermissions?.expires_at || '')

  const handleChange = () => {
    onChange({
      permission,
      can_edit: canEdit,
      can_delete: canDelete,
      can_share: canShare,
      can_comment: canComment,
      expires_at: expiresAt || undefined,
    })
  }

  const handlePermissionChange = (value: string) => {
    const newPermission = value as 'read' | 'write' | 'admin'
    setPermission(newPermission)

    // Auto-set granular permissions based on role
    if (newPermission === 'admin') {
      setCanEdit(true)
      setCanDelete(true)
      setCanShare(true)
      setCanComment(true)
    } else if (newPermission === 'write') {
      setCanEdit(true)
      setCanDelete(false)
      setCanShare(false)
      setCanComment(true)
    } else {
      setCanEdit(false)
      setCanDelete(false)
      setCanShare(false)
      setCanComment(true)
    }

    handleChange()
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="permission" className="flex items-center gap-2">
          <Shield className="h-4 w-4" />
          Permission Level
        </Label>
        <Select value={permission} onValueChange={handlePermissionChange}>
          <SelectTrigger id="permission">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="read">Read Only</SelectItem>
            <SelectItem value="write">Can Edit</SelectItem>
            <SelectItem value="admin">Admin</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-3 rounded-md border p-4">
        <p className="text-sm font-medium">Granular Permissions</p>

        <div className="flex items-center justify-between">
          <Label htmlFor="can-edit" className="flex items-center gap-2 cursor-pointer">
            <Edit3 className="h-4 w-4" />
            Can Edit
          </Label>
          <Switch
            id="can-edit"
            checked={canEdit}
            onCheckedChange={(checked) => {
              setCanEdit(checked)
              handleChange()
            }}
          />
        </div>

        <div className="flex items-center justify-between">
          <Label htmlFor="can-delete" className="flex items-center gap-2 cursor-pointer">
            <Trash2 className="h-4 w-4" />
            Can Delete
          </Label>
          <Switch
            id="can-delete"
            checked={canDelete}
            onCheckedChange={(checked) => {
              setCanDelete(checked)
              handleChange()
            }}
          />
        </div>

        <div className="flex items-center justify-between">
          <Label htmlFor="can-share" className="flex items-center gap-2 cursor-pointer">
            <Share2 className="h-4 w-4" />
            Can Share
          </Label>
          <Switch
            id="can-share"
            checked={canShare}
            onCheckedChange={(checked) => {
              setCanShare(checked)
              handleChange()
            }}
          />
        </div>

        <div className="flex items-center justify-between">
          <Label htmlFor="can-comment" className="flex items-center gap-2 cursor-pointer">
            <MessageSquare className="h-4 w-4" />
            Can Comment
          </Label>
          <Switch
            id="can-comment"
            checked={canComment}
            onCheckedChange={(checked) => {
              setCanComment(checked)
              handleChange()
            }}
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="expires-at" className="flex items-center gap-2">
          <Clock className="h-4 w-4" />
          Expires At (Optional)
        </Label>
        <Input
          id="expires-at"
          type="datetime-local"
          value={expiresAt}
          onChange={(e) => {
            setExpiresAt(e.target.value)
            handleChange()
          }}
        />
      </div>
    </div>
  )
}
