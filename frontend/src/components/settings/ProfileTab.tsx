import { useState, useEffect } from 'react'
import { profileService, Profile } from '@/services/api/profileService'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Avatar, AvatarImage, AvatarFallback } from '@/components/ui/avatar'
import { Loader2, User, Mail, Calendar, Image } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

export function ProfileTab() {
  const [profile, setProfile] = useState<Profile | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const [displayName, setDisplayName] = useState('')
  const [bio, setBio] = useState('')
  const [avatarUrl, setAvatarUrl] = useState('')
  const [avatarType, setAvatarType] = useState<'gravatar' | 'custom'>('gravatar')

  useEffect(() => {
    loadProfile()
  }, [])

  const loadProfile = async () => {
    try {
      setLoading(true)
      const data = await profileService.getProfile()
      setProfile(data)
      setDisplayName(data.display_name || '')
      setBio(data.bio || '')
      setAvatarUrl(data.avatar_url || '')
      setAvatarType(data.profile_picture_type as 'gravatar' | 'custom')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load profile')
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    try {
      setSaving(true)
      setError(null)
      setSuccess(false)

      const updated = await profileService.updateProfile({
        display_name: displayName || null,
        bio: bio || null,
        avatar_url: avatarUrl || null,
      })

      setProfile(updated)
      setSuccess(true)
      setTimeout(() => setSuccess(false), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update profile')
    } finally {
      setSaving(false)
    }
  }

  const handleAvatarTypeChange = async (type: 'gravatar' | 'custom') => {
    try {
      await profileService.setAvatarType(type)
      setAvatarType(type)
      await loadProfile()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update avatar type')
    }
  }

  const getAvatarUrl = () => {
    if (!profile) return ''
    if (avatarType === 'custom' && profile.avatar_url) {
      return profile.avatar_url
    }
    return profile.gravatar_url
  }

  const getInitials = () => {
    if (!profile) return 'U'
    if (profile.display_name) {
      const parts = profile.display_name.split(' ')
      return parts
        .map((p) => p[0])
        .slice(0, 2)
        .join('')
        .toUpperCase()
    }
    return profile.email[0].toUpperCase()
  }

  const formatDate = (dateString: string) => {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    }).format(new Date(dateString))
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (!profile) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
        Failed to load profile
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Profile</h2>
        <p className="text-sm text-muted-foreground">Manage your personal information and avatar</p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">{error}</div>
      )}

      {success && (
        <div className="rounded-lg border border-green-200 bg-green-50 p-4 text-green-800">
          Profile updated successfully!
        </div>
      )}

      <Card className="p-6">
        <div className="space-y-6">
          {/* Avatar Section */}
          <div className="flex items-start gap-6">
            <Avatar className="h-24 w-24">
              <AvatarImage src={getAvatarUrl()} alt={profile.email} />
              <AvatarFallback>{getInitials()}</AvatarFallback>
            </Avatar>

            <div className="flex-1 space-y-4">
              <div className="space-y-2">
                <Label htmlFor="avatar-type">Avatar Type</Label>
                <Select
                  value={avatarType}
                  onValueChange={(value) => handleAvatarTypeChange(value as 'gravatar' | 'custom')}
                >
                  <SelectTrigger id="avatar-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="gravatar">Gravatar (from {profile.email})</SelectItem>
                    <SelectItem value="custom">Custom URL</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {avatarType === 'gravatar' ? (
                    <>
                      Using Gravatar. Update your avatar at{' '}
                      <a
                        href="https://gravatar.com"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline"
                      >
                        gravatar.com
                      </a>
                    </>
                  ) : (
                    'Enter a custom image URL below'
                  )}
                </p>
              </div>

              {avatarType === 'custom' && (
                <div className="space-y-2">
                  <Label htmlFor="avatar-url">
                    <Image className="mr-2 inline h-4 w-4" />
                    Avatar URL
                  </Label>
                  <Input
                    id="avatar-url"
                    type="url"
                    placeholder="https://example.com/avatar.jpg"
                    value={avatarUrl}
                    onChange={(e) => setAvatarUrl(e.target.value)}
                  />
                </div>
              )}
            </div>
          </div>

          {/* Display Name */}
          <div className="space-y-2">
            <Label htmlFor="display-name">
              <User className="mr-2 inline h-4 w-4" />
              Display Name
            </Label>
            <Input
              id="display-name"
              placeholder="Your name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={100}
            />
            <p className="text-xs text-muted-foreground">{displayName.length}/100 characters</p>
          </div>

          {/* Bio */}
          <div className="space-y-2">
            <Label htmlFor="bio">Bio</Label>
            <Textarea
              id="bio"
              placeholder="Tell us about yourself..."
              value={bio}
              onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setBio(e.target.value)}
              maxLength={500}
              rows={4}
            />
            <p className="text-xs text-muted-foreground">{bio.length}/500 characters</p>
          </div>

          {/* Email (read-only) */}
          <div className="space-y-2">
            <Label>
              <Mail className="mr-2 inline h-4 w-4" />
              Email
            </Label>
            <Input value={profile.email} disabled />
            <p className="text-xs text-muted-foreground">Your email address cannot be changed</p>
          </div>

          {/* Account Info */}
          <div className="rounded-lg bg-muted p-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Calendar className="h-4 w-4" />
              <span>Member since {formatDate(profile.created_at)}</span>
            </div>
            {profile.last_login && (
              <div className="mt-2 text-sm text-muted-foreground">
                Last login: {formatDate(profile.last_login)}
              </div>
            )}
          </div>

          {/* Save Button */}
          <div className="flex justify-end">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  )
}
