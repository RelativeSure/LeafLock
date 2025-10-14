import { useState, useCallback, useEffect } from 'react'
import { type Announcement } from '@/components/AnnouncementBanner'
import { type SecureAPI } from '@/services/secureApi'

export const useAnnouncements = (api: SecureAPI, initializing: boolean) => {
  const [announcements, setAnnouncements] = useState<Announcement[]>([])
  const [announcementsLoading, setAnnouncementsLoading] = useState(false)

  const loadAnnouncements = useCallback(async () => {
    try {
      setAnnouncementsLoading(true)
      const response = await api.getAnnouncements()
      setAnnouncements(response.announcements || [])
    } catch (error) {
      console.warn('Failed to load announcements:', error)
    } finally {
      setAnnouncementsLoading(false)
    }
  }, [api])

  useEffect(() => {
    if (!initializing) {
      void loadAnnouncements()
    }
  }, [initializing, loadAnnouncements])

  return {
    announcements,
    announcementsLoading,
    loadAnnouncements,
  }
}
