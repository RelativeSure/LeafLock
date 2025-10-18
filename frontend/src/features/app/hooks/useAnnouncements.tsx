import { useCallback, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type Announcement } from '@/components/AnnouncementBanner'
import { type SecureAPI } from '@/services/secureApi'

export const useAnnouncements = (api: SecureAPI, initializing: boolean) => {
  const {
    data,
    refetch,
    isFetching: announcementsLoading,
    error,
  } = useQuery<Announcement[], Error>({
    queryKey: ['announcements'],
    queryFn: async () => {
      const response = await api.getAnnouncements()
      return response.announcements || []
    },
    staleTime: 1000 * 60 * 10,
    enabled: !initializing,
  })

  useEffect(() => {
    if (error) {
      console.warn('Failed to load announcements:', error)
    }
  }, [error])

  const announcements = data ?? []

  const loadAnnouncements = useCallback(async () => {
    const result = await refetch()
    if (result.error) {
      console.warn('Failed to load announcements:', result.error)
    }
  }, [refetch])

  return {
    announcements,
    announcementsLoading,
    loadAnnouncements,
  }
}
