import React from 'react'
import { useAuthStore } from '@/stores/authStore'
import { isOnAuthRoute, safeRedirectToLogin } from '@/lib/navigation'
import AppLayout from './app-layout'

export const ProtectedLayout: React.FC = () => {
  // Initialize auth store on mount (guarded to run once)
  const initializedRef = React.useRef(false)
  React.useEffect(() => {
    if (initializedRef.current) return
    initializedRef.current = true
    try {
      useAuthStore.getState().initialize()
    } catch (err) {
      console.warn('Auth initialize failed:', err)
    }
  }, [])

  const user = useAuthStore((state) => state.user)
  const isLoading = useAuthStore((state) => state.isLoading)
  const [dataLoaded, setDataLoaded] = React.useState(false)

  React.useEffect(() => {
    if (!isLoading && !user) {
      if (typeof window === 'undefined' || !isOnAuthRoute()) {
        safeRedirectToLogin()
      }
    }
  }, [user, isLoading])

  // Notes loading guarded to run once after auth is ready
  const notesLoadedRef = React.useRef(false)
  React.useEffect(() => {
    if (!isLoading && user && !notesLoadedRef.current) {
      notesLoadedRef.current = true
      import('@/stores/notesStore').then(({ useNotesStore }) => {
        const store = useNotesStore.getState()
        store
          .loadData()
          .then(() => store.initializeDefaultNote())
          .then(() => setDataLoaded(true))
          .catch((err) => {
            console.warn('Notes bootstrap failed:', err)
            setDataLoaded(true)
          })
      })
    }
  }, [isLoading, user])

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center animate-in fade-in-50 duration-500">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading LeafLock...</p>
        </div>
      </div>
    )
  }

  if (!dataLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center">
         <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <AppLayout>
       {/* AppLayout contains the SidebarProvider and Outlet */}
    </AppLayout>
  )
}
