import React from 'react'
import { useAuth, useUser } from '@clerk/clerk-react'
import { isOnAuthRoute, safeRedirectToLogin } from '@/lib/navigation'
import AppLayout from './app-layout'

export const ProtectedLayout: React.FC = () => {
  const { isSignedIn, isLoaded } = useAuth()
  const { user: clerkUser } = useUser()
  
  // Convert Clerk user to our expected format
  const user = clerkUser ? {
    id: clerkUser.id,
    email: clerkUser.primaryEmailAddress?.emailAddress || '',
    name: clerkUser.fullName || '',
    isAdmin: clerkUser.publicMetadata?.isAdmin === true || clerkUser.publicMetadata?.role === 'admin'
  } : null
  
  const isLoading = !isLoaded
  const [dataLoaded, setDataLoaded] = React.useState(false)

  React.useEffect(() => {
    if (isLoaded && !isSignedIn) {
      if (typeof window === 'undefined' || !isOnAuthRoute()) {
        safeRedirectToLogin()
      }
    }
  }, [isSignedIn, isLoaded])

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

  return <AppLayout>{/* AppLayout contains the SidebarProvider and Outlet */}</AppLayout>
}
