import React from 'react'
import { useAuth, useUser, useSession } from '@clerk/clerk-react'

export const ClerkAuthDebug: React.FC = () => {
  const { isSignedIn, isLoaded, sessionId, userId } = useAuth()
  const { user } = useUser()
  const { session } = useSession()

  const [mountedAt] = React.useState(() => Date.now())
  const [renderCount, setRenderCount] = React.useState(0)
  const [uptime, setUptime] = React.useState(0)
  const [timestamp, setTimestamp] = React.useState(() => new Date().toISOString())

  React.useEffect(() => {
    setRenderCount((prev) => prev + 1)
    setUptime(Date.now() - mountedAt)
    setTimestamp(new Date().toISOString())
  })

  const authState = {
    timestamp,
    uptime,
    renderCount,
    auth: {
      isLoaded,
      isSignedIn,
      sessionId,
      userId,
      hasSession: !!session,
      hasUser: !!user,
    },
    user: user
      ? {
          id: user.id,
          email: user.primaryEmailAddress?.emailAddress,
          fullName: user.fullName,
          publicMetadata: user.publicMetadata,
        }
      : null,
    session: session
      ? {
          id: session.id,
          status: session.status,
          lastActive: session.lastActiveAt || session.createdAt || new Date().toISOString(),
        }
      : null,
    clerkJs: !!(window as any).Clerk,
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'server',
  }

  const copyToClipboard = () => {
    navigator.clipboard.writeText(JSON.stringify(authState, null, 2))
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-md bg-black bg-opacity-80 text-white p-4 rounded-lg text-xs font-mono overflow-auto max-h-96">
      <div className="flex justify-between items-center mb-2">
        <h3 className="text-sm font-bold text-yellow-300">🔍 Auth Debug</h3>
        <button
          onClick={copyToClipboard}
          className="bg-blue-600 hover:bg-blue-700 px-2 py-1 rounded text-xs"
        >
          Copy
        </button>
      </div>

      {/* Simple status indicators */}
      <div className="grid grid-cols-2 gap-2 mb-2">
        <div className={`px-2 py-1 rounded ${isLoaded ? 'bg-green-600' : 'bg-yellow-600'}`}>
          Loaded: {isLoaded ? '✓' : '⋯'}
        </div>
        <div className={`px-2 py-1 rounded ${isSignedIn ? 'bg-green-600' : 'bg-red-600'}`}>
          Signed In: {isSignedIn ? '✓' : '✗'}
        </div>
      </div>

      {/* Detailed state */}
      <details className="mb-2">
        <summary className="cursor-pointer text-yellow-300 hover:text-yellow-200">
          Detailed Auth State
        </summary>
        <pre className="mt-2 p-2 bg-gray-900 rounded overflow-x-auto">
          {JSON.stringify(authState, null, 2)}
        </pre>
      </details>

      {/* Connection info */}
      {isSignedIn && session && (
        <div className="mt-2 p-2 bg-green-900 text-green-200 rounded">
          ✅ Session Active: {session.id?.substring(0, 8)}...
        </div>
      )}

      {!isLoaded && (
        <div className="mt-2 p-2 bg-yellow-900 text-yellow-200 rounded animate-pulse">
          ⏳ Loading auth state...
        </div>
      )}

      {isLoaded && !isSignedIn && !isOnAuthRoute() && (
        <div className="mt-2 p-2 bg-red-900 text-red-200 rounded animate-pulse">
          ⚠️ Not authenticated - redirecting soon...
        </div>
      )}
    </div>
  )
}

// Helper to check if on auth route
const isOnAuthRoute = () => {
  if (typeof window === 'undefined') return false
  return ['/login', '/register', '/forgot-password'].some((route) =>
    window.location.pathname.startsWith(route)
  )
}

export default ClerkAuthDebug
