/**
 * PWA utilities for service worker registration and management
 */

export function registerServiceWorker(): void {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', async () => {
      try {
        const registration = await navigator.serviceWorker.register('/sw.js', {
          scope: '/',
        })

        console.log('[PWA] Service Worker registered:', registration.scope)

        // Check for updates
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing
          if (!newWorker) return

          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              // New service worker available
              console.log('[PWA] New version available')

              // Notify user about update
              if (window.confirm('A new version is available. Reload to update?')) {
                newWorker.postMessage({ type: 'SKIP_WAITING' })
                window.location.reload()
              }
            }
          })
        })

        // Check for updates every hour
        setInterval(
          () => {
            registration.update()
          },
          60 * 60 * 1000
        )
      } catch (error) {
        console.error('[PWA] Service Worker registration failed:', error)
      }
    })

    // Handle controller change (new service worker activated)
    let refreshing = false
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!refreshing) {
        refreshing = true
        window.location.reload()
      }
    })
  }
}

export function unregisterServiceWorker(): void {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.ready
      .then((registration) => {
        registration.unregister()
        console.log('[PWA] Service Worker unregistered')
      })
      .catch((error) => {
        console.error('[PWA] Service Worker unregistration failed:', error)
      })
  }
}

/**
 * Check if app is running in standalone mode (installed as PWA)
 */
export function isPWA(): boolean {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    (window.navigator as any).standalone === true ||
    document.referrer.includes('android-app://')
  )
}

/**
 * Check if app can be installed (install prompt available)
 */
let deferredPrompt: any = null

export function setupInstallPrompt(): void {
  window.addEventListener('beforeinstallprompt', (e) => {
    // Prevent the mini-infobar from appearing on mobile
    e.preventDefault()
    // Stash the event so it can be triggered later
    deferredPrompt = e
    console.log('[PWA] Install prompt ready')

    // Dispatch custom event for UI to show install button
    window.dispatchEvent(new CustomEvent('pwa-installable'))
  })

  window.addEventListener('appinstalled', () => {
    console.log('[PWA] App installed')
    deferredPrompt = null
    // Dispatch custom event for analytics/UI update
    window.dispatchEvent(new CustomEvent('pwa-installed'))
  })
}

/**
 * Show install prompt to user
 */
export async function showInstallPrompt(): Promise<boolean> {
  if (!deferredPrompt) {
    console.warn('[PWA] Install prompt not available')
    return false
  }

  // Show the install prompt
  deferredPrompt.prompt()

  // Wait for the user to respond to the prompt
  const { outcome } = await deferredPrompt.userChoice

  console.log(`[PWA] User ${outcome === 'accepted' ? 'accepted' : 'dismissed'} the install prompt`)

  // Clear the deferredPrompt
  deferredPrompt = null

  return outcome === 'accepted'
}

/**
 * Request notification permission
 */
export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (!('Notification' in window)) {
    console.warn('[PWA] Notifications not supported')
    return 'denied'
  }

  if (Notification.permission === 'granted') {
    return 'granted'
  }

  if (Notification.permission !== 'denied') {
    const permission = await Notification.requestPermission()
    console.log('[PWA] Notification permission:', permission)
    return permission
  }

  return Notification.permission
}

/**
 * Subscribe to push notifications
 */
export async function subscribeToPushNotifications(): Promise<PushSubscription | null> {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    console.warn('[PWA] Push notifications not supported')
    return null
  }

  try {
    await navigator.serviceWorker.ready
    const permission = await requestNotificationPermission()

    if (permission !== 'granted') {
      console.warn('[PWA] Notification permission not granted')
      return null
    }

    // Note: You'll need to generate VAPID keys and configure this
    // For now, this is a placeholder
    console.log('[PWA] Push notification subscription ready')
    return null
  } catch (error) {
    console.error('[PWA] Push subscription failed:', error)
    return null
  }
}

/**
 * Check network status
 */
export function isOnline(): boolean {
  return navigator.onLine
}

/**
 * Listen for online/offline events
 */
export function setupNetworkListeners(onOnline?: () => void, onOffline?: () => void): () => void {
  const handleOnline = () => {
    console.log('[PWA] Network: ONLINE')
    onOnline?.()
  }

  const handleOffline = () => {
    console.log('[PWA] Network: OFFLINE')
    onOffline?.()
  }

  window.addEventListener('online', handleOnline)
  window.addEventListener('offline', handleOffline)

  // Return cleanup function
  return () => {
    window.removeEventListener('online', handleOnline)
    window.removeEventListener('offline', handleOffline)
  }
}

/**
 * Get cache storage size
 */
export async function getCacheSize(): Promise<number> {
  if (!('storage' in navigator) || !('estimate' in navigator.storage)) {
    return 0
  }

  try {
    const estimate = await navigator.storage.estimate()
    return estimate.usage || 0
  } catch (error) {
    console.error('[PWA] Failed to get cache size:', error)
    return 0
  }
}

/**
 * Clear all caches
 */
export async function clearAllCaches(): Promise<void> {
  if ('caches' in window) {
    const cacheNames = await caches.keys()
    await Promise.all(cacheNames.map((name) => caches.delete(name)))
    console.log('[PWA] All caches cleared')
  }
}
