// Service Worker for LeafLock PWA
// Provides offline functionality and caching

const CACHE_NAME = 'leaflock-v1.0.0'
const RUNTIME_CACHE = 'leaflock-runtime'

// Static assets to cache on install
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/favicon.ico',
  '/favicon.svg',
  '/apple-touch-icon.png',
  '/favicon-32.png',
  '/favicon-16.png',
  '/safari-pinned-tab.svg',
  '/site.webmanifest'
]

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('Service Worker installing...')

  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Caching static assets')
        return cache.addAll(STATIC_ASSETS)
      })
      .then(() => {
        // Force the waiting service worker to become the active service worker
        return self.skipWaiting()
      })
  )
})

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('Service Worker activating...')

  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== CACHE_NAME && cacheName !== RUNTIME_CACHE) {
              console.log('Deleting old cache:', cacheName)
              return caches.delete(cacheName)
            }
          })
        )
      })
      .then(() => {
        // Take control of all clients immediately
        return self.clients.claim()
      })
  )
})

// Fetch event - serve from cache when offline
self.addEventListener('fetch', (event) => {
  const { request } = event
  const url = new URL(request.url)

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return
  }

  // Skip cross-origin requests
  if (url.origin !== self.location.origin && !url.origin.includes('localhost')) {
    return
  }

  // Handle API requests
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(handleAPIRequest(request))
    return
  }

  // Handle static assets and navigation
  event.respondWith(
    caches.match(request)
      .then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse
        }

        // Try network first for new requests
        return fetch(request)
          .then((response) => {
            // Don't cache if not successful
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response
            }

            // Cache successful responses
            const responseToCache = response.clone()
            caches.open(RUNTIME_CACHE)
              .then((cache) => {
                cache.put(request, responseToCache)
              })

            return response
          })
          .catch(() => {
            // If we're offline and it's a navigation request, serve the cached index.html
            if (request.mode === 'navigate') {
              return caches.match('/index.html')
            }

            // For other requests, return a basic offline response
            return new Response('Offline', {
              status: 503,
              statusText: 'Service Unavailable'
            })
          })
      })
  )
})

// Handle API requests with offline queue support
async function handleAPIRequest(request) {
  try {
    // Try network first
    const response = await fetch(request)

    // Cache successful GET requests
    if (request.method === 'GET' && response.ok) {
      const cache = await caches.open(RUNTIME_CACHE)
      cache.put(request, response.clone())
    }

    return response
  } catch (error) {
    // Network failed - try cache for GET requests
    if (request.method === 'GET') {
      const cachedResponse = await caches.match(request)
      if (cachedResponse) {
        return cachedResponse
      }
    }

    // For non-GET requests when offline, store in IndexedDB queue
    if (request.method !== 'GET') {
      await queueOfflineRequest(request)

      return new Response(JSON.stringify({
        success: true,
        offline: true,
        message: 'Request queued for when online'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Return offline response
    return new Response(JSON.stringify({
      error: 'Offline',
      message: 'Please check your internet connection'
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

// Queue offline requests in IndexedDB
async function queueOfflineRequest(request) {
  try {
    const requestData = {
      url: request.url,
      method: request.method,
      headers: Object.fromEntries(request.headers.entries()),
      body: request.method !== 'GET' ? await request.text() : null,
      timestamp: Date.now()
    }

    // Store in IndexedDB
    const db = await openOfflineDB()
    const transaction = db.transaction(['requests'], 'readwrite')
    const store = transaction.objectStore('requests')
    await store.add(requestData)

    console.log('Queued offline request:', requestData.method, requestData.url)
  } catch (error) {
    console.error('Failed to queue offline request:', error)
  }
}

// Open IndexedDB for offline storage
function openOfflineDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('LeafLockOffline', 1)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)

    request.onupgradeneeded = (event) => {
      const db = event.target.result

      // Store for queued requests
      if (!db.objectStoreNames.contains('requests')) {
        const store = db.createObjectStore('requests', {
          keyPath: 'id',
          autoIncrement: true
        })
        store.createIndex('timestamp', 'timestamp')
      }

      // Store for cached notes
      if (!db.objectStoreNames.contains('notes')) {
        const notesStore = db.createObjectStore('notes', { keyPath: 'id' })
        notesStore.createIndex('updated_at', 'updated_at')
      }
    }
  })
}

// Listen for messages from the main thread
self.addEventListener('message', (event) => {
  const { type, data } = event.data

  switch (type) {
    case 'SKIP_WAITING':
      self.skipWaiting()
      break

    case 'SYNC_OFFLINE_REQUESTS':
      syncOfflineRequests()
      break

    case 'CACHE_NOTES':
      cacheNotesData(data)
      break

    default:
      console.log('Unknown message type:', type)
  }
})

// Sync queued requests when back online
async function syncOfflineRequests() {
  try {
    const db = await openOfflineDB()
    const transaction = db.transaction(['requests'], 'readwrite')
    const store = transaction.objectStore('requests')
    const requests = await store.getAll()

    console.log(`Syncing ${requests.length} offline requests...`)

    for (const requestData of requests) {
      try {
        const response = await fetch(requestData.url, {
          method: requestData.method,
          headers: requestData.headers,
          body: requestData.body
        })

        if (response.ok) {
          // Remove from queue on success
          await store.delete(requestData.id)
          console.log('Synced offline request:', requestData.method, requestData.url)
        }
      } catch (error) {
        console.error('Failed to sync request:', error)
        // Keep in queue for next attempt
      }
    }

    // Notify main thread of sync completion
    self.clients.matchAll().then(clients => {
      clients.forEach(client => {
        client.postMessage({
          type: 'SYNC_COMPLETE',
          data: { synced: requests.length }
        })
      })
    })

  } catch (error) {
    console.error('Failed to sync offline requests:', error)
  }
}

// Cache notes data for offline access
async function cacheNotesData(notes) {
  try {
    const db = await openOfflineDB()
    const transaction = db.transaction(['notes'], 'readwrite')
    const store = transaction.objectStore('notes')

    for (const note of notes) {
      await store.put(note)
    }

    console.log(`Cached ${notes.length} notes for offline access`)
  } catch (error) {
    console.error('Failed to cache notes:', error)
  }
}

// Background sync for when connection is restored
self.addEventListener('sync', (event) => {
  if (event.tag === 'offline-sync') {
    event.waitUntil(syncOfflineRequests())
  }
})

// Listen for online/offline events
self.addEventListener('online', () => {
  console.log('Service Worker: Back online, syncing requests...')
  syncOfflineRequests()
})

console.log('Service Worker loaded successfully')