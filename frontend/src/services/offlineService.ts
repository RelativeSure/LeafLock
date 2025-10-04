import { getStoredAuthToken } from '@/utils/auth'

/**
 * Offline service for managing PWA functionality and offline data
 */

export interface OfflineNote {
  id: string
  title: string
  content: string
  created_at: string
  updated_at: string
  folder_id?: string
  tags?: string[]
  offline_changes?: boolean
}

export interface QueuedRequest {
  id?: number
  url: string
  method: string
  headers: Record<string, string>
  body?: string
  timestamp: number
}

class OfflineService {
  private dbName = 'LeafLockOffline'
  private version = 1
  private db: IDBDatabase | null = null
  private swRegistration: ServiceWorkerRegistration | null = null

  constructor() {
    this.initServiceWorker()
    this.setupOnlineOfflineListeners()
  }

  /**
   * Initialize service worker
   */
  private async initServiceWorker() {
    if ('serviceWorker' in navigator) {
      try {
        this.swRegistration = await navigator.serviceWorker.register('/sw.js', {
          scope: '/'
        })

        console.log('✅ Service Worker registered successfully')

        // Listen for messages from service worker
        navigator.serviceWorker.addEventListener('message', this.handleSWMessage.bind(this))

        // Handle updates
        this.swRegistration.addEventListener('updatefound', () => {
          const newWorker = this.swRegistration!.installing
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New service worker available
                this.notifyUpdate()
              }
            })
          }
        })

      } catch (error) {
        console.error('❌ Service Worker registration failed:', error)
      }
    } else {
      console.warn('⚠️ Service Worker not supported')
    }
  }

  /**
   * Handle messages from service worker
   */
  private handleSWMessage(event: MessageEvent) {
    const { type, data } = event.data

    switch (type) {
      case 'SYNC_COMPLETE':
        console.log(`✅ Synced ${data.synced} offline requests`)
        this.dispatchEvent('sync-complete', data)
        break

      default:
        console.log('Unknown SW message:', type, data)
    }
  }

  /**
   * Setup online/offline event listeners
   */
  private setupOnlineOfflineListeners() {
    window.addEventListener('online', () => {
      console.log('🌐 Back online - syncing offline changes...')
      this.syncOfflineRequests()
      this.dispatchEvent('online')
    })

    window.addEventListener('offline', () => {
      console.log('📴 Gone offline - enabling offline mode...')
      this.dispatchEvent('offline')
    })
  }

  /**
   * Check if the app is currently online
   */
  isOnline(): boolean {
    return navigator.onLine
  }

  /**
   * Open IndexedDB connection
   */
  private async openDB(): Promise<IDBDatabase> {
    if (this.db) {
      return this.db
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version)

      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        this.db = request.result
        resolve(this.db)
      }

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result

        // Store for notes
        if (!db.objectStoreNames.contains('notes')) {
          const notesStore = db.createObjectStore('notes', { keyPath: 'id' })
          notesStore.createIndex('updated_at', 'updated_at')
          notesStore.createIndex('folder_id', 'folder_id')
        }

        // Store for queued requests
        if (!db.objectStoreNames.contains('requests')) {
          const requestsStore = db.createObjectStore('requests', {
            keyPath: 'id',
            autoIncrement: true
          })
          requestsStore.createIndex('timestamp', 'timestamp')
        }

        // Store for application data
        if (!db.objectStoreNames.contains('appData')) {
          db.createObjectStore('appData', { keyPath: 'key' })
        }
      }
    })
  }

  /**
   * Cache notes for offline access
   */
  async cacheNotes(notes: OfflineNote[]): Promise<void> {
    try {
      const db = await this.openDB()
      const transaction = db.transaction(['notes'], 'readwrite')
      const store = transaction.objectStore('notes')

      for (const note of notes) {
        await this.putInStore(store, note)
      }

      console.log(`📦 Cached ${notes.length} notes for offline access`)

      // Also send to service worker
      if (this.swRegistration?.active) {
        this.swRegistration.active.postMessage({
          type: 'CACHE_NOTES',
          data: notes
        })
      }
    } catch (error) {
      console.error('Failed to cache notes:', error)
    }
  }

  /**
   * Get cached notes
   */
  async getCachedNotes(): Promise<OfflineNote[]> {
    try {
      const db = await this.openDB()
      const transaction = db.transaction(['notes'], 'readonly')
      const store = transaction.objectStore('notes')

      return await this.getAllFromStore(store)
    } catch (error) {
      console.error('Failed to get cached notes:', error)
      return []
    }
  }

  /**
   * Save note offline
   */
  async saveNoteOffline(note: OfflineNote): Promise<void> {
    try {
      note.offline_changes = true
      note.updated_at = new Date().toISOString()

      const db = await this.openDB()
      const transaction = db.transaction(['notes'], 'readwrite')
      const store = transaction.objectStore('notes')

      await this.putInStore(store, note)
      console.log('💾 Saved note offline:', note.id)
    } catch (error) {
      console.error('Failed to save note offline:', error)
      throw error
    }
  }

  /**
   * Get notes with offline changes
   */
  async getNotesWithOfflineChanges(): Promise<OfflineNote[]> {
    try {
      const notes = await this.getCachedNotes()
      return notes.filter(note => note.offline_changes)
    } catch (error) {
      console.error('Failed to get notes with offline changes:', error)
      return []
    }
  }

  /**
   * Clear offline changes flag for synced notes
   */
  async clearOfflineChanges(noteIds: string[]): Promise<void> {
    try {
      const db = await this.openDB()
      const transaction = db.transaction(['notes'], 'readwrite')
      const store = transaction.objectStore('notes')

      for (const noteId of noteIds) {
        const note = await this.getFromStore(store, noteId)
        if (note) {
          note.offline_changes = false
          await this.putInStore(store, note)
        }
      }
    } catch (error) {
      console.error('Failed to clear offline changes:', error)
    }
  }

  /**
   * Queue request for when online
   */
  async queueRequest(url: string, options: RequestInit): Promise<void> {
    try {
      const requestData: QueuedRequest = {
        url,
        method: options.method || 'GET',
        headers: this.headersToObject(options.headers),
        body: options.body as string,
        timestamp: Date.now()
      }

      const db = await this.openDB()
      const transaction = db.transaction(['requests'], 'readwrite')
      const store = transaction.objectStore('requests')

      await this.putInStore(store, requestData)
      console.log('📤 Queued request for sync:', requestData.method, requestData.url)
    } catch (error) {
      console.error('Failed to queue request:', error)
    }
  }

  /**
   * Sync offline requests
   */
  async syncOfflineRequests(): Promise<void> {
    if (!this.isOnline()) {
      console.log('📴 Still offline, skipping sync')
      return
    }

    try {
      // Trigger sync via service worker
      if (this.swRegistration?.active) {
        this.swRegistration.active.postMessage({
          type: 'SYNC_OFFLINE_REQUESTS'
        })
      }

      // Also sync notes with offline changes
      await this.syncOfflineNotes()
    } catch (error) {
      console.error('Failed to sync offline requests:', error)
    }
  }

  /**
   * Sync notes with offline changes
   */
  private async syncOfflineNotes(): Promise<void> {
    try {
      const offlineNotes = await this.getNotesWithOfflineChanges()

      for (const note of offlineNotes) {
        try {
          // Attempt to sync note
          const token = getStoredAuthToken()
          const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': localStorage.getItem('csrf_token') || ''
          }
          if (token) {
            headers['Authorization'] = `Bearer ${token}`
          }

          const response = await fetch(`/api/v1/notes/${note.id}`, {
            method: 'PUT',
            headers,
            body: JSON.stringify({
              title_encrypted: note.title,
              content_encrypted: note.content
            })
          })

          if (response.ok) {
            await this.clearOfflineChanges([note.id])
            console.log('✅ Synced offline note:', note.id)
          }
        } catch (error) {
          console.error('Failed to sync note:', note.id, error)
        }
      }
    } catch (error) {
      console.error('Failed to sync offline notes:', error)
    }
  }

  /**
   * Install app prompt
   */
  async showInstallPrompt(): Promise<boolean> {
    if ('beforeinstallprompt' in window) {
      const event = (window as any).deferredPrompt
      if (event) {
        event.prompt()
        const result = await event.userChoice
        return result.outcome === 'accepted'
      }
    }
    return false
  }

  /**
   * Check if app is installed
   */
  isInstalled(): boolean {
    return window.matchMedia('(display-mode: standalone)').matches ||
           (window.navigator as any).standalone ||
           document.referrer.includes('android-app://')
  }

  /**
   * Get app data
   */
  async getAppData(key: string): Promise<any> {
    try {
      const db = await this.openDB()
      const transaction = db.transaction(['appData'], 'readonly')
      const store = transaction.objectStore('appData')

      const result = await this.getFromStore(store, key)
      return result?.value
    } catch (error) {
      console.error('Failed to get app data:', error)
      return null
    }
  }

  /**
   * Set app data
   */
  async setAppData(key: string, value: any): Promise<void> {
    try {
      const db = await this.openDB()
      const transaction = db.transaction(['appData'], 'readwrite')
      const store = transaction.objectStore('appData')

      await this.putInStore(store, { key, value })
    } catch (error) {
      console.error('Failed to set app data:', error)
    }
  }

  /**
   * Notify about service worker update
   */
  private notifyUpdate() {
    this.dispatchEvent('sw-update')
  }

  /**
   * Apply service worker update
   */
  async applyUpdate(): Promise<void> {
    if (this.swRegistration?.waiting) {
      this.swRegistration.waiting.postMessage({ type: 'SKIP_WAITING' })
      window.location.reload()
    }
  }

  /**
   * Helper methods for IndexedDB operations
   */
  private putInStore(store: IDBObjectStore, data: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = store.put(data)
      request.onsuccess = () => resolve()
      request.onerror = () => reject(request.error)
    })
  }

  private getFromStore(store: IDBObjectStore, key: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const request = store.get(key)
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
  }

  private getAllFromStore(store: IDBObjectStore): Promise<any[]> {
    return new Promise((resolve, reject) => {
      const request = store.getAll()
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
  }

  private headersToObject(headers: HeadersInit | undefined): Record<string, string> {
    if (!headers) return {}

    if (headers instanceof Headers) {
      const obj: Record<string, string> = {}
      headers.forEach((value, key) => {
        obj[key] = value
      })
      return obj
    }

    if (Array.isArray(headers)) {
      const obj: Record<string, string> = {}
      headers.forEach(([key, value]) => {
        obj[key] = value
      })
      return obj
    }

    return headers as Record<string, string>
  }

  /**
   * Dispatch custom events
   */
  private dispatchEvent(type: string, data?: any) {
    window.dispatchEvent(new CustomEvent(`offline-${type}`, { detail: data }))
  }
}

export const offlineService = new OfflineService()
