import { useEffect, useRef, useState } from 'react'

import type { Note } from '@/types'
import { useEncryption } from '@/lib/encryption-context'

interface DecryptedNoteCacheEntry {
  title: string
  content: string
  timestamp: number
}

export type DecryptedNoteCache = Record<string, DecryptedNoteCacheEntry>

export function useDecryptedNotes(notes: Note[]) {
  const { isUnlocked, decryptText } = useEncryption()
  const [cache, setCache] = useState<DecryptedNoteCache>({})
  const [isDecrypting, setIsDecrypting] = useState(false)
  const cacheRef = useRef(cache)

  useEffect(() => {
    cacheRef.current = cache
  }, [cache])

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      if (!isUnlocked) {
        if (!cancelled) {
          setCache({})
          setIsDecrypting(false)
        }
        return
      }

      setIsDecrypting(true)
      const nextCache: DecryptedNoteCache = {}
      const existing = cacheRef.current

      for (const note of notes) {
        const updatedTimestamp = (() => {
          try {
            return note.updatedAt ? new Date(note.updatedAt).getTime() : 0
          } catch {
            return 0
          }
        })()

        const cached = existing[note.id]
        if (cached && cached.timestamp === updatedTimestamp) {
          nextCache[note.id] = cached
          continue
        }

        try {
          const title = note.title ? await decryptText(note.title) : ''
          const content = note.content ? await decryptText(note.content) : ''
          nextCache[note.id] = {
            title,
            content,
            timestamp: updatedTimestamp,
          }
        } catch (error) {
          nextCache[note.id] = {
            title: note.title || '',
            content: note.content || '',
            timestamp: updatedTimestamp,
          }
        }
      }

      if (!cancelled) {
        setCache(nextCache)
        setIsDecrypting(false)
      }
    }

    run()

    return () => {
      cancelled = true
    }
  }, [notes, isUnlocked, decryptText])

  return {
    decryptedNotes: cache,
    isUnlocked,
    isDecrypting,
  }
}
