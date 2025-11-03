import { useEffect, useMemo, useRef, useState } from 'react'

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
  const signatureRef = useRef<string>('uninitialized')
  const unlockedRef = useRef<boolean | null>(null)
  const runIdRef = useRef(0)

  useEffect(() => {
    cacheRef.current = cache
  }, [cache])

  const notesSignature = useMemo(() => {
    if (!notes.length) return 'empty'
    return notes
      .map((note) => `${note.id}:${note.updatedAt ?? ''}:${note.title ?? ''}:${note.content ?? ''}`)
      .join('|')
  }, [notes])

  useEffect(() => {
    if (signatureRef.current === notesSignature && unlockedRef.current === isUnlocked) {
      return
    }

    signatureRef.current = notesSignature
    unlockedRef.current = isUnlocked

    const runId = (runIdRef.current += 1)

    const run = async () => {
      if (!isUnlocked) {
        if (runIdRef.current === runId) {
          setCache({})
          setIsDecrypting(false)
        }
        return
      }

      if (runIdRef.current !== runId) {
        return
      }

      setIsDecrypting(true)
      const nextCache: DecryptedNoteCache = {}
      const existing = cacheRef.current

      for (const note of notes) {
        const updatedTimestamp = (() => {
          if (!note.updatedAt) return 0
          try {
            const timestamp = new Date(note.updatedAt).getTime()
            return isNaN(timestamp) ? 0 : timestamp
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

      if (runIdRef.current === runId) {
        setCache(nextCache)
        setIsDecrypting(false)
      }
    }

    run()
  }, [notesSignature, isUnlocked, decryptText, notes])

  return {
    decryptedNotes: cache,
    isUnlocked,
    isDecrypting,
  }
}
