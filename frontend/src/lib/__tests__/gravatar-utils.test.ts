import { describe, it, expect, vi, beforeEach } from 'vitest'
import { getGravatarUrl, checkGravatarExists, getUserInitials } from '../gravatar-utils'

global.fetch = vi.fn()

describe('gravatar-utils', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('getGravatarUrl', () => {
    it('should generate Gravatar URL for email', () => {
      const url = getGravatarUrl('user@example.com')

      expect(url).toContain('https://www.gravatar.com/avatar/')
      expect(url).toContain('s=200') // Default size
      expect(url).toContain('d=identicon') // Default image
      expect(url).toContain('r=pg') // Rating
    })

    it('should generate consistent hash for same email', () => {
      const url1 = getGravatarUrl('user@example.com')
      const url2 = getGravatarUrl('user@example.com')

      expect(url1).toBe(url2)
    })

    it('should handle uppercase emails (normalize to lowercase)', () => {
      const url1 = getGravatarUrl('USER@EXAMPLE.COM')
      const url2 = getGravatarUrl('user@example.com')

      expect(url1).toBe(url2)
    })

    it('should trim whitespace from email', () => {
      const url1 = getGravatarUrl('  user@example.com  ')
      const url2 = getGravatarUrl('user@example.com')

      expect(url1).toBe(url2)
    })

    it('should use custom size', () => {
      const url = getGravatarUrl('user@example.com', 100)

      expect(url).toContain('s=100')
    })

    it('should use custom default image', () => {
      const url = getGravatarUrl('user@example.com', 200, 'monsterid')

      expect(url).toContain('d=monsterid')
    })

    it('should return empty string for empty email', () => {
      const url = getGravatarUrl('')

      expect(url).toBe('')
    })

    it('should handle all default image types', () => {
      const types: Array<'identicon' | 'monsterid' | 'wavatar' | 'retro' | 'robohash' | 'blank'> = [
        'identicon',
        'monsterid',
        'wavatar',
        'retro',
        'robohash',
        'blank',
      ]

      types.forEach((type) => {
        const url = getGravatarUrl('user@example.com', 200, type)
        expect(url).toContain(`d=${type}`)
      })
    })

    it('should generate different hashes for different emails', () => {
      const url1 = getGravatarUrl('user1@example.com')
      const url2 = getGravatarUrl('user2@example.com')

      expect(url1).not.toBe(url2)
    })

    it('should handle special characters in email', () => {
      const url = getGravatarUrl('user+tag@example.com')

      expect(url).toContain('https://www.gravatar.com/avatar/')
    })

    it('should handle international domain names', () => {
      const url = getGravatarUrl('user@例え.jp')

      expect(url).toContain('https://www.gravatar.com/avatar/')
    })
  })

  describe('checkGravatarExists', () => {
    it('should return true if Gravatar exists', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
      } as Response)

      const exists = await checkGravatarExists('user@example.com')

      expect(exists).toBe(true)
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('https://www.gravatar.com/avatar/'),
        { method: 'HEAD' }
      )
    })

    it('should return false if Gravatar does not exist', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
      } as Response)

      const exists = await checkGravatarExists('nonexistent@example.com')

      expect(exists).toBe(false)
    })

    it('should return false for empty email', async () => {
      const exists = await checkGravatarExists('')

      expect(exists).toBe(false)
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('should return false on network error', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Network error'))

      const exists = await checkGravatarExists('user@example.com')

      expect(exists).toBe(false)
    })

    it('should use minimal size (1) for check', async () => {
      vi.mocked(global.fetch).mockResolvedValue({ ok: true } as Response)

      await checkGravatarExists('user@example.com')

      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('s=1'), { method: 'HEAD' })
    })

    it('should use blank default for check', async () => {
      vi.mocked(global.fetch).mockResolvedValue({ ok: true } as Response)

      await checkGravatarExists('user@example.com')

      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('d=blank'), {
        method: 'HEAD',
      })
    })
  })

  describe('getUserInitials', () => {
    it('should return initials from first and last name', () => {
      const initials = getUserInitials('John Doe')

      expect(initials).toBe('JD')
    })

    it('should return first letter for single word name', () => {
      const initials = getUserInitials('John')

      expect(initials).toBe('J')
    })

    it('should handle three word names (first and last)', () => {
      const initials = getUserInitials('John Middle Doe')

      expect(initials).toBe('JD')
    })

    it('should return question mark for empty name', () => {
      const initials = getUserInitials('')

      expect(initials).toBe('?')
    })

    it('should trim whitespace from name', () => {
      const initials = getUserInitials('  John Doe  ')

      expect(initials).toBe('JD')
    })

    it('should handle multiple spaces between words', () => {
      const initials = getUserInitials('John    Doe')

      expect(initials).toBe('JD')
    })

    it('should uppercase lowercase names', () => {
      const initials = getUserInitials('john doe')

      expect(initials).toBe('JD')
    })

    it('should handle names with special characters', () => {
      const initials = getUserInitials('José García')

      expect(initials).toBe('JG')
    })

    it('should handle hyphenated last names', () => {
      const initials = getUserInitials('Mary Smith-Jones')

      expect(initials).toBe('MS')
    })

    it('should handle unicode names', () => {
      const initials = getUserInitials('李 明')

      expect(initials).toBe('李明')
    })

    it('should handle single character name', () => {
      const initials = getUserInitials('X')

      expect(initials).toBe('X')
    })

    it('should handle very long names (use first and last)', () => {
      const initials = getUserInitials('First Second Third Fourth Last')

      expect(initials).toBe('FL')
    })
  })
})
