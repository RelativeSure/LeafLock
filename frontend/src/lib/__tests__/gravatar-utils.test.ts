import { describe, it, expect, vi, beforeEach } from 'vitest'
import { getGravatarUrl, checkGravatarExists, getUserInitials } from '../gravatar-utils'

describe('gravatar-utils', () => {
  describe('getGravatarUrl', () => {
    it('should generate correct Gravatar URL for email', () => {
      const url = getGravatarUrl('test@example.com')

      expect(url).toContain('https://www.gravatar.com/avatar/')
      expect(url).toContain('s=200') // default size
      expect(url).toContain('d=identicon') // default image type
      expect(url).toContain('r=pg') // rating
    })

    it('should normalize email to lowercase', () => {
      const url1 = getGravatarUrl('Test@Example.COM')
      const url2 = getGravatarUrl('test@example.com')

      expect(url1).toBe(url2)
    })

    it('should trim whitespace from email', () => {
      const url1 = getGravatarUrl('  test@example.com  ')
      const url2 = getGravatarUrl('test@example.com')

      expect(url1).toBe(url2)
    })

    it('should use custom size', () => {
      const url = getGravatarUrl('test@example.com', 100)

      expect(url).toContain('s=100')
    })

    it('should use custom default image type', () => {
      const url = getGravatarUrl('test@example.com', 200, 'monsterid')

      expect(url).toContain('d=monsterid')
    })

    it('should support all default image types', () => {
      const types: Array<'identicon' | 'monsterid' | 'wavatar' | 'retro' | 'robohash' | 'blank'> =
        ['identicon', 'monsterid', 'wavatar', 'retro', 'robohash', 'blank']

      types.forEach((type) => {
        const url = getGravatarUrl('test@example.com', 200, type)
        expect(url).toContain(`d=${type}`)
      })
    })

    it('should return empty string for empty email', () => {
      expect(getGravatarUrl('')).toBe('')
    })

    it('should generate consistent hash for same email', () => {
      const url1 = getGravatarUrl('test@example.com')
      const url2 = getGravatarUrl('test@example.com')

      expect(url1).toBe(url2)
    })

    it('should generate different hash for different emails', () => {
      const url1 = getGravatarUrl('test1@example.com')
      const url2 = getGravatarUrl('test2@example.com')

      expect(url1).not.toBe(url2)
    })

    it('should use MD5 hash in URL', () => {
      // MD5 of 'test@example.com' is '55502f40dc8b7c769880b10874abc9d0'
      const url = getGravatarUrl('test@example.com')

      expect(url).toContain('55502f40dc8b7c769880b10874abc9d0')
    })

    it('should have rating parameter set to pg', () => {
      const url = getGravatarUrl('test@example.com')

      expect(url).toContain('r=pg')
    })

    it('should handle special characters in email', () => {
      const url = getGravatarUrl('test+tag@example.com')

      expect(url).toContain('https://www.gravatar.com/avatar/')
      expect(url).toMatch(/^https:\/\/www\.gravatar\.com\/avatar\/[a-f0-9]{32}\?/)
    })
  })

  describe('checkGravatarExists', () => {
    beforeEach(() => {
      global.fetch = vi.fn()
    })

    it('should return true if Gravatar exists (200 OK)', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
      } as Response)

      const result = await checkGravatarExists('test@example.com')

      expect(result).toBe(true)
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('https://www.gravatar.com/avatar/'),
        { method: 'HEAD' }
      )
    })

    it('should return false if Gravatar does not exist (404)', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
      } as Response)

      const result = await checkGravatarExists('test@example.com')

      expect(result).toBe(false)
    })

    it('should return false on network error', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Network error'))

      const result = await checkGravatarExists('test@example.com')

      expect(result).toBe(false)
    })

    it('should return false for empty email', async () => {
      const result = await checkGravatarExists('')

      expect(result).toBe(false)
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('should use blank as default image and size 1 for check', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
      } as Response)

      await checkGravatarExists('test@example.com')

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('s=1'),
        { method: 'HEAD' }
      )
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('d=blank'),
        { method: 'HEAD' }
      )
    })

    it('should use HEAD request for performance', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
      } as Response)

      await checkGravatarExists('test@example.com')

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ method: 'HEAD' })
      )
    })
  })

  describe('getUserInitials', () => {
    it('should return first letter of single word name', () => {
      expect(getUserInitials('John')).toBe('J')
    })

    it('should return first letters of first and last name', () => {
      expect(getUserInitials('John Doe')).toBe('JD')
    })

    it('should handle three or more words (first and last)', () => {
      expect(getUserInitials('John William Doe')).toBe('JD')
    })

    it('should uppercase initials', () => {
      expect(getUserInitials('john doe')).toBe('JD')
    })

    it('should return ? for empty string', () => {
      expect(getUserInitials('')).toBe('?')
    })

    it('should handle names with extra whitespace', () => {
      expect(getUserInitials('  John   Doe  ')).toBe('JD')
    })

    it('should handle names with multiple spaces between words', () => {
      expect(getUserInitials('John    Doe')).toBe('JD')
    })

    it('should handle names with tabs and newlines', () => {
      expect(getUserInitials('John\t\nDoe')).toBe('JD')
    })

    it('should handle single letter names', () => {
      expect(getUserInitials('J')).toBe('J')
    })

    it('should handle two single letters', () => {
      expect(getUserInitials('J D')).toBe('JD')
    })

    it('should handle names with numbers', () => {
      expect(getUserInitials('John123 Doe456')).toBe('JD')
    })

    it('should handle names with special characters', () => {
      expect(getUserInitials('Jöhn Döe')).toBe('JD')
    })

    it('should handle very long names', () => {
      expect(getUserInitials('John Middle1 Middle2 Middle3 Doe')).toBe('JD')
    })

    it('should handle names with hyphens', () => {
      expect(getUserInitials('Mary-Jane Watson')).toBe('MW')
    })

    it('should handle names with apostrophes', () => {
      expect(getUserInitials("O'Brien Smith")).toBe('OS')
    })
  })

  describe('integration scenarios', () => {
    it('should generate consistent Gravatar URLs for profile pictures', () => {
      const email = 'user@example.com'
      const smallAvatar = getGravatarUrl(email, 40)
      const largeAvatar = getGravatarUrl(email, 200)

      // Should have same hash but different sizes
      const hashMatch = smallAvatar.match(/avatar\/([a-f0-9]{32})/)
      const hashMatch2 = largeAvatar.match(/avatar\/([a-f0-9]{32})/)

      expect(hashMatch?.[1]).toBe(hashMatch2?.[1])
      expect(smallAvatar).toContain('s=40')
      expect(largeAvatar).toContain('s=200')
    })

    it('should handle user display with initials fallback', () => {
      const name = 'Test User'
      const initials = getUserInitials(name)

      expect(initials).toBe('TU')
      expect(initials.length).toBeLessThanOrEqual(2)
    })

    it('should handle empty or invalid inputs gracefully', () => {
      expect(getGravatarUrl('')).toBe('')
      expect(getUserInitials('')).toBe('?')
    })
  })
})
