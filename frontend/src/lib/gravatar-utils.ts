import CryptoJS from 'crypto-js'

/**
 * Generate Gravatar URL from email address
 * @param email - User's email address
 * @param size - Size of the avatar (default: 200)
 * @param defaultImage - Default image type if Gravatar not found
 * @returns Gravatar URL
 */
export function getGravatarUrl(
  email: string,
  size: number = 200,
  defaultImage: 'identicon' | 'monsterid' | 'wavatar' | 'retro' | 'robohash' | 'blank' = 'identicon'
): string {
  if (!email) return ''

  // Create MD5 hash of email (lowercase, trimmed)
  const hash = CryptoJS.MD5(email.toLowerCase().trim()).toString()

  // Build Gravatar URL
  const baseUrl = 'https://www.gravatar.com/avatar'
  const params = new URLSearchParams({
    s: size.toString(),
    d: defaultImage,
    r: 'pg' // Rating: G, PG, R, X (we use PG for safety)
  })

  return `${baseUrl}/${hash}?${params.toString()}`
}

/**
 * Check if Gravatar exists for email
 * @param email - User's email address
 * @returns Promise<boolean> - True if Gravatar exists
 */
export async function checkGravatarExists(email: string): Promise<boolean> {
  if (!email) return false

  try {
    const url = getGravatarUrl(email, 1, 'blank')
    const response = await fetch(url, { method: 'HEAD' })
    return response.ok
  } catch {
    return false
  }
}

/**
 * Get user initials from name
 * @param name - User's full name
 * @returns Initials string
 */
export function getUserInitials(name: string): string {
  if (!name) return '?'

  const words = name.trim().split(/\s+/)
  if (words.length === 1) {
    return words[0].charAt(0).toUpperCase()
  }

  return (words[0].charAt(0) + words[words.length - 1].charAt(0)).toUpperCase()
}
