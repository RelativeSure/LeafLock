import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { UserAvatar } from '../user-avatar'
import { useSettingsStore } from '@/stores/settingsStore'
import * as gravatarUtils from '@/lib/gravatar-utils'
import type { User } from '@/types'

// Mock dependencies
vi.mock('@/stores/settingsStore', () => ({
  useSettingsStore: vi.fn(),
}))

vi.mock('@/lib/gravatar-utils', () => ({
  getGravatarUrl: vi.fn(),
  getUserInitials: vi.fn(),
}))

describe('UserAvatar', () => {
  const mockUser: User = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user',
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01T00:00:00Z',
  }

  const defaultSettings = {
    profilePicture: {
      type: 'gravatar' as const,
      customUrl: null,
    },
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useSettingsStore).mockReturnValue({
      settings: defaultSettings,
    } as any)
    vi.mocked(gravatarUtils.getUserInitials).mockReturnValue('TU')
    vi.mocked(gravatarUtils.getGravatarUrl).mockReturnValue('https://gravatar.com/test')
  })

  describe('Rendering', () => {
    it('should render with null user', () => {
      render(<UserAvatar user={null} />)

      expect(screen.getByText('?')).toBeInTheDocument()
    })

    it('should render with gravatar by default', () => {
      render(<UserAvatar user={mockUser} />)

      expect(gravatarUtils.getGravatarUrl).toHaveBeenCalledWith('test@example.com', 32)
      expect(gravatarUtils.getUserInitials).toHaveBeenCalledWith('Test User')
      expect(screen.getByText('TU')).toBeInTheDocument()
    })

    it('should render with custom size', () => {
      render(<UserAvatar user={mockUser} size={64} />)

      expect(gravatarUtils.getGravatarUrl).toHaveBeenCalledWith('test@example.com', 64)
    })

    it('should apply custom className', () => {
      const { container } = render(<UserAvatar user={mockUser} className="custom-class" />)

      const avatar = container.querySelector('.custom-class')
      expect(avatar).toBeInTheDocument()
    })
  })

  describe('Profile Picture Types', () => {
    it('should render initials when type is initials', () => {
      vi.mocked(useSettingsStore).mockReturnValue({
        settings: {
          ...defaultSettings,
          profilePicture: {
            type: 'initials',
            customUrl: null,
          },
        },
      } as any)

      render(<UserAvatar user={mockUser} />)

      expect(screen.getByText('TU')).toBeInTheDocument()
      expect(gravatarUtils.getGravatarUrl).not.toHaveBeenCalled()
    })

    it('should render custom image when type is custom with URL', () => {
      vi.mocked(useSettingsStore).mockReturnValue({
        settings: {
          ...defaultSettings,
          profilePicture: {
            type: 'custom',
            customUrl: 'https://example.com/avatar.jpg',
          },
        },
      } as any)

      render(<UserAvatar user={mockUser} />)

      const img = screen.getByAltText('Test User')
      expect(img).toHaveAttribute('src', 'https://example.com/avatar.jpg')
      expect(screen.getByText('TU')).toBeInTheDocument()
    })

    it('should fallback to initials when custom type has no URL', () => {
      vi.mocked(useSettingsStore).mockReturnValue({
        settings: {
          ...defaultSettings,
          profilePicture: {
            type: 'custom',
            customUrl: null,
          },
        },
      } as any)

      render(<UserAvatar user={mockUser} />)

      expect(screen.getByText('TU')).toBeInTheDocument()
    })

    it('should render gravatar when type is gravatar', () => {
      vi.mocked(useSettingsStore).mockReturnValue({
        settings: {
          ...defaultSettings,
          profilePicture: {
            type: 'gravatar',
            customUrl: null,
          },
        },
      } as any)

      render(<UserAvatar user={mockUser} />)

      expect(gravatarUtils.getGravatarUrl).toHaveBeenCalledWith('test@example.com', 32)
      const img = screen.getByAltText('Test User')
      expect(img).toHaveAttribute('src', 'https://gravatar.com/test')
    })
  })

  describe('Ref forwarding', () => {
    it('should forward ref to Avatar component', () => {
      const ref = React.createRef<HTMLDivElement>()
      render(<UserAvatar user={mockUser} ref={ref} />)

      expect(ref.current).toBeInstanceOf(HTMLElement)
    })
  })

  describe('Avatar sizing', () => {
    it('should apply size to avatar style', () => {
      const { container } = render(<UserAvatar user={mockUser} size={48} />)

      const avatar = container.querySelector('[style*="width: 48px"]')
      expect(avatar).toBeInTheDocument()
    })

    it('should use default size of 32', () => {
      const { container } = render(<UserAvatar user={mockUser} />)

      const avatar = container.querySelector('[style*="width: 32px"]')
      expect(avatar).toBeInTheDocument()
    })
  })
})
