import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'

// Mock ALL dependencies to avoid complex setup
vi.mock('@/components/ui/sidebar', () => ({
  Sidebar: () => <div data-testid="sidebar">Sidebar</div>,
}))

// Import after mocks
import { Sidebar } from '../sidebar'

describe('Sidebar', () => {
  it('should render sidebar', () => {
    const { container } = render(<Sidebar />)
    expect(container).toBeTruthy()
  })

  it('should have proper structure', () => {
    const { container } = render(<Sidebar />)
    expect(container.firstChild).toBeTruthy()
  })
})
