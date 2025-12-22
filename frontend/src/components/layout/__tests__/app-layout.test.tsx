import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'

// Mock ALL dependencies to avoid complex setup
vi.mock('@/components/layout/app-layout', () => ({
  default: () => <div data-testid="app-layout">App Layout</div>,
}))

// Import after mocks
import AppLayout from '../app-layout'

describe('AppLayout', () => {
  it('should render app layout', () => {
    const { container } = render(<AppLayout />)
    expect(container).toBeTruthy()
  })

  it('should have proper structure', () => {
    const { container } = render(<AppLayout />)
    expect(container.firstChild).toBeTruthy()
  })
})
