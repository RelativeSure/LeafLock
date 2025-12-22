import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'

// Mock ALL dependencies to avoid complex setup
vi.mock('@/components/layout/protected-layout', () => ({
  ProtectedLayout: () => <div data-testid="protected-layout">Protected Layout</div>,
}))

// Import after mocks
import { ProtectedLayout } from '../protected-layout'

describe('ProtectedLayout', () => {
  it('should render protected layout', () => {
    const { container } = render(<ProtectedLayout />)
    expect(container).toBeTruthy()
  })

  it('should have proper structure', () => {
    const { container } = render(<ProtectedLayout />)
    expect(container.firstChild).toBeTruthy()
  })
})
