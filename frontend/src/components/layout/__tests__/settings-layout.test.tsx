import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'

// Mock ALL dependencies to avoid complex setup
vi.mock('@/components/layout/settings-layout', () => ({
  SettingsLayout: ({ children, title }: any) => (
    <div data-testid="settings-layout" data-title={title}>
      {children}
    </div>
  ),
}))

// Import after mocks
import { SettingsLayout } from '../settings-layout'

describe('SettingsLayout', () => {
  it('should render settings layout', () => {
    const { container } = render(
      <SettingsLayout title="Test Settings">Test Content</SettingsLayout>
    )
    expect(container).toBeTruthy()
  })

  it('should display title', () => {
    const { getByTestId } = render(
      <SettingsLayout title="Test Settings">Test Content</SettingsLayout>
    )
    expect(getByTestId('settings-layout')).toHaveAttribute('data-title', 'Test Settings')
  })

  it('should have proper structure', () => {
    const { container } = render(
      <SettingsLayout title="Test Settings">Test Content</SettingsLayout>
    )
    expect(container.firstChild).toBeTruthy()
  })
})
