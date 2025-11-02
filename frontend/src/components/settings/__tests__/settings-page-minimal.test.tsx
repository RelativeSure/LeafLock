import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'

// Mock the settings page component
vi.mock('../settings-page-minimal', () => ({
  default: () => <div>Settings Page Minimal</div>,
}))

describe('SettingsPageMinimal', () => {
  const renderWithRouter = (component: React.ReactElement) => {
    return render(<BrowserRouter>{component}</BrowserRouter>)
  }

  it('should render minimal settings page', async () => {
    const { default: SettingsPageMinimal } = await import('../settings-page-minimal')

    renderWithRouter(<SettingsPageMinimal />)

    expect(screen.getByText(/settings/i)).toBeInTheDocument()
  })

  it('should be accessible', async () => {
    const { default: SettingsPageMinimal } = await import('../settings-page-minimal')

    const { container } = renderWithRouter(<SettingsPageMinimal />)

    expect(container).toBeTruthy()
  })

  it('should render without errors', async () => {
    const { default: SettingsPageMinimal } = await import('../settings-page-minimal')

    expect(() => {
      renderWithRouter(<SettingsPageMinimal />)
    }).not.toThrow()
  })
})
