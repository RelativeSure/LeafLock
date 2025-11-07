import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ConfigDebug } from '../ConfigDebug'

vi.mock('@/hooks/useConfig', () => ({
  useConfig: () => ({
    environment: 'development',
    apiUrl: 'https://api.local',
    isRailway: false,
    serviceName: 'leaflock-web',
  }),
}))

describe('ConfigDebug', () => {
  const clipboardWrite = vi.fn()
  const reload = vi.fn()

  beforeEach(() => {
    Object.assign(navigator, { clipboard: { writeText: clipboardWrite } })
    Object.defineProperty(window, 'location', {
      value: { reload },
      writable: true,
    })
    // ensure flag enables rendering even if env not development
    process.env.VITE_SHOW_CONFIG = 'true'
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('renders debug card and toggles visibility', () => {
    render(<ConfigDebug />)

    const toggleButton = screen.getByRole('button', { name: '+' })
    fireEvent.click(toggleButton)

    expect(screen.getByText('Configuration Debug')).toBeInTheDocument()
    expect(screen.getByText('Environment:')).toBeInTheDocument()
    expect(screen.getByText('API URL:')).toBeInTheDocument()
  })

  it('copies config and reloads page', () => {
    render(<ConfigDebug />)

    const [copyButton, refreshButton] = screen.getAllByRole('button').slice(0, 2)

    fireEvent.click(copyButton)
    expect(clipboardWrite).toHaveBeenCalledWith(
      JSON.stringify(
        {
          environment: 'development',
          apiUrl: 'https://api.local',
          isRailway: false,
          serviceName: 'leaflock-web',
        },
        null,
        2
      )
    )

    fireEvent.click(refreshButton)
    expect(reload).toHaveBeenCalled()
  })
})
