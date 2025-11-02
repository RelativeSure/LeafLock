import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SettingsPage } from '../settings-page-minimal'

describe('SettingsPage', () => {
  it('renders static informational content', () => {
    render(<SettingsPage />)

    expect(screen.getByText('Settings')).toBeInTheDocument()
    expect(
      screen.getByText(/settings page is being rebuilt to resolve initialization issues/i)
    ).toBeInTheDocument()
  })
})
