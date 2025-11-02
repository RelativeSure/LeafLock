import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Switch } from '../components/ui/switch'

describe('Switch Component', () => {
  it('renders unchecked by default', () => {
    render(<Switch />)
    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeInTheDocument()
    expect(switchElement).not.toBeChecked()
  })

  it('renders checked when checked prop is true', () => {
    render(<Switch checked />)
    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeChecked()
  })

  it('can be disabled', () => {
    render(<Switch disabled />)
    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeDisabled()
  })

  it('accepts custom className', () => {
    render(<Switch className="custom-class" />)
    const switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass('custom-class')
  })
})
