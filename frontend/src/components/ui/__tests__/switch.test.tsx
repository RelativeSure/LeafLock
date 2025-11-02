import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Switch } from '../switch'

describe('Switch', () => {
  it('should render switch', () => {
    render(<Switch />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeInTheDocument()
  })

  it('should be unchecked by default', () => {
    render(<Switch />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).not.toBeChecked()
  })

  it('should be checked when checked prop is true', () => {
    render(<Switch checked={true} />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeChecked()
  })

  it('should toggle when clicked', () => {
    const handleChange = vi.fn()
    render(<Switch onCheckedChange={handleChange} />)

    const switchElement = screen.getByRole('switch')
    fireEvent.click(switchElement)

    expect(handleChange).toHaveBeenCalledWith(true)
  })

  it('should be disabled when disabled prop is true', () => {
    render(<Switch disabled={true} />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeDisabled()
  })

  it('should not toggle when disabled', () => {
    const handleChange = vi.fn()
    render(<Switch disabled={true} onCheckedChange={handleChange} />)

    const switchElement = screen.getByRole('switch')
    fireEvent.click(switchElement)

    expect(handleChange).not.toHaveBeenCalled()
  })

  it('should apply custom className', () => {
    render(<Switch className="custom-switch" />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass('custom-switch')
  })

  it('should handle controlled state', () => {
    const { rerender } = render(<Switch checked={false} />)
    expect(screen.getByRole('switch')).not.toBeChecked()

    rerender(<Switch checked={true} />)
    expect(screen.getByRole('switch')).toBeChecked()

    rerender(<Switch checked={false} />)
    expect(screen.getByRole('switch')).not.toBeChecked()
  })

  it('should support defaultChecked', () => {
    render(<Switch defaultChecked={true} />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeChecked()
  })

  it('should have proper aria attributes', () => {
    render(<Switch aria-label="Enable notifications" />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveAttribute('aria-label', 'Enable notifications')
  })

  it('should call onCheckedChange with correct value', () => {
    const handleChange = vi.fn()
    render(<Switch checked={false} onCheckedChange={handleChange} />)

    const switchElement = screen.getByRole('switch')

    // Click to turn on
    fireEvent.click(switchElement)
    expect(handleChange).toHaveBeenCalledWith(true)

    // Click again to turn off
    fireEvent.click(switchElement)
    expect(handleChange).toHaveBeenCalledWith(true) // Still called with true since checked=false prop
  })

  it('should support keyboard interaction', () => {
    const handleChange = vi.fn()
    render(<Switch onCheckedChange={handleChange} />)

    const switchElement = screen.getByRole('switch')
    switchElement.focus()

    fireEvent.keyDown(switchElement, { key: 'Enter' })
    expect(handleChange).toHaveBeenCalled()
  })

  it('should render with aria-checked attribute', () => {
    const { rerender } = render(<Switch checked={false} />)
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false')

    rerender(<Switch checked={true} />)
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'true')
  })
})
