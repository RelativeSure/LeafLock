import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Switch } from './switch'

describe('Switch Component', () => {
  it('renders unchecked by default', () => {
    render(<Switch />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeInTheDocument()
    expect(switchElement).not.toBeChecked()
    expect(switchElement).toHaveAttribute('aria-checked', 'false')
  })

  it('renders checked when checked prop is true', () => {
    render(<Switch checked />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeChecked()
    expect(switchElement).toHaveAttribute('aria-checked', 'true')
  })

  it('handles state changes', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()

    render(<Switch onCheckedChange={handleChange} />)

    const switchElement = screen.getByRole('switch')
    await user.click(switchElement)

    expect(handleChange).toHaveBeenCalledTimes(1)
    expect(handleChange).toHaveBeenCalledWith(true)
  })

  it('can be disabled', () => {
    render(<Switch disabled />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toBeDisabled()
    expect(switchElement).toHaveClass('disabled:cursor-not-allowed', 'disabled:opacity-50')
  })

  it('applies custom className', () => {
    render(<Switch className="custom-switch" />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass('custom-switch')
  })

  it('has proper focus styles', () => {
    render(<Switch />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass('focus-visible:outline-none', 'focus-visible:ring-2')
  })

  it('shows correct visual states for checked/unchecked', () => {
    const { rerender } = render(<Switch checked={false} />)

    let switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass('data-[state=unchecked]:bg-input')

    rerender(<Switch checked={true} />)
    switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass('data-[state=checked]:bg-primary')
  })

  it('forwards ref properly', () => {
    let switchRef: HTMLButtonElement | null = null

    render(
      <Switch
        ref={(el) => {
          switchRef = el
        }}
      />
    )

    expect(switchRef).toBeInstanceOf(HTMLButtonElement)
    expect(switchRef?.getAttribute('role')).toBe('switch')
  })

  it('handles keyboard interactions', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()

    render(<Switch onCheckedChange={handleChange} />)

    const switchElement = screen.getByRole('switch')
    switchElement.focus()
    await user.keyboard('{Space}')

    expect(handleChange).toHaveBeenCalledTimes(1)
    expect(handleChange).toHaveBeenCalledWith(true)
  })

  it('maintains focus ring offset', () => {
    render(<Switch />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass(
      'focus-visible:ring-offset-2',
      'focus-visible:ring-offset-background'
    )
  })

  it('has smooth transitions', () => {
    render(<Switch />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).toHaveClass('transition-colors')

    // Check thumb element has transition
    const thumbElement = switchElement.querySelector('[data-state]')
    expect(thumbElement).toHaveClass('transition-transform')
  })

  it('handles controlled state properly', async () => {
    const user = userEvent.setup()
    let checked = false
    const handleChange = vi.fn((newChecked) => {
      checked = newChecked
    })

    const { rerender } = render(<Switch checked={checked} onCheckedChange={handleChange} />)

    const switchElement = screen.getByRole('switch')
    expect(switchElement).not.toBeChecked()

    await user.click(switchElement)
    expect(handleChange).toHaveBeenCalledWith(true)

    // Simulate parent component updating state
    rerender(<Switch checked={true} onCheckedChange={handleChange} />)
    expect(screen.getByRole('switch')).toBeChecked()
  })

  it('supports aria-label for accessibility', () => {
    render(<Switch aria-label="Enable notifications" />)

    const switchElement = screen.getByRole('switch', { name: /enable notifications/i })
    expect(switchElement).toBeInTheDocument()
  })

  it('supports aria-labelledby for accessibility', () => {
    render(
      <div>
        <label id="switch-label">Dark mode</label>
        <Switch aria-labelledby="switch-label" />
      </div>
    )

    const switchElement = screen.getByRole('switch', { name: /dark mode/i })
    expect(switchElement).toBeInTheDocument()
    expect(switchElement).toHaveAttribute('aria-labelledby', 'switch-label')
  })
})
