import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Checkbox } from '../checkbox'

describe('Checkbox', () => {
  it('renders checkbox component', () => {
    render(<Checkbox />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toBeInTheDocument()
  })

  it('renders with unchecked state by default', () => {
    render(<Checkbox />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).not.toBeChecked()
    expect(checkbox).toHaveAttribute('data-state', 'unchecked')
  })

  it('renders with checked state when checked prop is true', () => {
    render(<Checkbox checked={true} onCheckedChange={() => {}} />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toBeChecked()
    expect(checkbox).toHaveAttribute('data-state', 'checked')
  })

  it('handles user interaction to toggle checked state', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Checkbox onCheckedChange={handleChange} />)

    const checkbox = screen.getByRole('checkbox')
    await user.click(checkbox)

    expect(handleChange).toHaveBeenCalledWith(true)
  })

  it('can be controlled with checked prop', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    const { rerender } = render(
      <Checkbox checked={false} onCheckedChange={handleChange} />
    )

    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveAttribute('data-state', 'unchecked')

    await user.click(checkbox)
    expect(handleChange).toHaveBeenCalledWith(true)

    rerender(<Checkbox checked={true} onCheckedChange={handleChange} />)
    expect(checkbox).toHaveAttribute('data-state', 'checked')
  })

  it('renders disabled checkbox when disabled prop is true', () => {
    render(<Checkbox disabled />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toBeDisabled()
  })

  it('does not trigger onChange when disabled', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Checkbox disabled onCheckedChange={handleChange} />)

    const checkbox = screen.getByRole('checkbox')
    await user.click(checkbox)

    expect(handleChange).not.toHaveBeenCalled()
  })

  it('applies custom className', () => {
    const customClass = 'custom-checkbox-class'
    render(<Checkbox className={customClass} />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveClass(customClass)
  })

  it('supports indeterminate state', () => {
    render(<Checkbox checked="indeterminate" onCheckedChange={() => {}} />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveAttribute('data-state', 'indeterminate')
  })

  it('forwards ref correctly', () => {
    const ref = vi.fn()
    render(<Checkbox ref={ref} />)
    expect(ref).toHaveBeenCalled()
  })

  it('renders check icon when checked', () => {
    const { container } = render(
      <Checkbox checked={true} onCheckedChange={() => {}} />
    )
    const indicator = container.querySelector('[data-slot="checkbox-indicator"]')
    expect(indicator).toBeInTheDocument()
  })

  it('applies aria-invalid styling when invalid', () => {
    render(<Checkbox aria-invalid={true} />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveAttribute('aria-invalid', 'true')
  })

  it('handles keyboard navigation', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Checkbox onCheckedChange={handleChange} />)

    const checkbox = screen.getByRole('checkbox')
    checkbox.focus()
    expect(checkbox).toHaveFocus()

    await user.keyboard('{Space}')
    expect(handleChange).toHaveBeenCalledWith(true)
  })

  it('can be used in a form', () => {
    render(
      <form>
        <Checkbox name="terms" value="accepted" />
      </form>
    )
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveAttribute('name', 'terms')
    expect(checkbox).toHaveAttribute('value', 'accepted')
  })

  it('supports required attribute', () => {
    render(<Checkbox required />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveAttribute('aria-required', 'true')
  })

  it('maintains peer class for CSS sibling selectors', () => {
    render(<Checkbox />)
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).toHaveClass('peer')
  })
})
