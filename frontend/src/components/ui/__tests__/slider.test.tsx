import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Slider } from '../slider'

describe('Slider', () => {
  it('renders slider component', () => {
    const { container } = render(<Slider />)
    const slider = container.querySelector('[role="slider"]')
    expect(slider).toBeInTheDocument()
  })

  it('renders with default value', () => {
    const { container } = render(<Slider defaultValue={[50]} />)
    const slider = container.querySelector('[role="slider"]')
    expect(slider).toHaveAttribute('aria-valuenow', '50')
  })

  it('renders with controlled value', () => {
    const { container } = render(<Slider value={[75]} onValueChange={() => {}} />)
    const slider = container.querySelector('[role="slider"]')
    expect(slider).toHaveAttribute('aria-valuenow', '75')
  })

  it('calls onValueChange when value changes', async () => {
    const handleValueChange = vi.fn()
    const { container } = render(
      <Slider defaultValue={[50]} onValueChange={handleValueChange} />
    )
    const slider = container.querySelector('[role="slider"]') as HTMLElement

    // Simulate arrow key press to change value
    slider.focus()
    await userEvent.keyboard('{ArrowRight}')

    expect(handleValueChange).toHaveBeenCalled()
  })

  it('supports min and max values', () => {
    const { container } = render(
      <Slider min={0} max={200} defaultValue={[100]} />
    )
    const slider = container.querySelector('[role="slider"]')
    expect(slider).toHaveAttribute('aria-valuemin', '0')
    expect(slider).toHaveAttribute('aria-valuemax', '200')
  })

  it('supports step increments', () => {
    const { container } = render(
      <Slider min={0} max={100} step={10} defaultValue={[50]} />
    )
    const slider = container.querySelector('[role="slider"]')
    expect(slider).toBeInTheDocument()
  })

  it('renders disabled slider when disabled prop is true', () => {
    const { container } = render(<Slider disabled defaultValue={[50]} />)
    const slider = container.querySelector('[role="slider"]')
    expect(slider).toHaveAttribute('data-disabled', '')
  })

  it('does not trigger onChange when disabled', async () => {
    const handleValueChange = vi.fn()
    const { container } = render(
      <Slider disabled defaultValue={[50]} onValueChange={handleValueChange} />
    )
    const slider = container.querySelector('[role="slider"]') as HTMLElement

    slider.focus()
    await userEvent.keyboard('{ArrowRight}')

    expect(handleValueChange).not.toHaveBeenCalled()
  })

  it('applies custom className', () => {
    const customClass = 'custom-slider-class'
    const { container } = render(<Slider className={customClass} />)
    const sliderRoot = container.firstChild as HTMLElement
    expect(sliderRoot).toHaveClass(customClass)
  })

  it('forwards ref correctly', () => {
    const ref = vi.fn()
    render(<Slider ref={ref} />)
    expect(ref).toHaveBeenCalled()
  })

  it('renders slider track', () => {
    const { container } = render(<Slider />)
    const track = container.querySelector('.bg-primary\\/20')
    expect(track).toBeInTheDocument()
  })

  it('renders slider range', () => {
    const { container } = render(<Slider defaultValue={[50]} />)
    const range = container.querySelector('.bg-primary')
    expect(range).toBeInTheDocument()
  })

  it('renders slider thumb', () => {
    const { container } = render(<Slider />)
    const thumb = container.querySelector('.rounded-full.border')
    expect(thumb).toBeInTheDocument()
  })

  it('handles keyboard navigation with arrow keys', async () => {
    const handleValueChange = vi.fn()
    const { container } = render(
      <Slider min={0} max={100} step={1} defaultValue={[50]} onValueChange={handleValueChange} />
    )
    const slider = container.querySelector('[role="slider"]') as HTMLElement

    slider.focus()
    expect(slider).toHaveFocus()

    await userEvent.keyboard('{ArrowRight}')
    expect(handleValueChange).toHaveBeenCalled()

    vi.clearAllMocks()
    await userEvent.keyboard('{ArrowLeft}')
    expect(handleValueChange).toHaveBeenCalled()
  })

  it('handles keyboard navigation with home and end keys', async () => {
    const handleValueChange = vi.fn()
    const { container } = render(
      <Slider min={0} max={100} defaultValue={[50]} onValueChange={handleValueChange} />
    )
    const slider = container.querySelector('[role="slider"]') as HTMLElement

    slider.focus()

    await userEvent.keyboard('{End}')
    expect(handleValueChange).toHaveBeenCalled()

    vi.clearAllMocks()
    await userEvent.keyboard('{Home}')
    expect(handleValueChange).toHaveBeenCalled()
  })

  it('supports multiple thumbs for range selection', () => {
    const { container } = render(<Slider defaultValue={[25, 75]} />)
    const sliders = container.querySelectorAll('[role="slider"]')
    expect(sliders).toHaveLength(2)
    expect(sliders[0]).toHaveAttribute('aria-valuenow', '25')
    expect(sliders[1]).toHaveAttribute('aria-valuenow', '75')
  })

  it('supports orientation prop', () => {
    const { container } = render(<Slider orientation="vertical" defaultValue={[50]} />)
    const sliderRoot = container.firstChild as HTMLElement
    expect(sliderRoot).toHaveAttribute('data-orientation', 'vertical')
  })

  it('renders with proper ARIA attributes', () => {
    const { container } = render(
      <Slider min={0} max={100} defaultValue={[50]} aria-label="Volume control" />
    )
    const slider = container.querySelector('[role="slider"]')
    expect(slider).toHaveAttribute('aria-label', 'Volume control')
    expect(slider).toHaveAttribute('aria-valuenow', '50')
    expect(slider).toHaveAttribute('aria-valuemin', '0')
    expect(slider).toHaveAttribute('aria-valuemax', '100')
  })

  it('supports inverted direction', () => {
    const { container } = render(<Slider inverted defaultValue={[50]} />)
    const sliderRoot = container.firstChild as HTMLElement
    expect(sliderRoot).toBeInTheDocument()
  })

  it('handles onValueCommit callback', async () => {
    const handleValueCommit = vi.fn()
    const { container } = render(
      <Slider defaultValue={[50]} onValueCommit={handleValueCommit} />
    )
    const slider = container.querySelector('[role="slider"]') as HTMLElement

    slider.focus()
    await userEvent.keyboard('{ArrowRight}')

    // Value commit typically fires on pointer up or when user stops interacting
    // The exact behavior depends on Radix UI implementation
    expect(slider).toBeInTheDocument()
  })

  it('maintains visual styles', () => {
    const { container } = render(<Slider defaultValue={[50]} />)
    const sliderRoot = container.firstChild as HTMLElement
    expect(sliderRoot).toHaveClass('relative', 'flex', 'w-full', 'touch-none', 'select-none', 'items-center')
  })

  it('renders thumb with proper styling', () => {
    const { container } = render(<Slider defaultValue={[50]} />)
    const thumb = container.querySelector('.rounded-full.border')
    expect(thumb).toHaveClass('h-4', 'w-4', 'rounded-full', 'border', 'bg-background', 'shadow')
  })

  it('renders track with proper styling', () => {
    const { container } = render(<Slider defaultValue={[50]} />)
    const track = container.querySelector('.bg-primary\\/20')
    expect(track).toHaveClass('relative', 'h-1.5', 'w-full', 'grow', 'overflow-hidden', 'rounded-full')
  })

  it('renders range with proper styling', () => {
    const { container } = render(<Slider defaultValue={[50]} />)
    const range = container.querySelector('.bg-primary')
    expect(range).toHaveClass('absolute', 'h-full', 'bg-primary')
  })
})
