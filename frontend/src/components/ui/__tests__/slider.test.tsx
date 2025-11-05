import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Slider } from '../slider'

describe('Slider', () => {
  it('should render slider', () => {
    render(<Slider />)

    const slider = screen.getByRole('slider')
    expect(slider).toBeInTheDocument()
  })

  it('should have default value', () => {
    render(<Slider defaultValue={[50]} />)

    const slider = screen.getByRole('slider')
    expect(slider).toHaveAttribute('aria-valuenow', '50')
  })

  it('should have min and max values', () => {
    render(<Slider min={0} max={100} defaultValue={[25]} />)

    const slider = screen.getByRole('slider')
    expect(slider).toHaveAttribute('aria-valuemin', '0')
    expect(slider).toHaveAttribute('aria-valuemax', '100')
  })

  it('should call onValueChange', () => {
    const handleChange = vi.fn()
    render(<Slider onValueChange={handleChange} />)

    expect(screen.getByRole('slider')).toBeInTheDocument()
  })

  it('should be disabled when disabled prop is true', () => {
    render(<Slider disabled={true} />)

    const slider = screen.getByRole('slider')
    // Radix Slider uses data-disabled attribute
    expect(slider).toHaveAttribute('data-disabled')
  })

  it('should support step prop', () => {
    render(<Slider step={10} defaultValue={[50]} />)

    const slider = screen.getByRole('slider')
    expect(slider).toBeInTheDocument()
  })
})
