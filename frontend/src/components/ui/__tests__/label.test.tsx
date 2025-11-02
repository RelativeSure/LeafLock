import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Label } from '../label'

describe('Label', () => {
  it('should render label text', () => {
    render(<Label>Username</Label>)
    expect(screen.getByText('Username')).toBeInTheDocument()
  })

  it('should render with htmlFor attribute', () => {
    render(<Label htmlFor="email">Email</Label>)
    const label = screen.getByText('Email')
    expect(label).toHaveAttribute('for', 'email')
  })

  it('should render with custom className', () => {
    const { container } = render(<Label className="custom-label">Text</Label>)
    expect(container.querySelector('.custom-label')).toBeInTheDocument()
  })

  it('should work with input', () => {
    render(
      <div>
        <Label htmlFor="username">Username</Label>
        <input id="username" type="text" />
      </div>
    )
    expect(screen.getByText('Username')).toBeInTheDocument()
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('should render empty label', () => {
    const { container } = render(<Label></Label>)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with children elements', () => {
    render(
      <Label>
        <span>Required</span> Field
      </Label>
    )
    expect(screen.getByText('Required')).toBeInTheDocument()
    expect(screen.getByText('Field')).toBeInTheDocument()
  })
})
