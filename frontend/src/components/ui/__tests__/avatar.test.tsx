import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Avatar, AvatarImage, AvatarFallback } from '../avatar'

describe('Avatar', () => {
  it('should render fallback', () => {
    render(
      <Avatar>
        <AvatarFallback>JD</AvatarFallback>
      </Avatar>
    )
    expect(screen.getByText('JD')).toBeInTheDocument()
  })

  it('should render image with fallback', () => {
    render(
      <Avatar>
        <AvatarImage src="https://example.com/avatar.jpg" alt="John" />
        <AvatarFallback>JD</AvatarFallback>
      </Avatar>
    )
    // Avatar shows fallback until image loads
    expect(screen.getByText('JD')).toBeInTheDocument()
  })

  it('should apply custom className', () => {
    const { container } = render(
      <Avatar className="custom">
        <AvatarFallback>AB</AvatarFallback>
      </Avatar>
    )
    expect(container.querySelector('.custom')).toBeInTheDocument()
  })
})
