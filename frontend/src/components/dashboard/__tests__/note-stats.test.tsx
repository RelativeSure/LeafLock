import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { NoteStats } from '../note-stats'

describe('NoteStats', () => {
  it('should render note statistics with empty content', () => {
    render(<NoteStats content="" />)

    expect(screen.getByText(/0 words/i)).toBeInTheDocument()
    expect(screen.getByText(/0 characters/i)).toBeInTheDocument()
    expect(screen.getByText(/0 min read/i)).toBeInTheDocument()
  })

  it('should display word count', () => {
    render(<NoteStats content="Hello world this is a test" />)

    expect(screen.getByText(/6 words/i)).toBeInTheDocument()
  })

  it('should display character count', () => {
    render(<NoteStats content="Hello world" />)

    expect(screen.getByText(/11 characters/i)).toBeInTheDocument()
  })

  it('should calculate reading time', () => {
    // 400 words = 2 min read at 200 words/min
    const content = Array(400).fill('word').join(' ')
    render(<NoteStats content={content} />)

    expect(screen.getByText(/400 words/i)).toBeInTheDocument()
    expect(screen.getByText(/2 min read/i)).toBeInTheDocument()
  })

  it('should strip HTML tags for accurate count', () => {
    render(<NoteStats content="<p>Hello <strong>world</strong></p>" />)

    expect(screen.getByText(/2 words/i)).toBeInTheDocument()
    expect(screen.getByText(/11 characters/i)).toBeInTheDocument()
  })

  it('should handle content with multiple spaces', () => {
    render(<NoteStats content="Hello    world    test" />)

    expect(screen.getByText(/3 words/i)).toBeInTheDocument()
  })

  it('should update stats when content changes', () => {
    const { rerender } = render(<NoteStats content="Hello" />)
    expect(screen.getByText(/1 words/i)).toBeInTheDocument()

    rerender(<NoteStats content="Hello world" />)
    expect(screen.getByText(/2 words/i)).toBeInTheDocument()
  })

  it('should render with proper styling', () => {
    const { container } = render(<NoteStats content="Test" />)
    expect(container.firstChild).toBeTruthy()
    expect(container.firstChild).toHaveClass('flex')
  })

  it('should round up reading time', () => {
    // 201 words = 2 min read (rounds up from 1.005)
    const content = Array(201).fill('word').join(' ')
    render(<NoteStats content={content} />)

    expect(screen.getByText(/2 min read/i)).toBeInTheDocument()
  })
})
