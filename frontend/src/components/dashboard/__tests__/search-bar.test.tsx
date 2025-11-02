import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SearchBar } from '../search-bar'

vi.mock('@/components/ui/input', () => ({
  Input: ({ onChange, value, ...props }: any) => (
    <input onChange={onChange} value={value} {...props} />
  ),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

describe('SearchBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render search input', () => {
    const onSearch = vi.fn()
    render(<SearchBar onSearch={onSearch} />)

    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('should call onSearch when typing', () => {
    const onSearch = vi.fn()
    render(<SearchBar onSearch={onSearch} />)

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'test query' } })

    expect(onSearch).toHaveBeenCalledWith('test query')
  })

  it('should accept placeholder prop', () => {
    const onSearch = vi.fn()
    render(<SearchBar onSearch={onSearch} placeholder="Search notes..." />)

    expect(screen.getByPlaceholderText('Search notes...')).toBeInTheDocument()
  })

  it('should handle empty search', () => {
    const onSearch = vi.fn()
    render(<SearchBar onSearch={onSearch} />)

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: '' } })

    expect(onSearch).toHaveBeenCalledWith('')
  })

  it('should handle special characters', () => {
    const onSearch = vi.fn()
    render(<SearchBar onSearch={onSearch} />)

    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: '@#$%' } })

    expect(onSearch).toHaveBeenCalledWith('@#$%')
  })

  it('should handle long search queries', () => {
    const onSearch = vi.fn()
    render(<SearchBar onSearch={onSearch} />)

    const longQuery = 'a'.repeat(100)
    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: longQuery } })

    expect(onSearch).toHaveBeenCalledWith(longQuery)
  })

  it('should render with custom className', () => {
    const onSearch = vi.fn()
    const { container } = render(<SearchBar onSearch={onSearch} className="custom-search" />)

    expect(container.firstChild).toHaveClass('custom-search')
  })

  it('should be disabled when disabled prop is true', () => {
    const onSearch = vi.fn()
    render(<SearchBar onSearch={onSearch} disabled={true} />)

    expect(screen.getByRole('textbox')).toBeDisabled()
  })
})
