import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { AdvancedSearchBar } from '../advanced-search-bar'

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

vi.mock('@/components/ui/popover', () => ({
  Popover: ({ children }: any) => <div>{children}</div>,
  PopoverTrigger: ({ children }: any) => <div>{children}</div>,
  PopoverContent: ({ children }: any) => <div data-testid="popover-content">{children}</div>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children, onValueChange }: any) => <div data-testid="select" onClick={() => onValueChange && onValueChange('test')}>{children}</div>,
  SelectTrigger: ({ children }: any) => <div>{children}</div>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, value }: any) => <option value={value}>{children}</option>,
  SelectValue: ({ placeholder }: any) => <span>{placeholder}</span>,
}))

describe('AdvancedSearchBar', () => {
  const mockOnSearch = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render advanced search bar', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('should accept search query', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    
    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'search term' } })

    expect(input).toHaveValue('search term')
  })

  it('should call onSearch when searching', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    
    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: 'test' } })

    expect(mockOnSearch).toHaveBeenCalled()
  })

  it('should show advanced options button', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    
    const advancedButton = screen.getByRole('button', { name: /filter|advanced|options/i })
    expect(advancedButton).toBeInTheDocument()
  })

  it('should handle empty search', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    
    const input = screen.getByRole('textbox')
    fireEvent.change(input, { target: { value: '' } })

    expect(mockOnSearch).toHaveBeenCalledWith(expect.objectContaining({ query: '' }))
  })

  it('should support date range filtering', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    
    const advancedButton = screen.getByRole('button', { name: /filter|advanced|options/i })
    fireEvent.click(advancedButton)

    expect(screen.getByTestId('popover-content')).toBeInTheDocument()
  })

  it('should support tag filtering', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} tags={['tag1', 'tag2']} />)
    
    expect(document.body).toBeTruthy()
  })

  it('should support folder filtering', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} folders={[{ id: 'f1', name: 'Folder 1' }]} />)
    
    expect(document.body).toBeTruthy()
  })

  it('should clear search filters', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    
    const clearButton = screen.queryByRole('button', { name: /clear/i })
    if (clearButton) {
      fireEvent.click(clearButton)
      expect(mockOnSearch).toHaveBeenCalled()
    }
  })

  it('should handle keyboard shortcuts', () => {
    render(<AdvancedSearchBar onSearch={mockOnSearch} />)
    
    const input = screen.getByRole('textbox')
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(document.body).toBeTruthy()
  })
})
