import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Input } from '../input'

describe('Input', () => {
  describe('basic rendering', () => {
    it('should render input element', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      expect(input).toBeInTheDocument()
    })

    it('should render with placeholder', () => {
      render(<Input placeholder="Enter text" />)
      const input = screen.getByPlaceholderText('Enter text')
      expect(input).toBeInTheDocument()
    })

    it('should render with default value', () => {
      render(<Input defaultValue="default text" />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      expect(input.value).toBe('default text')
    })

    it('should render with controlled value', () => {
      render(<Input value="controlled" onChange={vi.fn()} />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      expect(input.value).toBe('controlled')
    })
  })

  describe('input types', () => {
    it('should render with text type by default', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('type', 'text')
    })

    it('should render with email type', () => {
      render(<Input type="email" />)
      const input = document.querySelector('input[type="email"]')
      expect(input).toBeInTheDocument()
    })

    it('should render with password type', () => {
      render(<Input type="password" />)
      const input = document.querySelector('input[type="password"]')
      expect(input).toBeInTheDocument()
    })

    it('should render with number type', () => {
      render(<Input type="number" />)
      const input = document.querySelector('input[type="number"]')
      expect(input).toBeInTheDocument()
    })
  })

  describe('user interactions', () => {
    it('should call onChange when value changes', () => {
      const handleChange = vi.fn()
      render(<Input onChange={handleChange} />)
      const input = screen.getByRole('textbox')

      fireEvent.change(input, { target: { value: 'new value' } })

      expect(handleChange).toHaveBeenCalled()
    })

    it('should update value on user input', () => {
      const handleChange = vi.fn()
      render(<Input onChange={handleChange} />)
      const input = screen.getByRole('textbox') as HTMLInputElement

      fireEvent.change(input, { target: { value: 'test input' } })

      expect(input.value).toBe('test input')
    })

    it('should call onFocus when focused', () => {
      const handleFocus = vi.fn()
      render(<Input onFocus={handleFocus} />)
      const input = screen.getByRole('textbox')

      fireEvent.focus(input)

      expect(handleFocus).toHaveBeenCalled()
    })

    it('should call onBlur when blurred', () => {
      const handleBlur = vi.fn()
      render(<Input onBlur={handleBlur} />)
      const input = screen.getByRole('textbox')

      fireEvent.blur(input)

      expect(handleBlur).toHaveBeenCalled()
    })

    it('should call onKeyDown when key is pressed', () => {
      const handleKeyDown = vi.fn()
      render(<Input onKeyDown={handleKeyDown} />)
      const input = screen.getByRole('textbox')

      fireEvent.keyDown(input, { key: 'Enter' })

      expect(handleKeyDown).toHaveBeenCalled()
    })
  })

  describe('attributes and props', () => {
    it('should apply className prop', () => {
      render(<Input className="custom-class" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveClass('custom-class')
    })

    it('should be disabled when disabled prop is true', () => {
      render(<Input disabled />)
      const input = screen.getByRole('textbox')
      expect(input).toBeDisabled()
    })

    it('should be required when required prop is true', () => {
      render(<Input required />)
      const input = screen.getByRole('textbox')
      expect(input).toBeRequired()
    })

    it('should apply maxLength attribute', () => {
      render(<Input maxLength={10} />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('maxLength', '10')
    })

    it('should apply minLength attribute', () => {
      render(<Input minLength={5} />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('minLength', '5')
    })

    it('should apply pattern attribute', () => {
      render(<Input pattern="[0-9]*" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('pattern', '[0-9]*')
    })

    it('should apply readOnly attribute', () => {
      render(<Input readOnly />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('readOnly')
    })

    it('should apply autoComplete attribute', () => {
      render(<Input autoComplete="email" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('autoComplete', 'email')
    })

    it('should apply autoFocus attribute', () => {
      render(<Input autoFocus />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('autoFocus')
    })

    it('should apply id attribute', () => {
      render(<Input id="test-id" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('id', 'test-id')
    })

    it('should apply name attribute', () => {
      render(<Input name="test-name" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('name', 'test-name')
    })

    it('should apply aria-label attribute', () => {
      render(<Input aria-label="test label" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('aria-label', 'test label')
    })

    it('should apply aria-describedby attribute', () => {
      render(<Input aria-describedby="description" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('aria-describedby', 'description')
    })

    it('should apply data attributes', () => {
      render(<Input data-testid="custom-input" />)
      const input = screen.getByTestId('custom-input')
      expect(input).toBeInTheDocument()
    })
  })

  describe('edge cases', () => {
    it('should handle empty string value', () => {
      render(<Input value="" onChange={vi.fn()} />)
      const input = screen.getByRole('textbox') as HTMLInputElement
      expect(input.value).toBe('')
    })

    it('should handle null placeholder', () => {
      render(<Input placeholder={undefined} />)
      const input = screen.getByRole('textbox')
      expect(input).not.toHaveAttribute('placeholder')
    })

    it('should handle multiple className values', () => {
      render(<Input className="class1 class2 class3" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveClass('class1', 'class2', 'class3')
    })

    it('should not be disabled by default', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      expect(input).not.toBeDisabled()
    })

    it('should not be required by default', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      expect(input).not.toBeRequired()
    })
  })

  describe('form integration', () => {
    it('should work within a form', () => {
      const handleSubmit = vi.fn((e) => e.preventDefault())

      render(
        <form onSubmit={handleSubmit}>
          <Input name="test" />
          <button type="submit">Submit</button>
        </form>
      )

      const input = screen.getByRole('textbox') as HTMLInputElement
      const button = screen.getByRole('button')

      fireEvent.change(input, { target: { value: 'form value' } })
      fireEvent.click(button)

      expect(handleSubmit).toHaveBeenCalled()
      expect(input.value).toBe('form value')
    })

    it('should validate required field', () => {
      render(<Input required />)
      const input = screen.getByRole('textbox') as HTMLInputElement

      expect(input.validity.valid).toBe(false)

      fireEvent.change(input, { target: { value: 'valid' } })

      expect(input.validity.valid).toBe(true)
    })
  })

  describe('accessibility', () => {
    it('should be focusable', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')

      input.focus()

      expect(input).toHaveFocus()
    })

    it('should have proper role', () => {
      render(<Input />)
      const input = screen.getByRole('textbox')
      expect(input).toBeInTheDocument()
    })

    it('should support aria-invalid attribute', () => {
      render(<Input aria-invalid="true" />)
      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('aria-invalid', 'true')
    })

    it('should support aria-required attribute', () => {
      render(<Input required />)
      const input = screen.getByRole('textbox')
      expect(input).toBeRequired()
    })
  })
})
