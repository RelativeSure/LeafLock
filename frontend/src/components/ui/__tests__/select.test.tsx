import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Select,
  SelectTrigger,
  SelectContent,
  SelectItem,
  SelectValue,
  SelectGroup,
  SelectLabel,
  SelectSeparator,
} from '../select'

describe('Select', () => {
  it('renders select trigger', () => {
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    expect(screen.getByText('Select option')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    expect(screen.queryByText('Option 1')).not.toBeInTheDocument()
  })

  it('shows content when trigger is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Option 1')).toBeInTheDocument()
      expect(screen.getByText('Option 2')).toBeInTheDocument()
    })
  })

  it('selects an option when clicked', async () => {
    const user = userEvent.setup()
    const handleValueChange = vi.fn()
    render(
      <Select onValueChange={handleValueChange}>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Option 1')).toBeInTheDocument()
    })

    const option1 = screen.getByText('Option 1')
    await user.click(option1)

    expect(handleValueChange).toHaveBeenCalledWith('option1')
  })

  it('can be controlled with value prop', async () => {
    const user = userEvent.setup()
    const handleValueChange = vi.fn()
    const { rerender } = render(
      <Select value="option1" onValueChange={handleValueChange}>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Option 2')).toBeInTheDocument()
    })

    const option2 = screen.getByText('Option 2')
    await user.click(option2)

    expect(handleValueChange).toHaveBeenCalledWith('option2')

    rerender(
      <Select value="option2" onValueChange={handleValueChange}>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(trigger).toHaveTextContent('Option 2')
  })

  it('renders with defaultValue prop', () => {
    render(
      <Select defaultValue="option2">
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    expect(trigger).toHaveTextContent('Option 2')
  })

  it('renders select with groups', async () => {
    const user = userEvent.setup()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectLabel>Group 1</SelectLabel>
            <SelectItem value="option1">Option 1</SelectItem>
            <SelectItem value="option2">Option 2</SelectItem>
          </SelectGroup>
          <SelectSeparator />
          <SelectGroup>
            <SelectLabel>Group 2</SelectLabel>
            <SelectItem value="option3">Option 3</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Group 1')).toBeInTheDocument()
      expect(screen.getByText('Group 2')).toBeInTheDocument()
      expect(screen.getByText('Option 1')).toBeInTheDocument()
      expect(screen.getByText('Option 3')).toBeInTheDocument()
    })
  })

  it('applies custom className to trigger', () => {
    const customClass = 'custom-trigger-class'
    render(
      <Select>
        <SelectTrigger className={customClass}>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    const trigger = screen.getByRole('combobox')
    expect(trigger).toHaveClass(customClass)
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-content-class'
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent className={customClass}>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Option 1').closest('[role="listbox"]')
      expect(content).toHaveClass(customClass)
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <Select>
        <SelectTrigger ref={ref}>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent ref={ref}>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('forwards ref to item', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem ref={ref} value="option1">
            Option 1
          </SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('disables select when disabled prop is true', () => {
    render(
      <Select disabled>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    const trigger = screen.getByRole('combobox')
    expect(trigger).toBeDisabled()
  })

  it('does not open when disabled', async () => {
    const user = userEvent.setup()
    render(
      <Select disabled>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    expect(screen.queryByText('Option 1')).not.toBeInTheDocument()
  })

  it('disables individual items when disabled prop is true', async () => {
    const user = userEvent.setup()
    const handleValueChange = vi.fn()
    render(
      <Select onValueChange={handleValueChange}>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2" disabled>
            Option 2
          </SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Option 2')).toBeInTheDocument()
    })

    const option2 = screen.getByText('Option 2')
    expect(option2.closest('[role="option"]')).toHaveAttribute('aria-disabled', 'true')
  })

  it('calls onOpenChange when select opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Select onOpenChange={handleOpenChange}>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })
  })

  it('renders check icon on selected item', async () => {
    const user = userEvent.setup()
    render(
      <Select defaultValue="option1">
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      const option1 = screen.getByRole('option', { name: 'Option 1' })
      expect(option1).toHaveAttribute('data-state', 'checked')
    })
  })

  it('supports keyboard navigation', async () => {
    const user = userEvent.setup()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
          <SelectItem value="option3">Option 3</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    trigger.focus()
    expect(trigger).toHaveFocus()

    await user.keyboard('{Enter}')

    await waitFor(() => {
      expect(screen.getByText('Option 1')).toBeInTheDocument()
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <Select>
        <SelectTrigger data-testid="custom-trigger">
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('preserves additional props on item', async () => {
    const user = userEvent.setup()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1" data-testid="custom-item">
            Option 1
          </SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('custom-item')).toBeInTheDocument()
    })
  })

  it('renders chevron icon in trigger', () => {
    const { container } = render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    const chevron = container.querySelector('.lucide-chevron-down')
    expect(chevron).toBeInTheDocument()
  })

  it('supports position prop on content', async () => {
    const user = userEvent.setup()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent position="popper">
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Option 1')).toBeInTheDocument()
    })
  })

  it('renders multiple select options', async () => {
    const user = userEvent.setup()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
          <SelectItem value="option3">Option 3</SelectItem>
          <SelectItem value="option4">Option 4</SelectItem>
          <SelectItem value="option5">Option 5</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Option 1')).toBeInTheDocument()
      expect(screen.getByText('Option 2')).toBeInTheDocument()
      expect(screen.getByText('Option 3')).toBeInTheDocument()
      expect(screen.getByText('Option 4')).toBeInTheDocument()
      expect(screen.getByText('Option 5')).toBeInTheDocument()
    })
  })

  it('applies proper styling to trigger', () => {
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )
    const trigger = screen.getByRole('combobox')
    expect(trigger).toHaveClass('rounded-md', 'border')
  })

  it('closes content after selection', async () => {
    const user = userEvent.setup()
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByRole('combobox')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Option 1')).toBeInTheDocument()
    })

    const option = screen.getByText('Option 1')
    await user.click(option)

    await waitFor(() => {
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
    })
  })
})
