import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Popover, PopoverTrigger, PopoverContent } from '../popover'

describe('Popover', () => {
  it('should render popover trigger', () => {
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Popover Content</PopoverContent>
      </Popover>
    )

    expect(screen.getByText('Open Popover')).toBeInTheDocument()
  })

  it('should render popover with content', () => {
    render(
      <Popover defaultOpen={true}>
        <PopoverTrigger>Trigger</PopoverTrigger>
        <PopoverContent>Content inside popover</PopoverContent>
      </Popover>
    )

    expect(screen.getByText('Content inside popover')).toBeInTheDocument()
  })

  it('should apply custom className to content', () => {
    render(
      <Popover defaultOpen={true}>
        <PopoverTrigger>Trigger</PopoverTrigger>
        <PopoverContent className="custom-popover">Content</PopoverContent>
      </Popover>
    )

    const content = screen.getByText('Content')
    expect(content).toHaveClass('custom-popover')
  })
})
