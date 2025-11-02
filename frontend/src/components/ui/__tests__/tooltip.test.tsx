import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '../tooltip'

describe('Tooltip', () => {
  it('should render tooltip trigger', () => {
    render(
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger>Hover me</TooltipTrigger>
          <TooltipContent>Tooltip text</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )

    expect(screen.getByText('Hover me')).toBeInTheDocument()
  })

  it('should render tooltip with content', () => {
    render(
      <TooltipProvider>
        <Tooltip defaultOpen={true}>
          <TooltipTrigger>Trigger</TooltipTrigger>
          <TooltipContent>Helpful tooltip</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )

    expect(screen.getByText('Helpful tooltip')).toBeInTheDocument()
  })

  it('should support custom sideOffset', () => {
    render(
      <TooltipProvider>
        <Tooltip defaultOpen={true}>
          <TooltipTrigger>Trigger</TooltipTrigger>
          <TooltipContent sideOffset={10}>Content</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )

    expect(screen.getByText('Content')).toBeInTheDocument()
  })
})
