import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from '../collapsible'

describe('Collapsible', () => {
  it('renders collapsible root component', () => {
    render(
      <Collapsible>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    expect(screen.getByText('Toggle')).toBeInTheDocument()
  })

  it('renders with closed state by default', () => {
    render(
      <Collapsible>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Hidden Content</CollapsibleContent>
      </Collapsible>
    )
    const content = screen.queryByText('Hidden Content')
    expect(content).not.toBeVisible()
  })

  it('renders with open state when defaultOpen is true', () => {
    render(
      <Collapsible defaultOpen>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Visible Content</CollapsibleContent>
      </Collapsible>
    )
    expect(screen.getByText('Visible Content')).toBeVisible()
  })

  it('toggles content visibility when trigger is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Collapsible>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Toggleable Content</CollapsibleContent>
      </Collapsible>
    )

    const trigger = screen.getByText('Toggle')
    const content = screen.getByText('Toggleable Content')

    expect(content).not.toBeVisible()

    await user.click(trigger)
    expect(content).toBeVisible()

    await user.click(trigger)
    expect(content).not.toBeVisible()
  })

  it('can be controlled with open prop', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <Collapsible open={false} onOpenChange={handleOpenChange}>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Controlled Content</CollapsibleContent>
      </Collapsible>
    )

    const trigger = screen.getByText('Toggle')
    const content = screen.getByText('Controlled Content')

    expect(content).not.toBeVisible()

    await user.click(trigger)
    expect(handleOpenChange).toHaveBeenCalledWith(true)

    rerender(
      <Collapsible open={true} onOpenChange={handleOpenChange}>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Controlled Content</CollapsibleContent>
      </Collapsible>
    )

    expect(content).toBeVisible()
  })

  it('calls onOpenChange when state changes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Collapsible onOpenChange={handleOpenChange}>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )

    const trigger = screen.getByText('Toggle')
    await user.click(trigger)

    expect(handleOpenChange).toHaveBeenCalledWith(true)
  })

  it('supports disabled state', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Collapsible disabled onOpenChange={handleOpenChange}>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )

    const trigger = screen.getByText('Toggle')
    await user.click(trigger)

    expect(handleOpenChange).not.toHaveBeenCalled()
  })

  it('forwards ref to root element', () => {
    const ref = vi.fn()
    render(
      <Collapsible ref={ref}>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('applies data-slot attribute to root', () => {
    const { container } = render(
      <Collapsible>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    const root = container.querySelector('[data-slot="collapsible"]')
    expect(root).toBeInTheDocument()
  })

  it('applies data-slot attribute to trigger', () => {
    const { container } = render(
      <Collapsible>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    const trigger = container.querySelector('[data-slot="collapsible-trigger"]')
    expect(trigger).toBeInTheDocument()
  })

  it('applies data-slot attribute to content', () => {
    const { container } = render(
      <Collapsible defaultOpen>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    const content = container.querySelector('[data-slot="collapsible-content"]')
    expect(content).toBeInTheDocument()
  })

  it('can nest multiple collapsible components', async () => {
    const user = userEvent.setup()
    render(
      <Collapsible>
        <CollapsibleTrigger>Parent Toggle</CollapsibleTrigger>
        <CollapsibleContent>
          <div>Parent Content</div>
          <Collapsible>
            <CollapsibleTrigger>Child Toggle</CollapsibleTrigger>
            <CollapsibleContent>Child Content</CollapsibleContent>
          </Collapsible>
        </CollapsibleContent>
      </Collapsible>
    )

    const parentTrigger = screen.getByText('Parent Toggle')
    await user.click(parentTrigger)

    expect(screen.getByText('Parent Content')).toBeVisible()
    expect(screen.getByText('Child Content')).not.toBeVisible()

    const childTrigger = screen.getByText('Child Toggle')
    await user.click(childTrigger)

    expect(screen.getByText('Child Content')).toBeVisible()
  })

  it('handles keyboard navigation', async () => {
    const user = userEvent.setup()
    render(
      <Collapsible>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )

    const trigger = screen.getByText('Toggle')
    trigger.focus()
    expect(trigger).toHaveFocus()

    await user.keyboard('{Enter}')
    expect(screen.getByText('Content')).toBeVisible()

    await user.keyboard('{Enter}')
    expect(screen.getByText('Content')).not.toBeVisible()
  })

  it('supports custom className on trigger', () => {
    render(
      <Collapsible>
        <CollapsibleTrigger className="custom-trigger">Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    const trigger = screen.getByText('Toggle')
    expect(trigger).toHaveClass('custom-trigger')
  })

  it('supports custom className on content', () => {
    render(
      <Collapsible defaultOpen>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent className="custom-content">Content</CollapsibleContent>
      </Collapsible>
    )
    const content = screen.getByText('Content')
    expect(content).toHaveClass('custom-content')
  })

  it('preserves additional props on root', () => {
    render(
      <Collapsible data-testid="collapsible-root">
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    expect(screen.getByTestId('collapsible-root')).toBeInTheDocument()
  })

  it('preserves additional props on trigger', () => {
    render(
      <Collapsible>
        <CollapsibleTrigger data-testid="trigger">Toggle</CollapsibleTrigger>
        <CollapsibleContent>Content</CollapsibleContent>
      </Collapsible>
    )
    expect(screen.getByTestId('trigger')).toBeInTheDocument()
  })

  it('preserves additional props on content', () => {
    render(
      <Collapsible defaultOpen>
        <CollapsibleTrigger>Toggle</CollapsibleTrigger>
        <CollapsibleContent data-testid="content">Content</CollapsibleContent>
      </Collapsible>
    )
    expect(screen.getByTestId('content')).toBeInTheDocument()
  })
})
