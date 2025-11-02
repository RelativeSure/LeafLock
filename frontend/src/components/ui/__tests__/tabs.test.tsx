import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../tabs'

describe('Tabs', () => {
  it('renders tabs component', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(screen.getByText('Tab 1')).toBeInTheDocument()
  })

  it('renders with default value', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )
    expect(screen.getByText('Content 1')).toBeVisible()
    expect(screen.queryByText('Content 2')).not.toBeInTheDocument()
  })

  it('switches content when tab is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )

    expect(screen.getByText('Content 1')).toBeVisible()

    const tab2 = screen.getByText('Tab 2')
    await user.click(tab2)

    expect(screen.getByText('Content 2')).toBeVisible()
    expect(screen.queryByText('Content 1')).not.toBeInTheDocument()
  })

  it('can be controlled with value prop', async () => {
    const user = userEvent.setup()
    const handleValueChange = vi.fn()
    const { rerender } = render(
      <Tabs value="tab1" onValueChange={handleValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )

    const tab2 = screen.getByText('Tab 2')
    await user.click(tab2)

    expect(handleValueChange).toHaveBeenCalledWith('tab2')

    rerender(
      <Tabs value="tab2" onValueChange={handleValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )

    expect(screen.getByText('Content 2')).toBeVisible()
  })

  it('calls onValueChange when tab changes', async () => {
    const user = userEvent.setup()
    const handleValueChange = vi.fn()
    render(
      <Tabs defaultValue="tab1" onValueChange={handleValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )

    const tab2 = screen.getByText('Tab 2')
    await user.click(tab2)

    expect(handleValueChange).toHaveBeenCalledWith('tab2')
  })

  it('renders multiple tabs', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          <TabsTrigger value="tab3">Tab 3</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
        <TabsContent value="tab3">Content 3</TabsContent>
      </Tabs>
    )
    expect(screen.getByText('Tab 1')).toBeInTheDocument()
    expect(screen.getByText('Tab 2')).toBeInTheDocument()
    expect(screen.getByText('Tab 3')).toBeInTheDocument()
  })

  it('applies custom className to tabs root', () => {
    const customClass = 'custom-tabs-class'
    const { container } = render(
      <Tabs defaultValue="tab1" className={customClass}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    const tabs = container.querySelector('[data-slot="tabs"]')
    expect(tabs).toHaveClass(customClass)
  })

  it('applies custom className to tabs list', () => {
    const customClass = 'custom-list-class'
    const { container } = render(
      <Tabs defaultValue="tab1">
        <TabsList className={customClass}>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    const list = container.querySelector('[data-slot="tabs-list"]')
    expect(list).toHaveClass(customClass)
  })

  it('applies custom className to tab trigger', () => {
    const customClass = 'custom-trigger-class'
    const { container } = render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1" className={customClass}>
            Tab 1
          </TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    const trigger = container.querySelector('[data-slot="tabs-trigger"]')
    expect(trigger).toHaveClass(customClass)
  })

  it('applies custom className to tab content', () => {
    const customClass = 'custom-content-class'
    const { container } = render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1" className={customClass}>
          Content 1
        </TabsContent>
      </Tabs>
    )
    const content = container.querySelector('[data-slot="tabs-content"]')
    expect(content).toHaveClass(customClass)
  })

  it('forwards ref to tabs root', () => {
    const ref = vi.fn()
    render(
      <Tabs ref={ref} defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to tabs list', () => {
    const ref = vi.fn()
    render(
      <Tabs defaultValue="tab1">
        <TabsList ref={ref}>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to tab trigger', () => {
    const ref = vi.fn()
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger ref={ref} value="tab1">
            Tab 1
          </TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to tab content', () => {
    const ref = vi.fn()
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent ref={ref} value="tab1">
          Content 1
        </TabsContent>
      </Tabs>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('handles keyboard navigation', async () => {
    const user = userEvent.setup()
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
          <TabsTrigger value="tab3">Tab 3</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
        <TabsContent value="tab3">Content 3</TabsContent>
      </Tabs>
    )

    const tab1 = screen.getByText('Tab 1')
    await user.click(tab1)
    expect(tab1).toHaveFocus()

    await user.keyboard('{ArrowRight}')
    expect(screen.getByText('Tab 2')).toHaveFocus()

    await user.keyboard('{ArrowRight}')
    expect(screen.getByText('Tab 3')).toHaveFocus()

    await user.keyboard('{ArrowLeft}')
    expect(screen.getByText('Tab 2')).toHaveFocus()
  })

  it('applies data-slot attributes', () => {
    const { container } = render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(container.querySelector('[data-slot="tabs"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="tabs-list"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="tabs-trigger"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="tabs-content"]')).toBeInTheDocument()
  })

  it('disables tab trigger when disabled prop is true', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2" disabled>
            Tab 2
          </TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )
    const tab2 = screen.getByText('Tab 2')
    expect(tab2).toBeDisabled()
  })

  it('does not switch to disabled tab when clicked', async () => {
    const user = userEvent.setup()
    const handleValueChange = vi.fn()
    render(
      <Tabs defaultValue="tab1" onValueChange={handleValueChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2" disabled>
            Tab 2
          </TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )

    const tab2 = screen.getByText('Tab 2')
    await user.click(tab2)

    expect(handleValueChange).not.toHaveBeenCalled()
    expect(screen.getByText('Content 1')).toBeVisible()
  })

  it('supports orientation prop', () => {
    const { container } = render(
      <Tabs defaultValue="tab1" orientation="vertical">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    const tabs = container.querySelector('[data-slot="tabs"]')
    expect(tabs).toHaveAttribute('data-orientation', 'vertical')
  })

  it('preserves additional props on tabs root', () => {
    render(
      <Tabs defaultValue="tab1" data-testid="custom-tabs">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(screen.getByTestId('custom-tabs')).toBeInTheDocument()
  })

  it('preserves additional props on tabs list', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList data-testid="custom-list">
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(screen.getByTestId('custom-list')).toBeInTheDocument()
  })

  it('preserves additional props on tab trigger', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1" data-testid="custom-trigger">
            Tab 1
          </TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('preserves additional props on tab content', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1" data-testid="custom-content">
          Content 1
        </TabsContent>
      </Tabs>
    )
    expect(screen.getByTestId('custom-content')).toBeInTheDocument()
  })

  it('applies proper styling classes', () => {
    const { container } = render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    const tabs = container.querySelector('[data-slot="tabs"]')
    expect(tabs).toHaveClass('flex', 'flex-col', 'gap-2')
  })

  it('applies proper list styling', () => {
    const { container } = render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
      </Tabs>
    )
    const list = container.querySelector('[data-slot="tabs-list"]')
    expect(list).toHaveClass('inline-flex', 'h-9', 'rounded-lg')
  })

  it('indicates active state on trigger', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content 1</TabsContent>
        <TabsContent value="tab2">Content 2</TabsContent>
      </Tabs>
    )
    const tab1 = screen.getByText('Tab 1')
    expect(tab1).toHaveAttribute('data-state', 'active')

    const tab2 = screen.getByText('Tab 2')
    expect(tab2).toHaveAttribute('data-state', 'inactive')
  })
})
