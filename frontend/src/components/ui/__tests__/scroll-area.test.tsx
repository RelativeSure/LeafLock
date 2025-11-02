import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ScrollArea, ScrollBar } from '../scroll-area'

describe('ScrollArea', () => {
  it('should render children', () => {
    render(
      <ScrollArea>
        <div>Scrollable Content</div>
      </ScrollArea>
    )

    expect(screen.getByText('Scrollable Content')).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(
      <ScrollArea className="custom-scroll">
        <div>Content</div>
      </ScrollArea>
    )

    expect(container.querySelector('.custom-scroll')).toBeInTheDocument()
  })

  it('should render with custom height', () => {
    const { container } = render(
      <ScrollArea className="h-[200px]">
        <div>Content</div>
      </ScrollArea>
    )

    expect(container.querySelector('.h-\\[200px\\]')).toBeInTheDocument()
  })

  it('should render with ScrollBar', () => {
    render(
      <ScrollArea>
        <div>Content</div>
        <ScrollBar orientation="vertical" />
      </ScrollArea>
    )

    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('should render horizontal ScrollBar', () => {
    render(
      <ScrollArea>
        <div>Content</div>
        <ScrollBar orientation="horizontal" />
      </ScrollArea>
    )

    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('should render both vertical and horizontal scrollbars', () => {
    render(
      <ScrollArea>
        <div>Content</div>
        <ScrollBar orientation="vertical" />
        <ScrollBar orientation="horizontal" />
      </ScrollArea>
    )

    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('should handle large content', () => {
    render(
      <ScrollArea className="h-[100px]">
        <div style={{ height: '500px' }}>Large Content</div>
      </ScrollArea>
    )

    expect(screen.getByText('Large Content')).toBeInTheDocument()
  })

  it('should render with complex children', () => {
    render(
      <ScrollArea>
        <div>
          <h1>Title</h1>
          <p>Paragraph 1</p>
          <p>Paragraph 2</p>
          <ul>
            <li>Item 1</li>
            <li>Item 2</li>
          </ul>
        </div>
      </ScrollArea>
    )

    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Paragraph 1')).toBeInTheDocument()
    expect(screen.getByText('Item 1')).toBeInTheDocument()
  })
})
