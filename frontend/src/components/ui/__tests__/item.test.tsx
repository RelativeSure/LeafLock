import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  ItemGroup,
  Item,
  ItemMedia,
  ItemTitle,
  ItemDescription,
  ItemActions,
  ItemSeparator,
} from '../item'

describe('Item Components', () => {
  it('should render ItemGroup', () => {
    render(
      <ItemGroup>
        <Item>
          <ItemTitle>Test Item</ItemTitle>
        </Item>
      </ItemGroup>
    )
    expect(screen.getByText('Test Item')).toBeInTheDocument()
  })

  it('should render Item with title', () => {
    render(
      <Item>
        <ItemTitle>My Title</ItemTitle>
      </Item>
    )
    expect(screen.getByText('My Title')).toBeInTheDocument()
  })

  it('should render Item with description', () => {
    render(
      <Item>
        <ItemTitle>Title</ItemTitle>
        <ItemDescription>Description text</ItemDescription>
      </Item>
    )
    expect(screen.getByText('Description text')).toBeInTheDocument()
  })

  it('should render Item with media content', () => {
    render(
      <Item>
        <ItemMedia>🔥</ItemMedia>
        <ItemTitle>Title</ItemTitle>
      </Item>
    )
    expect(screen.getByText('🔥')).toBeInTheDocument()
  })

  it('should render Item with action', () => {
    render(
      <Item>
        <ItemTitle>Title</ItemTitle>
        <ItemActions>
          <button>Action</button>
        </ItemActions>
      </Item>
    )
    expect(screen.getByRole('button')).toBeInTheDocument()
  })

  it('should render ItemSeparator', () => {
    const { container } = render(
      <ItemGroup>
        <Item>
          <ItemTitle>Item 1</ItemTitle>
        </Item>
        <ItemSeparator />
        <Item>
          <ItemTitle>Item 2</ItemTitle>
        </Item>
      </ItemGroup>
    )
    expect(container.querySelector('[data-slot="item-separator"]')).toBeInTheDocument()
  })

  it('should apply custom className', () => {
    const { container } = render(
      <Item className="custom-class">
        <ItemTitle>Title</ItemTitle>
      </Item>
    )
    expect(container.querySelector('.custom-class')).toBeInTheDocument()
  })

  it('should render multiple items', () => {
    render(
      <ItemGroup>
        <Item>
          <ItemTitle>Item 1</ItemTitle>
        </Item>
        <Item>
          <ItemTitle>Item 2</ItemTitle>
        </Item>
        <Item>
          <ItemTitle>Item 3</ItemTitle>
        </Item>
      </ItemGroup>
    )
    expect(screen.getByText('Item 1')).toBeInTheDocument()
    expect(screen.getByText('Item 2')).toBeInTheDocument()
    expect(screen.getByText('Item 3')).toBeInTheDocument()
  })
})
