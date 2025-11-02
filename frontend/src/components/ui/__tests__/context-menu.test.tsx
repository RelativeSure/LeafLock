import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  ContextMenu,
  ContextMenuTrigger,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuCheckboxItem,
  ContextMenuRadioItem,
  ContextMenuLabel,
  ContextMenuSeparator,
  ContextMenuShortcut,
  ContextMenuGroup,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuRadioGroup,
} from '../context-menu'

describe('ContextMenu', () => {
  it('should render trigger without crashing', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>
          <div>Right click me</div>
        </ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem>Item 1</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Right click me')).toBeInTheDocument()
  })

  it('should render menu items', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem>Item 1</ContextMenuItem>
          <ContextMenuItem>Item 2</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })

  it('should render separator', () => {
    const { container } = render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem>Item 1</ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem>Item 2</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(container.querySelector('[role="separator"]')).toBeInTheDocument()
  })

  it('should render label', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuLabel>My Label</ContextMenuLabel>
          <ContextMenuItem>Item 1</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })

  it('should render checkbox item', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuCheckboxItem checked>Checkbox Item</ContextMenuCheckboxItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })

  it('should render radio items', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuRadioGroup value="option1">
            <ContextMenuRadioItem value="option1">Option 1</ContextMenuRadioItem>
            <ContextMenuRadioItem value="option2">Option 2</ContextMenuRadioItem>
          </ContextMenuRadioGroup>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })

  it('should render submenu', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuSub>
            <ContextMenuSubTrigger>More Options</ContextMenuSubTrigger>
            <ContextMenuSubContent>
              <ContextMenuItem>Sub Item 1</ContextMenuItem>
            </ContextMenuSubContent>
          </ContextMenuSub>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })

  it('should render menu group', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuGroup>
            <ContextMenuItem>Group Item 1</ContextMenuItem>
            <ContextMenuItem>Group Item 2</ContextMenuItem>
          </ContextMenuGroup>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })

  it('should render shortcut', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem>
            Item <ContextMenuShortcut>⌘K</ContextMenuShortcut>
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(
      <ContextMenu>
        <ContextMenuTrigger className="custom-trigger">Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem className="custom-item">Item</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(container.querySelector('.custom-trigger')).toBeInTheDocument()
  })

  it('should render disabled items', () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>Trigger</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem disabled>Disabled Item</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    )

    expect(screen.getByText('Trigger')).toBeInTheDocument()
  })
})
