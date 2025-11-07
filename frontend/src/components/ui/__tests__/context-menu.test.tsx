import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import {
  ContextMenu,
  ContextMenuTrigger,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuCheckboxItem,
  ContextMenuRadioGroup,
  ContextMenuRadioItem,
  ContextMenuLabel,
  ContextMenuSeparator,
  ContextMenuShortcut,
  ContextMenuSub,
  ContextMenuSubTrigger,
  ContextMenuSubContent,
} from '../context-menu'

describe('ContextMenu component wrappers', () => {
  it('renders trigger, items, and submenus', async () => {
    render(
      <ContextMenu>
        <ContextMenuTrigger>
          <button>Open Menu</button>
        </ContextMenuTrigger>
        <ContextMenuContent forceMount>
          <ContextMenuLabel inset>Actions</ContextMenuLabel>
          <ContextMenuItem>Primary Action</ContextMenuItem>
          <ContextMenuCheckboxItem checked>Persistent toggle</ContextMenuCheckboxItem>
          <ContextMenuRadioGroup value="a" onValueChange={() => {}}>
            <ContextMenuRadioItem value="a">Choice A</ContextMenuRadioItem>
            <ContextMenuRadioItem value="b">Choice B</ContextMenuRadioItem>
          </ContextMenuRadioGroup>
          <ContextMenuSeparator />
          <ContextMenuSub>
            <ContextMenuSubTrigger inset>More</ContextMenuSubTrigger>
            <ContextMenuSubContent forceMount>
              <ContextMenuItem>
                Nested Item <ContextMenuShortcut>⌘N</ContextMenuShortcut>
              </ContextMenuItem>
            </ContextMenuSubContent>
          </ContextMenuSub>
        </ContextMenuContent>
      </ContextMenu>
    )

    fireEvent.contextMenu(screen.getByText('Open Menu'))
    expect(await screen.findByText('Primary Action')).toBeInTheDocument()
    expect(screen.getByText('Nested Item')).toBeInTheDocument()
  })
})
