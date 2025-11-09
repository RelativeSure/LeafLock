import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import userEvent from '@testing-library/user-event'
import {
  Menubar,
  MenubarMenu,
  MenubarTrigger,
  MenubarContent,
  MenubarItem,
  MenubarSeparator,
  MenubarCheckboxItem,
  MenubarRadioGroup,
  MenubarRadioItem,
  MenubarSub,
  MenubarSubTrigger,
  MenubarSubContent,
  MenubarLabel,
  MenubarShortcut,
} from '../menubar'

describe('Menubar UI primitives', () => {
  it('renders nested primitives via the shared Radix context', async () => {
    const user = userEvent.setup()
    render(
      <Menubar data-testid="menubar">
        <MenubarMenu>
          <MenubarTrigger>File</MenubarTrigger>
          <MenubarContent forceMount>
            <MenubarItem>New Tab</MenubarItem>
            <MenubarSeparator />
            <MenubarCheckboxItem checked>Show Status Bar</MenubarCheckboxItem>
            <MenubarRadioGroup value="compact">
              <MenubarRadioItem value="compact">Compact Mode</MenubarRadioItem>
            </MenubarRadioGroup>
            <MenubarSub>
              <MenubarSubTrigger inset>Share</MenubarSubTrigger>
              <MenubarSubContent forceMount>
                <MenubarItem>Copy Link</MenubarItem>
              </MenubarSubContent>
            </MenubarSub>
            <MenubarLabel inset>Shortcuts</MenubarLabel>
            <MenubarShortcut>⌘N</MenubarShortcut>
          </MenubarContent>
        </MenubarMenu>
      </Menubar>
    )

    await user.click(screen.getByText('File'))

    expect(screen.getByTestId('menubar')).toBeInTheDocument()
    expect(screen.getByText('File')).toBeInTheDocument()
    expect(await screen.findByText('New Tab')).toBeInTheDocument()
    expect(screen.getByText('Show Status Bar')).toBeInTheDocument()
    expect(screen.getByText('Compact Mode')).toBeInTheDocument()
    expect(screen.getByText('Share')).toBeInTheDocument()
    await user.hover(screen.getByText('Share'))
    expect(await screen.findByText('Copy Link')).toBeInTheDocument()
    expect(screen.getByText('Shortcuts')).toBeInTheDocument()
    expect(screen.getByText('⌘N')).toBeInTheDocument()
  })

  it('honors custom class names on triggers and shortcuts', async () => {
    const user = userEvent.setup()
    render(
      <Menubar>
        <MenubarMenu>
          <MenubarTrigger className="custom-trigger">Edit</MenubarTrigger>
          <MenubarContent forceMount>
            <MenubarShortcut className="text-primary">⌘E</MenubarShortcut>
          </MenubarContent>
        </MenubarMenu>
      </Menubar>
    )

    await user.click(screen.getByText('Edit'))

    expect(screen.getByText('Edit')).toHaveClass('custom-trigger')
    expect(screen.getByText('⌘E')).toHaveClass('text-primary')
  })
})
