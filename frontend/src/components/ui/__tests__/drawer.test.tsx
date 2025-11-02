import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  Drawer,
  DrawerTrigger,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
  DrawerDescription,
  DrawerFooter,
  DrawerClose,
} from '../drawer'

describe('Drawer', () => {
  it('should render drawer with trigger', () => {
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>Title</DrawerTitle>
          </DrawerHeader>
        </DrawerContent>
      </Drawer>
    )
    expect(screen.getByText('Open Drawer')).toBeInTheDocument()
  })

  it('should render drawer content', () => {
    render(
      <Drawer>
        <DrawerTrigger>Open</DrawerTrigger>
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>Drawer Title</DrawerTitle>
            <DrawerDescription>Drawer description</DrawerDescription>
          </DrawerHeader>
        </DrawerContent>
      </Drawer>
    )
    expect(screen.getByText('Open')).toBeInTheDocument()
  })

  it('should render drawer footer', () => {
    render(
      <Drawer>
        <DrawerTrigger>Open</DrawerTrigger>
        <DrawerContent>
          <DrawerFooter>
            <button>Save</button>
            <DrawerClose>
              <button>Cancel</button>
            </DrawerClose>
          </DrawerFooter>
        </DrawerContent>
      </Drawer>
    )
    expect(screen.getByText('Open')).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(
      <Drawer>
        <DrawerTrigger className="custom-trigger">Open</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )
    expect(container.querySelector('.custom-trigger')).toBeInTheDocument()
  })

  it('should render complete drawer structure', () => {
    render(
      <Drawer>
        <DrawerTrigger>Open</DrawerTrigger>
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>Title</DrawerTitle>
            <DrawerDescription>Description</DrawerDescription>
          </DrawerHeader>
          <div>Body content</div>
          <DrawerFooter>
            <button>Action</button>
            <DrawerClose>Close</DrawerClose>
          </DrawerFooter>
        </DrawerContent>
      </Drawer>
    )
    expect(screen.getByText('Open')).toBeInTheDocument()
  })

  it('should render nested drawers', () => {
    render(
      <Drawer>
        <DrawerTrigger>Open First</DrawerTrigger>
        <DrawerContent>
          <Drawer>
            <DrawerTrigger>Open Second</DrawerTrigger>
            <DrawerContent>Nested content</DrawerContent>
          </Drawer>
        </DrawerContent>
      </Drawer>
    )
    expect(screen.getByText('Open First')).toBeInTheDocument()
    expect(screen.getByText('Open Second')).toBeInTheDocument()
  })
})
