import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  Sheet,
  SheetTrigger,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
  SheetClose,
} from '../sheet'

describe('Sheet', () => {
  it('should render sheet trigger', () => {
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Sheet Title</SheetTitle>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    )

    expect(screen.getByText('Open Sheet')).toBeInTheDocument()
  })

  it('should render sheet with full structure', () => {
    render(
      <Sheet defaultOpen={true}>
        <SheetTrigger>Trigger</SheetTrigger>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Title</SheetTitle>
            <SheetDescription>Description</SheetDescription>
          </SheetHeader>
          <div>Body content</div>
          <SheetFooter>
            <SheetClose>Close</SheetClose>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    )

    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Description')).toBeInTheDocument()
    expect(screen.getByText('Body content')).toBeInTheDocument()
    expect(screen.getByText('Close')).toBeInTheDocument()
  })

  it('should support different sides', () => {
    const { rerender } = render(
      <Sheet defaultOpen={true}>
        <SheetContent side="right">Content</SheetContent>
      </Sheet>
    )

    expect(screen.getByText('Content')).toBeInTheDocument()

    rerender(
      <Sheet defaultOpen={true}>
        <SheetContent side="left">Content Left</SheetContent>
      </Sheet>
    )

    expect(screen.getByText('Content Left')).toBeInTheDocument()
  })
})
