import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
} from '../table'

describe('Table', () => {
  it('renders table component', () => {
    render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(screen.getByText('Cell')).toBeInTheDocument()
  })

  it('renders with table header', () => {
    render(
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Header</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(screen.getByText('Header')).toBeInTheDocument()
  })

  it('renders with table footer', () => {
    render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
        <TableFooter>
          <TableRow>
            <TableCell>Footer</TableCell>
          </TableRow>
        </TableFooter>
      </Table>
    )
    expect(screen.getByText('Footer')).toBeInTheDocument()
  })

  it('renders with caption', () => {
    render(
      <Table>
        <TableCaption>Table Caption</TableCaption>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(screen.getByText('Table Caption')).toBeInTheDocument()
  })

  it('renders complete table structure', () => {
    render(
      <Table>
        <TableCaption>A list of items</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Email</TableHead>
            <TableHead>Role</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>John Doe</TableCell>
            <TableCell>john@example.com</TableCell>
            <TableCell>Admin</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Jane Smith</TableCell>
            <TableCell>jane@example.com</TableCell>
            <TableCell>User</TableCell>
          </TableRow>
        </TableBody>
        <TableFooter>
          <TableRow>
            <TableCell colSpan={3}>Total: 2 users</TableCell>
          </TableRow>
        </TableFooter>
      </Table>
    )

    expect(screen.getByText('A list of items')).toBeInTheDocument()
    expect(screen.getByText('Name')).toBeInTheDocument()
    expect(screen.getByText('Email')).toBeInTheDocument()
    expect(screen.getByText('Role')).toBeInTheDocument()
    expect(screen.getByText('John Doe')).toBeInTheDocument()
    expect(screen.getByText('Jane Smith')).toBeInTheDocument()
    expect(screen.getByText('Total: 2 users')).toBeInTheDocument()
  })

  it('applies custom className to table', () => {
    const customClass = 'custom-table-class'
    const { container } = render(
      <Table className={customClass}>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const table = container.querySelector('[data-slot="table"]')
    expect(table).toHaveClass(customClass)
  })

  it('applies custom className to table header', () => {
    const customClass = 'custom-header-class'
    const { container } = render(
      <Table>
        <TableHeader className={customClass}>
          <TableRow>
            <TableHead>Header</TableHead>
          </TableRow>
        </TableHeader>
      </Table>
    )
    const header = container.querySelector('[data-slot="table-header"]')
    expect(header).toHaveClass(customClass)
  })

  it('applies custom className to table body', () => {
    const customClass = 'custom-body-class'
    const { container } = render(
      <Table>
        <TableBody className={customClass}>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const body = container.querySelector('[data-slot="table-body"]')
    expect(body).toHaveClass(customClass)
  })

  it('applies custom className to table footer', () => {
    const customClass = 'custom-footer-class'
    const { container } = render(
      <Table>
        <TableFooter className={customClass}>
          <TableRow>
            <TableCell>Footer</TableCell>
          </TableRow>
        </TableFooter>
      </Table>
    )
    const footer = container.querySelector('[data-slot="table-footer"]')
    expect(footer).toHaveClass(customClass)
  })

  it('applies custom className to table row', () => {
    const customClass = 'custom-row-class'
    const { container } = render(
      <Table>
        <TableBody>
          <TableRow className={customClass}>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const row = container.querySelector('[data-slot="table-row"]')
    expect(row).toHaveClass(customClass)
  })

  it('applies custom className to table head', () => {
    const customClass = 'custom-head-class'
    const { container } = render(
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className={customClass}>Header</TableHead>
          </TableRow>
        </TableHeader>
      </Table>
    )
    const head = container.querySelector('[data-slot="table-head"]')
    expect(head).toHaveClass(customClass)
  })

  it('applies custom className to table cell', () => {
    const customClass = 'custom-cell-class'
    const { container } = render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell className={customClass}>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const cell = container.querySelector('[data-slot="table-cell"]')
    expect(cell).toHaveClass(customClass)
  })

  it('applies custom className to table caption', () => {
    const customClass = 'custom-caption-class'
    const { container } = render(
      <Table>
        <TableCaption className={customClass}>Caption</TableCaption>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const caption = container.querySelector('[data-slot="table-caption"]')
    expect(caption).toHaveClass(customClass)
  })

  it('forwards ref to table', () => {
    const ref = vi.fn()
    render(
      <Table ref={ref}>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to table header', () => {
    const ref = vi.fn()
    render(
      <Table>
        <TableHeader ref={ref}>
          <TableRow>
            <TableHead>Header</TableHead>
          </TableRow>
        </TableHeader>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to table body', () => {
    const ref = vi.fn()
    render(
      <Table>
        <TableBody ref={ref}>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to table footer', () => {
    const ref = vi.fn()
    render(
      <Table>
        <TableFooter ref={ref}>
          <TableRow>
            <TableCell>Footer</TableCell>
          </TableRow>
        </TableFooter>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to table row', () => {
    const ref = vi.fn()
    render(
      <Table>
        <TableBody>
          <TableRow ref={ref}>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to table head', () => {
    const ref = vi.fn()
    render(
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead ref={ref}>Header</TableHead>
          </TableRow>
        </TableHeader>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to table cell', () => {
    const ref = vi.fn()
    render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell ref={ref}>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to table caption', () => {
    const ref = vi.fn()
    render(
      <Table>
        <TableCaption ref={ref}>Caption</TableCaption>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('applies data-slot attributes', () => {
    const { container } = render(
      <Table>
        <TableCaption>Caption</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>Header</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
        <TableFooter>
          <TableRow>
            <TableCell>Footer</TableCell>
          </TableRow>
        </TableFooter>
      </Table>
    )

    expect(container.querySelector('[data-slot="table-container"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table-caption"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table-header"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table-body"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table-footer"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table-row"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table-head"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="table-cell"]')).toBeInTheDocument()
  })

  it('renders table with multiple columns', () => {
    render(
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Col 1</TableHead>
            <TableHead>Col 2</TableHead>
            <TableHead>Col 3</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>A1</TableCell>
            <TableCell>A2</TableCell>
            <TableCell>A3</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )

    expect(screen.getByText('Col 1')).toBeInTheDocument()
    expect(screen.getByText('Col 2')).toBeInTheDocument()
    expect(screen.getByText('Col 3')).toBeInTheDocument()
    expect(screen.getByText('A1')).toBeInTheDocument()
    expect(screen.getByText('A2')).toBeInTheDocument()
    expect(screen.getByText('A3')).toBeInTheDocument()
  })

  it('renders table with multiple rows', () => {
    render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>Row 1</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Row 2</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Row 3</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )

    expect(screen.getByText('Row 1')).toBeInTheDocument()
    expect(screen.getByText('Row 2')).toBeInTheDocument()
    expect(screen.getByText('Row 3')).toBeInTheDocument()
  })

  it('supports colSpan on cells', () => {
    render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell colSpan={3}>Spanning Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )

    const cell = screen.getByText('Spanning Cell')
    expect(cell).toHaveAttribute('colSpan', '3')
  })

  it('supports rowSpan on cells', () => {
    render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell rowSpan={2}>Spanning Cell</TableCell>
            <TableCell>Cell 2</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Cell 3</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )

    const cell = screen.getByText('Spanning Cell')
    expect(cell).toHaveAttribute('rowSpan', '2')
  })

  it('preserves additional props on table', () => {
    render(
      <Table data-testid="custom-table">
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    expect(screen.getByTestId('custom-table')).toBeInTheDocument()
  })

  it('preserves additional props on table header', () => {
    const { container } = render(
      <Table>
        <TableHeader data-testid="custom-header">
          <TableRow>
            <TableHead>Header</TableHead>
          </TableRow>
        </TableHeader>
      </Table>
    )
    expect(container.querySelector('[data-testid="custom-header"]')).toBeInTheDocument()
  })

  it('has proper display names', () => {
    expect(Table.displayName).toBe('Table')
    expect(TableHeader.displayName).toBe('TableHeader')
    expect(TableBody.displayName).toBe('TableBody')
    expect(TableFooter.displayName).toBe('TableFooter')
    expect(TableRow.displayName).toBe('TableRow')
    expect(TableHead.displayName).toBe('TableHead')
    expect(TableCell.displayName).toBe('TableCell')
    expect(TableCaption.displayName).toBe('TableCaption')
  })

  it('renders table container with overflow handling', () => {
    const { container } = render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const tableContainer = container.querySelector('[data-slot="table-container"]')
    expect(tableContainer).toHaveClass('overflow-x-auto', 'w-full', 'relative')
  })

  it('applies animation classes to table container', () => {
    const { container } = render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>Cell</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const tableContainer = container.querySelector('[data-slot="table-container"]')
    expect(tableContainer).toHaveClass('animate-in', 'fade-in-50', 'duration-300')
  })

  it('supports data-state attribute on rows', () => {
    const { container } = render(
      <Table>
        <TableBody>
          <TableRow data-state="selected">
            <TableCell>Selected Row</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const row = container.querySelector('[data-state="selected"]')
    expect(row).toBeInTheDocument()
  })

  it('renders table with alignment classes', () => {
    const { container } = render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>Left aligned</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const cell = container.querySelector('[data-slot="table-cell"]')
    expect(cell).toHaveClass('align-middle')
  })

  it('renders table head with proper styling', () => {
    const { container } = render(
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Header</TableHead>
          </TableRow>
        </TableHeader>
      </Table>
    )
    const head = container.querySelector('[data-slot="table-head"]')
    expect(head).toHaveClass('font-medium', 'text-left')
  })
})
