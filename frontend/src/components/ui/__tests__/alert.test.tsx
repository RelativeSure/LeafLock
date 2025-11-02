import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Alert, AlertTitle, AlertDescription } from '../alert'

describe('Alert', () => {
  it('should render alert with title and description', () => {
    render(
      <Alert>
        <AlertTitle>Alert Title</AlertTitle>
        <AlertDescription>Alert description text</AlertDescription>
      </Alert>
    )

    expect(screen.getByText('Alert Title')).toBeInTheDocument()
    expect(screen.getByText('Alert description text')).toBeInTheDocument()
  })

  it('should render default variant', () => {
    const { container } = render(
      <Alert>
        <AlertTitle>Title</AlertTitle>
      </Alert>
    )
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render destructive variant', () => {
    const { container } = render(
      <Alert variant="destructive">
        <AlertTitle>Error</AlertTitle>
      </Alert>
    )
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(
      <Alert className="custom-alert">
        <AlertTitle>Title</AlertTitle>
      </Alert>
    )
    expect(container.querySelector('.custom-alert')).toBeInTheDocument()
  })

  it('should render alert without title', () => {
    render(
      <Alert>
        <AlertDescription>Just description</AlertDescription>
      </Alert>
    )
    expect(screen.getByText('Just description')).toBeInTheDocument()
  })

  it('should render alert without description', () => {
    render(
      <Alert>
        <AlertTitle>Just title</AlertTitle>
      </Alert>
    )
    expect(screen.getByText('Just title')).toBeInTheDocument()
  })

  it('should render with icon', () => {
    render(
      <Alert>
        <span>ℹ️</span>
        <AlertTitle>Info</AlertTitle>
        <AlertDescription>Information message</AlertDescription>
      </Alert>
    )
    expect(screen.getByText('ℹ️')).toBeInTheDocument()
  })
})
