import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DashboardView } from '../dashboard-view'

// Mock user for localStorage
beforeEach(() => {
  localStorage.setItem('user', JSON.stringify({ id: 'test-user' }))
})

vi.mock('../note-editor', () => ({
  NoteEditor: () => <div data-testid="note-editor">Note Editor</div>,
}))

describe('DashboardView', () => {
  it('should render the dashboard container', () => {
    render(<DashboardView />)
    const container = document.querySelector('.h-full.w-full.flex.flex-col.bg-background')
    expect(container).toBeInTheDocument()
  })

  it('should render NoteEditor via Suspense', async () => {
    render(<DashboardView />)
    const editor = await screen.findByTestId('note-editor')
    expect(editor).toBeInTheDocument()
  })
})
