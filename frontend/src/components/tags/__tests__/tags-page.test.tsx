import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render } from '@testing-library/react'
import { TagsPage } from '../tags-page'
import { useNotesStore } from '@/stores/notesStore'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
}))

vi.mock('@/components/ui/input', () => ({
  Input: (props: any) => <input {...props} />,
}))

describe('TagsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useNotesStore).mockReturnValue({
      tags: [],
      notes: [],
      createTag: vi.fn(),
      deleteTag: vi.fn(),
      filterByTag: vi.fn(() => []),
    } as any)
  })

  it('should render tags page', () => {
    const { getByTestId } = render(<TagsPage />)
    expect(getByTestId('card')).toBeInTheDocument()
  })

  it('should render with tags', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        userId: '123',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: vi.fn(),
      deleteTag: vi.fn(),
      filterByTag: vi.fn(() => []),
    } as any)

    const { getByTestId } = render(<TagsPage />)
    expect(getByTestId('card')).toBeInTheDocument()
  })

  it('should render empty state', () => {
    const { getByTestId } = render(<TagsPage />)
    expect(getByTestId('card')).toBeInTheDocument()
  })
})
