import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render } from '@testing-library/react'
import { TemplatesPage } from '../templates-page'
import { useTemplatesStore } from '@/stores/templatesStore'

vi.mock('@/stores/templatesStore', () => ({
  useTemplatesStore: vi.fn(),
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

describe('TemplatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)
  })

  it('should render templates page', () => {
    const { getByTestId } = render(<TemplatesPage />)
    expect(getByTestId('card')).toBeInTheDocument()
  })

  it('should render with templates', () => {
    const mockTemplates = [
      {
        id: 'template-1',
        name: 'Meeting Notes',
        content: 'Template content',
        userId: '123',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    const { getByTestId } = render(<TemplatesPage />)
    expect(getByTestId('card')).toBeInTheDocument()
  })

  it('should render loading state', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      isLoading: true,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    const { getByTestId } = render(<TemplatesPage />)
    expect(getByTestId('card')).toBeInTheDocument()
  })
})
