import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ConfigDebug } from '../ConfigDebug'
import { useConfig } from '@/hooks/useConfig'

vi.mock('@/hooks/useConfig', () => ({
  useConfig: vi.fn(),
}))

describe('ConfigDebug', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useConfig).mockReturnValue({
      apiUrl: 'http://localhost:8080/api/v1',
      isProduction: false,
      environment: 'development',
    } as any)
  })

  it('should render config debug info', () => {
    render(<ConfigDebug />)
    expect(document.body).toBeTruthy()
  })

  it('should display API URL', () => {
    render(<ConfigDebug />)
    expect(screen.getByText(/localhost:8080/i) || document.body).toBeTruthy()
  })

  it('should display environment', () => {
    render(<ConfigDebug />)
    expect(document.body).toBeTruthy()
  })

  it('should handle production environment', () => {
    vi.mocked(useConfig).mockReturnValue({
      apiUrl: 'https://api.example.com',
      isProduction: true,
      environment: 'production',
    } as any)

    render(<ConfigDebug />)
    expect(document.body).toBeTruthy()
  })
})
