import { describe, it, expect, vi } from 'vitest'
import { useToast } from '../use-toast'
import { toast as sonnerToast } from 'sonner'

// Mock sonner
vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
    loading: vi.fn(),
    promise: vi.fn(),
    dismiss: vi.fn(),
  },
}))

describe('useToast', () => {
  it('should return toast object from sonner', () => {
    const { toast } = useToast()

    expect(toast).toBe(sonnerToast)
  })

  it('should expose toast methods', () => {
    const { toast } = useToast()

    expect(toast).toHaveProperty('success')
    expect(toast).toHaveProperty('error')
    expect(toast).toHaveProperty('info')
    expect(toast).toHaveProperty('warning')
    expect(toast).toHaveProperty('loading')
    expect(toast).toHaveProperty('promise')
    expect(toast).toHaveProperty('dismiss')
  })

  it('should allow calling toast methods', () => {
    const { toast } = useToast()

    toast.success('Success message')
    expect(sonnerToast.success).toHaveBeenCalledWith('Success message')

    toast.error('Error message')
    expect(sonnerToast.error).toHaveBeenCalledWith('Error message')
  })

  it('should return the same toast object on multiple calls', () => {
    const result1 = useToast()
    const result2 = useToast()

    expect(result1.toast).toBe(result2.toast)
  })
})
