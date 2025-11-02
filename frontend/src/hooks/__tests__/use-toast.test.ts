import { describe, it, expect, vi } from 'vitest'
import { useToast } from '../use-toast'

vi.mock('sonner', () => ({
  toast: vi.fn(),
}))

describe('use-toast', () => {
  it('should return toast function', () => {
    const { toast } = useToast()

    expect(toast).toBeDefined()
    expect(typeof toast).toBe('function')
  })

  it('should call sonner toast', () => {
    const { toast } = useToast()

    toast('Test message')

    expect(toast).toHaveBeenCalledWith('Test message')
  })

  it('should support toast options', () => {
    const { toast } = useToast()

    toast.success('Success message')
    toast.error('Error message')
    toast.info('Info message')
    toast.warning('Warning message')

    expect(toast.success).toHaveBeenCalledWith('Success message')
    expect(toast.error).toHaveBeenCalledWith('Error message')
  })
})
