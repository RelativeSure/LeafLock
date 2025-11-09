import { toast as sonnerToast } from 'sonner'

export function useToast(): { toast: typeof sonnerToast } {
  return {
    toast: sonnerToast,
  }
}
