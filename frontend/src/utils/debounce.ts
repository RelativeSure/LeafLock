export interface DebounceFunction {
  (...args: unknown[]): void
  cancel: () => void
}

export function debounce<T extends (...args: any[]) => void>(func: T, wait: number): DebounceFunction {
  let timeout: ReturnType<typeof setTimeout>

  const executedFunction = (...args: Parameters<T>) => {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }

    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }

  executedFunction.cancel = () => {
    clearTimeout(timeout)
  }

  return executedFunction
}
