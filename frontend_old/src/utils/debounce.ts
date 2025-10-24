export interface DebounceFunction<T extends (...args: any[]) => unknown> {
  (...args: Parameters<T>): void
  cancel: () => void
}

export function debounce<T extends (...args: any[]) => unknown>(
  func: T,
  wait: number
): DebounceFunction<T> {
  let timeout: ReturnType<typeof setTimeout>

  const executedFunction = ((...args: Parameters<T>) => {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }

    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }) as DebounceFunction<T>

  executedFunction.cancel = () => {
    clearTimeout(timeout)
  }

  return executedFunction
}
