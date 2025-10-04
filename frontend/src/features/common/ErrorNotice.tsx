import { cn } from '@/lib/utils'
import type { FC } from 'react'

export interface ErrorNoticeProps {
  error: string | Error
  onRetry?: () => void
  onDismiss?: () => void
  className?: string
}

const extractMessage = (error: string | Error): string => {
  if (typeof error === 'string') return error
  return error.message || 'An unexpected error occurred'
}

const suggestionFor = (error: string | Error): string => {
  const message = extractMessage(error).toLowerCase()

  if (message.includes('network') || message.includes('fetch')) {
    return 'Check your internet connection and try again.'
  }
  if (message.includes('unauthorized') || message.includes('401')) {
    return 'Your session may have expired. Please sign in again.'
  }
  if (message.includes('decrypt') || message.includes('encryption')) {
    return 'There was an issue with encryption. Try refreshing the page.'
  }
  return 'Please try again or refresh the page if the problem persists.'
}

export const ErrorNotice: FC<ErrorNoticeProps> = ({ error, onRetry, onDismiss, className }) => (
  <div
    className={cn('bg-red-900/50 border border-red-600 rounded-lg p-4', className)}
    role="alert"
  >
    <div className="flex items-start">
      <svg
        className="w-5 h-5 text-red-400 mr-3 mt-0.5"
        fill="currentColor"
        viewBox="0 0 20 20"
        aria-hidden="true"
      >
        <path
          fillRule="evenodd"
          d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
          clipRule="evenodd"
        />
      </svg>
      <div className="flex-1">
        <h3 className="text-red-200 font-medium mb-1">Something went wrong</h3>
        <p className="text-red-300 text-sm mb-2">{extractMessage(error)}</p>
        <p className="text-red-400 text-xs mb-4">{suggestionFor(error)}</p>

        <div className="flex flex-wrap gap-2">
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="bg-red-600 hover:bg-red-700 text-white px-3 py-1.5 rounded text-sm transition-colors"
            >
              Try again
            </button>
          )}
          {onDismiss && (
            <button
              type="button"
              onClick={onDismiss}
              className="text-red-200 hover:text-white text-sm"
            >
              Dismiss
            </button>
          )}
        </div>
      </div>
    </div>
  </div>
)
