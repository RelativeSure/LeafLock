/**
 * Error Logging Utility
 * Provides structured error logging for the frontend with context and stack traces
 */

export interface ErrorContext {
  timestamp: string
  level: 'error' | 'warn' | 'info' | 'debug'
  message: string
  error?: Error | string
  stack?: string
  url?: string
  userAgent?: string
  userId?: string
  componentStack?: string
  metadata?: Record<string, unknown>
}

export interface ErrorLoggerConfig {
  enableConsole?: boolean
  enableRemote?: boolean
  remoteEndpoint?: string
  environment?: string
}

class ErrorLogger {
  private config: ErrorLoggerConfig = {
    enableConsole: true,
    enableRemote: false,
    environment: import.meta.env.MODE || 'development',
  }

  constructor(config?: Partial<ErrorLoggerConfig>) {
    if (config) {
      this.config = { ...this.config, ...config }
    }
  }

  /**
   * Log an error with full context
   */
  logError(message: string, error?: Error | string, metadata?: Record<string, unknown>): void {
    const context = this.buildContext('error', message, error, metadata)
    this.log(context)
  }

  /**
   * Log a warning
   */
  logWarning(message: string, metadata?: Record<string, unknown>): void {
    const context = this.buildContext('warn', message, undefined, metadata)
    this.log(context)
  }

  /**
   * Log info message
   */
  logInfo(message: string, metadata?: Record<string, unknown>): void {
    const context = this.buildContext('info', message, undefined, metadata)
    this.log(context)
  }

  /**
   * Log debug message (only in development)
   */
  logDebug(message: string, metadata?: Record<string, unknown>): void {
    if (this.config.environment === 'development') {
      const context = this.buildContext('debug', message, undefined, metadata)
      this.log(context)
    }
  }

  /**
   * Build error context with all available information
   */
  private buildContext(
    level: ErrorContext['level'],
    message: string,
    error?: Error | string,
    metadata?: Record<string, unknown>
  ): ErrorContext {
    const context: ErrorContext = {
      timestamp: new Date().toISOString(),
      level,
      message,
      url: window.location.href,
      userAgent: navigator.userAgent,
      metadata,
    }

    // Extract error details
    if (error) {
      if (error instanceof Error) {
        context.error = error
        context.stack = error.stack
      } else {
        context.error = String(error)
      }
    }

    // Get user ID from localStorage if available
    const userId = localStorage.getItem('user_id')
    if (userId) {
      context.userId = userId
    }

    return context
  }

  /**
   * Output log entry
   */
  private log(context: ErrorContext): void {
    // Console logging
    if (this.config.enableConsole) {
      this.logToConsole(context)
    }

    // Remote logging (optional - for error tracking services)
    if (this.config.enableRemote && this.config.remoteEndpoint) {
      this.logToRemote(context)
    }

    // Store recent errors in sessionStorage for debugging
    this.storeRecentError(context)
  }

  /**
   * Log to browser console
   */
  private logToConsole(context: ErrorContext): void {
    const logMessage = `[${context.level.toUpperCase()}] ${context.message}`

    switch (context.level) {
      case 'error':
        console.error(logMessage, context)
        if (context.stack) {
          console.error('Stack trace:', context.stack)
        }
        break
      case 'warn':
        console.warn(logMessage, context)
        break
      case 'debug':
        console.debug(logMessage, context)
        break
      default:
        console.log(logMessage, context)
    }
  }

  /**
   * Send logs to remote endpoint (optional)
   */
  private async logToRemote(context: ErrorContext): Promise<void> {
    if (!this.config.remoteEndpoint) return

    try {
      await fetch(this.config.remoteEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(context),
      })
    } catch (err) {
      // Silent fail - don't log errors about logging
      console.warn('Failed to send error to remote endpoint:', err)
    }
  }

  /**
   * Store recent errors in sessionStorage for debugging
   */
  private storeRecentError(context: ErrorContext): void {
    try {
      const key = 'leaflock_recent_errors'
      const stored = sessionStorage.getItem(key)
      const errors: ErrorContext[] = stored ? JSON.parse(stored) : []

      // Keep only last 50 errors
      errors.push(context)
      if (errors.length > 50) {
        errors.shift()
      }

      // Store serializable version (without Error objects)
      const serializable = errors.map((err) => ({
        ...err,
        error: err.error instanceof Error ? err.error.message : err.error,
      }))

      sessionStorage.setItem(key, JSON.stringify(serializable))
    } catch (err) {
      // Silent fail - storage might be full
    }
  }

  /**
   * Get recent errors from sessionStorage
   */
  static getRecentErrors(): ErrorContext[] {
    try {
      const stored = sessionStorage.getItem('leaflock_recent_errors')
      return stored ? JSON.parse(stored) : []
    } catch {
      return []
    }
  }

  /**
   * Clear stored errors
   */
  static clearRecentErrors(): void {
    try {
      sessionStorage.removeItem('leaflock_recent_errors')
    } catch {
      // Silent fail
    }
  }
}

// Export singleton instance
export const errorLogger = new ErrorLogger()

// Export class for custom instances
export { ErrorLogger }

// Capture unhandled errors
if (typeof window !== 'undefined') {
  window.addEventListener('error', (event) => {
    errorLogger.logError('Unhandled error', event.error, {
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno,
    })
  })

  window.addEventListener('unhandledrejection', (event) => {
    errorLogger.logError('Unhandled promise rejection', event.reason, {
      promise: 'Promise rejection',
    })
  })
}
