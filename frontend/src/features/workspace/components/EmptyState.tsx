import React from 'react'
import { FileText } from 'lucide-react'

interface EmptyStateProps {
  title?: string
  description?: string
  icon?: React.ReactNode
  className?: string
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'Select a note or create a new one',
  description = 'Your notes are end-to-end encrypted for maximum privacy',
  icon,
  className = '',
}) => {
  return (
    <main
      className={`flex-1 flex items-center justify-center ${className}`}
      role="main"
      aria-label="Empty state"
    >
      <div className="text-center max-w-md px-4">
        <div className="flex justify-center mb-4" aria-hidden="true">
          {icon || <FileText className="w-16 h-16 text-muted-foreground/60" strokeWidth={1.5} />}
        </div>
        <p className="text-muted-foreground text-lg mb-2">{title}</p>
        <p className="text-muted-foreground/70 text-sm">{description}</p>
      </div>
    </main>
  )
}
