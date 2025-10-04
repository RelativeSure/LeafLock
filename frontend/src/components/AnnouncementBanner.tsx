import React, { useState, useEffect } from 'react'
import { X, Info, AlertTriangle, CheckCircle, AlertCircle } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

export interface Announcement {
  id: string
  title: string
  content: string
  visibility: 'all' | 'logged_in'
  style: {
    backgroundColor?: string
    textColor?: string
    borderColor?: string
    icon?: 'info' | 'warning' | 'success' | 'error'
    fontSize?: 'small' | 'normal' | 'large'
    animation?: 'none' | 'fade' | 'slide' | 'pulse'
  }
  dismissible: boolean
  priority: number
  start_date?: string
  end_date?: string
  created_at: string
  active?: boolean
}

interface AnnouncementBannerProps {
  announcements: Announcement[]
  onDismiss?: (id: string) => void
  className?: string
}

const iconMap = {
  info: Info,
  warning: AlertTriangle,
  success: CheckCircle,
  error: AlertCircle,
}

const AnnouncementBanner: React.FC<AnnouncementBannerProps> = ({
  announcements,
  onDismiss,
  className = '',
}) => {
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set())

  // Load dismissed announcements from localStorage
  useEffect(() => {
    try {
      const dismissed = localStorage.getItem('dismissedAnnouncements')
      if (dismissed) {
        setDismissedIds(new Set(JSON.parse(dismissed)))
      }
    } catch (error) {
      console.warn('Failed to load dismissed announcements:', error)
    }
  }, [])

  // Save dismissed announcements to localStorage
  const saveDismissedIds = (ids: Set<string>) => {
    try {
      localStorage.setItem('dismissedAnnouncements', JSON.stringify([...ids]))
    } catch (error) {
      console.warn('Failed to save dismissed announcements:', error)
    }
  }

  const handleDismiss = (id: string) => {
    const newDismissedIds = new Set(dismissedIds)
    newDismissedIds.add(id)
    setDismissedIds(newDismissedIds)
    saveDismissedIds(newDismissedIds)
    onDismiss?.(id)
  }

  // Filter out dismissed announcements and sort by priority
  const visibleAnnouncements = announcements
    .filter(announcement => !dismissedIds.has(announcement.id))
    .sort((a, b) => b.priority - a.priority || new Date(b.created_at).getTime() - new Date(a.created_at).getTime())

  if (visibleAnnouncements.length === 0) {
    return null
  }

  return (
    <div className={`space-y-2 ${className}`}>
      {visibleAnnouncements.map((announcement) => {
        const Icon = iconMap[announcement.style.icon || 'info']

        const bgColor = announcement.style.backgroundColor || '#f0f9ff'
        const textColor = announcement.style.textColor || '#0c4a6e'
        const borderColor = announcement.style.borderColor || '#0ea5e9'

        const fontSize = announcement.style.fontSize === 'small' ? 'text-sm' :
                        announcement.style.fontSize === 'large' ? 'text-lg' : 'text-base'

        const animationClass = announcement.style.animation === 'fade' ? 'animate-in fade-in duration-500' :
                             announcement.style.animation === 'slide' ? 'animate-in slide-in-from-top-2 duration-500' :
                             announcement.style.animation === 'pulse' ? 'animate-pulse' : ''

        return (
          <Card
            key={announcement.id}
            className={`relative border-l-4 ${fontSize} ${animationClass}`}
            style={{
              backgroundColor: bgColor,
              color: textColor,
              borderLeftColor: borderColor,
            }}
          >
            <div className="flex items-start gap-3 p-4">
              {Icon && (
                <Icon
                  className="h-5 w-5 flex-shrink-0 mt-0.5"
                  style={{ color: borderColor }}
                />
              )}

              <div className="flex-1 min-w-0">
                <h3 className="font-semibold mb-1">{announcement.title}</h3>
                <div className="prose prose-sm max-w-none">
                  <ReactMarkdown
                    components={{
                      // Customize markdown rendering for security and styling
                      a: ({ href, children, ...props }) => (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="underline hover:no-underline"
                          style={{ color: textColor }}
                          {...props}
                        >
                          {children}
                        </a>
                      ),
                      code: ({ children, ...props }) => (
                        <code
                          className="bg-black/10 px-1 py-0.5 rounded text-sm"
                          {...props}
                        >
                          {children}
                        </code>
                      ),
                      pre: ({ children, ...props }) => (
                        <pre
                          className="bg-black/10 p-2 rounded-md overflow-x-auto text-sm"
                          {...props}
                        >
                          {children}
                        </pre>
                      ),
                    }}
                  >
                    {announcement.content}
                  </ReactMarkdown>
                </div>
              </div>

              {announcement.dismissible && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="flex-shrink-0 h-6 w-6 p-0 hover:bg-black/10"
                  onClick={() => handleDismiss(announcement.id)}
                  style={{ color: textColor }}
                >
                  <X className="h-4 w-4" />
                  <span className="sr-only">Dismiss announcement</span>
                </Button>
              )}
            </div>
          </Card>
        )
      })}
    </div>
  )
}

export default AnnouncementBanner
