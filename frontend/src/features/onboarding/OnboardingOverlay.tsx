import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import type { FC, ReactNode } from 'react'

export interface OnboardingOverlayProps {
  step: number
  onNext: () => void
  onPrev: () => void
  onSkip: () => void
  onComplete: () => void
}

const steps: Array<{ title: string; content: string; icon: ReactNode }> = [
  {
    title: 'Welcome to LeafLock!',
    content:
      "Your notes are protected with end-to-end encryption. Only you can read your content, even we can't see it.",
    icon: (
      <svg className="w-12 h-12 text-blue-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6l4 2" />
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10"
        />
      </svg>
    ),
  },
  {
    title: 'Secure Encryption',
    content:
      'We use end-to-end encryption with strong cryptography. Your master key never leaves your device.',
    icon: (
      <svg className="w-12 h-12 text-green-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 11c0-1.105-.672-2-1.5-2S9 9.895 9 11v2h6v-2c0-1.105-.672-2-1.5-2S12 9.895 12 11z"
        />
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 11h14v9H5z" />
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 11V7a5 5 0 0110 0v4" />
      </svg>
    ),
  },
  {
    title: 'Collaboration Ready',
    content:
      'Share notes securely with team members. You control permissions and access for every shared note.',
    icon: (
      <svg className="w-12 h-12 text-purple-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4z" />
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 22v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
      </svg>
    ),
  },
]

export const OnboardingOverlay: FC<OnboardingOverlayProps> = ({ step, onNext, onPrev, onSkip, onComplete }) => {
  const currentStep = Math.min(step, steps.length - 1)
  const isLast = currentStep === steps.length - 1
  const { title, content, icon } = steps[currentStep]

  return (
    <div className="fixed inset-0 bg-background/90 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-background border rounded-lg shadow-lg max-w-lg w-full">
        <div className="p-6 text-center space-y-4">
          {icon}
          <h2 className="text-2xl font-semibold">{title}</h2>
          <p className="text-muted-foreground text-sm leading-relaxed">{content}</p>
        </div>

        <div className="flex items-center justify-between px-6 py-4 border-t bg-muted/40">
          <div className="flex gap-1">
            {steps.map((_, index) => (
              <span
                key={index}
                className={cn(
                  'h-2 w-2 rounded-full transition-colors',
                  index === currentStep ? 'bg-primary' : 'bg-muted-foreground/40'
                )}
              />
            ))}
          </div>

          <div className="flex gap-2">
            {currentStep > 0 && (
              <Button variant="outline" onClick={onPrev}>
                Back
              </Button>
            )}
            <Button variant="ghost" onClick={onSkip}>
              Skip
            </Button>
            <Button onClick={isLast ? onComplete : onNext}>{isLast ? 'Finish' : 'Next'}</Button>
          </div>
        </div>
      </div>
    </div>
  )
}
