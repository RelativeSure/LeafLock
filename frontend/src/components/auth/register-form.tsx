/**
 * Pure Clerk Registration Form
 *
 * @description
 * Pure Clerk authentication implementation.
 * This component uses Clerk's native SignUp component with custom styling.
 *
 * @features
 * - Pure Clerk SignUp component with custom appearance
 * - No legacy authentication methods
 * - Direct integration with Clerk's authentication system
 * - Custom styling to match LeafLock design system
 */

import * as React from 'react'
import { SignUp } from '@clerk/clerk-react'
import { Button } from '@/components/ui/button'

export function RegisterForm({
  onToggleMode,
  animatedTitle,
}: {
  onToggleMode: () => void
  animatedTitle?: React.ReactNode
}) {
  return (
    <div className="w-full max-w-md mx-auto">
      {animatedTitle && <div className="mb-8 text-center">{animatedTitle}</div>}

      <SignUp
        routing="path"
        path="/register"
        signInUrl="/login"
        fallbackRedirectUrl="/"
        appearance={{
          elements: {
            // Root container
            rootBox: 'w-full',
            card: 'w-full bg-transparent border-0 shadow-none p-0 space-y-6',

            // Header
            headerTitle: 'clerk-title-enhanced',
            headerSubtitle: 'clerk-subtitle-enhanced',

            // Form fields
            formFieldLabel: 'clerk-label-enhanced',
            formFieldInput: 'clerk-input-enhanced',
            formFieldInput__emailAddress: 'clerk-input-enhanced',
            formFieldInput__password: 'clerk-input-enhanced',
            formFieldInput__firstName: 'clerk-input-enhanced',
            formFieldInput__lastName: 'clerk-input-enhanced',
            formFieldInputShowPasswordButton:
              'text-muted-foreground hover:text-foreground hover:scale-110 transition-all',
            formFieldErrorText: 'clerk-message-error-enhanced',
            formFieldSuccessText: 'clerk-message-success-enhanced',
            formFieldHintText: 'text-muted-foreground text-xs mt-2',

            // Primary action buttons
            formButtonPrimary: 'clerk-button-primary-enhanced',
            formButtonReset: 'clerk-button-secondary-enhanced',

            // Social auth buttons
            socialButtonsBlockButton: 'clerk-social-button-enhanced',
            socialButtonsBlockButtonText: 'font-medium',
            socialButtonsProviderIcon: 'clerk-social-icon-enhanced',

            // Footer and links
            footerActionText: 'clerk-footer-text-enhanced',
            footerActionLink: 'clerk-footer-link-enhanced',
            footer: 'clerk-footer-enhanced',

            // Divider
            dividerLine: 'clerk-divider-enhanced',
            dividerText: 'clerk-divider-text-enhanced',

            // Loading and spinners
            spinner: 'clerk-spinner-enhanced',
          },
          variables: {
            colorPrimary: '#3b82f6',
            colorBackground: 'transparent',
            colorText: '#f8fafc',
            colorInputBackground: 'rgba(30, 41, 59, 0.8)',
            colorInputText: '#f8fafc',
            fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            fontSize: '16px',
            borderRadius: '12px',
            spacingUnit: '6px',
          },
          layout: {
            socialButtonsPlacement: 'bottom',
            socialButtonsVariant: 'blockButton',
            helpPageUrl: '/help',
            showOptionalFields: true,
          },
        }}
      />

      <div className="mt-6 text-center">
        <p className="text-sm text-muted-foreground">
          Already have an account?{' '}
          <Button
            variant="link"
            onClick={onToggleMode}
            className="text-primary hover:text-primary/90 font-medium underline-offset-4 hover:underline transition-all p-0 h-auto"
          >
            Sign in
          </Button>
        </p>
      </div>
    </div>
  )
}
