import React, { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Mail, ArrowLeft } from 'lucide-react'
import { toast } from 'sonner'

interface ForgotPasswordFormProps {
  onToggleMode: () => void
}

export const ForgotPasswordForm: React.FC<ForgotPasswordFormProps> = ({ onToggleMode }) => {
  const [email, setEmail] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isSubmitted, setIsSubmitted] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      // TODO: Implement actual password reset API call
      await new Promise(resolve => setTimeout(resolve, 1000)) // Simulate API call

      setIsSubmitted(true)
      toast.success('Password reset link sent to your email')
    } catch (error) {
      toast.error('Failed to send password reset link')
    } finally {
      setIsLoading(false)
    }
  }

  if (isSubmitted) {
    return (
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center">
          <h1 className="text-2xl font-bold text-white">Check your email</h1>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-center text-slate-300">
            We've sent a password reset link to <strong>{email}</strong>
          </p>
          <p className="text-center text-sm text-slate-400">
            Didn't receive the email? Check your spam folder or try again.
          </p>
          <div className="space-y-2">
            <Button
              type="button"
              variant="outline"
              className="w-full"
              onClick={() => setIsSubmitted(false)}
            >
              Try again
            </Button>
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={onToggleMode}
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to login
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="text-center">
        <h1 className="text-2xl font-bold text-white">Reset your password</h1>
        <p className="text-sm text-slate-400">
          Enter your email address and we'll send you a link to reset your password.
        </p>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <div className="relative">
              <Mail className="absolute left-3 top-3 h-4 w-4 text-muted transition-smooth" />
              <Input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="pl-10"
              />
            </div>
          </div>

          <Button
            type="submit"
            className="w-full transition-bounce hover-lift"
            disabled={isLoading}
          >
            {isLoading ? 'Sending...' : 'Send reset link'}
          </Button>

          <div className="text-center">
            <Button
              type="button"
              variant="ghost"
              onClick={onToggleMode}
              className="text-sm"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to login
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
