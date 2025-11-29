import { Loader2 } from 'lucide-react'

interface ClerkLoadingProps {
  className?: string
  text?: string
}

export function ClerkLoading({ className = '', text = 'Loading...' }: ClerkLoadingProps) {
  return (
    <div className={`flex flex-col items-center justify-center p-8 space-y-4 ${className}`}>
      <Loader2 className="h-8 w-8 animate-spin text-primary" />
      <p className="text-muted-foreground text-sm animate-pulse">{text}</p>
    </div>
  )
}

export function ClerkAuthLoading() {
  return (
    <div className="min-h-screen flex items-center justify-center p-4 animate-in fade-in-50 duration-700 relative overflow-hidden bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <div className="w-full max-w-md text-center space-y-6">
        <div className="flex justify-center">
          <Loader2 className="h-12 w-12 animate-spin text-primary" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl font-semibold text-foreground">Authenticating...</h2>
          <p className="text-muted-foreground">Please wait while we prepare your secure session</p>
        </div>
      </div>
    </div>
  )
}
