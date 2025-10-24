import { useState } from "react"
import { useAuthStore } from "@/stores"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { UserPlus, Lock, Mail, User, Check, X } from "lucide-react"

export function RegisterForm({ onToggleMode }: { onToggleMode: () => void }) {
  const { register } = useAuthStore()
  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [error, setError] = useState("")
  const [isLoading, setIsLoading] = useState(false)

  // Name validation
  const nameValid = name.trim().length >= 2
  const nameHasValidChars = /^[a-zA-Z\s\-']+$/.test(name)

  // Email validation
  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)

  // Password complexity validation
  const passwordMinLength = password.length >= 8
  const passwordHasUppercase = /[A-Z]/.test(password)
  const passwordHasLowercase = /[a-z]/.test(password)
  const passwordHasNumber = /[0-9]/.test(password)
  const passwordHasSpecial = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)
  const passwordsMatch = password === confirmPassword && confirmPassword.length > 0

  const allPasswordRequirementsMet =
    passwordMinLength &&
    passwordHasUppercase &&
    passwordHasLowercase &&
    passwordHasNumber &&
    passwordHasSpecial &&
    passwordsMatch

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")

    // Validate name
    if (!nameValid) {
      setError("Name must be at least 2 characters")
      return
    }

    if (!nameHasValidChars) {
      setError("Name can only contain letters, spaces, hyphens, and apostrophes")
      return
    }

    // Validate email
    if (!emailValid) {
      setError("Please enter a valid email address")
      return
    }

    // Validate password
    if (!allPasswordRequirementsMet) {
      setError("Please meet all password requirements")
      return
    }

    setIsLoading(true)

    try {
      await register(email, password, name)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed")
    } finally {
      setIsLoading(false)
    }
  }

  const ValidationIndicator = ({ valid, text }: { valid: boolean; text: string }) => (
    <div className="flex items-center gap-2 text-xs transition-smooth">
      {valid ? (
        <Check className="w-3 h-3 text-green-500 animate-scale-in" />
      ) : (
        <X className="w-3 h-3 text-muted-foreground" />
      )}
      <span className={valid ? "text-green-500" : "text-muted-foreground"}>{text}</span>
    </div>
  )

  return (
    <Card className="w-full max-w-md animate-scale-in hover-lift">
      <CardHeader className="space-y-1">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-primary/10 mb-4 mx-auto animate-bounce-in">
          <UserPlus className="w-6 h-6 text-primary" />
        </div>
        <CardTitle className="text-2xl text-center">Create an account</CardTitle>
        <CardDescription className="text-center">Start taking secure, encrypted notes</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleRegister} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Full Name</Label>
            <div className="relative">
              <User className="absolute left-3 top-3 h-4 w-4 text-muted transition-smooth" />
              <Input
                id="name"
                type="text"
                placeholder="John Doe"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="pl-10 transition-smooth"
                required
              />
            </div>
            {name.length > 0 && (
              <div className="space-y-1 p-2 bg-muted/50 rounded-md">
                <ValidationIndicator valid={nameValid} text="At least 2 characters" />
                <ValidationIndicator valid={nameHasValidChars} text="Valid characters only" />
              </div>
            )}
          </div>

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
                className="pl-10 transition-smooth"
                required
              />
            </div>
            {email.length > 0 && (
              <div className="space-y-1 p-2 bg-muted/50 rounded-md">
                <ValidationIndicator valid={emailValid} text="Valid email format" />
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-4 w-4 text-muted transition-smooth" />
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="pl-10 transition-smooth"
                required
              />
            </div>
            {password.length > 0 && (
              <div className="space-y-1 p-2 bg-muted/50 rounded-md">
                <ValidationIndicator valid={passwordMinLength} text="At least 8 characters" />
                <ValidationIndicator valid={passwordHasUppercase} text="One uppercase letter (A-Z)" />
                <ValidationIndicator valid={passwordHasLowercase} text="One lowercase letter (a-z)" />
                <ValidationIndicator valid={passwordHasNumber} text="One number (0-9)" />
                <ValidationIndicator valid={passwordHasSpecial} text="One special character (!@#$%...)" />
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirm-password">Confirm Password</Label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-4 w-4 text-muted transition-smooth" />
              <Input
                id="confirm-password"
                type="password"
                placeholder="••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="pl-10 transition-smooth"
                required
              />
            </div>
            {confirmPassword.length > 0 && (
              <div className="space-y-1 p-2 bg-muted/50 rounded-md">
                <ValidationIndicator valid={passwordsMatch} text="Passwords match" />
              </div>
            )}
          </div>

          {error && <div className="text-sm text-danger bg-danger/10 p-3 rounded-md animate-slide-in">{error}</div>}

          <Button type="submit" className="w-full transition-bounce hover-lift" disabled={isLoading}>
            {isLoading ? "Creating account..." : "Create account"}
          </Button>

          <div className="text-center text-sm text-muted-foreground">
            Already have an account?{" "}
            <button type="button" onClick={onToggleMode} className="text-primary hover:underline transition-smooth">
              Sign in
            </button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
