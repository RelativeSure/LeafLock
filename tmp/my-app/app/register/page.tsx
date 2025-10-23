import Link from "next/link"
import { RegisterForm } from "@/components/register-form"
import { PenLine } from "lucide-react"

export default function RegisterPage() {
  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-background">
      <div className="w-full max-w-md space-y-8">
        {/* Logo */}
        <div className="flex flex-col items-center gap-2">
          <Link href="/" className="flex items-center gap-2 group">
            <PenLine className="h-8 w-8 text-accent group-hover:text-accent/80 transition-colors" />
            <span className="text-2xl font-semibold text-foreground">Notely</span>
          </Link>
        </div>

        {/* Form Card */}
        <div className="bg-card border border-border rounded-2xl p-8 shadow-sm">
          <div className="space-y-2 text-center mb-8">
            <h1 className="text-3xl font-bold text-foreground text-balance">Create your account</h1>
            <p className="text-muted-foreground leading-relaxed">Start capturing your thoughts today</p>
          </div>

          <RegisterForm />

          <div className="mt-6 text-center text-sm">
            <span className="text-muted-foreground">Already have an account? </span>
            <Link href="/login" className="text-accent hover:text-accent/80 font-medium transition-colors">
              Sign in
            </Link>
          </div>
        </div>

        <p className="text-center text-xs text-muted-foreground">
          By signing up, you agree to our Terms of Service and Privacy Policy
        </p>
      </div>
    </div>
  )
}
