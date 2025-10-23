import Link from "next/link"
import { Button } from "@/components/ui/button"
import { PenLine, Sparkles, Tags, FileText } from "lucide-react"

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <PenLine className="h-6 w-6 text-accent" />
            <span className="text-xl font-serif font-semibold text-foreground">Elegant Notes</span>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login">
              <Button variant="ghost" className="text-foreground">
                Log in
              </Button>
            </Link>
            <Link href="/register">
              <Button className="bg-primary text-primary-foreground hover:bg-primary/90">Sign up</Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1 flex items-center justify-center px-4 py-16">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <div className="space-y-4">
            <h1 className="text-5xl md:text-7xl font-serif font-bold text-balance leading-tight text-foreground">
              Your thoughts, beautifully organized
            </h1>
            <p className="text-xl md:text-2xl text-muted-foreground text-balance max-w-2xl mx-auto leading-relaxed">
              A distraction-free space to capture ideas, organize with tags, and write with elegant templates.
            </p>
          </div>

          <div className="flex items-center justify-center gap-4 pt-4">
            <Link href="/register">
              <Button size="lg" className="bg-primary text-primary-foreground hover:bg-primary/90 text-lg px-8">
                Get Started
              </Button>
            </Link>
            <Link href="/login">
              <Button size="lg" variant="outline" className="text-lg px-8 bg-transparent">
                Sign In
              </Button>
            </Link>
          </div>

          {/* Features */}
          <div className="grid md:grid-cols-3 gap-8 pt-16">
            <div className="space-y-3 text-center">
              <div className="flex justify-center">
                <div className="h-12 w-12 rounded-xl bg-accent/10 flex items-center justify-center">
                  <Sparkles className="h-6 w-6 text-accent" />
                </div>
              </div>
              <h3 className="text-lg font-serif font-semibold text-foreground">Smart Templates</h3>
              <p className="text-muted-foreground leading-relaxed">
                Start with pre-designed templates for meetings, journals, and more.
              </p>
            </div>

            <div className="space-y-3 text-center">
              <div className="flex justify-center">
                <div className="h-12 w-12 rounded-xl bg-accent/10 flex items-center justify-center">
                  <Tags className="h-6 w-6 text-accent" />
                </div>
              </div>
              <h3 className="text-lg font-serif font-semibold text-foreground">Organize with Tags</h3>
              <p className="text-muted-foreground leading-relaxed">
                Keep your notes organized with powerful tagging and filtering.
              </p>
            </div>

            <div className="space-y-3 text-center">
              <div className="flex justify-center">
                <div className="h-12 w-12 rounded-xl bg-accent/10 flex items-center justify-center">
                  <FileText className="h-6 w-6 text-accent" />
                </div>
              </div>
              <h3 className="text-lg font-serif font-semibold text-foreground">Distraction-Free</h3>
              <p className="text-muted-foreground leading-relaxed">
                Focus on your writing with a clean, minimal interface.
              </p>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border bg-card py-8">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p>© 2025 Elegant Notes. Crafted with care for thoughtful writers.</p>
        </div>
      </footer>
    </div>
  )
}
