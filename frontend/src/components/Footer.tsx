import React from 'react'
import { ExternalLink, Book, Github, Shield, FileText } from 'lucide-react'

interface FooterProps {
  className?: string
  variant?: 'default' | 'minimal'
}

const Footer: React.FC<FooterProps> = ({ className = '', variant = 'default' }) => {
  if (variant === 'minimal') {
    return (
      <footer className={`mt-8 ${className}`}>
        <div className="container mx-auto px-4 py-3">
          <div className="flex flex-col items-center gap-3">
            {/* Essential links only */}
            <div className="flex items-center gap-4 text-xs">
              <a
                href="https://docs.leaflock.app/privacy-policy"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground/80 hover:text-foreground transition-colors"
              >
                Privacy
              </a>
              <a
                href="https://docs.leaflock.app/terms-of-use"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground/80 hover:text-foreground transition-colors"
              >
                Terms
              </a>
              <a
                href="https://docs.leaflock.app"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground/80 hover:text-foreground transition-colors"
              >
                Docs
              </a>
            </div>
            {/* Copyright */}
            <p className="text-xs text-muted-foreground/70">
              © {new Date().getFullYear()} LeafLock. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    )
  }

  return (
    <footer className={`border-t bg-background mt-auto ${className}`}>
      <div className="container mx-auto px-4 sm:px-6 py-4 md:py-5">
        <div className="flex flex-col md:flex-row justify-between items-center gap-4 md:gap-6">
          {/* Logo and description */}
          <div className="flex flex-col items-center md:items-start">
            <div className="flex items-center gap-2 mb-1.5">
              <Shield className="h-4 w-4 text-primary" />
              <span className="font-semibold text-sm text-foreground">LeafLock</span>
            </div>
            <p className="text-xs text-muted-foreground/80 text-center md:text-left">
              Secure end-to-end encrypted notes
            </p>
          </div>

          {/* Links */}
          <div className="flex flex-wrap justify-center items-center gap-x-5 gap-y-2 md:gap-x-6">
            <a
              href="https://docs.leaflock.app"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <Book className="h-3.5 w-3.5" />
              <span>Docs</span>
              <ExternalLink className="h-3 w-3 opacity-70" />
            </a>

            <a
              href="https://github.com/RelativeSure/notes"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <Github className="h-3.5 w-3.5" />
              <span>GitHub</span>
              <ExternalLink className="h-3 w-3 opacity-70" />
            </a>

            <a
              href="https://docs.leaflock.app/privacy-policy"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <Shield className="h-3.5 w-3.5" />
              <span>Privacy</span>
              <ExternalLink className="h-3 w-3 opacity-70" />
            </a>

            <a
              href="https://docs.leaflock.app/terms-of-use"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>Terms</span>
              <ExternalLink className="h-3 w-3 opacity-70" />
            </a>
          </div>
        </div>

        {/* Copyright */}
        <div className="mt-3 pt-3 border-t border-border/50 text-center">
          <p className="text-xs text-muted-foreground/70">
            © {new Date().getFullYear()} LeafLock. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  )
}

export default Footer