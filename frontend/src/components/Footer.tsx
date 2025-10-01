import React from 'react'
import { ExternalLink, Book, Github, Shield, FileText } from 'lucide-react'

interface FooterProps {
  className?: string
  variant?: 'default' | 'minimal'
}

const Footer: React.FC<FooterProps> = ({ className = '', variant = 'default' }) => {
  if (variant === 'minimal') {
    return (
      <footer className={`mt-12 ${className}`}>
        <div className="container mx-auto px-4 py-2">
          <div className="flex flex-col items-center space-y-2">
            {/* Essential links only */}
            <div className="flex items-center space-x-4 text-xs">
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
            <p className="text-[10px] text-muted-foreground/70">
              © {new Date().getFullYear()} LeafLock. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    )
  }

  return (
    <footer className={`border-t bg-background mt-auto ${className}`}>
      <div className="container mx-auto px-4 py-3">
        <div className="flex flex-col md:flex-row justify-between items-center space-y-3 md:space-y-0">
          {/* Logo and description */}
          <div className="flex flex-col items-center md:items-start">
            <div className="flex items-center space-x-2 mb-1">
              <Shield className="h-4 w-4 text-primary" />
              <span className="font-semibold text-sm text-foreground">LeafLock</span>
            </div>
            <p className="text-xs text-muted-foreground/80 text-center md:text-left">
              Secure end-to-end encrypted notes
            </p>
          </div>

          {/* Links */}
          <div className="flex flex-wrap justify-center items-center gap-x-4 gap-y-1 md:gap-x-5">
            <a
              href="https://docs.leaflock.app"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <Book className="h-3 w-3" />
              <span>Docs</span>
              <ExternalLink className="h-2.5 w-2.5" />
            </a>

            <a
              href="https://github.com/RelativeSure/notes"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <Github className="h-3 w-3" />
              <span>GitHub</span>
              <ExternalLink className="h-2.5 w-2.5" />
            </a>

            <a
              href="https://docs.leaflock.app/privacy-policy"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <Shield className="h-3 w-3" />
              <span>Privacy</span>
              <ExternalLink className="h-2.5 w-2.5" />
            </a>

            <a
              href="https://docs.leaflock.app/terms-of-use"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-xs text-muted-foreground/80 hover:text-foreground transition-colors"
            >
              <FileText className="h-3 w-3" />
              <span>Terms</span>
              <ExternalLink className="h-2.5 w-2.5" />
            </a>
          </div>
        </div>

        {/* Copyright */}
        <div className="mt-2 text-center">
          <p className="text-[10px] text-muted-foreground/70">
            © {new Date().getFullYear()} LeafLock. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  )
}

export default Footer