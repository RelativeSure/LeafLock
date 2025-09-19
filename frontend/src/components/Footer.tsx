import React from 'react'
import { ExternalLink, Book, Github, Shield, FileText } from 'lucide-react'

interface FooterProps {
  className?: string
}

const Footer: React.FC<FooterProps> = ({ className = '' }) => {
  return (
    <footer className={`border-t bg-background mt-auto ${className}`}>
      <div className="container mx-auto px-4 py-6">
        <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
          {/* Logo and description */}
          <div className="flex flex-col items-center md:items-start">
            <div className="flex items-center space-x-2 mb-2">
              <Shield className="h-5 w-5 text-primary" />
              <span className="font-semibold text-foreground">LeafLock</span>
            </div>
            <p className="text-sm text-muted-foreground text-center md:text-left">
              Secure end-to-end encrypted notes
            </p>
          </div>

          {/* Links */}
          <div className="flex flex-col md:flex-row items-center space-y-2 md:space-y-0 md:space-x-6">
            <a
              href="/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <Book className="h-4 w-4" />
              <span>Documentation</span>
              <ExternalLink className="h-3 w-3" />
            </a>

            <a
              href="https://github.com/RelativeSure/notes"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <Github className="h-4 w-4" />
              <span>GitHub</span>
              <ExternalLink className="h-3 w-3" />
            </a>

            <a
              href="/docs/privacy-policy"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <Shield className="h-4 w-4" />
              <span>Privacy</span>
              <ExternalLink className="h-3 w-3" />
            </a>

            <a
              href="/docs/terms-of-use"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <FileText className="h-4 w-4" />
              <span>Terms</span>
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>

        {/* Copyright */}
        <div className="mt-4 pt-4 border-t text-center">
          <p className="text-xs text-muted-foreground">
            © {new Date().getFullYear()} LeafLock. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  )
}

export default Footer