import React from 'react'

interface FooterProps {
  className?: string
}

const Footer: React.FC<FooterProps> = ({ className = '' }) => {
  return (
    <footer className={`border-t border-border/40 bg-background py-3 px-4 ${className}`}>
      <div className="container mx-auto">
        <div className="flex flex-wrap items-center justify-center gap-3 text-xs">
          <span className="text-muted-foreground/70">© {new Date().getFullYear()} LeafLock</span>
          <span className="text-muted-foreground/50">•</span>
          <a
            href="https://docs.leaflock.app"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground/80 hover:text-foreground transition-colors"
          >
            Docs
          </a>
          <span className="text-muted-foreground/50">•</span>
          <a
            href="https://github.com/RelativeSure/notes"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground/80 hover:text-foreground transition-colors"
          >
            GitHub
          </a>
          <span className="text-muted-foreground/50">•</span>
          <a
            href="https://github.com/RelativeSure/notes/discussions"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground/80 hover:text-foreground transition-colors"
          >
            Community
          </a>
          <span className="text-muted-foreground/50">•</span>
          <a
            href="https://docs.leaflock.app/privacy-policy"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground/80 hover:text-foreground transition-colors"
          >
            Privacy
          </a>
          <span className="text-muted-foreground/50">•</span>
          <a
            href="https://docs.leaflock.app/terms-of-use"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground/80 hover:text-foreground transition-colors"
          >
            Terms
          </a>
        </div>
      </div>
    </footer>
  )
}

export default Footer
