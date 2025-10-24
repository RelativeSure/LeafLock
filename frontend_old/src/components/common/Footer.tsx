import React from 'react'
import './footer.css'

interface FooterProps {
  className?: string
}

export const Footer: React.FC<FooterProps> = ({ className = '' }) => {
  return (
    <footer className={`app-footer ${className}`}>
      <div className="container mx-auto">
        <div className="footer-links">
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
