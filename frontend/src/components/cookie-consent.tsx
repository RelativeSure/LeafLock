"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { X, Cookie, ExternalLink } from "lucide-react"

export function CookieConsent() {
  const [showBanner, setShowBanner] = useState(() => {
    const consent = localStorage.getItem("cookie_consent")
    return !consent
  })

  const handleAccept = () => {
    localStorage.setItem("cookie_consent", "accepted")
    setShowBanner(false)
  }

  const handleDecline = () => {
    localStorage.setItem("cookie_consent", "declined")
    setShowBanner(false)
  }

  if (!showBanner) return null

  return (
    <div className="fixed bottom-4 left-4 right-4 z-50 animate-in slide-in-from-bottom-5 duration-500 md:left-auto md:right-4 md:max-w-md">
      <Card className="p-4 shadow-lg border-2">
        <div className="flex items-start gap-3">
          <Cookie className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
          <div className="flex-1 space-y-3">
            <div>
              <h3 className="font-semibold text-sm mb-1">Cookie Notice</h3>
              <p className="text-xs text-muted-foreground">
                We use essential cookies to store your data locally in your browser. No tracking or analytics cookies
                are used.{" "}
                <a
                  href="https://docs.leaflock.app/privacy"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center gap-1"
                >
                  Learn more
                  <ExternalLink className="h-3 w-3" />
                </a>
              </p>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleAccept} size="sm" className="flex-1">
                Accept
              </Button>
              <Button onClick={handleDecline} size="sm" variant="outline" className="flex-1 bg-transparent">
                Decline
              </Button>
            </div>
          </div>
          <Button variant="ghost" size="icon" className="h-6 w-6 flex-shrink-0" onClick={handleDecline}>
            <X className="h-4 w-4" />
          </Button>
        </div>
      </Card>
    </div>
  )
}
