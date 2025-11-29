/**
 * Mobile Detection Hook
 * 
 * @description
 * React hook for detecting mobile device viewport sizes using window.matchMedia.
 * Provides responsive behavior by tracking viewport width against a breakpoint threshold.
 * 
 * @usage
 * const isMobile = useIsMobile()
 * 
 * return (
 *   <div>
 *     {isMobile ? <MobileComponent /> : <DesktopComponent />}
 *   </div>
 * )
 * 
 * @breakpoint
 * Default mobile breakpoint: 768px (standard tablet portrait threshold)
 * Returns true when viewport width < 768px
 * 
 * @performance
 * - Uses matchMedia API for efficient viewport tracking
 * - Event listener cleanup on unmount
 * - Initial state set synchronously to prevent layout shift
 */
import * as React from 'react'

const MOBILE_BREAKPOINT = 768

/**
 * Detects if current viewport is mobile-sized
 * 
 * @returns boolean - true if viewport width < 768px, false otherwise
 * @default false - Returns false during SSR or before client-side hydration
 * 
 * @implementation
 * - Uses window.matchMedia for efficient breakpoint detection
 * - Updates state on viewport resize events
 * - Handles initial render and subsequent viewport changes
 * 
 * @accessibility
 * Helps implement responsive design patterns for touch vs pointer interfaces
 */
export function useIsMobile() {
  const [isMobile, setIsMobile] = React.useState<boolean | undefined>(undefined)

  React.useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`)
    const onChange = () => {
      setIsMobile(window.innerWidth < MOBILE_BREAKPOINT)
    }
    mql.addEventListener('change', onChange)
    setIsMobile(window.innerWidth < MOBILE_BREAKPOINT)
    return () => mql.removeEventListener('change', onChange)
  }, [])

  return !!isMobile
}
