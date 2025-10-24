import { useState, useCallback } from 'react'

export const useOnboarding = () => {
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [onboardingStep, setOnboardingStep] = useState(0)

  const handleOnboardingNext = useCallback(() => {
    setOnboardingStep((prev) => prev + 1)
  }, [])

  const handleOnboardingPrev = useCallback(() => {
    setOnboardingStep((prev) => Math.max(0, prev - 1))
  }, [])

  const handleOnboardingSkip = useCallback(() => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }, [])

  const handleOnboardingComplete = useCallback(() => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }, [])

  const checkAndShowOnboarding = useCallback(() => {
    const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding')
    if (!hasSeenOnboarding) {
      setShowOnboarding(true)
    }
  }, [])

  return {
    // State
    showOnboarding,
    onboardingStep,

    // Actions
    handleOnboardingNext,
    handleOnboardingPrev,
    handleOnboardingSkip,
    handleOnboardingComplete,
    checkAndShowOnboarding,
    setShowOnboarding,
  }
}
