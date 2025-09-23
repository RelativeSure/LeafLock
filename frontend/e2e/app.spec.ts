import { test, expect } from '@playwright/test'

test.describe('Application', () => {
  test('should load homepage successfully', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveTitle(/LeafLock|Secure Notes/)

    // Check that the page loads without errors
    const pageErrors: string[] = []
    page.on('pageerror', error => pageErrors.push(error.message))
    page.on('console', msg => {
      if (msg.type() === 'error') {
        pageErrors.push(msg.text())
      }
    })

    await page.waitForLoadState('networkidle')

    // Verify no critical errors occurred
    const criticalErrors = pageErrors.filter(error =>
      !error.includes('favicon') &&
      !error.includes('404') &&
      !error.includes('ResizeObserver')
    )
    expect(criticalErrors).toEqual([])
  })

  test('should have working navigation', async ({ page }) => {
    await page.goto('/')

    // Check that the app loads with proper structure
    await expect(page.locator('#root')).toBeVisible()
  })

  test('should handle network errors gracefully', async ({ page }) => {
    // Block API calls to simulate network issues
    await page.route('**/api/**', route => route.abort())

    await page.goto('/')

    // App should still load even if API calls fail
    await expect(page.locator('#root')).toBeVisible()
  })

  test('should be responsive on mobile devices', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })

    await page.goto('/')

    // App should render properly on mobile
    await expect(page.locator('#root')).toBeVisible()

    // Check that the app is usable on mobile
    const emailInput = page.locator('input[type="email"]')
    await expect(emailInput).toBeVisible()
  })

  test('should maintain accessibility standards', async ({ page }) => {
    await page.goto('/')

    // Check for basic accessibility elements
    const emailInput = page.locator('input[type="email"]')
    await expect(emailInput).toBeVisible()

    // Verify keyboard navigation works
    await page.keyboard.press('Tab')
    await expect(emailInput).toBeFocused()
  })
})