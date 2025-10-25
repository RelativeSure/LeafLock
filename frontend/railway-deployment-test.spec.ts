import { test, expect } from '@playwright/test'

test.describe('Railway Deployment Test', () => {
  test('should load the application and test navigation menu', async ({ page }) => {
    // Navigate to the Railway deployment
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app')

    // Wait for the page to load
    await page.waitForLoadState('networkidle')

    // Check if the page loads without JavaScript errors
    const errors: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text())
      }
    })

    // Check for the main application elements
    await expect(page.locator('h1')).toContainText('LeafLock')

    // Test navigation menu
    const navigationMenu = page.locator('[role="navigation"]')
    await expect(navigationMenu).toBeVisible()

    // Test Tools dropdown
    const toolsTrigger = page.locator('text=Tools').first()
    await expect(toolsTrigger).toBeVisible()
    await toolsTrigger.click()

    // Check if dropdown opens
    await expect(page.locator('text=Templates')).toBeVisible()
    await expect(page.locator('text=Tags')).toBeVisible()
    await expect(page.locator('text=Settings')).toBeVisible()

    // Test Resources dropdown
    const resourcesTrigger = page.locator('text=Resources').first()
    await expect(resourcesTrigger).toBeVisible()
    await resourcesTrigger.click()

    // Check if dropdown opens
    await expect(page.locator('text=Documentation')).toBeVisible()
    await expect(page.locator('text=GitHub')).toBeVisible()

    // Test login functionality
    const loginButton = page.locator('text=Sign In').first()
    if (await loginButton.isVisible()) {
      await loginButton.click()

      // Fill in login form
      await page.fill('input[type="email"]', 'mail@rasmusj.dk')
      await page.fill('input[type="password"]', 'UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz')

      // Submit login
      await page.click('button[type="submit"]')

      // Wait for redirect to dashboard
      await page.waitForURL('**/dashboard', { timeout: 10000 })

      // Check if dashboard loads
      await expect(page.locator('text=Dashboard')).toBeVisible()

      // Test navigation to settings page
      const settingsLink = page.locator('text=Settings').first()
      await settingsLink.click()

      // Wait for settings page to load
      await page.waitForURL('**/settings', { timeout: 5000 })

      // Check if settings page loads
      await expect(page.locator('text=Backup & Restore')).toBeVisible()
      await expect(page.locator('text=Export Backup')).toBeVisible()

      // Test navigation to templates page
      const templatesLink = page.locator('text=Templates').first()
      await templatesLink.click()

      // Wait for templates page to load
      await page.waitForURL('**/templates', { timeout: 5000 })

      // Check if templates page loads
      await expect(page.locator('text=My Templates')).toBeVisible()

      // Test navigation to tags page
      const tagsLink = page.locator('text=Tags').first()
      await tagsLink.click()

      // Wait for tags page to load
      await page.waitForURL('**/tags', { timeout: 5000 })

      // Check if tags page loads
      await expect(page.locator('text=Create New Tag')).toBeVisible()
    }

    // Check for any JavaScript errors
    if (errors.length > 0) {
      console.log('JavaScript errors found:', errors)
      throw new Error(`JavaScript errors detected: ${errors.join(', ')}`)
    }

    console.log('✅ All tests passed! Railway deployment is working correctly.')
  })
})
