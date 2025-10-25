import { test, expect } from '@playwright/test'

test.describe('Railway Deployment Debug Test', () => {
  test('should debug what is on the page', async ({ page }) => {
    // Navigate to the Railway deployment
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app')

    // Wait for the page to load
    await page.waitForLoadState('networkidle')

    // Take a screenshot for debugging
    await page.screenshot({ path: 'railway-debug.png', fullPage: true })

    // Get page title
    const title = await page.title()
    console.log('Page title:', title)

    // Get all text content
    const bodyText = await page.locator('body').textContent()
    console.log('Body text:', bodyText?.substring(0, 500))

    // Check for any h1 elements
    const h1Elements = await page.locator('h1').all()
    console.log('Found h1 elements:', h1Elements.length)

    // Check for any elements with LeafLock text
    const leafLockElements = await page.locator('text=LeafLock').all()
    console.log('Found LeafLock elements:', leafLockElements.length)

    // Check for navigation elements
    const navElements = await page.locator('[role="navigation"]').all()
    console.log('Found navigation elements:', navElements.length)

    // Check for any buttons
    const buttons = await page.locator('button').all()
    console.log('Found buttons:', buttons.length)

    // Check console errors
    const errors: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text())
        console.log('Console error:', msg.text())
      }
    })

    // Wait a bit more to catch any delayed errors
    await page.waitForTimeout(3000)

    console.log('Total console errors:', errors.length)

    // Just check if the page loads without crashing
    expect(page.url()).toContain('railway.app')
  })
})
