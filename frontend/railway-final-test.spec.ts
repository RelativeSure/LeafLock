import { test, expect } from '@playwright/test'

test('Railway deployment should work without JavaScript errors', async ({ page }) => {
  const errors: string[] = []

  page.on('pageerror', (error) => {
    errors.push(error.message)
    console.log('❌ JavaScript error:', error.message)
  })

  console.log('🌐 Navigating to Railway deployment...')
  await page.goto('https://frontend-leaflock-pr-363.up.railway.app')
  await page.waitForLoadState('networkidle')
  await page.waitForTimeout(5000)

  console.log(`Found ${errors.length} JavaScript errors`)

  if (errors.length > 0) {
    console.log('Errors:', errors)
  }

  // Check if React mounted
  const hasContent = await page.locator('body').textContent()
  console.log('Body has content:', hasContent && hasContent.length > 100)

  // Check for LeafLock text
  const leafLockText = await page.locator('text=LeafLock').count()
  console.log('Found LeafLock text elements:', leafLockText)

  // Check for navigation menu
  const navMenu = await page.locator('[role="navigation"]').count()
  console.log('Found navigation menu elements:', navMenu)

  // Check for buttons
  const buttons = await page.locator('button').count()
  console.log('Found button elements:', buttons)

  // Take a screenshot for debugging
  await page.screenshot({ path: 'railway-final-test.png', fullPage: true })
  console.log('📸 Screenshot saved as railway-final-test.png')

  // The test passes if we have no JavaScript errors
  expect(errors.length).toBe(0)

  if (errors.length === 0) {
    console.log('✅ SUCCESS: Railway deployment is working without JavaScript errors!')
  }
})
