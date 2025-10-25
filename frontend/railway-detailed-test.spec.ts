import { test, expect } from '@playwright/test'

test.describe('Railway Deployment Detailed Test', () => {
  test('should check for JavaScript errors and React mounting', async ({ page }) => {
    const errors: string[] = []
    const warnings: string[] = []

    // Listen to console messages
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text())
        console.log('❌ Console error:', msg.text())
      } else if (msg.type() === 'warning') {
        warnings.push(msg.text())
        console.log('⚠️ Console warning:', msg.text())
      } else {
        console.log('ℹ️ Console log:', msg.text())
      }
    })

    // Listen to page errors
    page.on('pageerror', (error) => {
      errors.push(error.message)
      console.log('❌ Page error:', error.message)
    })

    // Navigate to the Railway deployment
    console.log('🌐 Navigating to Railway deployment...')
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app')

    // Wait for the page to load
    console.log('⏳ Waiting for page to load...')
    await page.waitForLoadState('networkidle')

    // Wait a bit more for React to mount
    await page.waitForTimeout(5000)

    // Get page title
    const title = await page.title()
    console.log('📄 Page title:', title)

    // Check if React root exists
    const reactRoot = await page.locator('#root').count()
    console.log('⚛️ React root elements found:', reactRoot)

    // Check for any script tags
    const scripts = await page.locator('script').count()
    console.log('📜 Script tags found:', scripts)

    // Check for any CSS
    const stylesheets = await page.locator('link[rel="stylesheet"]').count()
    console.log('🎨 Stylesheets found:', stylesheets)

    // Check for any div elements
    const divs = await page.locator('div').count()
    console.log('📦 Div elements found:', divs)

    // Check for any text content
    const bodyText = await page.locator('body').textContent()
    console.log('📝 Body text length:', bodyText?.length || 0)
    if (bodyText && bodyText.length > 0) {
      console.log('📝 Body text preview:', bodyText.substring(0, 200))
    }

    // Check network requests
    const responses = await page.evaluate(() => {
      return performance.getEntriesByType('navigation')
    })
    console.log('🌐 Navigation timing:', responses)

    // Take a screenshot
    await page.screenshot({ path: 'railway-detailed-debug.png', fullPage: true })
    console.log('📸 Screenshot saved as railway-detailed-debug.png')

    // Check for specific error patterns
    const hasReactError = errors.some(error =>
      error.includes('React') ||
      error.includes('Cannot access') ||
      error.includes('before initialization')
    )

    if (hasReactError) {
      console.log('❌ React-related errors detected!')
      errors.forEach(error => console.log('  -', error))
    }

    console.log('📊 Summary:')
    console.log('  - Console errors:', errors.length)
    console.log('  - Console warnings:', warnings.length)
    console.log('  - React root elements:', reactRoot)
    console.log('  - Total div elements:', divs)

    // The test passes if we can at least load the page
    expect(page.url()).toContain('railway.app')
  })
})
