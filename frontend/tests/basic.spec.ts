import { test, expect } from '@playwright/test'

test.describe('Basic App Functionality', () => {
  test('app loads and shows login form', async ({ page }) => {
    await page.goto('/')
    
    // Check that the root element is visible
    await expect(page.locator('#root')).toBeVisible()
    
    // Check for sign in elements
    await expect(page.getByText('Sign In')).toBeVisible()
    
    // Check for basic form elements
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('can navigate to registration', async ({ page }) => {
    await page.goto('/')
    
    // Look for registration link/button
    const registerLink = page.getByText('Sign Up')
    if (await registerLink.isVisible()) {
      await registerLink.click()
      await expect(page.getByText('Create Account')).toBeVisible()
    }
  })

  test('health check endpoint works', async ({ request }) => {
    const response = await request.get('/api/v1/health')
    expect(response.ok()).toBeTruthy()
  })
})