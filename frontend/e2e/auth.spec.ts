import { test, expect } from './fixtures/auth-setup'
import { generateUniqueEmail } from './fixtures/test-data'

test.describe('Authentication', () => {
  test('should display login form on homepage', async ({ authPage }) => {
    await authPage.goto()
    await authPage.expectToBeOnAuthPage()
  })

  test('should register a new user successfully', async ({ authPage }) => {
    const email = generateUniqueEmail()
    const password = 'VerySecurePassword123!'

    await authPage.goto()
    await authPage.register(email, password)
    await authPage.expectToBeRedirectedToNotes()
  })

  test('should login existing user successfully', async ({ authPage }) => {
    // First register a user
    const email = generateUniqueEmail()
    const password = 'VerySecurePassword123!'

    await authPage.goto()
    await authPage.register(email, password)
    await authPage.expectToBeRedirectedToNotes()

    // Logout (navigate to home to trigger logout in this simple test)
    await authPage.goto()

    // Then login with same credentials
    await authPage.login(email, password)
    await authPage.expectToBeRedirectedToNotes()
  })

  test('should show error for invalid login', async ({ authPage, page }) => {
    await authPage.goto()
    await authPage.login('invalid@example.com', 'wrongpassword')

    // Expect to stay on auth page (not redirected)
    await expect(page).toHaveURL('/')
    await authPage.expectToBeOnAuthPage()
  })

  test('should validate password requirements', async ({ authPage, page }) => {
    const email = generateUniqueEmail()

    await authPage.goto()
    await authPage.toggleToRegisterLink.click()

    // Try with weak password
    await authPage.emailInput.fill(email)
    await authPage.passwordInput.fill('123')
    await authPage.registerButton.click()

    // Should stay on registration page
    await expect(page).toHaveURL('/')
  })

  test('should show password strength indicator during registration', async ({ authPage, page }) => {
    const email = generateUniqueEmail()

    await authPage.goto()
    await authPage.toggleToRegisterLink.click()

    await authPage.emailInput.fill(email)

    // Password strength indicator should be visible when registering
    await authPage.passwordInput.fill('VerySecurePassword123!')

    // Check that we're still in registration mode (password strength visible)
    await expect(page.locator('text=Use 12+ characters')).toBeVisible()
  })
})