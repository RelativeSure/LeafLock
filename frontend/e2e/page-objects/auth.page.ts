import { expect, type Locator, type Page } from '@playwright/test'

export class AuthPage {
  readonly page: Page
  readonly emailInput: Locator
  readonly passwordInput: Locator
  readonly loginButton: Locator
  readonly registerButton: Locator
  readonly toggleToRegisterLink: Locator
  readonly toggleToLoginLink: Locator

  constructor(page: Page) {
    this.page = page
    this.emailInput = page.locator('input[type="email"]')
    this.passwordInput = page.locator('input[type="password"]')
    this.loginButton = page.getByRole('button', { name: 'Login' })
    this.registerButton = page.getByRole('button', { name: 'Create Account' })
    this.toggleToRegisterLink = page.getByRole('button', { name: 'Need an account? Register' })
    this.toggleToLoginLink = page.getByRole('button', { name: 'Already have an account? Login' })
  }

  async goto() {
    await this.page.goto('/')
  }

  async login(email: string, password: string) {
    await this.emailInput.fill(email)
    await this.passwordInput.fill(password)

    // Wait for the login button to be ready and click it
    await expect(this.loginButton).toBeEnabled()
    await this.loginButton.click()

    // Wait for any loading state to complete
    await expect(this.loginButton).not.toHaveText('Processing...')
  }

  async register(email: string, password: string) {
    await this.toggleToRegisterLink.click()
    await this.emailInput.fill(email)
    await this.passwordInput.fill(password)

    // Wait for the register button to be ready and click it
    await expect(this.registerButton).toBeEnabled()
    await this.registerButton.click()

    // Wait for any loading state to complete
    await expect(this.registerButton).not.toHaveText('Processing...')
  }

  async expectToBeOnAuthPage() {
    await expect(this.emailInput).toBeVisible()
    await expect(this.passwordInput).toBeVisible()
  }

  async expectToBeRedirectedToNotes() {
    // Wait for the notes view to appear (app uses state-based routing, not URL routing)
    await expect(this.page.getByRole('button', { name: 'New Note' })).toBeVisible({ timeout: 10000 })
    // Additional verification that we're in the notes interface
    await expect(
      this.page.locator('[data-testid="notes-list"]')
        .or(this.page.getByText('No notes yet'))
        .or(this.page.getByText('No notes found'))
    ).toBeVisible()
  }
}