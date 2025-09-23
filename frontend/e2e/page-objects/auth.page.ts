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
    await this.loginButton.click()
  }

  async register(email: string, password: string) {
    await this.toggleToRegisterLink.click()
    await this.emailInput.fill(email)
    await this.passwordInput.fill(password)
    await this.registerButton.click()
  }

  async expectToBeOnAuthPage() {
    await expect(this.emailInput).toBeVisible()
    await expect(this.passwordInput).toBeVisible()
  }

  async expectToBeRedirectedToNotes() {
    await this.page.waitForURL('**/notes')
    await expect(this.page).toHaveURL(/\/notes/)
  }
}