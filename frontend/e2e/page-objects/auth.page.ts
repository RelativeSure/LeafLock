import { expect, type Locator, type Page } from '@playwright/test'

export class AuthPage {
  readonly page: Page
  readonly emailInput: Locator
  readonly passwordInput: Locator
  readonly confirmPasswordInput: Locator
  readonly loginButton: Locator
  readonly registerButton: Locator
  readonly toggleToRegisterLink: Locator
  readonly toggleToLoginLink: Locator

  constructor(page: Page) {
    this.page = page
    this.emailInput = page.locator('input[type="email"]')
    this.passwordInput = page.locator('input[type="password"]').first()
    this.confirmPasswordInput = page.locator('input[type="password"]').nth(1)
    this.loginButton = page.getByRole('button', { name: /sign in/i })
    this.registerButton = page.getByRole('button', { name: /sign up/i })
    this.toggleToRegisterLink = page.getByText(/sign up/i)
    this.toggleToLoginLink = page.getByText(/sign in/i)
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
    await this.confirmPasswordInput.fill(password)
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