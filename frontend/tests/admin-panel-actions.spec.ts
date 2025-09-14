import { test, expect } from '@playwright/test'

test.beforeEach(async ({ context }) => {
  const token = process.env.E2E_TOKEN || ''
  await context.addInitScript((t) => {
    if (t) localStorage.setItem('secure_token', t as string)
  }, token)
})

test('Admin can load roles and assign/remove role via UI', async ({ page }) => {
  const base = process.env.BASE_URL || 'http://localhost:3000'
  const userId = process.env.E2E_USER_ID || ''

  await page.goto(base)

  // Open admin section
  const summary = page.getByText('Admin')
  await expect(summary).toBeVisible()
  await summary.click()

  // Fill user id
  const userInput = page.getByPlaceholder('User ID (UUID)')
  await userInput.fill(userId)

  // Load roles
  await page.getByRole('button', { name: 'Load Roles' }).click()
  await expect(page.getByText('Current roles:')).toBeVisible()

  // Assign moderator
  await page.getByRole('button', { name: 'Assign Role' }).click()
  await expect(page.getByText('Assigned moderator')).toBeVisible()

  // Remove moderator
  await page.getByRole('button', { name: 'Remove Role' }).click()
  await expect(page.getByText('Removed moderator')).toBeVisible()
})

