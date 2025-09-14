import { test, expect } from '@playwright/test'

test('Admin section is visible when enabled', async ({ page }) => {
  await page.goto('/')

  // Admin summary should be present even before login if enabled by build flag
  const summary = page.getByText('Admin')
  await expect(summary).toBeVisible()

  // Expand details and expect login required note (since not logged in)
  await summary.click()
  await expect(page.getByText('Login required to use the admin panel.')).toBeVisible()
})

