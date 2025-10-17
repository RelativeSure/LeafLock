import { test, expect } from '@playwright/test'
import type { Route } from '@playwright/test'

const PASSWORD = 'Playwright123!#'
const SALT_BYTES = Uint8Array.from([
  12, 54, 98, 210, 45, 67, 189, 240, 121, 34, 200, 156, 43, 87, 165, 78, 11, 234, 156, 4, 88, 199,
  32, 58, 174, 201, 14, 65, 173, 250, 92, 39,
])
const SALT_BASE64 = Buffer.from(SALT_BYTES).toString('base64')

const createJwt = (payload: Record<string, unknown>): string => {
  const base64Url = (value: string) =>
    Buffer.from(value)
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
  const header = base64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const body = base64Url(JSON.stringify(payload))
  return `${header}.${body}.signature`
}

const corsHeaders = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'Content-Type, Authorization, X-CSRF-Token',
  'access-control-allow-methods': 'GET,POST,OPTIONS',
}

test.describe('Import/Export dialog', () => {
  test('supports closing and export actions', async ({ page }) => {
    let nowIso = new Date().toISOString()

    const consoleWarnings: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'warning' || msg.type() === 'error') {
        consoleWarnings.push(msg.text())
      }
    })

    await page.addInitScript(({ salt }) => {
      window.localStorage.setItem('user_salt', salt)
      window.localStorage.setItem('hasSeenOnboarding', 'true')
    }, { salt: SALT_BASE64 })

    const token = createJwt({
      user_id: 'user-123',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })

    const fulfillJson = (route: Route, body: unknown) =>
      route.fulfill({
        status: 200,
        headers: {
          ...corsHeaders,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      })

    const fulfillOptions = (route: Route) =>
      route.fulfill({
        status: 200,
        headers: corsHeaders,
      })

    await page.route('**/api/v1/auth/registration', (route) => {
      if (route.request().method() === 'OPTIONS') return fulfillOptions(route)
      return fulfillJson(route, { enabled: true })
    })

    await page.route('**/api/v1/announcements', (route) => {
      if (route.request().method() === 'OPTIONS') return fulfillOptions(route)
      return fulfillJson(route, { announcements: [] })
    })

    await page.route('**/api/v1/auth/login', (route) => {
      if (route.request().method() === 'OPTIONS') return fulfillOptions(route)
      const payload = route.request().postDataJSON() ?? {}
      expect(payload.email).toBeTruthy()
      expect(payload.password).toBeTruthy()
      return fulfillJson(route, {
        message: 'Login successful',
        token,
        user_id: 'user-123',
        workspace_id: 'workspace-1',
      })
    })

    await page.route('**/api/v1/admin/health', (route) => {
      if (route.request().method() === 'OPTIONS') return fulfillOptions(route)
      return fulfillJson(route, { status: 'ok' })
    })

    let lastNoteTimestamp = new Date().toISOString()
    const notePlainTitle = 'Playwright Test Note'
    const notePlainContent = 'This is a Playwright-generated note.'
    const encryptedNote = {
      id: 'note-1',
      title_encrypted: JSON.stringify(notePlainTitle),
      content_encrypted: JSON.stringify(JSON.stringify(notePlainContent)),
      created_at: lastNoteTimestamp,
      updated_at: lastNoteTimestamp,
    }

    await page.addInitScript(
      ({ exportResponse }) => {
        const originalFetch = window.fetch.bind(window)
        ;(window as any).__ACCOUNT_EXPORT_CALLED__ = false
        window.fetch = async (...args: Parameters<typeof fetch>) => {
          const input = args[0]
          const url = typeof input === 'string' ? input : input.url
          if (url.includes('/api/v1/account/export')) {
            ;(window as any).__ACCOUNT_EXPORT_CALLED__ = true
            try {
              const response = await originalFetch(...args)
              if (!response || !response.ok) {
                throw new Error('fallback')
              }
              return response
            } catch {
              return new Response(JSON.stringify(exportResponse), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
              })
            }
          }
          return originalFetch(...args)
        }
      },
      {
        exportResponse: {
          version: '1.0',
          exported_at: new Date().toISOString(),
          user: { email: 'tester@example.com', created_at: new Date().toISOString() },
          notes: [
            {
              id: 'note-1',
              title: notePlainTitle,
              content: notePlainContent,
            },
          ],
        },
      }
    )

    await page.route('**/api/v1/notes', (route) => {
      if (route.request().method() === 'OPTIONS') return fulfillOptions(route)
      if (route.request().method() === 'GET') {
        lastNoteTimestamp = new Date().toISOString()
        return fulfillJson(route, {
          notes: [{ ...encryptedNote, created_at: lastNoteTimestamp, updated_at: lastNoteTimestamp }],
        })
      }
      return fulfillJson(route, { success: true })
    })

    const storageInfo = {
      storage_used: 25_600,
      storage_limit: 5 * 1024 * 1024,
      storage_remaining: 5 * 1024 * 1024 - 25_600,
      usage_percentage: (25_600 / (5 * 1024 * 1024)) * 100,
    }
    await page.route('**/api/v1/user/storage', (route) => {
      if (route.request().method() === 'OPTIONS') return fulfillOptions(route)
      return fulfillJson(route, storageInfo)
    })

    let noteExportCalled = false
    await page.route('**/api/v1/notes/note-1/export', (route) => {
      if (route.request().method() === 'OPTIONS') return fulfillOptions(route)
      const body = route.request().postDataJSON()
      expect(body).toEqual({ format: 'markdown' })
      noteExportCalled = true
      return fulfillJson(route, {
        content: '# Exported Content',
        filename: 'note-1.md',
        format: 'markdown',
      })
    })

    await page.goto('/')

    await page.getByLabel('Email').fill('tester@example.com')
    await page.locator('input[name="password"]').fill(PASSWORD)
    await page.getByRole('button', { name: 'Login' }).click()

    const importExportTrigger = page.getByRole('button', { name: 'Import/Export' })
    await expect(importExportTrigger).toBeVisible()

    await expect(
      page.locator('[data-note-button]').filter({ hasText: notePlainTitle }).first()
    ).toContainText(notePlainTitle)

    await importExportTrigger.click()

    const dialog = page.getByRole('dialog', { name: 'Import & Export Notes' })
    await expect(dialog).toBeVisible()

    await dialog
      .getByRole('button', { name: 'Close' })
      .first()
      .evaluate((button) => (button as HTMLButtonElement).click())
    await expect(dialog).toBeHidden()

    await importExportTrigger.click()
    await expect(dialog).toBeVisible()

    const noteExportAlert = page.waitForEvent('dialog')
    const dialogExportButton = dialog.getByRole('button', { name: /Export as/i })
    await Promise.all([
      page.waitForRequest('**/api/v1/notes/note-1/export'),
      dialogExportButton.click(),
    ])
    const exportDialog = await noteExportAlert
    expect(exportDialog.message()).toContain('Export successful')
    await exportDialog.accept()
    expect(noteExportCalled).toBe(true)

    const accountExportAlert = page.waitForEvent('dialog')
    const accountExportButton = dialog.getByRole('button', { name: 'Export Everything' })
    await accountExportButton.scrollIntoViewIfNeeded()
    await accountExportButton.evaluate((button) => (button as HTMLButtonElement).click())
    const accountDialog = await accountExportAlert
    expect(accountDialog.message()).toContain('Your full data export has started downloading')
    await accountDialog.accept()
    const accountExportFlag = await page.evaluate(
      () => Boolean((window as any).__ACCOUNT_EXPORT_CALLED__)
    )
    expect(accountExportFlag).toBe(true)
    expect(consoleWarnings.some((msg) => msg.includes('Missing Description'))).toBe(false)
  })
})
