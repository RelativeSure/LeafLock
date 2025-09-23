import { test as base, expect } from '@playwright/test'
import { AuthPage } from '../page-objects/auth.page'
import { NotesPage } from '../page-objects/notes.page'
import { generateUniqueEmail } from './test-data'

type TestFixtures = {
  authPage: AuthPage
  notesPage: NotesPage
  authenticatedUser: { email: string; password: string }
}

export const test = base.extend<TestFixtures>({
  authPage: async ({ page }, use) => {
    const authPage = new AuthPage(page)
    await use(authPage)
  },

  notesPage: async ({ page }, use) => {
    const notesPage = new NotesPage(page)
    await use(notesPage)
  },

  authenticatedUser: async ({ authPage }, use) => {
    const email = generateUniqueEmail()
    const password = 'VerySecurePassword123!'

    await authPage.goto()
    await authPage.register(email, password)
    await authPage.expectToBeRedirectedToNotes()

    await use({ email, password })
  },
})

export { expect } from '@playwright/test'