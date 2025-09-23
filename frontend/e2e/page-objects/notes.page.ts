import { expect, type Locator, type Page } from '@playwright/test'

export class NotesPage {
  readonly page: Page
  readonly newNoteButton: Locator
  readonly notesList: Locator
  readonly searchInput: Locator
  readonly noteEditor: Locator
  readonly saveDraftButton: Locator
  readonly publishButton: Locator
  readonly deleteButton: Locator
  readonly logoutButton: Locator

  constructor(page: Page) {
    this.page = page
    this.newNoteButton = page.getByRole('button', { name: /new note/i })
    this.notesList = page.locator('[data-testid="notes-list"]')
    this.searchInput = page.locator('input[placeholder*="search" i]')
    this.noteEditor = page.locator('.ProseMirror')
    this.saveDraftButton = page.getByRole('button', { name: /save.*draft/i })
    this.publishButton = page.getByRole('button', { name: /publish/i })
    this.deleteButton = page.getByRole('button', { name: /delete/i })
    this.logoutButton = page.getByRole('button', { name: /logout/i })
  }

  async goto() {
    await this.page.goto('/notes')
  }

  async expectToBeOnNotesPage() {
    await expect(this.page).toHaveURL(/\/notes/)
    await expect(this.newNoteButton).toBeVisible()
  }

  async createNewNote() {
    await this.newNoteButton.click()
    await expect(this.noteEditor).toBeVisible()
  }

  async writeNote(content: string) {
    await this.noteEditor.click()
    await this.noteEditor.fill(content)
  }

  async saveDraft() {
    await this.saveDraftButton.click()
  }

  async publishNote() {
    await this.publishButton.click()
  }

  async deleteNote() {
    await this.deleteButton.click()
    // Confirm deletion if there's a confirmation dialog
    const confirmButton = this.page.getByRole('button', { name: /confirm|delete|yes/i })
    if (await confirmButton.isVisible({ timeout: 1000 })) {
      await confirmButton.click()
    }
  }

  async searchNotes(query: string) {
    await this.searchInput.fill(query)
    await this.page.waitForTimeout(500) // Wait for search debounce
  }

  async expectNoteInList(content: string) {
    await expect(this.notesList.getByText(content, { exact: false })).toBeVisible()
  }

  async expectNoteNotInList(content: string) {
    await expect(this.notesList.getByText(content, { exact: false })).not.toBeVisible()
  }

  async openNote(content: string) {
    await this.notesList.getByText(content, { exact: false }).click()
    await expect(this.noteEditor).toBeVisible()
  }

  async logout() {
    await this.logoutButton.click()
  }
}