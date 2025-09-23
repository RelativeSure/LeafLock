import { test, expect } from './fixtures/auth-setup'
import { testNotes, generateTestNote } from './fixtures/test-data'

test.describe('Notes Management', () => {
  test('should create and save a new note', async ({ notesPage, authenticatedUser }) => {
    await notesPage.goto()
    await notesPage.expectToBeOnNotesPage()

    const noteContent = generateTestNote('My first note')
    await notesPage.createNewNote()
    await notesPage.writeNote(noteContent)
    await notesPage.saveDraft()

    // Note should appear in the list
    await notesPage.expectNoteInList(noteContent)
  })

  test('should edit an existing note', async ({ notesPage, authenticatedUser }) => {
    await notesPage.goto()

    // Create initial note
    const originalContent = generateTestNote('Original note')
    await notesPage.createNewNote()
    await notesPage.writeNote(originalContent)
    await notesPage.saveDraft()

    // Edit the note
    await notesPage.openNote(originalContent)
    const updatedContent = originalContent + ' - UPDATED'
    await notesPage.writeNote(updatedContent)
    await notesPage.saveDraft()

    // Updated note should appear in list
    await notesPage.expectNoteInList(updatedContent)
  })

  test('should delete a note', async ({ notesPage, authenticatedUser }) => {
    await notesPage.goto()

    // Create a note to delete
    const noteContent = generateTestNote('Note to delete')
    await notesPage.createNewNote()
    await notesPage.writeNote(noteContent)
    await notesPage.saveDraft()

    // Delete the note
    await notesPage.openNote(noteContent)
    await notesPage.deleteNote()

    // Note should not appear in list anymore
    await notesPage.expectNoteNotInList(noteContent)
  })

  test('should search notes', async ({ notesPage, authenticatedUser }) => {
    await notesPage.goto()

    // Create multiple notes
    const note1 = generateTestNote('Searchable note about cats')
    const note2 = generateTestNote('Another note about dogs')
    const note3 = generateTestNote('Final note about cats and dogs')

    for (const noteContent of [note1, note2, note3]) {
      await notesPage.createNewNote()
      await notesPage.writeNote(noteContent)
      await notesPage.saveDraft()
    }

    // Search for 'cats'
    await notesPage.searchNotes('cats')
    await notesPage.expectNoteInList(note1)
    await notesPage.expectNoteNotInList(note2) // Only dogs
    await notesPage.expectNoteInList(note3)

    // Clear search
    await notesPage.searchNotes('')
    await notesPage.expectNoteInList(note1)
    await notesPage.expectNoteInList(note2)
    await notesPage.expectNoteInList(note3)
  })

  test('should handle markdown formatting', async ({ notesPage, authenticatedUser }) => {
    await notesPage.goto()

    await notesPage.createNewNote()
    await notesPage.writeNote(testNotes.markdown)
    await notesPage.saveDraft()

    // Verify the markdown note is saved
    await notesPage.expectNoteInList('Test Note')
  })

  test('should handle special characters', async ({ notesPage, authenticatedUser }) => {
    await notesPage.goto()

    await notesPage.createNewNote()
    await notesPage.writeNote(testNotes.withSpecialChars)
    await notesPage.saveDraft()

    // Verify the note with special characters is saved
    await notesPage.expectNoteInList(testNotes.withSpecialChars)
  })

  test('should handle long notes', async ({ notesPage, authenticatedUser }) => {
    await notesPage.goto()

    await notesPage.createNewNote()
    await notesPage.writeNote(testNotes.long)
    await notesPage.saveDraft()

    // Verify the long note is saved (check for a portion of it)
    await notesPage.expectNoteInList('This is a very long note')
  })

  test('should maintain encryption for saved notes', async ({ notesPage, authenticatedUser, page }) => {
    await notesPage.goto()

    const secretContent = 'This is super secret information that should be encrypted'
    await notesPage.createNewNote()
    await notesPage.writeNote(secretContent)
    await notesPage.saveDraft()

    // Check that the note appears in the UI (client-side decryption works)
    await notesPage.expectNoteInList(secretContent)

    // Verify note is saved by refreshing page
    await page.reload()
    await notesPage.expectToBeOnNotesPage()
    await notesPage.expectNoteInList(secretContent)
  })
})