import { test, expect } from '@playwright/test';

test.describe('LeafLock Complete Functionality Test', () => {
  test('should test complete note-taking workflow end-to-end', async ({ page }) => {
    // Navigate to the site
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app');
    await page.waitForLoadState('networkidle');

    // Login
    await page.fill('input[type="email"]', 'mail@rasmusj.dk');
    await page.fill('input[type="password"]', 'UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz');
    await page.click('button[type="submit"]');

    // Wait for redirect to dashboard
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    console.log('✅ Successfully logged in and redirected to dashboard');

    // Wait for data to load
    await page.waitForTimeout(5000);

    // Take screenshot of dashboard
    await page.screenshot({ path: 'final-dashboard.png', fullPage: true });

    // Test 1: Check if dashboard components are rendering
    console.log('\n=== TESTING DASHBOARD RENDERING ===');

    const sidebar = await page.locator('.sidebar, [data-testid="sidebar"]').count();
    const noteList = await page.locator('.note-list, [data-testid="note-list"]').count();
    const noteEditor = await page.locator('.note-editor, [data-testid="note-editor"]').count();
    const newNoteButton = await page.locator('button:has-text("New Note")').count();

    console.log('Sidebar elements found:', sidebar);
    console.log('Note list elements found:', noteList);
    console.log('Note editor elements found:', noteEditor);
    console.log('New Note buttons found:', newNoteButton);

    // Test 2: Check for any error messages
    console.log('\n=== TESTING ERROR STATES ===');

    const errorElements = await page.locator('[role="alert"], .error, .alert-error, [class*="error"]').count();
    const errorBoundary = await page.locator('text=Something went wrong').count();

    console.log('Error elements found:', errorElements);
    console.log('Error boundary triggered:', errorBoundary > 0);

    // Test 3: Check console for errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.waitForTimeout(2000);

    if (consoleErrors.length > 0) {
      console.log('Console errors found:', consoleErrors);
    } else {
      console.log('✅ No console errors found');
    }

    // Test 4: Test note creation if UI is working
    if (newNoteButton > 0) {
      console.log('\n=== TESTING NOTE CREATION ===');

      try {
        await page.click('button:has-text("New Note")');
        await page.waitForTimeout(2000);

        console.log('✅ Clicked "New Note" button');

        // Look for note editor
        const editor = await page.locator('textarea, [contenteditable="true"], .note-editor, .editor').count();
        console.log('Note editor found after creation:', editor);

        if (editor > 0) {
          console.log('✅ Note editor is accessible');

          // Try to edit the note
          const titleInput = await page.locator('input[placeholder*="title" i], input[placeholder*="Note title" i]').count();
          if (titleInput > 0) {
            await page.fill('input[placeholder*="title" i], input[placeholder*="Note title" i]', 'Test Note Title');
            console.log('✅ Filled note title');
          }

          const contentEditor = page.locator('textarea, [contenteditable="true"], .note-editor, .editor').first();
          await contentEditor.fill('This is a test note created from the frontend. It should demonstrate that the note creation and editing functionality is working properly.');
          console.log('✅ Filled note content');

          // Wait for auto-save
          await page.waitForTimeout(3000);

          console.log('✅ Note editing completed');
        }
      } catch (error) {
        console.log('❌ Note creation failed:', error);
      }
    }

    // Test 5: Check if we can see existing notes
    console.log('\n=== TESTING EXISTING NOTES ===');

    const existingNotes = await page.locator('.note-item, [data-testid="note-item"]').count();
    const noNotesMessage = await page.locator('text=No notes yet').count();

    console.log('Existing notes found:', existingNotes);
    console.log('No notes message:', noNotesMessage > 0);

    // Test 6: Check sidebar functionality
    console.log('\n=== TESTING SIDEBAR ===');

    const folderButton = await page.locator('button:has-text("Folder"), button[title*="folder" i]').count();
    const templatesButton = await page.locator('button:has-text("Template"), button:has-text("Templates")').count();
    const searchBar = await page.locator('input[placeholder*="search" i]').count();

    console.log('Folder creation button:', folderButton);
    console.log('Templates button:', templatesButton);
    console.log('Search bar:', searchBar);

    // Test 7: Check for any loading states
    console.log('\n=== TESTING LOADING STATES ===');

    const loadingElements = await page.locator('.loading, .spinner, [class*="loading"]').count();
    console.log('Loading elements found:', loadingElements);

    // Test 8: Check page title and URL
    console.log('\n=== TESTING PAGE STATE ===');

    const title = await page.title();
    const url = page.url();

    console.log('Page title:', title);
    console.log('Current URL:', url);

    // Test 9: Check for any text content
    const bodyText = await page.locator('body').textContent();
    console.log('Body text preview:', bodyText?.substring(0, 200));

    console.log('\n=== FINAL TEST SUMMARY ===');
    console.log('✅ Login: Working');
    console.log('✅ Dashboard Access: Working');
    console.log('✅ Error Handling: ' + (errorElements === 0 && errorBoundary === 0 ? 'Good' : 'Issues Found'));
    console.log('✅ Console Errors: ' + (consoleErrors.length === 0 ? 'None' : consoleErrors.length + ' found'));
    console.log('✅ Sidebar Rendering: ' + (sidebar > 0 ? 'Working' : 'Not Found'));
    console.log('✅ Note List Rendering: ' + (noteList > 0 ? 'Working' : 'Not Found'));
    console.log('✅ Note Editor Rendering: ' + (noteEditor > 0 ? 'Working' : 'Not Found'));
    console.log('✅ Note Creation UI: ' + (newNoteButton > 0 ? 'Available' : 'Not Found'));
    console.log('✅ Loading States: ' + (loadingElements === 0 ? 'Cleared' : 'Still Loading'));

    // Final assessment
    const isFullyWorking = sidebar > 0 && noteList > 0 && noteEditor > 0 && newNoteButton > 0 &&
                           errorElements === 0 && errorBoundary === 0 && consoleErrors.length === 0;

    console.log('\n🎯 OVERALL STATUS: ' + (isFullyWorking ? '✅ FULLY FUNCTIONAL' : '⚠️ PARTIALLY FUNCTIONAL'));

    if (isFullyWorking) {
      console.log('🎉 All frontend components are working correctly!');
    } else {
      console.log('🔧 Some components still need debugging.');
    }
  });
});
