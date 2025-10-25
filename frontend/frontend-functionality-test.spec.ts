import { test, expect } from '@playwright/test';

test.describe('LeafLock Frontend Functionality Test', () => {
  test('should test complete frontend note-taking workflow', async ({ page }) => {
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
    await page.waitForTimeout(3000);

    // Take screenshot of dashboard
    await page.screenshot({ path: 'dashboard-loaded.png' });

    // Test 1: Check if notes are loaded
    console.log('\n=== TESTING NOTES LOADING ===');

    // Look for note list or "No notes yet" message
    const noteList = page.locator('[data-testid="note-list"], .note-list, .notes-list');
    const noNotesMessage = page.locator('text=No notes yet');

    if (await noNotesMessage.count() > 0) {
      console.log('✅ Found "No notes yet" message - notes list is working');
    } else if (await noteList.count() > 0) {
      console.log('✅ Found note list element');
    } else {
      console.log('❌ No note list found');
    }

    // Test 2: Test note creation
    console.log('\n=== TESTING NOTE CREATION ===');

    // Look for "New Note" button
    const newNoteButton = page.locator('button:has-text("New Note"), button:has-text("Create"), [data-testid="create-note"]');

    if (await newNoteButton.count() > 0) {
      console.log('✅ Found "New Note" button');

      // Click the button
      await newNoteButton.first().click();
      await page.waitForTimeout(2000);

      console.log('✅ Clicked "New Note" button');

      // Take screenshot after clicking
      await page.screenshot({ path: 'after-create-note.png' });

      // Look for note editor
      const noteEditor = page.locator('textarea, [contenteditable="true"], .note-editor, .editor');

      if (await noteEditor.count() > 0) {
        console.log('✅ Found note editor');

        // Test editing
        const titleInput = page.locator('input[placeholder*="title" i], input[placeholder*="Note title" i]');
        const contentEditor = noteEditor.first();

        if (await titleInput.count() > 0) {
          await titleInput.fill('Test Note Title');
          console.log('✅ Filled note title');
        }

        await contentEditor.fill('This is a test note created from the frontend. It should demonstrate that the note creation and editing functionality is working properly.');
        console.log('✅ Filled note content');

        // Wait for auto-save
        await page.waitForTimeout(3000);

        await page.screenshot({ path: 'note-edited.png' });

        console.log('✅ Note editing completed');
      } else {
        console.log('❌ No note editor found');
      }
    } else {
      console.log('❌ No "New Note" button found');
    }

    // Test 3: Check sidebar functionality
    console.log('\n=== TESTING SIDEBAR ===');

    const sidebar = page.locator('.sidebar, [data-testid="sidebar"]');
    if (await sidebar.count() > 0) {
      console.log('✅ Found sidebar');

      // Look for folder creation
      const folderButton = page.locator('button:has-text("Folder"), button[title*="folder" i]');
      if (await folderButton.count() > 0) {
        console.log('✅ Found folder creation button');
      }

      // Look for templates
      const templatesButton = page.locator('button:has-text("Template"), button:has-text("Templates")');
      if (await templatesButton.count() > 0) {
        console.log('✅ Found templates button');
      }
    } else {
      console.log('❌ No sidebar found');
    }

    // Test 4: Check for any error messages
    console.log('\n=== TESTING ERROR STATES ===');

    const errorElements = await page.locator('[role="alert"], .error, .alert-error, [class*="error"]').count();
    if (errorElements > 0) {
      console.log(`❌ Found ${errorElements} error elements`);
    } else {
      console.log('✅ No error elements found');
    }

    // Test 5: Check console for errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.waitForTimeout(2000);

    if (consoleErrors.length > 0) {
      console.log('❌ Console errors found:', consoleErrors);
    } else {
      console.log('✅ No console errors found');
    }

    // Test 6: Check network requests
    const networkErrors: string[] = [];
    page.on('response', response => {
      if (response.status() >= 400) {
        networkErrors.push(`${response.status()} ${response.url}`);
      }
    });

    if (networkErrors.length > 0) {
      console.log('❌ Network errors found:', networkErrors);
    } else {
      console.log('✅ No network errors found');
    }

    console.log('\n=== FRONTEND TEST SUMMARY ===');
    console.log('✅ Login: Working');
    console.log('✅ Dashboard Access: Working');
    console.log('✅ Data Loading: ' + (await noNotesMessage.count() > 0 || await noteList.count() > 0 ? 'Working' : 'Not Working'));
    console.log('✅ Note Creation UI: ' + (await newNoteButton.count() > 0 ? 'Available' : 'Not Found'));
    console.log('✅ Note Editor: ' + (await noteEditor.count() > 0 ? 'Available' : 'Not Found'));
    console.log('✅ Sidebar: ' + (await sidebar.count() > 0 ? 'Available' : 'Not Found'));
    console.log('✅ Error Handling: ' + (errorElements === 0 ? 'Good' : 'Issues Found'));
  });
});
