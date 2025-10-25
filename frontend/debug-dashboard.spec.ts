import { test, expect } from '@playwright/test';

test.describe('Debug Dashboard Rendering', () => {
  test('should debug what is actually being rendered on the dashboard', async ({ page }) => {
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

    // Take screenshot
    await page.screenshot({ path: 'debug-dashboard.png', fullPage: true });

    // Get all HTML content to see what's actually rendered
    const htmlContent = await page.content();
    console.log('HTML Content Length:', htmlContent.length);

    // Check for specific elements
    const sidebar = await page.locator('.sidebar, [data-testid="sidebar"]').count();
    const noteList = await page.locator('.note-list, [data-testid="note-list"]').count();
    const noteEditor = await page.locator('.note-editor, [data-testid="note-editor"]').count();
    const newNoteButton = await page.locator('button:has-text("New Note")').count();

    console.log('Sidebar elements found:', sidebar);
    console.log('Note list elements found:', noteList);
    console.log('Note editor elements found:', noteEditor);
    console.log('New Note buttons found:', newNoteButton);

    // Check for any error messages in console
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Check for React errors
    const reactErrors: string[] = [];
    page.on('pageerror', error => {
      reactErrors.push(error.message);
    });

    await page.waitForTimeout(2000);

    if (consoleErrors.length > 0) {
      console.log('Console errors:', consoleErrors);
    }

    if (reactErrors.length > 0) {
      console.log('React errors:', reactErrors);
    }

    // Check if there are any loading states
    const loadingElements = await page.locator('.loading, .spinner, [class*="loading"]').count();
    console.log('Loading elements found:', loadingElements);

    // Check for any error boundaries
    const errorBoundaries = await page.locator('[data-testid="error-boundary"], .error-boundary').count();
    console.log('Error boundaries found:', errorBoundaries);

    // Get the page title
    const title = await page.title();
    console.log('Page title:', title);

    // Check if the page is actually the dashboard
    const url = page.url();
    console.log('Current URL:', url);

    // Check for any text content that might indicate what's being rendered
    const bodyText = await page.locator('body').textContent();
    console.log('Body text preview:', bodyText?.substring(0, 200));

    console.log('\n=== DEBUG SUMMARY ===');
    console.log('URL:', url);
    console.log('Title:', title);
    console.log('Sidebar:', sidebar);
    console.log('Note List:', noteList);
    console.log('Note Editor:', noteEditor);
    console.log('New Note Button:', newNoteButton);
    console.log('Console Errors:', consoleErrors.length);
    console.log('React Errors:', reactErrors.length);
    console.log('Loading Elements:', loadingElements);
    console.log('Error Boundaries:', errorBoundaries);
  });
});
