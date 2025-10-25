import { test, expect } from '@playwright/test';

test.describe('Simple Frontend Test', () => {
  test('should test basic frontend functionality', async ({ page }) => {
    // Navigate to the site
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app');
    await page.waitForLoadState('networkidle');

    console.log('✅ Site loaded successfully');

    // Check if we can see the login form
    const emailInput = await page.locator('input[type="email"]').count();
    const passwordInput = await page.locator('input[type="password"]').count();
    const submitButton = await page.locator('button[type="submit"]').count();

    console.log('Email input found:', emailInput);
    console.log('Password input found:', passwordInput);
    console.log('Submit button found:', submitButton);

    if (emailInput > 0 && passwordInput > 0 && submitButton > 0) {
      console.log('✅ Login form is present');

      // Try to login
      await page.fill('input[type="email"]', 'mail@rasmusj.dk');
      await page.fill('input[type="password"]', 'UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz');
      await page.click('button[type="submit"]');

      console.log('✅ Login form submitted');

      // Wait a bit and check what happens
      await page.waitForTimeout(5000);

      const currentUrl = page.url();
      console.log('Current URL after login:', currentUrl);

      // Check if we're on dashboard
      if (currentUrl.includes('/dashboard')) {
        console.log('✅ Successfully redirected to dashboard');

        // Wait for data to load
        await page.waitForTimeout(5000);

        // Check for error boundary
        const errorBoundary = await page.locator('text=Something went wrong').count();
        console.log('Error boundary triggered:', errorBoundary > 0);

        if (errorBoundary > 0) {
          // Get the error details
          const errorDetails = await page.locator('details summary').textContent();
          console.log('Error details summary:', errorDetails);

          // Try to expand the error details
          await page.click('details summary');
          await page.waitForTimeout(1000);

          const errorText = await page.locator('details pre').textContent();
          console.log('Full error text:', errorText);
        }

        // Check for dashboard components
        const sidebar = await page.locator('.sidebar, [data-testid="sidebar"]').count();
        const noteList = await page.locator('.note-list, [data-testid="note-list"]').count();
        const noteEditor = await page.locator('.note-editor, [data-testid="note-editor"]').count();

        console.log('Sidebar found:', sidebar);
        console.log('Note list found:', noteList);
        console.log('Note editor found:', noteEditor);

        // Take a screenshot
        await page.screenshot({ path: 'simple-test.png', fullPage: true });

      } else {
        console.log('❌ Not redirected to dashboard, current URL:', currentUrl);
      }
    } else {
      console.log('❌ Login form not found');
    }
  });
});
