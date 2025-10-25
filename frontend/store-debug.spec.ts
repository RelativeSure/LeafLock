import { test, expect } from '@playwright/test';

test.describe('Store State Debug Test', () => {
  test('should debug store state and component rendering', async ({ page }) => {
    // Navigate to the site
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app');
    await page.waitForLoadState('networkidle');

    // Login
    await page.fill('input[type="email"]', 'mail@rasmusj.dk');
    await page.fill('input[type="password"]', 'UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz');
    await page.click('button[type="submit"]');

    // Wait for redirect to dashboard
    await page.waitForURL('**/dashboard', { timeout: 10000 });

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

      // Check if there are any console logs that might help
      const consoleLogs: string[] = [];
      page.on('console', msg => {
        consoleLogs.push(`${msg.type()}: ${msg.text()}`);
      });

      await page.waitForTimeout(2000);

      if (consoleLogs.length > 0) {
        console.log('Console logs:', consoleLogs);
      }
    }

    // Check if we can see any loading states
    const loadingElements = await page.locator('.loading, .spinner, [class*="loading"]').count();
    console.log('Loading elements found:', loadingElements);

    // Check if we can see any dashboard content at all
    const bodyText = await page.locator('body').textContent();
    console.log('Body text preview:', bodyText?.substring(0, 500));

    // Take a screenshot
    await page.screenshot({ path: 'store-debug.png', fullPage: true });
  });
});
