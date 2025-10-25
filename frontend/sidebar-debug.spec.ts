import { test, expect } from '@playwright/test';

test.describe('Sidebar Debug Test', () => {
  test('should capture console logs from Sidebar component', async ({ page }) => {
    // Capture console logs
    const consoleLogs: string[] = []
    page.on('console', msg => {
      consoleLogs.push(`${msg.type()}: ${msg.text()}`)
    })

    // Navigate to the site
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app');
    await page.waitForLoadState('networkidle');

    // Login
    await page.fill('input[type="email"]', 'mail@rasmusj.dk');
    await page.fill('input[type="password"]', 'UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz');
    await page.click('button[type="submit"]');

    // Wait for redirect to dashboard
    await page.waitForURL('**/dashboard', { timeout: 10000 });

    // Wait for data to load and console logs
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

    // Print all console logs
    console.log('Console logs captured:')
    consoleLogs.forEach(log => console.log(log))

    // Take a screenshot
    await page.screenshot({ path: 'sidebar-debug.png', fullPage: true });
  });
});
