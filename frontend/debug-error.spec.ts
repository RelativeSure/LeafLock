import { test, expect } from '@playwright/test';

test.describe('Debug Dashboard Error', () => {
  test('should capture the actual error causing the dashboard to fail', async ({ page }) => {
    // Capture console errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Capture page errors
    const pageErrors: string[] = [];
    page.on('pageerror', error => {
      pageErrors.push(error.message);
    });

    // Capture unhandled promise rejections
    const unhandledRejections: string[] = [];
    page.on('unhandledrejection', rejection => {
      unhandledRejections.push(rejection.reason?.toString() || 'Unknown rejection');
    });

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

    // Wait for any errors to be captured
    await page.waitForTimeout(5000);

    // Take screenshot
    await page.screenshot({ path: 'error-dashboard.png', fullPage: true });

    console.log('\n=== ERROR ANALYSIS ===');
    console.log('Console Errors:', consoleErrors);
    console.log('Page Errors:', pageErrors);
    console.log('Unhandled Rejections:', unhandledRejections);

    // Check if there's an error boundary message
    const errorMessage = await page.locator('text=Something went wrong').count();
    console.log('Error boundary triggered:', errorMessage > 0);

    if (errorMessage > 0) {
      const errorText = await page.locator('text=Something went wrong').textContent();
      console.log('Error message:', errorText);
    }

    // Check for any React error information
    const reactError = await page.locator('[data-testid="error-boundary"], .error-boundary').count();
    console.log('React error boundary found:', reactError);

    // Get the full HTML to see what's being rendered
    const htmlContent = await page.content();
    console.log('HTML Content Length:', htmlContent.length);

    // Look for any error details in the HTML
    if (htmlContent.includes('error') || htmlContent.includes('Error')) {
      console.log('Error-related content found in HTML');
    }

    console.log('\n=== SUMMARY ===');
    console.log('Total Console Errors:', consoleErrors.length);
    console.log('Total Page Errors:', pageErrors.length);
    console.log('Total Unhandled Rejections:', unhandledRejections.length);
    console.log('Error Boundary Triggered:', errorMessage > 0);

    // Log the first few errors for debugging
    if (consoleErrors.length > 0) {
      console.log('First Console Error:', consoleErrors[0]);
    }
    if (pageErrors.length > 0) {
      console.log('First Page Error:', pageErrors[0]);
    }
    if (unhandledRejections.length > 0) {
      console.log('First Unhandled Rejection:', unhandledRejections[0]);
    }
  });
});
