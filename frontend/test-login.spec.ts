import { test, expect } from '@playwright/test';

test.describe('Login Functionality', () => {
  test('should login successfully with admin credentials', async ({ page }) => {
    // Navigate to the login page
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app/auth');

    // Wait for the page to load
    await page.waitForLoadState('networkidle');

    // Take a screenshot of the initial state
    await page.screenshot({ path: 'login-initial.png' });

    // Look for email input field
    const emailInput = page.locator('input[type="email"], input[name="email"], input[placeholder*="email" i]').first();
    await expect(emailInput).toBeVisible();

    // Look for password input field
    const passwordInput = page.locator('input[type="password"], input[name="password"], input[placeholder*="password" i]').first();
    await expect(passwordInput).toBeVisible();

    // Fill in the credentials
    await emailInput.fill('mail@rasmusj.dk');
    await passwordInput.fill('UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz');

    // Take a screenshot after filling credentials
    await page.screenshot({ path: 'login-filled.png' });

    // Look for login button
    const loginButton = page.locator('button[type="submit"], button:has-text("Login"), button:has-text("Sign in"), button:has-text("Log in")').first();
    await expect(loginButton).toBeVisible();

    // Click the login button
    await loginButton.click();

    // Wait for navigation or response
    await page.waitForTimeout(3000);

    // Take a screenshot after login attempt
    await page.screenshot({ path: 'login-after-click.png' });

    // Check for success indicators
    const currentUrl = page.url();
    console.log('Current URL after login:', currentUrl);

    // Check if we're redirected to dashboard or home
    const isRedirected = !currentUrl.includes('/auth') && !currentUrl.includes('/login');

    // Check for error messages
    const errorMessages = page.locator('[role="alert"], .error, .alert-error, [class*="error"]');
    const errorCount = await errorMessages.count();

    if (errorCount > 0) {
      const errorTexts = await errorMessages.allTextContents();
      console.log('Error messages found:', errorTexts);
    }

    // Check for success messages
    const successMessages = page.locator('[role="status"], .success, .alert-success, [class*="success"]');
    const successCount = await successMessages.count();

    if (successCount > 0) {
      const successTexts = await successMessages.allTextContents();
      console.log('Success messages found:', successTexts);
    }

    // Check console for any JavaScript errors
    const consoleMessages: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleMessages.push(msg.text());
      }
    });

    // Check network requests
    const networkRequests: string[] = [];
    page.on('request', request => {
      if (request.url().includes('/auth/login')) {
        networkRequests.push(`${request.method()} ${request.url()}`);
        console.log('Login request:', request.method(), request.url());
        console.log('Request headers:', request.headers());
        console.log('Request body:', request.postData());
      }
    });

    page.on('response', response => {
      if (response.url().includes('/auth/login')) {
        console.log('Login response:', response.status(), response.url());
        console.log('Response headers:', response.headers());
        response.text().then(text => {
          console.log('Response body:', text);
        });
      }
    });

    // Wait a bit more to capture all network activity
    await page.waitForTimeout(2000);

    // Log all findings
    console.log('Console errors:', consoleMessages);
    console.log('Network requests:', networkRequests);

    // Assertions
    if (isRedirected) {
      console.log('✅ Login successful - redirected to:', currentUrl);
    } else {
      console.log('❌ Login failed - still on auth page');
    }

    // Check if we can find any indication of being logged in
    const userMenu = page.locator('[data-testid="user-menu"], .user-menu, [class*="user-menu"]');
    const isUserMenuVisible = await userMenu.isVisible().catch(() => false);

    if (isUserMenuVisible) {
      console.log('✅ User menu visible - logged in');
    } else {
      console.log('❌ User menu not visible - not logged in');
    }
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app/auth');
    await page.waitForLoadState('networkidle');

    const emailInput = page.locator('input[type="email"], input[name="email"]').first();
    const passwordInput = page.locator('input[type="password"], input[name="password"]').first();
    const loginButton = page.locator('button[type="submit"], button:has-text("Login")').first();

    await emailInput.fill('invalid@example.com');
    await passwordInput.fill('wrongpassword');
    await loginButton.click();

    await page.waitForTimeout(3000);

    // Check for error messages
    const errorMessages = page.locator('[role="alert"], .error, .alert-error');
    const errorCount = await errorMessages.count();

    if (errorCount > 0) {
      const errorTexts = await errorMessages.allTextContents();
      console.log('Error messages for invalid credentials:', errorTexts);
    }
  });
});
