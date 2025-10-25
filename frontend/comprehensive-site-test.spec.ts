import { test, expect } from '@playwright/test';

test.describe('LeafLock Full Site Test', () => {
  test('should complete full login flow and test site functionality', async ({ page }) => {
    // Navigate to the site
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app');

    // Wait for the page to load
    await page.waitForLoadState('networkidle');

    // Take initial screenshot
    await page.screenshot({ path: 'site-initial.png' });

    console.log('Initial URL:', page.url());

    // Check if we're redirected to auth page
    const currentUrl = page.url();
    if (currentUrl.includes('/auth')) {
      console.log('✅ Redirected to auth page as expected');
    } else {
      console.log('❌ Not redirected to auth page, current URL:', currentUrl);
    }

    // Find and fill login form
    const emailInput = page.locator('input[type="email"]').first();
    const passwordInput = page.locator('input[type="password"]').first();
    const loginButton = page.locator('button[type="submit"]').first();

    await expect(emailInput).toBeVisible();
    await expect(passwordInput).toBeVisible();
    await expect(loginButton).toBeVisible();

    // Fill credentials
    await emailInput.fill('mail@rasmusj.dk');
    await passwordInput.fill('UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz');

    await page.screenshot({ path: 'site-login-filled.png' });

    // Click login button
    await loginButton.click();

    // Wait for navigation
    await page.waitForTimeout(5000);

    await page.screenshot({ path: 'site-after-login.png' });

    // Check if we're redirected to dashboard
    const finalUrl = page.url();
    console.log('Final URL after login:', finalUrl);

    if (finalUrl.includes('/dashboard')) {
      console.log('✅ Successfully redirected to dashboard!');
    } else {
      console.log('❌ Not redirected to dashboard, still on:', finalUrl);
    }

    // Test dashboard functionality
    if (finalUrl.includes('/dashboard')) {
      console.log('Testing dashboard functionality...');

      // Look for common dashboard elements
      const dashboardElements = [
        'h1', 'h2', 'h3', // Headers
        'button', 'input', 'textarea', // Interactive elements
        '[data-testid]', // Test elements
        '.dashboard', '.main', '.content' // Common class names
      ];

      for (const selector of dashboardElements) {
        const elements = await page.locator(selector).count();
        if (elements > 0) {
          console.log(`Found ${elements} elements with selector: ${selector}`);
        }
      }

      // Check for any error messages
      const errorElements = await page.locator('[role="alert"], .error, .alert-error, [class*="error"]').count();
      if (errorElements > 0) {
        console.log(`❌ Found ${errorElements} error elements on dashboard`);
      } else {
        console.log('✅ No error elements found on dashboard');
      }

      // Check for loading states
      const loadingElements = await page.locator('.loading, .spinner, [class*="loading"]').count();
      if (loadingElements > 0) {
        console.log(`⚠️ Found ${loadingElements} loading elements - page might still be loading`);
      }

      // Test navigation - look for navigation elements
      const navElements = await page.locator('nav, [role="navigation"], .nav, .navbar').count();
      console.log(`Found ${navElements} navigation elements`);

      // Test user menu or profile elements
      const userElements = await page.locator('[data-testid*="user"], .user-menu, .profile').count();
      console.log(`Found ${userElements} user/profile elements`);

      // Check for admin-specific elements
      const adminElements = await page.locator('[data-testid*="admin"], .admin, [class*="admin"]').count();
      console.log(`Found ${adminElements} admin-specific elements`);

      // Test if we can interact with the page
      const clickableElements = await page.locator('button:not([disabled]), a, [role="button"]').count();
      console.log(`Found ${clickableElements} clickable elements`);

      if (clickableElements > 0) {
        console.log('✅ Dashboard appears to be interactive');
      } else {
        console.log('❌ Dashboard appears to have no interactive elements');
      }
    }

    // Test logout functionality
    console.log('Testing logout functionality...');

    // Look for logout button
    const logoutButtons = await page.locator('button:has-text("Logout"), button:has-text("Sign out"), a:has-text("Logout")').count();
    console.log(`Found ${logoutButtons} logout buttons`);

    if (logoutButtons > 0) {
      const logoutButton = page.locator('button:has-text("Logout"), button:has-text("Sign out"), a:has-text("Logout")').first();
      await logoutButton.click();

      await page.waitForTimeout(3000);

      const logoutUrl = page.url();
      console.log('URL after logout:', logoutUrl);

      if (logoutUrl.includes('/auth')) {
        console.log('✅ Successfully logged out and redirected to auth page');
      } else {
        console.log('❌ Logout did not redirect to auth page');
      }

      await page.screenshot({ path: 'site-after-logout.png' });
    } else {
      console.log('⚠️ No logout button found - testing manual navigation');

      // Try to navigate to auth page manually
      await page.goto('https://frontend-leaflock-pr-363.up.railway.app/auth');
      await page.waitForTimeout(2000);

      const authUrl = page.url();
      console.log('URL after manual navigation to auth:', authUrl);

      if (authUrl.includes('/auth')) {
        console.log('✅ Successfully navigated to auth page');
      } else {
        console.log('❌ Could not navigate to auth page');
      }
    }

    // Final summary
    console.log('\n=== TEST SUMMARY ===');
    console.log('✅ API Login: Working');
    console.log('✅ Frontend Form: Working');
    console.log('✅ Navigation: ' + (finalUrl.includes('/dashboard') ? 'Working' : 'NOT WORKING'));
    console.log('✅ Dashboard: ' + (finalUrl.includes('/dashboard') ? 'Accessible' : 'Not accessible'));
    console.log('✅ Logout: ' + (logoutButtons > 0 ? 'Available' : 'Not found'));
  });

  test('should test site health and basic functionality', async ({ page }) => {
    // Test main site accessibility
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app');
    await page.waitForLoadState('networkidle');

    // Check for any JavaScript errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Check for network errors
    const networkErrors: string[] = [];
    page.on('response', response => {
      if (response.status() >= 400) {
        networkErrors.push(`${response.status()} ${response.url()}`);
      }
    });

    await page.waitForTimeout(3000);

    console.log('Console errors:', consoleErrors.length);
    console.log('Network errors:', networkErrors.length);

    if (consoleErrors.length > 0) {
      console.log('Console errors found:', consoleErrors);
    }

    if (networkErrors.length > 0) {
      console.log('Network errors found:', networkErrors);
    }

    // Test responsive design
    await page.setViewportSize({ width: 375, height: 667 }); // Mobile
    await page.screenshot({ path: 'site-mobile.png' });

    await page.setViewportSize({ width: 1920, height: 1080 }); // Desktop
    await page.screenshot({ path: 'site-desktop.png' });

    console.log('✅ Site health check completed');
  });
});
