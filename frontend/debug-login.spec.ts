import { test, expect } from '@playwright/test';

test.describe('Detailed Login Debug', () => {
  test('should debug login form submission', async ({ page }) => {
    // Navigate to the login page
    await page.goto('https://frontend-leaflock-pr-363.up.railway.app/auth');

    // Wait for the page to load
    await page.waitForLoadState('networkidle');

    // Take initial screenshot
    await page.screenshot({ path: 'debug-initial.png' });

    // Log all network requests
    const requests: any[] = [];
    const responses: any[] = [];

    page.on('request', request => {
      requests.push({
        url: request.url(),
        method: request.method(),
        headers: request.headers(),
        postData: request.postData()
      });
      console.log('REQUEST:', request.method(), request.url());
    });

    page.on('response', response => {
      responses.push({
        url: response.url(),
        status: response.status(),
        headers: response.headers()
      });
      console.log('RESPONSE:', response.status(), response.url());
    });

    // Log all console messages
    page.on('console', msg => {
      console.log('CONSOLE:', msg.type(), msg.text());
    });

    // Find all input fields
    const inputs = await page.locator('input').all();
    console.log('Found inputs:', inputs.length);

    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i];
      const type = await input.getAttribute('type');
      const name = await input.getAttribute('name');
      const placeholder = await input.getAttribute('placeholder');
      console.log(`Input ${i}: type=${type}, name=${name}, placeholder=${placeholder}`);
    }

    // Find all buttons
    const buttons = await page.locator('button').all();
    console.log('Found buttons:', buttons.length);

    for (let i = 0; i < buttons.length; i++) {
      const button = buttons[i];
      const text = await button.textContent();
      const type = await button.getAttribute('type');
      console.log(`Button ${i}: text="${text}", type=${type}`);
    }

    // Try to find email input
    let emailInput = null;
    for (const input of inputs) {
      const type = await input.getAttribute('type');
      const name = await input.getAttribute('name');
      const placeholder = await input.getAttribute('placeholder');

      if (type === 'email' || name === 'email' || (placeholder && placeholder.toLowerCase().includes('email'))) {
        emailInput = input;
        break;
      }
    }

    // Try to find password input
    let passwordInput = null;
    for (const input of inputs) {
      const type = await input.getAttribute('type');
      const name = await input.getAttribute('name');
      const placeholder = await input.getAttribute('placeholder');

      if (type === 'password' || name === 'password' || (placeholder && placeholder.toLowerCase().includes('password'))) {
        passwordInput = input;
        break;
      }
    }

    // Try to find submit button
    let submitButton = null;
    for (const button of buttons) {
      const text = await button.textContent();
      const type = await button.getAttribute('type');

      if (type === 'submit' || (text && (text.toLowerCase().includes('login') || text.toLowerCase().includes('sign in')))) {
        submitButton = button;
        break;
      }
    }

    console.log('Email input found:', !!emailInput);
    console.log('Password input found:', !!passwordInput);
    console.log('Submit button found:', !!submitButton);

    if (emailInput && passwordInput) {
      // Fill the form
      await emailInput.fill('mail@rasmusj.dk');
      await passwordInput.fill('UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz');

      await page.screenshot({ path: 'debug-filled.png' });

      if (submitButton) {
        // Click submit button
        console.log('Clicking submit button...');
        await submitButton.click();

        // Wait for any network activity
        await page.waitForTimeout(5000);

        await page.screenshot({ path: 'debug-after-submit.png' });

        console.log('Total requests made:', requests.length);
        console.log('Total responses received:', responses.length);

        // Check if any requests were made to the API
        const apiRequests = requests.filter(req => req.url.includes('/api/'));
        console.log('API requests:', apiRequests.length);

        if (apiRequests.length === 0) {
          console.log('❌ NO API REQUESTS MADE - Frontend form submission is broken!');
        } else {
          console.log('✅ API requests made:', apiRequests.map(req => `${req.method} ${req.url}`));
        }
      } else {
        console.log('❌ No submit button found');
      }
    } else {
      console.log('❌ Could not find email or password inputs');
    }

    // Check current URL
    const currentUrl = page.url();
    console.log('Final URL:', currentUrl);

    // Check for any error messages on the page
    const errorElements = await page.locator('[role="alert"], .error, .alert-error, [class*="error"]').all();
    console.log('Error elements found:', errorElements.length);

    for (let i = 0; i < errorElements.length; i++) {
      const text = await errorElements[i].textContent();
      console.log(`Error ${i}:`, text);
    }
  });
});
