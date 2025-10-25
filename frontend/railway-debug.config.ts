import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: 'railway-debug-test.spec.ts',
  timeout: 30000,
  retries: 1,
  use: {
    baseURL: 'https://frontend-leaflock-pr-363.up.railway.app',
    headless: false, // Run in headed mode to see what's happening
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
})
