import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: 'railway-detailed-test.spec.ts',
  timeout: 60000,
  retries: 0,
  use: {
    baseURL: 'https://frontend-leaflock-pr-363.up.railway.app',
    headless: true,
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
