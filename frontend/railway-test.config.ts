import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: 'railway-deployment-test.spec.ts',
  timeout: 30000,
  retries: 2,
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
