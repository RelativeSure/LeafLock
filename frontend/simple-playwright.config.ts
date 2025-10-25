import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './',
  fullyParallel: true,
  retries: 0,
  timeout: 30 * 1000,
  use: {
    trace: 'on-first-retry',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
