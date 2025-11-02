import { defineConfig, devices } from '@playwright/test'

const E2E_PORT = Number.parseInt(process.env.E2E_PORT ?? '4173', 10)
const HOST = '127.0.0.1'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  timeout: 60 * 1000,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'https://frontend-leaflock-pr-363.up.railway.app',
    trace: 'on-first-retry',
    video: 'retain-on-failure',
  },
  // Disable webServer for deployed testing
  // webServer: {
  //   command: `pnpm dev -- --host ${HOST} --port ${E2E_PORT}`,
  //   port: E2E_PORT,
  //   reuseExistingServer: !process.env.CI,
  //   timeout: 120 * 1000,
  // },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
  ],
})
