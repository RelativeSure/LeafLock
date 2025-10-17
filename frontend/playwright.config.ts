import { defineConfig, devices } from '@playwright/test'

const port = process.env.PORT ?? '3000'
const host = process.env.HOST ?? '127.0.0.1'
const baseURL = process.env.BASE_URL ?? `http://${host}:${port}`
const shouldStartWebServer = process.env.PLAYWRIGHT_SKIP_WEBSERVER !== 'true'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0, // Reduced from 2 to 1
  workers: process.env.CI ? 2 : undefined, // Increased from 1 to 2 for parallel execution
  timeout: process.env.CI ? 60_000 : 30_000, // Increase timeout for CI (Docker is slower)

  reporter: process.env.CI ? 'github' : 'list',

  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: shouldStartWebServer
    ? {
        command: `pnpm run dev -- --host ${host} --port ${port}`,
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      }
    : {
        // When using external server (docker-compose), just verify it's running
        command: 'echo "Using external server from docker-compose"',
        url: baseURL,
        reuseExistingServer: true,
        timeout: 120_000,
      },
})
