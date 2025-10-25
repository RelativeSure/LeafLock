import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: 'final-test.spec.ts',
  timeout: 30000,
  use: {
    headless: true,
  },
})
