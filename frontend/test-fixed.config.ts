import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: 'test-fixed.spec.ts',
  timeout: 30000,
  use: {
    headless: true,
  },
})
