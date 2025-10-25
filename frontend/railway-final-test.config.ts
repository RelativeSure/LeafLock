import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: 'railway-final-test.spec.ts',
  timeout: 30000,
  use: {
    headless: true,
  },
})
