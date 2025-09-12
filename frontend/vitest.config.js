import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.js'],
    coverage: {
      reporter: ['text', 'json', 'html', 'lcov'],
      reportsDirectory: './coverage',
      exclude: [
        'node_modules/',
        'src/test-utils.jsx',
        'src/test-setup.js',
        '**/*.test.{js,jsx}',
        '**/*.spec.{js,jsx}',
        'src/main.jsx',
        'vite.config.js',
        'vitest.config.js'
      ],
      include: ['src/**/*.{js,jsx}'],
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        },
        'src/App.jsx': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85
        }
      },
      all: true
    },
    testTimeout: 10000,
    hookTimeout: 10000,
    teardownTimeout: 5000,
    isolate: true,
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: true,
      },
    },
    retry: {
      count: 2
    },
    bail: 1,
    logHeapUsage: true,
    passWithNoTests: false,
    allowOnly: false,
    watch: {
      ignored: ['**/node_modules/**', '**/coverage/**']
    }
  },
  esbuild: {
    target: 'node14'
  },
  define: {
    'import.meta.vitest': false
  }
});