import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      include: ['buffer', 'crypto', 'events', 'process', 'stream', 'vm'],
    }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      crypto: 'crypto-browserify',
    },
  },
  optimizeDeps: {
    include: ['buffer', 'crypto-browserify', 'process'],
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    globals: true,
  },
});
