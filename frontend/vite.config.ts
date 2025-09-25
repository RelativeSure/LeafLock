import path from 'path';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [
    react({
      // Optimize babel for faster builds
      babel: {
        compact: process.env.NODE_ENV === 'production',
      },
    }),
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
      '@': path.resolve(path.dirname(fileURLToPath(import.meta.url)), './src'),
      crypto: 'crypto-browserify',
    },
  },
  optimizeDeps: {
    include: ['buffer', 'crypto-browserify', 'process'],
    // Force optimization of frequently used dependencies
    force: process.env.NODE_ENV === 'development',
  },
  build: {
    // Optimize build performance and bundle size
    target: 'esnext',
    minify: 'esbuild', // Use esbuild instead of terser (faster and built-in)
    cssCodeSplit: true,
    sourcemap: false, // Disable sourcemaps for production for faster builds
    rollupOptions: {
      output: {
        // Enable code splitting for better caching
        manualChunks: {
          vendor: ['react', 'react-dom'],
          crypto: ['libsodium-wrappers', 'crypto-browserify'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-label', '@radix-ui/react-select'],
          editor: ['@tiptap/react', '@tiptap/starter-kit', '@tiptap/extension-table'],
          utils: ['zustand', '@tanstack/react-query', 'clsx', 'tailwind-merge'],
        },
        // Optimize chunk loading
        chunkFileNames: 'assets/js/[name]-[hash].js',
        entryFileNames: 'assets/js/[name]-[hash].js',
        assetFileNames: 'assets/[ext]/[name]-[hash].[ext]',
      },
    },
    // Increase chunk size warning threshold
    chunkSizeWarningLimit: 1000,
    // ESBuild options for production optimization
    esbuild: {
      drop: ['console', 'debugger'],
    },
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
