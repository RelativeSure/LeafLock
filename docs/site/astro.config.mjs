import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  site: 'https://docs.leaflock.app/',
  base: '/',
  output: 'static',
  markdown: {
    shikiConfig: {
      theme: 'github-light',
    },
  },
  build: {
    assets: 'assets'
  },
  vite: {
    css: {
      preprocessorOptions: {
        scss: {
          api: 'modern-compiler'
        }
      }
    }
  }
});