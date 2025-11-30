/**
 * Runtime Configuration Loader
 *
 * This script loads environment variables at runtime, allowing them to be
 * injected after the build process. This is crucial for deployment platforms
 * like Railway where environment variables may not be available at build time.
 *
 * Variables are exposed via window.__ENV__ and can be accessed by the application.
 */

(function() {
  'use strict';

  // Create global runtime configuration object
  window.__ENV__ = window.__ENV__ || {};

  // Try to load from server-injected meta tags first
  const clerkKeyMeta = document.querySelector('meta[name="clerk-publishable-key"]');
  if (clerkKeyMeta && clerkKeyMeta.content) {
    window.__ENV__.VITE_CLERK_PUBLISHABLE_KEY = clerkKeyMeta.content;
  }

  const apiUrlMeta = document.querySelector('meta[name="api-url"]');
  if (apiUrlMeta && apiUrlMeta.content) {
    window.__ENV__.VITE_API_URL = apiUrlMeta.content;
  }

  // Fallback to build-time environment variables (embedded by Vite)
  if (!window.__ENV__.VITE_CLERK_PUBLISHABLE_KEY) {
    // This will be undefined if not set at build time
    window.__ENV__.VITE_CLERK_PUBLISHABLE_KEY = typeof import.meta !== 'undefined'
      ? import.meta.env.VITE_CLERK_PUBLISHABLE_KEY
      : undefined;
  }

  if (!window.__ENV__.VITE_API_URL) {
    window.__ENV__.VITE_API_URL = typeof import.meta !== 'undefined'
      ? import.meta.env.VITE_API_URL
      : undefined;
  }

  // Log configuration status (only in development)
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    console.log('🔧 Runtime Config Loaded:', {
      hasClerkKey: !!window.__ENV__.VITE_CLERK_PUBLISHABLE_KEY,
      clerkKeyPrefix: window.__ENV__.VITE_CLERK_PUBLISHABLE_KEY
        ? window.__ENV__.VITE_CLERK_PUBLISHABLE_KEY.substring(0, 10) + '...'
        : 'NOT SET',
      apiUrl: window.__ENV__.VITE_API_URL || 'NOT SET'
    });
  }

  // Emit ready event for app initialization
  window.dispatchEvent(new CustomEvent('runtime-config-ready', {
    detail: window.__ENV__
  }));
})();
