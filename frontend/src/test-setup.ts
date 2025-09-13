// Global test setup for Vitest
import { vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import '@testing-library/jest-dom';

// Clean up after each test
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.resetAllMocks();
});

// Mock IntersectionObserver
global.IntersectionObserver = vi.fn(() => ({
  disconnect: vi.fn(),
  observe: vi.fn(),
  unobserve: vi.fn(),
}));

// Mock ResizeObserver
global.ResizeObserver = vi.fn(() => ({
  disconnect: vi.fn(),
  observe: vi.fn(),
  unobserve: vi.fn(),
}));

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock window.scrollTo
Object.defineProperty(window, 'scrollTo', {
  writable: true,
  value: vi.fn(),
});

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

// Mock performance API
global.performance = {
  ...performance,
  mark: vi.fn(),
  measure: vi.fn(),
  getEntriesByName: vi.fn(() => []),
  getEntriesByType: vi.fn(() => []),
  clearMarks: vi.fn(),
  clearMeasures: vi.fn(),
  now: vi.fn(() => Date.now()),
};

// Mock requestAnimationFrame
global.requestAnimationFrame = vi.fn((cb) => setTimeout(cb, 0));
global.cancelAnimationFrame = vi.fn((id) => clearTimeout(id));

// Mock URL constructor for blob URLs
global.URL = {
  ...global.URL,
  createObjectURL: vi.fn(() => 'mock-url'),
  revokeObjectURL: vi.fn(),
};

// Mock File and FileReader for upload tests
global.File = class MockFile {
  constructor(bits, name, options = {}) {
    this.name = name;
    this.size = bits.length;
    this.type = options.type || '';
    this.lastModified = options.lastModified || Date.now();
  }
};

global.FileReader = class MockFileReader {
  constructor() {
    this.readyState = 0;
    this.result = null;
    this.error = null;
  }

  readAsText(file) {
    setTimeout(() => {
      this.readyState = 2;
      this.result = 'mock file content';
      this.onload?.({ target: this });
    }, 0);
  }

  readAsDataURL(file) {
    setTimeout(() => {
      this.readyState = 2;
      this.result = 'data:text/plain;base64,bW9jayBmaWxlIGNvbnRlbnQ=';
      this.onload?.({ target: this });
    }, 0);
  }
};

// Mock clipboard API
Object.defineProperty(navigator, 'clipboard', {
  writable: true,
  value: {
    writeText: vi.fn().mockResolvedValue(),
    readText: vi.fn().mockResolvedValue('mock clipboard content'),
  },
});

// Mock geolocation API
Object.defineProperty(navigator, 'geolocation', {
  writable: true,
  value: {
    getCurrentPosition: vi.fn(),
    watchPosition: vi.fn(),
    clearWatch: vi.fn(),
  },
});

// Mock Notification API
global.Notification = class MockNotification {
  static permission = 'granted';
  static requestPermission = vi.fn().mockResolvedValue('granted');
  
  constructor(title, options = {}) {
    this.title = title;
    this.body = options.body;
    this.icon = options.icon;
    this.tag = options.tag;
    this.onclick = null;
    this.onclose = null;
    this.onerror = null;
    this.onshow = null;
  }

  close() {
    this.onclose?.();
  }
};

// Mock Service Worker API
Object.defineProperty(navigator, 'serviceWorker', {
  writable: true,
  value: {
    register: vi.fn().mockResolvedValue({
      installing: null,
      waiting: null,
      active: null,
      scope: 'https://localhost:3000/',
      update: vi.fn().mockResolvedValue(),
      unregister: vi.fn().mockResolvedValue(true),
    }),
    getRegistration: vi.fn().mockResolvedValue(null),
    getRegistrations: vi.fn().mockResolvedValue([]),
  },
});

// Mock indexedDB for offline storage tests
global.indexedDB = {
  open: vi.fn(),
  deleteDatabase: vi.fn(),
  databases: vi.fn().mockResolvedValue([]),
};

// Mock WebSocket for real-time features
global.WebSocket = class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.onopen = null;
    this.onclose = null;
    this.onerror = null;
    this.onmessage = null;
    
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.({ type: 'open' });
    }, 0);
  }

  send(data) {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ type: 'close', code: 1000, reason: 'Normal closure' });
  }
};

// Mock crypto.getRandomValues for secure random generation
Object.defineProperty(crypto, 'getRandomValues', {
  writable: true,
  value: vi.fn((array) => {
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
    return array;
  }),
});

// Mock TextEncoder/TextDecoder for older environments
if (!global.TextEncoder) {
  global.TextEncoder = class MockTextEncoder {
    encode(string) {
      return new Uint8Array(string.split('').map(char => char.charCodeAt(0)));
    }
  };
}

if (!global.TextDecoder) {
  global.TextDecoder = class MockTextDecoder {
    decode(bytes) {
      return String.fromCharCode(...bytes);
    }
  };
}

// Global error handler for unhandled promise rejections
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Promise Rejection:', reason);
});

// Global uncaught exception handler
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.VITEST = 'true';