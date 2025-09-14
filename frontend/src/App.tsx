import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import sodium from 'libsodium-wrappers';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Lock, Shield, MessageSquare } from 'lucide-react';

// shadcn/ui components
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import AdminPage from './AdminPage';

// Types
interface Note {
  id: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
  title_encrypted?: string;
  content_encrypted?: string;
}

interface AuthResponse {
  token: string;
  user_id: string;
  mfa_required?: boolean;
  session?: string;
}

interface ErrorBoundaryProps {
  error: string | Error;
  onRetry?: () => void;
  onDismiss?: () => void;
  className?: string;
}

interface OnboardingOverlayProps {
  step: number;
  onNext: () => void;
  onPrev: () => void;
  onSkip: () => void;
  onComplete: () => void;
}

interface LoadingOverlayProps {
  message?: string;
}

interface MarkdownRendererProps {
  content: string;
}

type ViewType = 'login' | 'notes' | 'editor' | 'unlock' | 'admin';
type EncryptionStatus = 'locked' | 'unlocked';
type ThemeType = 'light' | 'dark' | 'system';

// Debounce function type
interface DebounceFunction {
  (...args: any[]): void;
  cancel: () => void;
}

// Theme context
interface ThemeContextType {
  theme: ThemeType;
  effectiveTheme: 'light' | 'dark';
  setTheme: (theme: ThemeType) => void;
}

const ThemeContext = React.createContext<ThemeContextType | undefined>(undefined);

// Theme provider component
const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<ThemeType>('system');
  
  // Get system preference
  const getSystemTheme = (): 'light' | 'dark' => {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  };
  
  const [effectiveTheme, setEffectiveTheme] = useState<'light' | 'dark'>(getSystemTheme());

  // Load theme from cookie
  useEffect(() => {
    const savedTheme = document.cookie
      .split('; ')
      .find(row => row.startsWith('theme='))
      ?.split('=')[1] as ThemeType;
    
    if (savedTheme && ['light', 'dark', 'system'].includes(savedTheme)) {
      setThemeState(savedTheme);
    }
  }, []);

  // Update effective theme when theme or system preference changes
  useEffect(() => {
    const updateEffectiveTheme = () => {
      const newEffectiveTheme = theme === 'system' ? getSystemTheme() : theme;
      setEffectiveTheme(newEffectiveTheme);
      
      // Apply theme to document
      document.documentElement.classList.remove('light', 'dark');
      document.documentElement.classList.add(newEffectiveTheme);
    };

    updateEffectiveTheme();

    // Listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', updateEffectiveTheme);
    
    return () => mediaQuery.removeEventListener('change', updateEffectiveTheme);
  }, [theme]);

  const setTheme = (newTheme: ThemeType) => {
    setThemeState(newTheme);
    // Save to cookie (expires in 1 year)
    const expires = new Date();
    expires.setFullYear(expires.getFullYear() + 1);
    document.cookie = `theme=${newTheme}; expires=${expires.toUTCString()}; path=/; SameSite=Strict`;
  };

  return (
    <ThemeContext.Provider value={{ theme, effectiveTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

// Hook to use theme
const useTheme = () => {
  const context = React.useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return context;
};

// Secure Crypto Service for E2E Encryption
class CryptoService {
  public masterKey: Uint8Array | null = null;
  public derivedKey: Uint8Array | null = null;
  public sodiumReady: boolean = false;

  constructor() {
    this.initSodium();
  }

  async initSodium(): Promise<void> {
    if (!this.sodiumReady) {
      try {
        console.log('🧪 Initializing sodium library...');
        await sodium.ready;
        
        // Verify all required functions are available
        const requiredFunctions = [
          'crypto_secretbox_easy',
          'crypto_secretbox_open_easy', 
          'crypto_secretbox_NONCEBYTES',
          'from_string',
          'to_string',
          'to_base64',
          'from_base64',
          'base64_variants'
        ];
        
        for (const func of requiredFunctions) {
          if (typeof (sodium as any)[func] === 'undefined') {
            throw new Error(`Sodium function ${func} is not available`);
          }
        }
        
        this.sodiumReady = true;
        console.log('🧪 Sodium library initialized successfully with all functions');
      } catch (err) {
        console.error('💥 Failed to initialize sodium:', err);
        this.sodiumReady = false;
        throw err;
      }
    }
  }

  async deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    
    // Use PBKDF2 with high iterations for key derivation
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: 600000, // High iteration count for security
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return new Uint8Array(derivedBits);
  }

  async encryptData(plaintext: string): Promise<string> {
    await this.initSodium();
    if (!this.masterKey) throw new Error('No encryption key set');
    
    // Ensure sodium is fully ready before using its functions
    if (!this.sodiumReady || 
        typeof (sodium as any).crypto_secretbox_easy !== 'function' ||
        typeof (sodium as any).crypto_secretbox_NONCEBYTES !== 'number' ||
        typeof (sodium as any).from_string !== 'function') {
      console.warn('Sodium not ready, waiting and re-initializing...');
      await sodium.ready;
      this.sodiumReady = true;
      
      // Double check after waiting
      if (typeof (sodium as any).crypto_secretbox_easy !== 'function') {
        throw new Error('Sodium encryption functions not available');
      }
    }
    
    // Use Web Crypto API for nonce generation to avoid sodium timing issues  
    const nonce = new Uint8Array((sodium as any).crypto_secretbox_NONCEBYTES);
    crypto.getRandomValues(nonce);
    
    const messageBytes = (sodium as any).from_string(plaintext);
    const ciphertext = (sodium as any).crypto_secretbox_easy(messageBytes, nonce, this.masterKey);
    
    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);
    
    return (sodium as any).to_base64(combined, (sodium as any).base64_variants.ORIGINAL);
  }

  async decryptData(encryptedData: string): Promise<string> {
    await this.initSodium();
    if (!this.masterKey) throw new Error('No decryption key set');
    
    // Ensure sodium is fully ready before using its functions
    if (!this.sodiumReady || typeof (sodium as any).crypto_secretbox_open_easy !== 'function') {
      console.warn('Sodium not ready for decryption, waiting...');
      await sodium.ready;
      this.sodiumReady = true;
    }
    
    const combined = (sodium as any).from_base64(encryptedData, (sodium as any).base64_variants.ORIGINAL);
    const nonce = combined.slice(0, (sodium as any).crypto_secretbox_NONCEBYTES);
    const ciphertext = combined.slice((sodium as any).crypto_secretbox_NONCEBYTES);
    
    const decrypted = (sodium as any).crypto_secretbox_open_easy(ciphertext, nonce, this.masterKey);
    return (sodium as any).to_string(decrypted);
  }

  async generateSalt(): Promise<Uint8Array> {
    await this.initSodium();
    // Use standard Web Crypto API for salt generation to avoid sodium timing issues
    const saltBytes = new Uint8Array(32); // 32 bytes for salt
    crypto.getRandomValues(saltBytes);
    console.log('🧂 Generated salt using Web Crypto API');
    return saltBytes;
  }

  async setMasterKey(key: Uint8Array): Promise<void> {
    this.masterKey = key;
  }

  isSodiumReady(): boolean {
    return this.sodiumReady && 
           typeof (sodium as any).crypto_secretbox_easy === 'function' &&
           typeof (sodium as any).crypto_secretbox_NONCEBYTES === 'number';
  }
}

const cryptoService = new CryptoService();

// Secure API Service with encryption
class SecureAPI {
  private baseURL: string;
  private token: string | null;
  private onUnauthorized: (() => void) | null = null;

  constructor(baseURL: string = '/api/v1') {
    this.baseURL = baseURL;
    this.token = localStorage.getItem('secure_token');
  }

  async request(endpoint: string, options: RequestInit = {}): Promise<any> {
    const url = `${this.baseURL}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {})
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    console.log('🔗 API Request:', { url, method: options.method || 'GET', headers: Object.keys(headers) });

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include',
        mode: 'cors'
      });

      console.log('📡 API Response:', { status: response.status, statusText: response.statusText, url });

      if (!response.ok) {
        // Try to get error message from response body
        let errorMessage = `HTTP ${response.status}`;
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
          console.error('❌ API Error Response:', errorData);
        } catch (parseError) {
          console.error('❌ Could not parse error response:', parseError);
        }
        
        if (response.status === 401) {
          console.log('🚨 401 Unauthorized - triggering logout');
          this.handleUnauthorized();
        }
        throw new Error(errorMessage);
      }

      const data = await response.json();
      console.log('✅ API Success:', { endpoint, data: Object.keys(data) });
      return data;
    } catch (error) {
      console.error('💥 API request failed:', { url, error: (error as Error).message });
      throw error;
    }
  }

  handleUnauthorized(): void {
    console.log('🔒 Handling unauthorized access');
    this.clearToken();
    localStorage.removeItem('user_salt');
    
    // Call the callback to update React state
    if (this.onUnauthorized) {
      this.onUnauthorized();
    }
  }

  setUnauthorizedCallback(callback: () => void): void {
    this.onUnauthorized = callback;
  }

  setToken(token: string): void {
    this.token = token;
    localStorage.setItem('secure_token', token);
    // Derive and store current_user_id from JWT if possible
    try {
      const payload = JSON.parse(atob(token.split('.')[1] || ''));
      if (payload && typeof payload.user_id === 'string') {
        localStorage.setItem('current_user_id', payload.user_id);
      }
    } catch {}
  }

  clearToken(): void {
    this.token = null;
    localStorage.removeItem('secure_token');
  }

  async validateToken(): Promise<boolean> {
    if (!this.token) {
      console.log('❌ No token to validate');
      return false;
    }

    try {
      console.log('🔍 Validating token...');
      // Use a lightweight endpoint to check token validity with timeout
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Token validation timeout')), 5000)
      );
      
      await Promise.race([
        this.request('/health'),
        timeoutPromise
      ]);
      
      console.log('✅ Token is valid');
      return true;
    } catch (error) {
      console.log('❌ Token validation failed:', (error as Error).message);
      return false;
    }
  }

  async login(email: string, password: string, mfaCode?: string): Promise<AuthResponse> {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, mfa_code: mfaCode })
    });
    
    if (response.token) {
      this.setToken(response.token);
    }
    if (response.user_id) {
      try { localStorage.setItem('current_user_id', response.user_id); } catch {}
    }
    
    return response;
  }

  async register(email: string, password: string): Promise<AuthResponse> {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    
    if (response.token) {
      this.setToken(response.token);
    }
    if (response.user_id) {
      try { localStorage.setItem('current_user_id', response.user_id); } catch {}
    }
    
    return response;
  }

  async createNote(title: string, content: string): Promise<any> {
    // Encrypt note content before sending
    const encryptedTitle = await cryptoService.encryptData(title);
    const encryptedContent = await cryptoService.encryptData(JSON.stringify(content));
    
    return this.request('/notes', {
      method: 'POST',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent
      })
    });
  }
  // Admin helpers
  async adminHealth(): Promise<boolean> {
    const r = await this.request('/admin/health')
    return r && r.status === 'ok'
  }
  async adminSetAdmin(userId: string, admin: boolean): Promise<any> {
    return this.request(`/admin/users/${userId}/admin`, {
      method: 'PUT',
      body: JSON.stringify({ admin })
    })
  }
  async adminGetUserRoles(userId: string): Promise<any> {
    return this.request(`/admin/users/${userId}/roles`)
  }
  async adminListUsers(params?: Record<string, string | number | boolean>): Promise<any> {
    const query = new URLSearchParams()
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null || v === '') continue
        query.set(k, String(v))
      }
    }
    const qs = query.toString()
    return this.request(`/admin/users${qs ? `?${qs}` : ''}`)
  }
  async adminExportUsersCsv(params?: Record<string, string | number | boolean>): Promise<Blob> {
    const query = new URLSearchParams()
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null || v === '') continue
        query.set(k, String(v))
      }
    }
    const qs = query.toString()
    const url = `${this.baseURL}/admin/users.csv${qs ? `?${qs}` : ''}`
    const response = await fetch(url, { headers: { ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}) }, credentials: 'include', mode: 'cors' })
    if (!response.ok) throw new Error(`Export failed: ${response.status}`)
    return await response.blob()
  }
  async adminAssignRole(userId: string, role: string): Promise<any> {
    return this.request(`/admin/users/${userId}/roles`, {
      method: 'POST',
      body: JSON.stringify({ role })
    })
  }
  async adminRemoveRole(userId: string, role: string): Promise<any> {
    return this.request(`/admin/users/${userId}/roles/${role}`, { method: 'DELETE' })
  }
  async adminBulkRole(action: 'assign'|'remove', role: string, filters: Record<string, any>): Promise<any> {
    return this.request('/admin/users/roles/bulk', {
      method: 'POST',
      body: JSON.stringify({ action, role, ...filters })
    })
  }
  async adminBulkAdmin(action: 'grant'|'revoke', filters: Record<string, any>): Promise<any> {
    return this.request('/admin/users/admin/bulk', {
      method: 'POST',
      body: JSON.stringify({ action, ...filters })
    })
  }
  async adminGetRegistration(): Promise<{ enabled: boolean }> {
    return this.request('/admin/settings/registration')
  }
  async adminSetRegistration(enabled: boolean): Promise<{ enabled: boolean }> {
    return this.request('/admin/settings/registration', {
      method: 'PUT',
      body: JSON.stringify({ enabled })
    })
  }

  async getNotes(): Promise<Note[]> {
    const response = await this.request('/notes');
    const notes = response.notes || response || [];
    
    // Decrypt notes
    const decryptedNotes = await Promise.all(
      notes.map(async (note: any) => {
        try {
          const title = await cryptoService.decryptData(note.title_encrypted);
          const content = JSON.parse(await cryptoService.decryptData(note.content_encrypted));
          return { ...note, title, content };
        } catch (err) {
          console.error('Failed to decrypt note:', note.id);
          return null;
        }
      })
    );
    
    return decryptedNotes.filter((note): note is Note => note !== null);
  }

  async updateNote(noteId: string, title: string, content: string): Promise<any> {
    // Encrypt note content before sending
    const encryptedTitle = await cryptoService.encryptData(title);
    const encryptedContent = await cryptoService.encryptData(JSON.stringify(content));
    
    return this.request(`/notes/${noteId}`, {
      method: 'PUT',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent
      })
    });
  }

  async deleteNote(noteId: string): Promise<any> {
    return this.request(`/notes/${noteId}`, {
      method: 'DELETE'
    });
  }

  async getTrash(): Promise<Note[]> {
    const response = await this.request('/trash');
    const trashedNotes = response.notes || response || [];
    
    // Decrypt trashed notes
    const decryptedNotes = await Promise.all(
      trashedNotes.map(async (note: any) => {
        try {
          const title = await cryptoService.decryptData(note.title_encrypted);
          const content = JSON.parse(await cryptoService.decryptData(note.content_encrypted));
          return { ...note, title, content };
        } catch (err) {
          console.error('Failed to decrypt trashed note:', note.id);
          return null;
        }
      })
    );
    
    return decryptedNotes.filter((note): note is Note => note !== null);
  }

  async restoreNote(noteId: string): Promise<any> {
    return this.request(`/trash/${noteId}/restore`, {
      method: 'PUT'
    });
  }

  async permanentlyDeleteNote(noteId: string): Promise<any> {
    return this.request(`/trash/${noteId}`, {
      method: 'DELETE'
    });
  }
}

const api = new SecureAPI();

// Loading Skeleton Components
const NoteSkeleton: React.FC = () => (
  <div className="p-4 border-b border-gray-700 animate-pulse">
    <div className="h-4 bg-gray-600 rounded w-3/4 mb-2"></div>
    <div className="h-3 bg-gray-700 rounded w-full mb-1"></div>
    <div className="h-3 bg-gray-700 rounded w-2/3 mb-2"></div>
    <div className="h-3 bg-gray-700 rounded w-1/4"></div>
  </div>
);

const NoteListSkeleton: React.FC = () => (
  <div>
    {[...Array(5)].map((_, i) => (
      <NoteSkeleton key={i} />
    ))}
  </div>
);

const LoadingOverlay: React.FC<LoadingOverlayProps> = ({ message = 'Loading...' }) => (
  <div className="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center z-50">
    <div className="bg-gray-800 rounded-lg p-8 flex flex-col items-center">
      <svg className="animate-spin h-8 w-8 text-blue-500 mb-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
      <p className="text-white text-lg font-medium">{message}</p>
      <p className="text-gray-400 text-sm mt-2">Initializing secure encryption...</p>
    </div>
  </div>
);

const ErrorBoundary: React.FC<ErrorBoundaryProps> = ({ error, onRetry, onDismiss, className = "" }) => {
  const getErrorMessage = (error: string | Error): string => {
    if (typeof error === 'string') return error;
    if (error?.message) return error.message;
    return 'An unexpected error occurred';
  };

  const getErrorSuggestions = (error: string | Error): string => {
    const message = getErrorMessage(error).toLowerCase();
    
    if (message.includes('network') || message.includes('fetch')) {
      return 'Check your internet connection and try again.';
    }
    if (message.includes('unauthorized') || message.includes('401')) {
      return 'Your session may have expired. Please sign in again.';
    }
    if (message.includes('decrypt') || message.includes('encryption')) {
      return 'There was an issue with encryption. Try refreshing the page.';
    }
    return 'Please try again or refresh the page if the problem persists.';
  };

  return (
    <div className={`bg-red-900/50 border border-red-600 rounded-lg p-4 ${className}`} role="alert">
      <div className="flex items-start">
        <svg className="w-5 h-5 text-red-400 mr-3 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
        </svg>
        <div className="flex-1">
          <h3 className="text-red-200 font-medium mb-1">Something went wrong</h3>
          <p className="text-red-300 text-sm mb-2">{getErrorMessage(error)}</p>
          <p className="text-red-400 text-xs mb-4">{getErrorSuggestions(error)}</p>
          
          <div className="flex space-x-3">
            {onRetry && (
              <button
                onClick={onRetry}
                className="bg-red-600 hover:bg-red-700 text-white text-sm px-3 py-1.5 rounded transition focus:outline-none focus:ring-2 focus:ring-red-500/50"
              >
                Try Again
              </button>
            )}
            {onDismiss && (
              <button
                onClick={onDismiss}
                className="text-red-300 hover:text-white text-sm px-3 py-1.5 rounded transition focus:outline-none focus:ring-2 focus:ring-red-500/50"
              >
                Dismiss
              </button>
            )}
          </div>
        </div>
      </div>
      <div className="text-center py-4 text-xs text-muted-foreground">
        <a href="https://github.com/RelativeSure/notes/discussions" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:underline">
          <MessageSquare className="w-3 h-3" /> Join GitHub Discussions
        </a>
      </div>
    </div>
  );
};

// Onboarding Component
const OnboardingOverlay: React.FC<OnboardingOverlayProps> = ({ step, onNext, onPrev, onSkip, onComplete }) => {
  const onboardingSteps = [
    {
      title: "Welcome to LeafLock!",
      content: "Your notes are protected with end-to-end encryption. Only you can read your content, even we can't see it.",
      icon: (
        <svg className="w-12 h-12 text-blue-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      ),
    },
    {
      title: "Create Your First Note",
      content: "Click 'New Encrypted Note' to start writing. Your notes are automatically saved and encrypted as you type.",
      icon: (
        <svg className="w-12 h-12 text-green-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4v16m8-8H4" />
        </svg>
      ),
    },
    {
      title: "Search and Organize",
      content: "Use the search bar to quickly find your notes. All searching happens locally - your data never leaves your device unencrypted.",
      icon: (
        <svg className="w-12 h-12 text-purple-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      ),
    },
    {
      title: "Stay Secure",
      content: "Always log out when you're done, especially on shared computers. Your encryption keys are tied to your session.",
      icon: (
        <svg className="w-12 h-12 text-red-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
  ];

  const currentStep = onboardingSteps[step] || onboardingSteps[0];
  const isLastStep = step === onboardingSteps.length - 1;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg shadow-xl p-8 max-w-md w-full">
        <div className="text-center">
          {currentStep.icon}
          <h2 className="text-2xl font-bold text-white mb-4">{currentStep.title}</h2>
          <p className="text-gray-300 mb-6 leading-relaxed">{currentStep.content}</p>
          
          <div className="flex justify-center mb-6">
            <div className="flex space-x-2">
              {onboardingSteps.map((_, index) => (
                <div
                  key={index}
                  className={`w-2 h-2 rounded-full ${
                    index === step ? 'bg-blue-500' : 'bg-gray-600'
                  }`}
                />
              ))}
            </div>
          </div>
          
          <div className="flex justify-between">
            <button
              onClick={onSkip}
              className="text-gray-400 hover:text-white transition focus:outline-none focus:underline"
            >
              Skip Tour
            </button>
            
            <div className="flex space-x-3">
              {step > 0 && (
                <button
                  onClick={onPrev}
                  className="px-4 py-2 text-gray-300 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-gray-500/50 rounded"
                >
                  Back
                </button>
              )}
              <button
                onClick={isLastStep ? onComplete : onNext}
                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition focus:outline-none focus:ring-2 focus:ring-blue-500/50"
              >
                {isLastStep ? 'Get Started' : 'Next'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Markdown Renderer with Error Boundary
const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content }) => {
  const [renderError, setRenderError] = useState<string | null>(null);
  
  useEffect(() => {
    // Reset error when content changes
    setRenderError(null);
  }, [content]);
  
  try {
    if (renderError) {
      return (
        <div className="bg-red-900/50 border border-red-600 rounded-lg p-4">
          <h3 className="text-red-200 font-medium mb-2">Preview Error</h3>
          <p className="text-red-300 text-sm mb-2">Unable to render markdown preview</p>
          <p className="text-red-400 text-xs">{renderError}</p>
          <button
            onClick={() => setRenderError(null)}
            className="mt-3 text-xs text-red-300 hover:text-red-200 underline"
          >
            Try Again
          </button>
        </div>
      );
    }

    return (
      <div className="text-gray-200">
        <ReactMarkdown 
          remarkPlugins={[remarkGfm]}
          components={{
          // Style headings
          h1: ({children}) => <h1 className="text-2xl font-bold text-white mb-4 border-b border-gray-600 pb-2">{children}</h1>,
          h2: ({children}) => <h2 className="text-xl font-semibold text-white mb-3 mt-6">{children}</h2>,
          h3: ({children}) => <h3 className="text-lg font-medium text-white mb-2 mt-4">{children}</h3>,
          // Style paragraphs
          p: ({children}) => <p className="text-gray-200 mb-4 leading-relaxed">{children}</p>,
          // Style lists
          ul: ({children}) => <ul className="text-gray-200 mb-4 ml-6 list-disc">{children}</ul>,
          ol: ({children}) => <ol className="text-gray-200 mb-4 ml-6 list-decimal">{children}</ol>,
          li: ({children}) => <li className="mb-1">{children}</li>,
          // Style code
          code: ({children}) => <code className="bg-gray-800 text-blue-300 px-1 py-0.5 rounded text-sm">{children}</code>,
          pre: ({children}) => <pre className="bg-gray-800 text-gray-200 p-4 rounded-lg overflow-x-auto mb-4">{children}</pre>,
          // Style links
          a: ({children, href}) => <a href={href} className="text-blue-400 hover:text-blue-300 underline" target="_blank" rel="noopener noreferrer">{children}</a>,
          // Style blockquotes
          blockquote: ({children}) => <blockquote className="border-l-4 border-blue-500 pl-4 my-4 text-gray-300 italic">{children}</blockquote>,
          // Style tables
          table: ({children}) => <table className="w-full mb-4 border-collapse">{children}</table>,
          thead: ({children}) => <thead className="bg-gray-800">{children}</thead>,
          th: ({children}) => <th className="border border-gray-600 px-3 py-2 text-left text-white font-semibold">{children}</th>,
          td: ({children}) => <td className="border border-gray-600 px-3 py-2 text-gray-200">{children}</td>,
        }}
      >
        {content}
        </ReactMarkdown>
      </div>
    );
  } catch (err) {
    console.error('Markdown component error:', err);
    return (
      <div className="bg-red-900/50 border border-red-600 rounded-lg p-4">
        <h3 className="text-red-200 font-medium mb-2">Preview Error</h3>
        <p className="text-red-300 text-sm mb-2">Unable to render markdown preview</p>
        <p className="text-red-400 text-xs">{(err as Error).message || 'Unknown error'}</p>
      </div>
    );
  }
};

// Utility function for debouncing with cancel support
function debounce(func: (...args: any[]) => void, wait: number): DebounceFunction {
  let timeout: NodeJS.Timeout;
  function executedFunction(...args: any[]) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  }
  
  // Add cancel method
  executedFunction.cancel = () => {
    clearTimeout(timeout);
  };
  
  return executedFunction;
}

// Theme Toggle Component
const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useTheme();
  const [isOpen, setIsOpen] = useState(false);

  const themeOptions = [
    { 
      value: 'system' as ThemeType, 
      label: 'System', 
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      )
    },
    { 
      value: 'light' as ThemeType, 
      label: 'Light', 
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
        </svg>
      )
    },
    { 
      value: 'dark' as ThemeType, 
      label: 'Dark', 
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
      )
    }
  ];

  const currentOption = themeOptions.find(option => option.value === theme);

  return (
    <div className="relative">
      <Button
        onClick={() => setIsOpen(!isOpen)}
        variant="ghost"
        size="sm"
        className="flex items-center px-3 py-1 text-sm"
        aria-label="Theme selector"
        title="Change theme"
      >
        {currentOption?.icon}
        <span className="ml-1">{currentOption?.label}</span>
        <svg className="w-3 h-3 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </Button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setIsOpen(false)} />
          <div className="absolute right-0 top-full mt-1 w-32 bg-popover border border-border rounded-lg shadow-lg z-20">
            {themeOptions.map((option) => (
              <Button
                key={option.value}
                onClick={() => {
                  setTheme(option.value);
                  setIsOpen(false);
                }}
                variant="ghost"
                className={`w-full flex items-center justify-start px-3 py-2 text-sm first:rounded-t-lg last:rounded-b-lg h-auto ${
                  theme === option.value ? 'text-primary bg-accent' : 'text-popover-foreground'
                }`}
              >
                {option.icon}
                <span className="ml-2">{option.label}</span>
              </Button>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

// Login Component with shadcn/ui
interface LoginViewProps {
  onAuthenticated?: () => void;
}

const LoginView: React.FC<LoginViewProps> = ({ onAuthenticated }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const calculatePasswordStrength = (pwd: string): number => {
    let strength = 0;
    if (pwd.length >= 12) strength++;
    if (pwd.length >= 16) strength++;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++;
    if (/[0-9]/.test(pwd)) strength++;
    if (/[^A-Za-z0-9]/.test(pwd)) strength++;
    return strength;
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const pwd = e.target.value;
    setPassword(pwd);
    setPasswordStrength(calculatePasswordStrength(pwd));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      console.log('🔐 Starting authentication...', { 
        mode: isRegistering ? 'REGISTRATION' : 'LOGIN',
        isRegistering, 
        email, 
        hasPassword: !!password,
        passwordLength: password?.length 
      });
      
      // Ensure sodium is ready
      await cryptoService.initSodium();
      console.log('✅ Sodium initialized');

      if (isRegistering) {
        console.log('🔄 REGISTRATION MODE - Validating inputs...');
        if (password.length < 12) {
          setError('Password must be at least 12 characters for registration');
          return;
        }
        
        console.log('📝 Attempting registration with email:', email);
        const response = await api.register(email, password);
        console.log('✅ Registration successful:', { userId: response.user_id, hasToken: !!response.token });
        
        // For registration, generate a salt and store it
        const salt = await cryptoService.generateSalt();
        const saltBase64 = btoa(String.fromCharCode(...salt));
        localStorage.setItem('user_salt', saltBase64);
        console.log('🧂 Generated and stored salt for new user');
        
        const key = await cryptoService.deriveKeyFromPassword(password, salt);
        await cryptoService.setMasterKey(key);
        console.log('🔑 Master key derived and set');
        
        // Notify parent we're authenticated without hard reload
        onAuthenticated?.();
      } else {
        console.log('🔑 LOGIN MODE - Attempting login with email:', email);
        const response = await api.login(email, password, mfaCode);
        console.log('✅ Login API successful:', { hasToken: !!response.token });
        
        if (response.mfa_required) {
          console.log('🔒 MFA required');
          setMfaRequired(true);
          return;
        }
        
        // For login, try to get stored salt or generate a new one
        let salt: Uint8Array;
        const storedSalt = localStorage.getItem('user_salt');
        if (storedSalt) {
          const saltString = atob(storedSalt);
          salt = new Uint8Array(saltString.split('').map(char => char.charCodeAt(0)));
          console.log('🧂 Using stored salt');
        } else {
          salt = await cryptoService.generateSalt();
          const saltBase64 = btoa(String.fromCharCode(...salt));
          localStorage.setItem('user_salt', saltBase64);
          console.log('🧂 Generated new salt (no stored salt found)');
        }
        
        const key = await cryptoService.deriveKeyFromPassword(password, salt);
        await cryptoService.setMasterKey(key);
        console.log('🔑 Master key derived and set');
        
        // Notify parent we're authenticated without hard reload
        onAuthenticated?.();
      }
    } catch (err) {
      console.error('💥 Authentication failed:', { 
        mode: isRegistering ? 'REGISTRATION' : 'LOGIN',
        error: (err as Error).message,
        fullError: err 
      });
      
      // Provide context-aware error messages
      let errorMessage = (err as Error).message;
      if (!errorMessage) {
        errorMessage = isRegistering ? 
          'Registration failed. Please check your email and password.' : 
          'Login failed. Please check your credentials.';
      }
      
      // Special handling for common errors
      if (errorMessage.includes('Invalid credentials') && isRegistering) {
        errorMessage = 'Registration failed. Please try a different email address.';
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center mb-4">
            <div className="flex items-center space-x-2">
              <Lock className="h-8 w-8 text-primary" />
              <CardTitle className="text-2xl">LeafLock</CardTitle>
            </div>
          </div>
          <CardDescription className="text-center">
            Your secure note-taking application
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                placeholder="Enter your email"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={handlePasswordChange}
                required
                minLength={12}
                autoComplete={isRegistering ? "new-password" : "current-password"}
                placeholder="Enter your password"
              />
              {isRegistering && (
                <div className="space-y-2">
                  <div className="flex space-x-1" role="progressbar" aria-valuenow={passwordStrength} aria-valuemax={5}>
                    {[...Array(5)].map((_, i) => (
                      <div
                        key={i}
                        className={`h-2 flex-1 rounded ${
                          i < passwordStrength
                            ? passwordStrength <= 2 ? 'bg-destructive' 
                              : passwordStrength <= 3 ? 'bg-yellow-500' 
                              : 'bg-green-500'
                            : 'bg-muted'
                        }`}
                      />
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Use 12+ characters with mixed case, numbers & symbols
                  </p>
                </div>
              )}
            </div>

            {mfaRequired && (
              <div className="space-y-2">
                <Label htmlFor="mfa">2FA Code</Label>
                <Input
                  id="mfa"
                  type="text"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="000000"
                  maxLength={6}
                  required={mfaRequired}
                  autoComplete="one-time-code"
                />
                <p className="text-xs text-muted-foreground">
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
            )}

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button
              type="submit"
              className="w-full"
              disabled={loading}
            >
              {loading ? 'Processing...' : (isRegistering ? 'Create Account' : 'Login')}
            </Button>

            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setIsRegistering(!isRegistering);
                setError(null);
                setMfaRequired(false);
              }}
            >
              {isRegistering ? 'Already have an account? Login' : 'Need an account? Register'}
            </Button>
          </form>
        </CardContent>
      </Card>
      <div className="mt-4 text-center text-sm text-muted-foreground">
        <a href="https://github.com/RelativeSure/notes/discussions" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:underline">
          <MessageSquare className="w-4 h-4" /> Join GitHub Discussions
        </a>
      </div>
    </div>
  );
};

// Main App Component  
function SecureNotesApp() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentView, setCurrentView] = useState<ViewType>('login');
  const [notes, setNotes] = useState<Note[]>([]);
  const [trashedNotes, setTrashedNotes] = useState<Note[]>([]);
  const [selectedNote, setSelectedNote] = useState<Note | null>(null);
  const [encryptionStatus, setEncryptionStatus] = useState<EncryptionStatus>('locked');
  const [viewingTrash, setViewingTrash] = useState(false);
  const [loading, setLoading] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [, setError] = useState<string | null>(null);
  const [notesError, setNotesError] = useState<string | null>(null);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [onboardingStep, setOnboardingStep] = useState(0);
  const [isAdmin, setIsAdmin] = useState(false);

  console.log('🔄 SecureNotesApp render - initializing:', initializing, 'isAuthenticated:', isAuthenticated, 'currentView:', currentView);

  // Centralized logout function
  const handleLogout = useCallback(() => {
    console.log('🚪 Performing complete logout...');
    
    // Clear all auth-related state
    api.clearToken();
    cryptoService.masterKey = null;
    localStorage.removeItem('user_salt');
    
    // Reset React state
    setIsAuthenticated(false);
    setCurrentView('login');
    setEncryptionStatus('locked');
    setNotes([]);
    setSelectedNote(null);
    setError(null);
    setNotesError(null);
    setIsAdmin(false);
    
    console.log('✅ Complete logout finished');
  }, []);

  // Set up API unauthorized callback
  useEffect(() => {
    api.setUnauthorizedCallback(handleLogout);
  }, [handleLogout]);

  // Periodic admin re-check while authenticated
  useEffect(() => {
    if (!isAuthenticated) return;
    let mounted = true;
    const tick = async () => {
      try {
        const ok = await api.adminHealth();
        if (!mounted) return;
        if (ok !== isAdmin) {
          setIsAdmin(!!ok);
          if (!ok && currentView === 'admin') {
            setCurrentView('notes');
          }
        }
      } catch {
        if (isAdmin && currentView === 'admin') {
          setCurrentView('notes');
        }
        setIsAdmin(false);
      }
    };
    const id = setInterval(tick, 15000);
    tick();
    return () => { mounted = false; clearInterval(id); };
  }, [isAuthenticated, isAdmin, currentView]);

  useEffect(() => {
    // Check if user has a valid session
    const initializeApp = async () => {
      try {
        console.log('🚀 Starting app initialization...');
        const token = localStorage.getItem('secure_token');
        // Backfill current_user_id from JWT if missing
        if (token && !localStorage.getItem('current_user_id')) {
          try {
            const payload = JSON.parse(atob(token.split('.')[1] || ''));
            if (payload && typeof payload.user_id === 'string') {
              localStorage.setItem('current_user_id', payload.user_id);
            }
          } catch {}
        }
        if (token) {
          console.log('🔐 Found stored token, validating...');
          
          // Validate token with backend before trusting it (with timeout)
          let isValid = false;
          try {
            console.log('🔍 Validating token with 3-second timeout...');
            const timeoutPromise = new Promise<boolean>((_, reject) =>
              setTimeout(() => reject(new Error('Validation timeout')), 3000)
            );
            isValid = await Promise.race([
              api.validateToken(),
              timeoutPromise
            ]);
          } catch (err) {
            console.warn('⚠️ Token validation failed:', err);
            // If validation fails (network error, timeout, etc.), treat as invalid
            isValid = false;
          }
          
          if (isValid) {
            console.log('✅ Token valid, checking encryption key...');
            // Probe admin status via admin health endpoint (403 for non-admins)
            try {
              const adminOk = await api.adminHealth();
              setIsAdmin(!!adminOk);
            } catch {
              setIsAdmin(false);
            }
            
            // Check if we have the master key - if not, user needs to re-enter password
            if (!cryptoService.masterKey) {
              console.log('🔐 No master key - user needs to re-enter password');
              setIsAuthenticated(true);
              setCurrentView('unlock'); // New view for password re-entry
              setEncryptionStatus('locked');
            } else {
              console.log('🔑 Master key found, initializing app...');
              setIsAuthenticated(true);
              setCurrentView('notes');
              setEncryptionStatus('unlocked');
              
              // Load notes but don't wait for it to avoid hanging
              loadNotes().catch(err => {
                console.error('Failed to load notes during init:', err);
              });
              
              // Check if user needs onboarding
              const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding');
              if (!hasSeenOnboarding) {
                setShowOnboarding(true);
              }
            }
          } else {
            console.log('❌ Token invalid, clearing and redirecting to login');
            // Don't call handleLogout here as it might cause loops
            api.clearToken();
            localStorage.removeItem('user_salt');
            cryptoService.masterKey = null;
            setIsAuthenticated(false);
            setCurrentView('login');
            setEncryptionStatus('locked');
          }
        } else {
          console.log('ℹ️ No stored token found - showing login');
          setIsAuthenticated(false);
          setCurrentView('login');
          setEncryptionStatus('locked');
        }
      } catch (err) {
        console.error('💥 Failed to initialize app:', err);
        setError('Failed to initialize application');
        // Clear state without calling handleLogout
        setIsAuthenticated(false);
        setCurrentView('login');
        setEncryptionStatus('locked');
      } finally {
        console.log('🏁 App initialization complete, setting initializing = false');
        setInitializing(false);
        console.log('✅ setInitializing(false) called');
      }
    };
    
    initializeApp();
  }, []);  // Remove handleLogout dependency to prevent loops

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Only handle shortcuts when authenticated and not in onboarding
      if (!isAuthenticated || showOnboarding) return;

      // Cmd/Ctrl + N: New note
      if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
        e.preventDefault();
        setSelectedNote(null);
        setCurrentView('editor');
      }

      // Cmd/Ctrl + K: Search notes (focus search)
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.getElementById('search-notes');
        if (searchInput) {
          searchInput.focus();
        }
      }

      // Escape: Close current view/go back
      if (e.key === 'Escape') {
        if (selectedNote || currentView === 'editor') {
          setSelectedNote(null);
          setCurrentView('notes');
        }
      }

      // Cmd/Ctrl + S: Manual save (if in editor)
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (selectedNote || currentView === 'editor') {
          // Trigger save if we're in the editor
          const saveButton = document.querySelector('[data-save-action]') as HTMLButtonElement;
          if (saveButton) {
            saveButton.click();
          }
        }
      }

      // Arrow navigation in notes list
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        const noteButtons = document.querySelectorAll('[data-note-button]') as NodeListOf<HTMLElement>;
        const currentIndex = Array.from(noteButtons).findIndex(btn => btn === document.activeElement);
        
        if (currentIndex !== -1) {
          e.preventDefault();
          let nextIndex;
          if (e.key === 'ArrowDown') {
            nextIndex = Math.min(currentIndex + 1, noteButtons.length - 1);
          } else {
            nextIndex = Math.max(currentIndex - 1, 0);
          }
          noteButtons[nextIndex]?.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isAuthenticated, showOnboarding, selectedNote, currentView]);

  const loadNotes = async () => {
    try {
      setLoading(true);
      setNotesError(null);
      console.log('📝 Loading notes...');
      const fetchedNotes = await api.getNotes();
      setNotes(fetchedNotes);
      console.log(`✅ Loaded ${fetchedNotes.length} notes`);
    } catch (err) {
      console.error('💥 Failed to load notes:', err);
      
      // Check if it's an authentication error
      if ((err as Error).message.includes('401') || (err as Error).message.includes('Unauthorized')) {
        console.log('🚨 Authentication error while loading notes - logging out');
        handleLogout();
        return; // Don't set error message, just logout
      }
      
      setNotesError((err as Error).message || 'Failed to load notes');
    } finally {
      setLoading(false);
    }
  };

  const loadTrash = async () => {
    try {
      setLoading(true);
      setNotesError(null);
      console.log('🗑️ Loading trash...');
      const fetchedTrash = await api.getTrash();
      setTrashedNotes(fetchedTrash);
      console.log(`✅ Loaded ${fetchedTrash.length} trashed notes`);
    } catch (err) {
      console.error('💥 Failed to load trash:', err);
      
      // Check if it's an authentication error
      if ((err as Error).message.includes('401') || (err as Error).message.includes('Unauthorized')) {
        console.log('🚨 Authentication error while loading trash - logging out');
        handleLogout();
        return;
      }
      
      setNotesError((err as Error).message || 'Failed to load trash');
    } finally {
      setLoading(false);
    }
  };

  const handleRestoreNote = async (noteId: string) => {
    try {
      console.log('♻️ Restoring note:', noteId);
      await api.restoreNote(noteId);
      console.log('✅ Note restored successfully');
      
      // Reload both lists to reflect changes
      await Promise.all([loadNotes(), loadTrash()]);
      
      // Clear selected note if it was the restored one
      if (selectedNote && selectedNote.id === noteId) {
        setSelectedNote(null);
      }
    } catch (err) {
      console.error('💥 Failed to restore note:', err);
      setNotesError((err as Error).message || 'Failed to restore note');
    }
  };

  const handlePermanentDelete = async (noteId: string) => {
    try {
      console.log('🗑️ Permanently deleting note:', noteId);
      await api.permanentlyDeleteNote(noteId);
      console.log('✅ Note permanently deleted');
      
      // Reload trash to reflect changes
      await loadTrash();
      
      // Clear selected note if it was the deleted one
      if (selectedNote && selectedNote.id === noteId) {
        setSelectedNote(null);
      }
    } catch (err) {
      console.error('💥 Failed to permanently delete note:', err);
      setNotesError((err as Error).message || 'Failed to permanently delete note');
    }
  };

  const handleOnboardingNext = () => {
    setOnboardingStep(prev => prev + 1);
  };

  const handleOnboardingPrev = () => {
    setOnboardingStep(prev => Math.max(0, prev - 1));
  };

  const handleOnboardingSkip = () => {
    localStorage.setItem('hasSeenOnboarding', 'true');
    setShowOnboarding(false);
    setOnboardingStep(0);
  };

  const handleOnboardingComplete = () => {
    localStorage.setItem('hasSeenOnboarding', 'true');
    setShowOnboarding(false);
    setOnboardingStep(0);
  };

  // Notes Editor Component
  const NotesEditor: React.FC = () => {
    const [title, setTitle] = useState(selectedNote?.title || '');
    const [content, setContent] = useState(selectedNote?.content || '');
    const [saving, setSaving] = useState(false);
    const [lastSaved, setLastSaved] = useState<Date | null>(null);
    const [saveError, setSaveError] = useState<string | null>(null);
    const [isPreviewMode, setIsPreviewMode] = useState(false); // true = preview, false = edit

    // Use refs to access current values inside debounced function
    const titleRef = useRef(title);
    const contentRef = useRef(content);
    const selectedNoteRef = useRef(selectedNote);
    const debouncedAutosaveRef = useRef<DebounceFunction | null>(null);
    
    // Keep refs in sync with state
    useEffect(() => {
      titleRef.current = title;
      contentRef.current = content;
      selectedNoteRef.current = selectedNote;
    }, [title, content, selectedNote]);

    // Initialize content when selectedNote changes
    useEffect(() => {
      if (selectedNote) {
        setTitle(selectedNote.title || '');
        setContent(selectedNote.content || '');
        setLastSaved(selectedNote.updated_at ? new Date(selectedNote.updated_at) : null);
      } else {
        setTitle('');
        setContent('');
        setLastSaved(null);
      }
    }, [selectedNote]);

    const handleSave = useCallback(async () => {
      // Prevent concurrent saves
      if (saving) {
        console.log('💾 Save already in progress, skipping duplicate');
        return;
      }
      
      setSaving(true);
      setSaveError(null);
      
      // Cancel any pending debounced saves when manual save occurs
      if (debouncedAutosaveRef.current) {
        debouncedAutosaveRef.current.cancel();
        console.log('🚫 Cancelled pending autosave due to manual save');
      }
      
      try {
        // Check if encryption is ready before attempting to save
        if (!cryptoService.isSodiumReady()) {
          console.warn('⚠️ Sodium not ready, skipping autosave');
          setSaveError('Encryption not ready - please try manual save');
          return;
        }

        // Use current values from refs
        const currentTitle = titleRef.current;
        const currentContent = contentRef.current;
        const currentSelectedNote = selectedNoteRef.current;
        
        if (currentSelectedNote) {
          // Update existing note
          await api.updateNote(currentSelectedNote.id, currentTitle, currentContent);
          console.log('✅ Updated existing note:', currentSelectedNote.id);
          
          // Update the selectedNote state with new content
          setSelectedNote({
            ...currentSelectedNote,
            title: currentTitle,
            content: currentContent,
            updated_at: new Date().toISOString()
          });
          
          // Update the note in the notes list
          setNotes(prevNotes => 
            prevNotes.map(note => 
              note.id === currentSelectedNote.id 
                ? { ...note, title: currentTitle, content: currentContent, updated_at: new Date().toISOString() }
                : note
            )
          );
        } else {
          // Create new note and capture the response
          const response = await api.createNote(currentTitle, currentContent);
          console.log('✅ Created new note with ID:', response.id);
          
          // Create complete note object
          const newNote: Note = {
            id: response.id,
            title: currentTitle || 'Untitled',
            content: currentContent,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          };
          
          // Set the newly created note as selected
          setSelectedNote(newNote);
          
          // Add to notes list without full reload to prevent aggressive refresh
          setNotes(prevNotes => [newNote, ...prevNotes]);
        }
        setLastSaved(new Date());
      } catch (err) {
        console.error('Failed to save note:', err);
        setSaveError((err as Error).message || 'Failed to save note');
      } finally {
        setSaving(false);
      }
    }, []);

    // Create a stable debounced function using useMemo to prevent recreation
    const debouncedSave = useMemo(() => {
      const debouncedFunc = debounce(async () => {
        // Check current values from refs and ensure content actually changed
        const currentNote = selectedNoteRef.current;
        const currentTitle = titleRef.current;
        const currentContent = contentRef.current;
        
        // Only save if content has actually changed from the loaded note
        if (currentNote && (currentTitle !== currentNote.title || currentContent !== currentNote.content)) {
          try {
            await handleSave();
            console.log('✅ Autosave completed');
          } catch (err) {
            console.error('💥 Autosave failed:', err);
            setSaveError((err as Error).message || 'Autosave failed');
          }
        }
      }, 3000); // Increased delay to 3 seconds for better UX
      
      // Store reference for cancellation
      debouncedAutosaveRef.current = debouncedFunc;
      return debouncedFunc;
    }, [handleSave]);

    // Only trigger autosave when content actually changes AND not during initial load
    useEffect(() => {
      // Don't autosave if we just loaded the note or if content is empty
      if ((title || content) && selectedNote && (title !== selectedNote.title || content !== selectedNote.content)) {
        debouncedSave();
      }
    }, [title, content, debouncedSave, selectedNote]);

    return (
      <div className="flex-1 flex flex-col" role="main" aria-label="Note editor">
        <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
          <label htmlFor="note-title" className="sr-only">
            Note title
          </label>
          <input
            id="note-title"
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Note title..."
            className="w-full bg-transparent text-xl font-semibold text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded px-2 py-1 -mx-2"
          />
          <div className="flex items-center justify-between mt-2 text-sm text-gray-400" aria-live="polite">
            <div className="flex items-center">
              {saving && (
                <span className="flex items-center">
                  <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24" aria-hidden="true">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <span>Saving...</span>
                  <span className="sr-only">Your note is being saved</span>
                </span>
              )}
              {!saving && lastSaved && (
                <span>Last saved {lastSaved.toLocaleTimeString()}</span>
              )}
              {!saving && !lastSaved && (title || content) && (
                <span className="text-yellow-400">Unsaved changes</span>
              )}
            </div>
            
            <div className="flex items-center space-x-4">
              {/* Preview Toggle Switch */}
              <div className="flex items-center gap-2">
                <Label htmlFor="preview-toggle" className="text-sm text-gray-300">
                  Edit
                </Label>
                <Switch
                  id="preview-toggle"
                  checked={isPreviewMode}
                  onCheckedChange={setIsPreviewMode}
                  className="data-[state=checked]:bg-blue-600"
                />
                <Label htmlFor="preview-toggle" className="text-sm text-gray-300">
                  Preview
                </Label>
              </div>

              {/* Manual Save Button */}
              <button
                data-save-action
                onClick={handleSave}
                disabled={saving || (!title && !content)}
                className="flex items-center px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-sm rounded transition-colors"
                title="Save note manually (Ctrl+S)"
              >
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                Save
              </button>
              
              {/* Encryption Status */}
              <span className="flex items-center" aria-label="Encryption status">
                <svg className="w-4 h-4 mr-1 text-green-500" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                  <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                Encrypted
              </span>
            </div>
          </div>
        </header>
        
        {saveError && (
          <div className="px-6 py-2">
            <ErrorBoundary 
              error={saveError}
              onRetry={handleSave}
              onDismiss={() => setSaveError(null)}
              className="mb-4"
            />
          </div>
        )}
        
        <div className="flex-1 flex">
          {/* Edit Mode */}
          {!isPreviewMode && (
            <div className="w-full p-6">
              <label htmlFor="note-content" className="sr-only">
                Note content
              </label>
              <textarea
                id="note-content"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Start writing your secure note... You can use Markdown formatting!"
                className="w-full h-full bg-transparent text-gray-200 placeholder-gray-500 focus:outline-none resize-none focus:ring-2 focus:ring-blue-500/50 rounded p-2 -m-2"
                aria-describedby="editor-help"
              />
              <p id="editor-help" className="sr-only">
                This note is automatically encrypted and saved as you type. Supports Markdown formatting.
              </p>
            </div>
          )}

          {/* Preview Mode */}
          {isPreviewMode && (
            <div className="w-full p-6 overflow-y-auto">
              <div className="prose prose-invert max-w-none">
                {content ? (
                  <MarkdownRenderer content={content} />
                ) : (
                  <p className="text-gray-500 italic">
                    Preview will appear here when you start writing...
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Notes List Component
  const NotesList: React.FC = () => {
    const [searchQuery, setSearchQuery] = useState('');
    
    const currentNotes = viewingTrash ? trashedNotes : notes;
    const filteredNotes = currentNotes.filter(note =>
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
      <nav className="w-full md:w-80 bg-card md:border-r border-border flex flex-col h-full" role="navigation" aria-label={viewingTrash ? "Trash list" : "Notes list"}>
        <div className="p-4 border-b border-border">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold text-foreground">
              {viewingTrash ? 'Trash' : 'Notes'}
            </h2>
            {viewingTrash && (
              <Badge variant="secondary" className="text-xs">
                {trashedNotes.length} items
              </Badge>
            )}
          </div>
          
          <div className="relative">
            <label htmlFor="search-notes" className="sr-only">
              {viewingTrash ? 'Search trash' : 'Search notes'}
            </label>
            <svg className="absolute left-3 top-2.5 w-5 h-5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <Input
              id="search-notes"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={viewingTrash ? "Search trash..." : "Search notes..."}
              className="w-full pl-10"
              aria-describedby="search-help"
            />
            <p id="search-help" className="sr-only">
              {viewingTrash ? 'Search through your trashed notes' : 'Search through your notes by title or content'}
            </p>
          </div>
        </div>
        
        <div className="flex-1 overflow-y-auto" role="list" aria-label="Notes">
          {notesError ? (
            <div className="p-4">
              <ErrorBoundary 
                error={notesError}
                onRetry={() => loadNotes()}
                onDismiss={() => setNotesError(null)}
              />
            </div>
          ) : loading ? (
            <NoteListSkeleton />
          ) : filteredNotes.length > 0 ? (
            filteredNotes.map(note => (
            <div
              key={note.id}
              className={`border-b border-border ${
                selectedNote?.id === note.id ? 'bg-accent' : ''
              }`}
            >
              <div className="flex">
                <button
                  data-note-button
                  onClick={() => {
                    if (!viewingTrash) {
                      setSelectedNote(note);
                      // On mobile, switch to editor view when selecting a note
                      if (window.innerWidth < 768) {
                        setCurrentView('editor');
                      }
                    }
                  }}
                  className={`flex-1 text-left p-4 md:p-4 py-6 md:py-4 cursor-pointer hover:bg-accent active:bg-accent transition focus:outline-none focus:bg-accent focus:ring-2 focus:ring-ring ${
                    viewingTrash ? 'cursor-default' : ''
                  }`}
                  role="listitem"
                  aria-pressed={selectedNote?.id === note.id}
                  aria-describedby={`note-${note.id}-date`}
                  disabled={viewingTrash}
                >
                  <h3 className="font-medium text-foreground mb-1">{note.title || 'Untitled'}</h3>
                  <p className="text-sm text-muted-foreground line-clamp-2">
                    {note.content || 'No content'}
                  </p>
                  <p id={`note-${note.id}-date`} className="text-xs text-muted-foreground mt-2">
                    {viewingTrash ? 'Deleted' : 'Modified'} {new Date(note.updated_at).toLocaleDateString()}
                  </p>
                </button>
                
                {/* Action buttons */}
                <div className="flex flex-col justify-center px-2 py-2 space-y-1">
                  {viewingTrash ? (
                    <>
                      {/* Restore button */}
                      <button
                        onClick={() => handleRestoreNote(note.id)}
                        className="p-2 text-green-400 hover:text-green-300 hover:bg-green-900/50 rounded transition focus:outline-none focus:ring-2 focus:ring-green-500/50"
                        title="Restore note"
                        aria-label="Restore note"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
                        </svg>
                      </button>
                      
                      {/* Permanent delete button */}
                      <button
                        onClick={() => {
                          if (confirm('Permanently delete this note? This cannot be undone.')) {
                            handlePermanentDelete(note.id);
                          }
                        }}
                        className="p-2 text-red-400 hover:text-red-300 hover:bg-red-900/50 rounded transition focus:outline-none focus:ring-2 focus:ring-red-500/50"
                        title="Delete permanently"
                        aria-label="Delete permanently"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </>
                  ) : (
                    /* Delete button for regular notes */
                    <button
                      onClick={() => {
                        if (confirm('Move this note to trash?')) {
                          api.deleteNote(note.id).then(() => {
                            // Remove from notes list
                            setNotes(prevNotes => prevNotes.filter(n => n.id !== note.id));
                            // Clear selection if this note was selected
                            if (selectedNote?.id === note.id) {
                              setSelectedNote(null);
                            }
                          }).catch(err => {
                            console.error('Failed to delete note:', err);
                            setNotesError(err.message || 'Failed to delete note');
                          });
                        }
                      }}
                      className="p-2 text-red-400 hover:text-red-300 hover:bg-red-900/50 rounded transition focus:outline-none focus:ring-2 focus:ring-red-500/50"
                      title="Move to trash"
                      aria-label="Move to trash"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H7a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>
            </div>
            ))
          ) : (
            <div className="p-4 text-center text-gray-500" role="status" aria-live="polite">
              {viewingTrash ? (
                searchQuery ? 'No items found in trash' : 'Trash is empty'
              ) : (
                searchQuery ? 'No notes found' : 'No notes yet'
              )}
            </div>
          )}
        </div>
        
        {!viewingTrash && (
          <div className="p-4 border-t border-border">
            <Button
              onClick={() => {
                setSelectedNote(null);
                setCurrentView('editor');
              }}
              className="w-full"
              aria-describedby="new-note-help"
            >
              New Note
            </Button>
            <p id="new-note-help" className="sr-only">
              Create a new note
            </p>
          </div>
        )}
      </nav>
    );
  };

  // Main App Layout
  const AppLayout: React.FC = () => {
    return (
      <div className="h-screen flex flex-col md:flex-row bg-background">
        <div className="md:hidden flex items-center justify-between bg-card border-b border-border px-4 py-3">
          <h1 className="text-lg font-semibold text-foreground">LeafLock</h1>
          <Button
            onClick={() => setCurrentView(currentView === 'notes' ? 'editor' : 'notes')}
            variant="ghost"
            size="sm"
            className="p-1"
            aria-label={currentView === 'notes' ? 'Show editor' : 'Show notes list'}
          >
            {currentView === 'notes' ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            )}
          </Button>
        </div>

        <div className={`${currentView === 'notes' || selectedNote || currentView === 'editor' ? 'hidden md:block' : 'block'} w-full md:w-80`}>
          <NotesList />
        </div>
        
        <div className={`${currentView === 'notes' && !selectedNote ? 'hidden md:flex' : 'flex'} flex-1 flex-col`}>
          <header className="hidden md:flex bg-card border-b border-border px-6 py-3 items-center justify-between">
            <div className="flex items-center space-x-4">
              <h1 className="text-lg font-semibold text-foreground">LeafLock</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <ThemeToggle />
              
              <button
                onClick={() => {
                  setViewingTrash(!viewingTrash);
                  if (!viewingTrash) {
                    loadTrash();
                  }
                }}
                className={`flex items-center px-3 py-1 text-sm rounded transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
                  viewingTrash 
                    ? 'bg-red-600 text-white' 
                    : 'text-gray-400 hover:text-white'
                }`}
                aria-label={viewingTrash ? "Exit trash view" : "View trash"}
                title={viewingTrash ? "Exit trash view" : "View trash"}
              >
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H7a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                {viewingTrash ? 'Exit Trash' : 'Trash'}
              </button>
              
              {isAdmin && (
                <button
                  onClick={() => setCurrentView('admin')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Admin panel"
                  title="Admin panel"
                >
                  <Shield className="w-5 h-5" />
                </button>
              )}

              <button
                onClick={handleLogout}
                className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                aria-label="Sign out"
                title="Sign out"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
              </button>
            </div>
          </header>
          
          {selectedNote || currentView === 'editor' ? (
            <NotesEditor />
          ) : (
            <main className="flex-1 flex items-center justify-center" role="main">
              <div className="text-center">
                <svg className="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <p className="text-gray-500">Select a note or create a new one</p>
                <p className="text-gray-600 text-sm mt-2">Your notes are end-to-end encrypted for maximum privacy</p>
              </div>
            </main>
          )}
        </div>
      </div>
    );
  };

  // Security check: Only force logout if locked in an unexpected view
  useEffect(() => {
    if (!initializing && encryptionStatus === 'locked' && isAuthenticated && currentView !== 'unlock') {
      console.log('🚨 Security check: Locked while authenticated outside unlock view - forcing logout');
      setIsAuthenticated(false);
      setCurrentView('login');
    }
  }, [encryptionStatus, isAuthenticated, initializing, currentView]);

  if (initializing) {
    return <LoadingOverlay message="Starting LeafLock" />;
  }

  // Unlock View - for when user is authenticated but master key is missing
  const UnlockView: React.FC = () => {
    const [password, setPassword] = useState('');
    const [unlocking, setUnlocking] = useState(false);
    const [unlockError, setUnlockError] = useState<string | null>(null);

    const handleUnlock = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!password.trim()) return;

      setUnlocking(true);
      setUnlockError(null);

      try {
        console.log('🔓 Attempting to unlock with re-entered password...');
        
        // Get the stored salt
        const storedSalt = localStorage.getItem('user_salt');
        if (!storedSalt) {
          throw new Error('No stored salt found - please log in again');
        }

        const salt = new Uint8Array(Array.from(atob(storedSalt), c => c.charCodeAt(0)));
        const key = await cryptoService.deriveKeyFromPassword(password, salt);
        await cryptoService.setMasterKey(key);
        
        console.log('🔑 Master key restored successfully');
        setCurrentView('notes');
        setEncryptionStatus('unlocked');
        await loadNotes();
        
      } catch (err) {
        console.error('💥 Failed to unlock:', err);
        setUnlockError((err as Error).message || 'Invalid password');
      } finally {
        setUnlocking(false);
      }
    };

    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center px-4">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <svg className="mx-auto h-12 w-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <h2 className="mt-6 text-3xl font-bold text-white">Locked</h2>
            <p className="mt-2 text-sm text-gray-400">
              Your session is valid but your notes are locked. Enter your password to decrypt your notes.
            </p>
          </div>

          <form className="mt-8 space-y-6" onSubmit={handleUnlock}>
            <div>
              <label htmlFor="unlock-password" className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <input
                id="unlock-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-colors"
                placeholder="Enter your password"
                required
                autoFocus
              />
            </div>

            {unlockError && (
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-3" role="alert">
                <p className="text-red-200 text-sm">{unlockError}</p>
              </div>
            )}

            <div className="flex space-x-4">
              <button
                type="submit"
                disabled={unlocking || !password.trim()}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded-lg transition duration-200"
              >
                {unlocking ? 'Unlocking...' : 'Unlock Notes'}
              </button>
              
              <button
                type="button"
                onClick={handleLogout}
                className="px-4 py-2 text-gray-400 hover:text-white text-sm transition-colors"
              >
                Logout
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  };

  return (
    <>
      {isAuthenticated && isAdmin && currentView === 'admin' ? (
        <AdminPage api={api} onBack={() => setCurrentView('notes')} />
      ) : isAuthenticated && encryptionStatus === 'unlocked' ? (
        <>
          <AppLayout />
        </>
      ) : isAuthenticated && currentView === 'unlock' ? (
        <UnlockView />
      ) : (
        <LoginView
          onAuthenticated={async () => {
            // User has a valid token and master key; transition to notes
            setIsAuthenticated(true);
            setCurrentView('notes');
            setEncryptionStatus('unlocked');
            // Determine admin status
            try {
              const adminOk = await api.adminHealth();
              setIsAdmin(!!adminOk);
            } catch { setIsAdmin(false); }
            try {
              await loadNotes();
            } catch (e) {
              console.error('Failed to load notes after auth:', e);
            }
            const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding');
            if (!hasSeenOnboarding) setShowOnboarding(true);
          }}
        />
      )}
      {/* Admin panel is now accessible via header icon for admins only */}
      {showOnboarding && isAuthenticated && encryptionStatus === 'unlocked' && (
        <OnboardingOverlay 
          step={onboardingStep}
          onNext={handleOnboardingNext}
          onPrev={handleOnboardingPrev}
          onSkip={handleOnboardingSkip}
          onComplete={handleOnboardingComplete}
        />
      )}
    </>
  );
}

// Main App component wrapped with ThemeProvider
const App: React.FC = () => {
  return (
    <ThemeProvider>
      <SecureNotesApp />
    </ThemeProvider>
  );
};

export default App;
