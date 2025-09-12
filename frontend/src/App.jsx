import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import sodium from 'libsodium-wrappers';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Lock, ShieldCheck, Eye, EyeOff, Mail, Key, AlertTriangle, CheckCircle, X, Plus, Search, Save, FileText, Loader2 } from 'lucide-react';

// UI Components
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './components/ui/card';
import { Textarea } from './components/ui/textarea';
import { ScrollArea } from './components/ui/scroll-area';
import { Badge } from './components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from './components/ui/alert';
import { Separator } from './components/ui/separator';
import { cn } from './lib/utils';

// Secure Crypto Service for E2E Encryption
class CryptoService {
  constructor() {
    this.masterKey = null;
    this.derivedKey = null;
    this.sodiumReady = false;
    this.initSodium();
  }

  async initSodium() {
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
          if (typeof sodium[func] === 'undefined') {
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

  async deriveKeyFromPassword(password, salt) {
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
        salt: salt,
        iterations: 600000, // High iteration count for security
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return new Uint8Array(derivedBits);
  }

  async encryptData(plaintext) {
    await this.initSodium();
    if (!this.masterKey) throw new Error('No encryption key set');
    
    // Ensure sodium is fully ready before using its functions
    if (!this.sodiumReady || 
        typeof sodium.crypto_secretbox_easy !== 'function' ||
        typeof sodium.crypto_secretbox_NONCEBYTES !== 'number' ||
        typeof sodium.from_string !== 'function') {
      console.warn('Sodium not ready, waiting and re-initializing...');
      await sodium.ready;
      this.sodiumReady = true;
      
      // Double check after waiting
      if (typeof sodium.crypto_secretbox_easy !== 'function') {
        throw new Error('Sodium encryption functions not available');
      }
    }
    
    // Use Web Crypto API for nonce generation to avoid sodium timing issues  
    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES);
    crypto.getRandomValues(nonce);
    
    const messageBytes = sodium.from_string(plaintext);
    const ciphertext = sodium.crypto_secretbox_easy(messageBytes, nonce, this.masterKey);
    
    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);
    
    return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL);
  }

  async decryptData(encryptedData) {
    await this.initSodium();
    if (!this.masterKey) throw new Error('No decryption key set');
    
    // Ensure sodium is fully ready before using its functions
    if (!this.sodiumReady || typeof sodium.crypto_secretbox_open_easy !== 'function') {
      console.warn('Sodium not ready for decryption, waiting...');
      await sodium.ready;
      this.sodiumReady = true;
    }
    
    const combined = sodium.from_base64(encryptedData, sodium.base64_variants.ORIGINAL);
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES);
    
    const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, this.masterKey);
    return sodium.to_string(decrypted);
  }

  async generateSalt() {
    await this.initSodium();
    // Use standard Web Crypto API for salt generation to avoid sodium timing issues
    const saltBytes = new Uint8Array(32); // 32 bytes for salt
    crypto.getRandomValues(saltBytes);
    console.log('🧂 Generated salt using Web Crypto API');
    return saltBytes;
  }

  async setMasterKey(key) {
    this.masterKey = key;
  }

  isSodiumReady() {
    return this.sodiumReady && 
           typeof sodium.crypto_secretbox_easy === 'function' &&
           typeof sodium.crypto_secretbox_NONCEBYTES === 'number';
  }
}

const cryptoService = new CryptoService();

// Loading Overlay Component
const LoadingOverlay = ({ message = 'Loading...' }) => (
  <div className="fixed inset-0 bg-background/95 backdrop-blur-sm flex items-center justify-center z-50">
    <Card className="p-8 shadow-2xl border-0">
      <CardContent className="flex flex-col items-center space-y-4">
        <div className="relative">
          <div className="w-12 h-12 border-4 border-muted rounded-full animate-spin border-t-primary"></div>
        </div>
        <div className="text-center">
          <h3 className="text-lg font-medium text-foreground">{message}</h3>
          <p className="text-sm text-muted-foreground mt-1">Initializing secure encryption...</p>
        </div>
      </CardContent>
    </Card>
  </div>
);

// Onboarding Component
const OnboardingOverlay = ({ step, onNext, onPrev, onSkip, onComplete }) => {
  const onboardingSteps = [
    {
      title: "Welcome to Secure Notes!",
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

// Secure API Service with encryption
class SecureAPI {
  constructor(baseURL = '/api/v1') {
    this.baseURL = baseURL;
    this.token = localStorage.getItem('secure_token');
    this.onUnauthorized = null; // Callback for 401 responses
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
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
      console.error('💥 API request failed:', { url, error: error.message });
      throw error;
    }
  }

  handleUnauthorized() {
    console.log('🔒 Handling unauthorized access');
    this.clearToken();
    localStorage.removeItem('user_salt');
    
    // Call the callback to update React state
    if (this.onUnauthorized) {
      this.onUnauthorized();
    }
  }

  setUnauthorizedCallback(callback) {
    this.onUnauthorized = callback;
  }

  setToken(token) {
    this.token = token;
    localStorage.setItem('secure_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('secure_token');
  }

  async validateToken() {
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
      console.log('❌ Token validation failed:', error.message);
      return false;
    }
  }

  async register(email, password) {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    
    if (response.token) {
      this.setToken(response.token);
    }
    
    return response;
  }

  async login(email, password, mfaCode) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, mfa_code: mfaCode })
    });
    
    if (response.token) {
      this.setToken(response.token);
    }
    
    return response;
  }

  async createNote(title, content) {
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

  async getNotes() {
    const response = await this.request('/notes');
    const notes = response.notes || response || [];
    
    // Decrypt notes
    const decryptedNotes = await Promise.all(
      notes.map(async (note) => {
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
    
    return decryptedNotes.filter(note => note !== null);
  }

  async updateNote(noteId, title, content) {
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

  async deleteNote(noteId) {
    return this.request(`/notes/${noteId}`, {
      method: 'DELETE'
    });
  }
}

const api = new SecureAPI();

// Main App Component
export default function SecureNotesApp() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentView, setCurrentView] = useState('login');
  const [notes, setNotes] = useState([]);
  const [selectedNote, setSelectedNote] = useState(null);
  const [encryptionStatus, setEncryptionStatus] = useState('locked');
  const [loading, setLoading] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [error, setError] = useState(null);
  const [notesError, setNotesError] = useState(null);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [onboardingStep, setOnboardingStep] = useState(0);

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
    
    console.log('✅ Complete logout finished');
  }, []);

  // Set up API unauthorized callback
  useEffect(() => {
    api.setUnauthorizedCallback(handleLogout);
  }, [handleLogout]);

  useEffect(() => {
    // Check if user has a valid session
    const initializeApp = async () => {
      try {
        console.log('🚀 Starting app initialization...');
        const token = localStorage.getItem('secure_token');
        if (token) {
          console.log('🔐 Found stored token, validating...');
          
          // Validate token with backend before trusting it (with timeout)
          const isValid = await api.validateToken();
          
          if (isValid) {
            console.log('✅ Token valid, checking encryption key...');
            
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
    const handleKeyDown = (e) => {
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
          const saveButton = document.querySelector('[data-save-action]');
          if (saveButton) {
            saveButton.click();
          }
        }
      }

      // Arrow navigation in notes list
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        const noteButtons = document.querySelectorAll('[data-note-button]');
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
      if (err.message.includes('401') || err.message.includes('Unauthorized')) {
        console.log('🚨 Authentication error while loading notes - logging out');
        handleLogout();
        return; // Don't set error message, just logout
      }
      
      setNotesError(err.message || 'Failed to load notes');
    } finally {
      setLoading(false);
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

  // Login Component
  const LoginView = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mfaCode, setMfaCode] = useState('');
    const [mfaRequired, setMfaRequired] = useState(false);
    const [isRegistering, setIsRegistering] = useState(false);
    const [passwordStrength, setPasswordStrength] = useState(0);
    const [showPassword, setShowPassword] = useState(false);

    const calculatePasswordStrength = (pwd) => {
      let strength = 0;
      if (pwd.length >= 12) strength++;
      if (pwd.length >= 16) strength++;
      if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++;
      if (/[0-9]/.test(pwd)) strength++;
      if (/[^A-Za-z0-9]/.test(pwd)) strength++;
      return strength;
    };

    const handlePasswordChange = (e) => {
      const pwd = e.target.value;
      setPassword(pwd);
      setPasswordStrength(calculatePasswordStrength(pwd));
    };

    const handleSubmit = async (e) => {
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
          
          setIsAuthenticated(true);
          setCurrentView('notes');
          setEncryptionStatus('unlocked');
          
          // Check if this is a new user
          const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding');
          if (!hasSeenOnboarding) {
            setShowOnboarding(true);
          }
        } else {
          console.log('🔑 LOGIN MODE - Attempting login with email:', email);
          const response = await api.login(email, password, mfaCode);
          console.log('✅ Login API successful:', { hasToken: !!response.token, hasSession: !!response.session });
          
          if (response.mfa_required) {
            console.log('🔒 MFA required');
            setMfaRequired(true);
            return;
          }
          
          // For login, try to get stored salt or generate a new one
          let salt;
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
          
          setIsAuthenticated(true);
          setCurrentView('notes');
          setEncryptionStatus('unlocked');
          await loadNotes();
        }
      } catch (err) {
        console.error('💥 Authentication failed:', { 
          mode: isRegistering ? 'REGISTRATION' : 'LOGIN',
          error: err.message,
          fullError: err 
        });
        
        // Provide context-aware error messages
        let errorMessage = err.message;
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
        <Card className="w-full max-w-md shadow-2xl border-0 bg-card/95 backdrop-blur">
          <CardHeader className="space-y-1 pb-6">
            <div className="flex items-center justify-center mb-4">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-xl bg-primary/10">
                  <Lock className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-2xl font-bold bg-gradient-to-r from-primary to-primary/70 bg-clip-text text-transparent">
                  Secure Notes
                </CardTitle>
              </div>
            </div>
            <Alert className="border-primary/20 bg-primary/5">
              <ShieldCheck className="h-4 w-4 text-primary" />
              <AlertDescription className="text-sm text-muted-foreground">
                End-to-end encrypted • Zero-knowledge architecture • Your data stays private
              </AlertDescription>
            </Alert>
          </CardHeader>

          <CardContent className="space-y-6">
            <form onSubmit={handleSubmit} className="space-y-6" noValidate>
              <div className="space-y-2">
                <label htmlFor="email-input" className="text-sm font-medium text-foreground">
                  Email
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="email-input"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-10"
                    placeholder="Enter your email"
                    required
                    autoComplete="email"
                    aria-describedby={error ? 'form-error' : undefined}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="password-input" className="text-sm font-medium text-foreground">
                  Password
                </label>
                <div className="relative">
                  <Key className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="password-input"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={handlePasswordChange}
                    className="pl-10 pr-10"
                    placeholder="Enter your password"
                    required
                    minLength={12}
                    autoComplete={isRegistering ? "new-password" : "current-password"}
                    aria-describedby={isRegistering ? 'password-strength password-help' : undefined}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <Eye className="h-4 w-4 text-muted-foreground" />
                    )}
                  </Button>
                </div>
                {isRegistering && (
                  <div className="mt-3">
                    <div className="flex space-x-1" role="progressbar" aria-valuenow={passwordStrength} aria-valuemax="5" aria-label="Password strength">
                      {[...Array(5)].map((_, i) => (
                        <div
                          key={i}
                          className={cn(
                            "h-2 flex-1 rounded-full transition-colors",
                            i < passwordStrength
                              ? passwordStrength <= 2 
                                ? 'bg-destructive' 
                                : passwordStrength <= 3 
                                ? 'bg-yellow-500' 
                                : 'bg-green-500'
                              : 'bg-muted'
                          )}
                          aria-hidden="true"
                        />
                      ))}
                    </div>
                    <p id="password-help" className="text-xs text-muted-foreground mt-2">
                      Use 12+ characters with mixed case, numbers & symbols
                    </p>
                    <p id="password-strength" className="sr-only">
                      Password strength: {passwordStrength === 0 ? 'Very weak' : passwordStrength <= 2 ? 'Weak' : passwordStrength <= 3 ? 'Fair' : passwordStrength === 4 ? 'Good' : 'Strong'}
                    </p>
                  </div>
                )}
              </div>

              {mfaRequired && (
                <div className="space-y-2">
                  <label htmlFor="mfa-input" className="text-sm font-medium text-foreground">
                    2FA Code
                  </label>
                  <Input
                    id="mfa-input"
                    type="text"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    placeholder="000000"
                    maxLength={6}
                    required={mfaRequired}
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    className="text-center text-lg tracking-widest"
                    aria-describedby="mfa-help"
                  />
                  <p id="mfa-help" className="text-xs text-muted-foreground">
                    Enter the 6-digit code from your authenticator app
                  </p>
                </div>
              )}

              {error && (
                <Alert variant="destructive" role="alert" aria-live="polite">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription id="form-error">
                    {error}
                  </AlertDescription>
                </Alert>
              )}

              <Button
                type="submit"
                disabled={loading}
                className="w-full h-11 bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70 font-semibold"
                aria-describedby={loading ? 'loading-status' : undefined}
              >
                {loading ? (
                  <div className="flex items-center">
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Processing...
                    <span id="loading-status" className="sr-only">Please wait while we process your request</span>
                  </div>
                ) : (
                  isRegistering ? 'Create Secure Account' : 'Login Securely'
                )}
              </Button>
            </form>
          </CardContent>

          <CardFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                const newMode = !isRegistering;
                console.log('🔄 Switching mode:', { 
                  from: isRegistering ? 'REGISTRATION' : 'LOGIN',
                  to: newMode ? 'REGISTRATION' : 'LOGIN',
                  isRegistering: newMode
                });
                setIsRegistering(newMode);
                setError(null);
                setMfaRequired(false);
              }}
              className="w-full text-muted-foreground hover:text-foreground"
            >
              {isRegistering ? 'Already have an account? Login' : 'Need an account? Register'}
            </Button>
          </CardFooter>
        </Card>
      </div>
    );
  };

  // Markdown Renderer with Error Boundary
  const MarkdownRenderer = ({ content }) => {
    const [renderError, setRenderError] = useState(null);
    
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
        <ReactMarkdown 
          remarkPlugins={[remarkGfm]}
          className="text-gray-200"
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
      );
    } catch (err) {
      console.error('Markdown component error:', err);
      return (
        <div className="bg-red-900/50 border border-red-600 rounded-lg p-4">
          <h3 className="text-red-200 font-medium mb-2">Preview Error</h3>
          <p className="text-red-300 text-sm mb-2">Unable to render markdown preview</p>
          <p className="text-red-400 text-xs">{err.message || 'Unknown error'}</p>
        </div>
      );
    }
  };

  // Notes Editor Component
  const NotesEditor = () => {
    const [title, setTitle] = useState(selectedNote?.title || '');
    const [content, setContent] = useState(selectedNote?.content || '');
    const [saving, setSaving] = useState(false);
    const [lastSaved, setLastSaved] = useState(null);
    const [saveError, setSaveError] = useState(null);
    const [viewMode, setViewMode] = useState('edit'); // 'edit', 'preview', 'split'

    // Use refs to access current values inside debounced function
    const titleRef = useRef(title);
    const contentRef = useRef(content);
    const selectedNoteRef = useRef(selectedNote);
    
    // Keep refs in sync with state
    useEffect(() => {
      titleRef.current = title;
      contentRef.current = content;
      selectedNoteRef.current = selectedNote;
    }, [title, content, selectedNote]);

    const handleSave = useCallback(async () => {
      setSaving(true);
      setSaveError(null);
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
          // Don't reload notes for updates, just update timestamp
        } else {
          // Create new note and capture the response
          const response = await api.createNote(currentTitle, currentContent);
          console.log('✅ Created new note with ID:', response.id);
          
          // Create complete note object
          const newNote = {
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
        setSaveError(err.message || 'Failed to save note');
      } finally {
        setSaving(false);
      }
    }, []);

    // Create a stable debounced function using useMemo to prevent recreation
    const debouncedSave = useMemo(() => {
      return debounce(async () => {
        // Check current values from refs
        if (titleRef.current || contentRef.current) {
          try {
            await handleSave();
          } catch (err) {
            console.error('Autosave failed:', err);
            setSaveError(err.message || 'Autosave failed');
            // Don't crash the app, just show the error
          }
        }
      }, 2000);
    }, [handleSave]);

    // Only trigger autosave when content actually changes
    useEffect(() => {
      if (title || content) {
        debouncedSave();
      }
    }, [title, content, debouncedSave]);

    return (
      <div className="flex-1 flex flex-col" role="main" aria-label="Note editor">
        <Card className="flex-1 flex flex-col border-0 rounded-none bg-card/50">
          <CardHeader className="pb-4">
            <Input
              id="note-title"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Note title..."
              className="text-xl font-semibold bg-transparent border-0 px-0 focus:ring-0 placeholder:text-muted-foreground/60"
              aria-label="Note title"
            />
            <div className="flex items-center justify-between mt-3" aria-live="polite">
              <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                {saving && (
                  <div className="flex items-center">
                    <Loader2 className="h-4 w-4 mr-2 animate-spin text-primary" />
                    <span className="text-primary">Saving...</span>
                    <span className="sr-only">Your note is being saved</span>
                  </div>
                )}
                {!saving && lastSaved && (
                  <div className="flex items-center">
                    <CheckCircle className="h-4 w-4 mr-2 text-green-500" />
                    <span>Saved {lastSaved.toLocaleTimeString()}</span>
                  </div>
                )}
                {!saving && !lastSaved && (title || content) && (
                  <div className="flex items-center">
                    <AlertTriangle className="h-4 w-4 mr-2 text-yellow-500" />
                    <span className="text-yellow-500">Unsaved changes</span>
                  </div>
                )}
              </div>
              
              <div className="flex items-center space-x-2">
                {/* View Mode Toggle */}
                <div className="flex items-center bg-muted/50 rounded-lg p-1">
                  <Button
                    variant={viewMode === 'edit' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setViewMode('edit')}
                    className="h-8 px-3 text-xs"
                  >
                    Edit
                  </Button>
                  <Button
                    variant={viewMode === 'preview' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setViewMode('preview')}
                    className="h-8 px-3 text-xs"
                  >
                    Preview
                  </Button>
                  <Button
                    variant={viewMode === 'split' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setViewMode('split')}
                    className="h-8 px-3 text-xs"
                  >
                    Split
                  </Button>
                </div>

                {/* Manual Save Button */}
                <Button
                  onClick={handleSave}
                  disabled={saving || (!title && !content)}
                  size="sm"
                  className="h-8"
                  data-save-action
                >
                  <Save className="w-3 h-3 mr-1" />
                  Save
                </Button>
                
                {/* Encryption Status */}
                <Badge variant="secondary" className="text-xs">
                  <ShieldCheck className="w-3 h-3 mr-1 text-green-500" />
                  Encrypted
                </Badge>
              </div>
            </div>
          </CardHeader>
          
          {saveError && (
            <div className="px-6 pb-4">
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  {saveError}
                  <div className="flex gap-2 mt-3">
                    <Button variant="outline" size="sm" onClick={handleSave}>
                      Try Again
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => setSaveError(null)}>
                      Dismiss
                    </Button>
                  </div>
                </AlertDescription>
              </Alert>
            </div>
          )}
          
          <CardContent className="flex-1 flex p-0">
            {/* Edit Mode */}
            {(viewMode === 'edit' || viewMode === 'split') && (
              <div className={`${viewMode === 'split' ? 'w-1/2 border-r border-border' : 'w-full'} p-6 flex flex-col`}>
                <Textarea
                  id="note-content"
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder="Start writing your secure note... You can use Markdown formatting!"
                  className="flex-1 min-h-0 bg-transparent border-0 p-0 text-base resize-none focus:ring-0 placeholder:text-muted-foreground/60"
                  aria-describedby="editor-help"
                />
                <p id="editor-help" className="sr-only">
                  This note is automatically encrypted and saved as you type. Supports Markdown formatting.
                </p>
              </div>
            )}

            {/* Preview Mode */}
            {(viewMode === 'preview' || viewMode === 'split') && (
              <ScrollArea className={`${viewMode === 'split' ? 'w-1/2' : 'w-full'} p-6`}>
                <div className="prose prose-invert max-w-none">
                  {content ? (
                    <MarkdownRenderer content={content} />
                  ) : (
                    <div className="text-center text-muted-foreground/60 py-8">
                      <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p className="italic">
                        Preview will appear here when you start writing...
                      </p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>
    );
  };

  // Notes List Component
  const NotesList = () => {
    const [searchQuery, setSearchQuery] = useState('');
    
    const filteredNotes = notes.filter(note =>
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
      <Card className="w-full md:w-80 h-full border-r-0 rounded-none md:rounded-none md:border-r border-0 md:border bg-card/50" role="navigation" aria-label="Notes list">
        <CardHeader className="pb-4">
          <div className="relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              id="search-notes"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search notes..."
              className="pl-10 bg-background/50 border-border/50"
              aria-describedby="search-help"
            />
            <p id="search-help" className="sr-only">
              Search through your encrypted notes by title or content
            </p>
          </div>
        </CardHeader>
        
        <CardContent className="flex-1 p-0">
          <ScrollArea className="h-full">
            {notesError ? (
              <div className="p-4">
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    {notesError}
                    <div className="flex gap-2 mt-3">
                      <Button variant="outline" size="sm" onClick={() => loadNotes()}>
                        Try Again
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => setNotesError(null)}>
                        Dismiss
                      </Button>
                    </div>
                  </AlertDescription>
                </Alert>
              </div>
            ) : loading ? (
              <div className="space-y-3 p-4">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="animate-pulse">
                    <div className="h-4 bg-muted rounded w-3/4 mb-2"></div>
                    <div className="h-3 bg-muted/70 rounded w-full mb-1"></div>
                    <div className="h-3 bg-muted/70 rounded w-2/3"></div>
                  </div>
                ))}
              </div>
            ) : filteredNotes.length > 0 ? (
              <div className="space-y-1">
                {filteredNotes.map(note => (
                  <Button
                    key={note.id}
                    data-note-button
                    variant="ghost"
                    onClick={() => {
                      setSelectedNote(note);
                      if (window.innerWidth < 768) {
                        setCurrentView('editor');
                      }
                    }}
                    className={cn(
                      "w-full justify-start h-auto p-4 text-left hover:bg-accent/50 focus:bg-accent/50",
                      selectedNote?.id === note.id && "bg-accent text-accent-foreground"
                    )}
                    role="listitem"
                    aria-pressed={selectedNote?.id === note.id}
                  >
                    <div className="w-full space-y-1">
                      <div className="flex items-center justify-between">
                        <h3 className="font-medium truncate flex-1">
                          {note.title || 'Untitled'}
                        </h3>
                        <Badge variant="secondary" className="ml-2 text-xs">
                          <FileText className="w-3 h-3 mr-1" />
                          {new Date(note.updated_at).toLocaleDateString()}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground line-clamp-2 text-left">
                        {note.content || 'No content'}
                      </p>
                    </div>
                  </Button>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-muted-foreground" role="status" aria-live="polite">
                <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p className="text-sm">
                  {searchQuery ? 'No notes found' : 'No notes yet'}
                </p>
                {searchQuery && (
                  <p className="text-xs mt-1">Try a different search term</p>
                )}
              </div>
            )}
          </ScrollArea>
        </CardContent>
        
        <CardFooter className="pt-4">
          <Button
            onClick={() => {
              setSelectedNote(null);
              setCurrentView('editor');
            }}
            className="w-full bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70 font-semibold"
            aria-describedby="new-note-help"
          >
            <Plus className="w-4 h-4 mr-2" />
            New Encrypted Note
          </Button>
          <p id="new-note-help" className="sr-only">
            Create a new end-to-end encrypted note
          </p>
        </CardFooter>
      </Card>
    );
  };

  // Main App Layout
  const AppLayout = () => {
    return (
      <div className="h-screen flex flex-col md:flex-row bg-background">
        <div className="md:hidden flex items-center justify-between bg-card border-b border-border px-4 py-3">
          <div className="flex items-center space-x-2">
            <Lock className="w-5 h-5 text-primary" />
            <h1 className="text-lg font-semibold text-foreground">Secure Notes</h1>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setCurrentView(currentView === 'notes' ? 'editor' : 'notes')}
            aria-label={currentView === 'notes' ? 'Show editor' : 'Show notes list'}
          >
            {currentView === 'notes' ? (
              <Plus className="w-5 h-5" />
            ) : (
              <FileText className="w-5 h-5" />
            )}
          </Button>
        </div>

        <div className={`${currentView === 'notes' || selectedNote || currentView === 'editor' ? 'hidden md:block' : 'block'} w-full md:w-80`}>
          <NotesList />
        </div>
        
        <div className={`${currentView === 'notes' && !selectedNote && currentView !== 'editor' ? 'hidden md:flex' : 'flex'} flex-1 flex-col`}>
          <header className="hidden md:flex bg-card/50 border-b border-border px-6 py-3 items-center justify-between backdrop-blur">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2" role="status" aria-live="polite">
                {encryptionStatus === 'locked' ? (
                  <Badge variant="destructive" className="text-xs">
                    <Lock className="w-3 h-3 mr-1" />
                    Locked
                    <span className="sr-only">
                      Authentication required - you are currently locked out
                    </span>
                  </Badge>
                ) : (
                  <Badge variant="secondary" className="text-xs">
                    <ShieldCheck className="w-3 h-3 mr-1 text-green-500" />
                    Encryption Active
                    <span className="sr-only">
                      Your notes are encrypted and secure
                    </span>
                  </Badge>
                )}
              </div>
            </div>
            
            <div className="flex items-center space-x-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={handleLogout}
                className="text-muted-foreground hover:text-destructive"
                aria-label="Sign out"
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
          </header>
          
          {selectedNote || currentView === 'editor' ? (
            <NotesEditor />
          ) : (
            <main className="flex-1 flex items-center justify-center bg-muted/20" role="main">
              <div className="text-center max-w-sm">
                <div className="mb-6">
                  <FileText className="w-20 h-20 mx-auto text-muted-foreground/40 mb-4" />
                </div>
                <h2 className="text-xl font-semibold text-foreground mb-2">Welcome to Secure Notes</h2>
                <p className="text-muted-foreground mb-4">Select a note from the sidebar or create a new one to get started</p>
                <Badge variant="secondary" className="text-xs">
                  <ShieldCheck className="w-3 h-3 mr-1 text-green-500" />
                  End-to-end encrypted for maximum privacy
                </Badge>
              </div>
            </main>
          )}
        </div>
      </div>
    );
  };

  // Security check: If encryption status is locked, force logout immediately
  useEffect(() => {
    if (!initializing && encryptionStatus === 'locked' && isAuthenticated) {
      console.log('🚨 Security check: User is authenticated but locked - forcing logout');
      setIsAuthenticated(false);
      setCurrentView('login');
    }
  }, [encryptionStatus, isAuthenticated, initializing]);

  if (initializing) {
    return <LoadingOverlay message="Starting Secure Notes" />;
  }

  // Unlock View - for when user is authenticated but master key is missing
  const UnlockView = () => {
    const [password, setPassword] = useState('');
    const [unlocking, setUnlocking] = useState(false);
    const [unlockError, setUnlockError] = useState(null);

    const handleUnlock = async (e) => {
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
        setUnlockError(err.message || 'Invalid password');
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
      {isAuthenticated && encryptionStatus === 'unlocked' ? (
        <AppLayout />
      ) : isAuthenticated && currentView === 'unlock' ? (
        <UnlockView />
      ) : (
        <LoginView />
      )}
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

// Utility function for debouncing
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}