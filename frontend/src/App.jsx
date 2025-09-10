import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import sodium from 'libsodium-wrappers';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

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

// Loading Skeleton Components
const NoteSkeleton = () => (
  <div className="p-4 border-b border-gray-700 animate-pulse">
    <div className="h-4 bg-gray-600 rounded w-3/4 mb-2"></div>
    <div className="h-3 bg-gray-700 rounded w-full mb-1"></div>
    <div className="h-3 bg-gray-700 rounded w-2/3 mb-2"></div>
    <div className="h-3 bg-gray-700 rounded w-1/4"></div>
  </div>
);

const NoteListSkeleton = () => (
  <div>
    {[...Array(5)].map((_, i) => (
      <NoteSkeleton key={i} />
    ))}
  </div>
);

const LoadingOverlay = ({ message = 'Loading...' }) => (
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

const ErrorBoundary = ({ error, onRetry, onDismiss, className = "" }) => {
  const getErrorMessage = (error) => {
    if (typeof error === 'string') return error;
    if (error?.message) return error.message;
    return 'An unexpected error occurred';
  };

  const getErrorSuggestions = (error) => {
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
    </div>
  );
};

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
        console.log('🔐 Starting authentication...', { isRegistering, email, hasPassword: !!password });
        
        // Ensure sodium is ready
        await cryptoService.initSodium();
        console.log('✅ Sodium initialized');

        if (isRegistering) {
          if (password.length < 12) {
            setError('Password must be at least 12 characters');
            return;
          }
          
          console.log('📝 Attempting registration...');
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
          console.log('🔑 Attempting login...');
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
        console.error('💥 Authentication failed:', err);
        // Show the actual error message instead of generic ones
        const errorMessage = err.message || (isRegistering ? 'Registration failed' : 'Login failed');
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <main className="bg-gray-800 rounded-lg shadow-xl p-6 md:p-8 w-full max-w-md" role="main">
          <header className="flex items-center justify-center mb-8">
            <div className="flex items-center space-x-2">
              <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <h1 className="text-2xl font-bold text-white">Secure Notes</h1>
            </div>
          </header>
          
          <div className="bg-yellow-900/50 border border-yellow-600 rounded-lg p-4 mb-6" role="note" aria-label="Security information">
            <p className="text-yellow-200 text-sm">
              <span className="sr-only">Security features: </span>
              🔐 End-to-end encrypted • Zero-knowledge architecture • Your data stays private
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6" noValidate>
            <div>
              <label htmlFor="email-input" className="block text-sm font-medium text-gray-300 mb-2">
                Email
              </label>
              <input
                id="email-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-colors"
                required
                autoComplete="email"
                aria-describedby={error ? 'form-error' : undefined}
              />
            </div>

            <div>
              <label htmlFor="password-input" className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <input
                id="password-input"
                type="password"
                value={password}
                onChange={handlePasswordChange}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-colors"
                required
                minLength={12}
                autoComplete={isRegistering ? "new-password" : "current-password"}
                aria-describedby={isRegistering ? 'password-strength password-help' : undefined}
              />
              {isRegistering && (
                <div className="mt-2">
                  <div className="flex space-x-1" role="progressbar" aria-valuenow={passwordStrength} aria-valuemax="5" aria-label="Password strength">
                    {[...Array(5)].map((_, i) => (
                      <div
                        key={i}
                        className={`h-2 flex-1 rounded ${
                          i < passwordStrength
                            ? passwordStrength <= 2 ? 'bg-red-500' 
                              : passwordStrength <= 3 ? 'bg-yellow-500' 
                              : 'bg-green-500'
                            : 'bg-gray-600'
                        }`}
                        aria-hidden="true"
                      />
                    ))}
                  </div>
                  <p id="password-help" className="text-xs text-gray-400 mt-1">
                    Use 12+ characters with mixed case, numbers & symbols
                  </p>
                  <p id="password-strength" className="sr-only">
                    Password strength: {passwordStrength === 0 ? 'Very weak' : passwordStrength <= 2 ? 'Weak' : passwordStrength <= 3 ? 'Fair' : passwordStrength === 4 ? 'Good' : 'Strong'}
                  </p>
                </div>
              )}
            </div>

            {mfaRequired && (
              <div>
                <label htmlFor="mfa-input" className="block text-sm font-medium text-gray-300 mb-2">
                  2FA Code
                </label>
                <input
                  id="mfa-input"
                  type="text"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-colors"
                  placeholder="000000"
                  maxLength={6}
                  required={mfaRequired}
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  aria-describedby="mfa-help"
                />
                <p id="mfa-help" className="text-xs text-gray-400 mt-1">
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
            )}

            {error && (
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-3" role="alert" aria-live="polite">
                <p id="form-error" className="text-red-200 text-sm">
                  <span className="sr-only">Error: </span>{error}
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded-lg transition duration-200 focus:ring-2 focus:ring-blue-500/50 focus:outline-none"
              aria-describedby={loading ? 'loading-status' : undefined}
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Processing...
                  <span id="loading-status" className="sr-only">Please wait while we process your request</span>
                </span>
              ) : (
                isRegistering ? 'Create Secure Account' : 'Login Securely'
              )}
            </button>

            <button
              type="button"
              onClick={() => {
                setIsRegistering(!isRegistering);
                setError(null);
                setMfaRequired(false);
              }}
              className="w-full text-gray-400 hover:text-white text-sm transition-colors focus:outline-none focus:underline"
            >
              {isRegistering ? 'Already have an account? Login' : 'Need an account? Register'}
            </button>
          </form>
        </main>
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
              {/* View Mode Toggle */}
              <div className="flex items-center bg-gray-700 rounded p-1">
                <button
                  onClick={() => setViewMode('edit')}
                  className={`px-2 py-1 text-sm rounded transition-colors ${
                    viewMode === 'edit' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:text-white'
                  }`}
                  title="Edit mode"
                >
                  Edit
                </button>
                <button
                  onClick={() => setViewMode('preview')}
                  className={`px-2 py-1 text-sm rounded transition-colors ${
                    viewMode === 'preview' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:text-white'
                  }`}
                  title="Preview mode"
                >
                  Preview
                </button>
                <button
                  onClick={() => setViewMode('split')}
                  className={`px-2 py-1 text-sm rounded transition-colors ${
                    viewMode === 'split' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:text-white'
                  }`}
                  title="Split view"
                >
                  Split
                </button>
              </div>

              {/* Manual Save Button */}
              <button
                onClick={handleSave}
                disabled={saving || (!title && !content)}
                className="flex items-center px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-sm rounded transition-colors"
                title="Save note manually"
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
          {(viewMode === 'edit' || viewMode === 'split') && (
            <div className={`${viewMode === 'split' ? 'w-1/2 border-r border-gray-700' : 'w-full'} p-6`}>
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
          {(viewMode === 'preview' || viewMode === 'split') && (
            <div className={`${viewMode === 'split' ? 'w-1/2' : 'w-full'} p-6 overflow-y-auto`}>
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
  const NotesList = () => {
    const [searchQuery, setSearchQuery] = useState('');
    
    const filteredNotes = notes.filter(note =>
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
      <nav className="w-full md:w-80 bg-gray-800 md:border-r border-gray-700 flex flex-col h-full" role="navigation" aria-label="Notes list">
        <div className="p-4 border-b border-gray-700">
          <div className="relative">
            <label htmlFor="search-notes" className="sr-only">
              Search notes
            </label>
            <svg className="absolute left-3 top-2.5 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              id="search-notes"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search notes..."
              className="w-full pl-10 pr-4 py-2 bg-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              aria-describedby="search-help"
            />
            <p id="search-help" className="sr-only">
              Search through your encrypted notes by title or content
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
            <button
              key={note.id}
              data-note-button
              onClick={() => {
                setSelectedNote(note);
                // On mobile, switch to editor view when selecting a note
                if (window.innerWidth < 768) {
                  setCurrentView('editor');
                }
              }}
              className={`w-full text-left p-4 md:p-4 py-6 md:py-4 border-b border-gray-700 cursor-pointer hover:bg-gray-700 active:bg-gray-600 transition focus:outline-none focus:bg-gray-700 focus:ring-2 focus:ring-blue-500/50 ${
                selectedNote?.id === note.id ? 'bg-gray-700' : ''
              }`}
              role="listitem"
              aria-pressed={selectedNote?.id === note.id}
              aria-describedby={`note-${note.id}-date`}
            >
              <h3 className="font-medium text-white mb-1">{note.title || 'Untitled'}</h3>
              <p className="text-sm text-gray-400 line-clamp-2">
                {note.content || 'No content'}
              </p>
              <p id={`note-${note.id}-date`} className="text-xs text-gray-500 mt-2">
                {new Date(note.updated_at).toLocaleDateString()}
              </p>
            </button>
            ))
          ) : (
            <div className="p-4 text-center text-gray-500" role="status" aria-live="polite">
              {searchQuery ? 'No notes found' : 'No notes yet'}
            </div>
          )}
        </div>
        
        <div className="p-4 border-t border-gray-700">
          <button
            onClick={() => {
              setSelectedNote(null);
              setCurrentView('editor');
            }}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            aria-describedby="new-note-help"
          >
            New Encrypted Note
          </button>
          <p id="new-note-help" className="sr-only">
            Create a new end-to-end encrypted note
          </p>
        </div>
      </nav>
    );
  };

  // Main App Layout
  const AppLayout = () => {
    return (
      <div className="h-screen flex flex-col md:flex-row bg-gray-900">
        <div className="md:hidden flex items-center justify-between bg-gray-800 border-b border-gray-700 px-4 py-3">
          <h1 className="text-lg font-semibold text-white">Secure Notes</h1>
          <button
            onClick={() => setCurrentView(currentView === 'notes' ? 'editor' : 'notes')}
            className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
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
          </button>
        </div>

        <div className={`${currentView === 'notes' || selectedNote || currentView === 'editor' ? 'hidden md:block' : 'block'} w-full md:w-80`}>
          <NotesList />
        </div>
        
        <div className={`${currentView === 'notes' && !selectedNote && currentView !== 'editor' ? 'hidden md:flex' : 'flex'} flex-1 flex-col`}>
          <header className="hidden md:flex bg-gray-800 border-b border-gray-700 px-6 py-3 items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2" role="status" aria-live="polite">
                {encryptionStatus === 'locked' ? (
                  <>
                    <svg className="w-5 h-5 text-red-500" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                      <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                    </svg>
                    <span className="text-sm text-red-400 font-medium">
                      🔒 Locked
                    </span>
                    <span className="sr-only">
                      Authentication required - you are currently locked out
                    </span>
                  </>
                ) : (
                  <>
                    <div className="w-2 h-2 rounded-full bg-green-500" aria-hidden="true" />
                    <span className="text-sm text-gray-400">
                      Encryption Active
                    </span>
                    <span className="sr-only">
                      Your notes are encrypted and secure
                    </span>
                  </>
                )}
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
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