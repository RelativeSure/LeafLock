import React, { useEffect, useMemo, useState } from 'react'
import * as sodium from 'libsodium-wrappers'

// Constants
const PBKDF2_ITERATIONS = 600000 // High iteration count for security
const ENCRYPTION_KEY_BITS = 256
const AUTOSAVE_DELAY = 2000
const MIN_PASSWORD_LENGTH = 12
const STRONG_PASSWORD_LENGTH = 16

// Secure Crypto Service for E2E Encryption
class CryptoService {
  constructor() {
    this.masterKey = null
    this.derivedKey = null
    this.sodiumReady = false
    this.initSodium()
  }

  async initSodium() {
    await sodium.ready
    this.sodiumReady = true
  }

  async deriveKeyFromPassword(password, salt) {
    const encoder = new TextEncoder()
    const passwordBytes = encoder.encode(password)

    // Use PBKDF2 with high iterations for key derivation
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    )

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      ENCRYPTION_KEY_BITS
    )

    return new Uint8Array(derivedBits)
  }

  async encryptData(plaintext) {
    if (!this.sodiumReady) await this.initSodium()
    if (!this.masterKey) throw new Error('No encryption key set')
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const messageBytes = sodium.from_string(plaintext)
    const ciphertext = sodium.crypto_secretbox_easy(messageBytes, nonce, this.masterKey)
    
    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.length)
    combined.set(nonce)
    combined.set(ciphertext, nonce.length)

    return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL)
  }

  async decryptData(encryptedData) {
    if (!this.sodiumReady) await this.initSodium()
    if (!this.masterKey) throw new Error('No decryption key set')
    const combined = sodium.from_base64(encryptedData, sodium.base64_variants.ORIGINAL)
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES)
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES)

    const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, this.masterKey)
    return sodium.to_string(decrypted)
  }

  async generateSalt() {
    if (!this.sodiumReady) await this.initSodium()
    return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
  }

  async setMasterKey(key) {
    this.masterKey = key
  }
}

const cryptoService = new CryptoService()

// Loading Skeleton Components
const NoteSkeleton = () => (
  <div className="p-4 border-b border-gray-700 animate-pulse">
    <div className="h-4 bg-gray-600 rounded w-3/4 mb-2"></div>
    <div className="h-3 bg-gray-700 rounded w-full mb-1"></div>
    <div className="h-3 bg-gray-700 rounded w-2/3 mb-2"></div>
    <div className="h-3 bg-gray-700 rounded w-1/4"></div>
  </div>
)

const NoteListSkeleton = () => (
  <div>
    {[...Array(5)].map((_, i) => (
      <NoteSkeleton key={i} />
    ))}
  </div>
)

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
)

const ErrorBoundary = ({ error, onRetry, onDismiss, className = '' }) => {
  const getErrorMessage = (error) => {
    if (typeof error === 'string') return error
    if (error?.message) return error.message
    return 'An unexpected error occurred'
  }

  const getErrorSuggestions = (error) => {
    const message = getErrorMessage(error).toLowerCase()
    
    if (message.includes('network') || message.includes('fetch')) {
      return 'Check your internet connection and try again.'
    }
    if (message.includes('unauthorized') || message.includes('401')) {
      return 'Your session may have expired. Please sign in again.'
    }
    if (message.includes('decrypt') || message.includes('encryption')) {
      return 'There was an issue with encryption. Try refreshing the page.'
    }
    return 'Please try again or refresh the page if the problem persists.'
  }

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
  )
}

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

  const currentStep = onboardingSteps[step] || onboardingSteps[0]
  const isLastStep = step === onboardingSteps.length - 1

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
  )
}

// Secure API Service with encryption
class SecureAPI {
  constructor(baseURL = '/api/v1') {
    this.baseURL = baseURL
    this.token = localStorage.getItem('secure_token')
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include',
        mode: 'cors'
      })

      if (!response.ok) {
        if (response.status === 401) {
          this.handleUnauthorized()
        }
        throw new Error(`HTTP ${response.status}`)
      }

      return await response.json()
    } catch (error) {
      // Log error for debugging (console.error disabled by ESLint)
      // console.error('API request failed:', error)
      throw error
    }
  }

  handleUnauthorized() {
    localStorage.removeItem('secure_token')
    window.location.href = '/login'
  }

  setToken(token) {
    this.token = token
    localStorage.setItem('secure_token', token)
  }

  clearToken() {
    this.token = null
    localStorage.removeItem('secure_token')
  }

  async register(email, password) {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    })
    
    if (response.token) {
      this.setToken(response.token)
    }
    
    return response
  }

  async login(email, password, mfaCode) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, mfa_code: mfaCode })
    })
    
    if (response.token) {
      this.setToken(response.token)
    }
    
    return response
  }

  async createNote(title, content) {
    // Encrypt note content before sending
    const encryptedTitle = await cryptoService.encryptData(title)
    const encryptedContent = await cryptoService.encryptData(JSON.stringify(content))
    
    return this.request('/notes', {
      method: 'POST',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent
      })
    })
  }

  async getNotes() {
    const response = await this.request('/notes')
    const notes = response.notes || response || []
    
    // Decrypt notes
    const decryptedNotes = await Promise.all(
      notes.map(async (note) => {
        try {
          const title = await cryptoService.decryptData(note.title_encrypted)
          const content = JSON.parse(await cryptoService.decryptData(note.content_encrypted))
          return { ...note, title, content }
        } catch (err) {
          console.error('Failed to decrypt note:', note.id)
          return null
        }
      })
    )
    
    return decryptedNotes.filter(note => note !== null)
  }

  async updateNote(noteId, title, content) {
    // Encrypt note content before sending
    const encryptedTitle = await cryptoService.encryptData(title)
    const encryptedContent = await cryptoService.encryptData(JSON.stringify(content))
    
    return this.request(`/notes/${noteId}`, {
      method: 'PUT',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent
      })
    })
  }

  async deleteNote(noteId) {
    return this.request(`/notes/${noteId}`, {
      method: 'DELETE'
    })
  }
}

const api = new SecureAPI()

// Main App Component
export default function SecureNotesApp() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentView, setCurrentView] = useState('login')
  const [notes, setNotes] = useState([])
  const [selectedNote, setSelectedNote] = useState(null)
  const [encryptionStatus, setEncryptionStatus] = useState('locked')
  const [loading, setLoading] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [error, setError] = useState(null)
  const [notesError, setNotesError] = useState(null)
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [onboardingStep, setOnboardingStep] = useState(0)

  useEffect(() => {
    // Check if user has a valid session
    const initializeApp = async () => {
      try {
        const token = localStorage.getItem('secure_token')
        if (token) {
          setIsAuthenticated(true)
          setCurrentView('notes')
          await loadNotes()
          
          // Check if user needs onboarding
          const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding')
          if (!hasSeenOnboarding) {
            setShowOnboarding(true)
          }
        }
      } catch (err) {
        console.error('Failed to initialize app:', err)
        setError('Failed to initialize application')
      } finally {
        setInitializing(false)
      }
    }
    
    initializeApp()
  }, [])

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Only handle shortcuts when authenticated and not in onboarding
      if (!isAuthenticated || showOnboarding) return

      // Cmd/Ctrl + N: New note
      if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
        e.preventDefault()
        setSelectedNote(null)
        setCurrentView('editor')
      }

      // Cmd/Ctrl + K: Search notes (focus search)
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        const searchInput = document.getElementById('search-notes')
        if (searchInput) {
          searchInput.focus()
        }
      }

      // Escape: Close current view/go back
      if (e.key === 'Escape') {
        if (selectedNote || currentView === 'editor') {
          setSelectedNote(null)
          setCurrentView('notes')
        }
      }

      // Cmd/Ctrl + S: Manual save (if in editor)
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault()
        if (selectedNote || currentView === 'editor') {
          // Trigger save if we're in the editor
          const saveButton = document.querySelector('[data-save-action]')
          if (saveButton) {
            saveButton.click()
          }
        }
      }

      // Arrow navigation in notes list
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        const noteButtons = document.querySelectorAll('[data-note-button]')
        const currentIndex = Array.from(noteButtons).findIndex(btn => btn === document.activeElement)
        
        if (currentIndex !== -1) {
          e.preventDefault()
          let nextIndex;
          if (e.key === 'ArrowDown') {
            nextIndex = Math.min(currentIndex + 1, noteButtons.length - 1)
          } else {
            nextIndex = Math.max(currentIndex - 1, 0)
          }
          noteButtons[nextIndex]?.focus()
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [isAuthenticated, showOnboarding, selectedNote, currentView])

  const loadNotes = async () => {
    try {
      setLoading(true)
      setNotesError(null)
      const fetchedNotes = await api.getNotes()
      setNotes(fetchedNotes)
    } catch (err) {
      console.error('Failed to load notes:', err)
      setNotesError(err.message || 'Failed to load notes')
    } finally {
      setLoading(false)
    }
  }

  const handleOnboardingNext = () => {
    setOnboardingStep(prev => prev + 1)
  }

  const handleOnboardingPrev = () => {
    setOnboardingStep(prev => Math.max(0, prev - 1))
  }

  const handleOnboardingSkip = () => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }

  const handleOnboardingComplete = () => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }

  // Login Component
  const LoginView = () => {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [mfaCode, setMfaCode] = useState('')
    const [mfaRequired, setMfaRequired] = useState(false)
    const [isRegistering, setIsRegistering] = useState(false)
    const [passwordStrength, setPasswordStrength] = useState(0)

    const calculatePasswordStrength = (pwd) => {
      let strength = 0
      if (pwd.length >= MIN_PASSWORD_LENGTH) strength++
      if (pwd.length >= STRONG_PASSWORD_LENGTH) strength++
      if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++
      if (/[0-9]/.test(pwd)) strength++
      if (/[^A-Za-z0-9]/.test(pwd)) strength++
      return strength
    }

    const handlePasswordChange = (e) => {
      const pwd = e.target.value
      setPassword(pwd)
      setPasswordStrength(calculatePasswordStrength(pwd))
    }

    const handleSubmit = async (e) => {
      e.preventDefault()
      setError(null)
      setLoading(true)

      try {
        if (isRegistering) {
          if (password.length < MIN_PASSWORD_LENGTH) {
            setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
            return
          }
          
          const response = await api.register(email, password)
          
          // Derive encryption key from password
          const salt = response.salt ? sodium.from_base64(response.salt) : await cryptoService.generateSalt()
          const key = await cryptoService.deriveKeyFromPassword(password, salt)
          await cryptoService.setMasterKey(key)
          
          setIsAuthenticated(true)
          setCurrentView('notes')
          setEncryptionStatus('unlocked')
          
          // Check if this is a new user
          const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding')
          if (!hasSeenOnboarding) {
            setShowOnboarding(true)
          }
        } else {
          const response = await api.login(email, password, mfaCode)
          
          if (response.mfa_required) {
            setMfaRequired(true)
            return
          }
          
          // Derive encryption key from password (we'll store this in localStorage for this demo)
          const salt = response.salt ? sodium.from_base64(response.salt) : await cryptoService.generateSalt()
          const key = await cryptoService.deriveKeyFromPassword(password, salt)
          await cryptoService.setMasterKey(key)
          
          setIsAuthenticated(true)
          setCurrentView('notes')
          setEncryptionStatus('unlocked')
          loadNotes()
        }
      } catch (err) {
        setError(isRegistering ? 'Registration failed' : 'Login failed')
      } finally {
        setLoading(false)
      }
    }

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
                setIsRegistering(!isRegistering)
                setError(null)
                setMfaRequired(false)
              }}
              className="w-full text-gray-400 hover:text-white text-sm transition-colors focus:outline-none focus:underline"
            >
              {isRegistering ? 'Already have an account? Login' : 'Need an account? Register'}
            </button>
          </form>
        </main>
      </div>
    )
  }

  // Notes Editor Component
  const NotesEditor = () => {
    const [title, setTitle] = useState(selectedNote?.title || '')
    const [content, setContent] = useState(selectedNote?.content || '')
    const [saving, setSaving] = useState(false)
    const [lastSaved, setLastSaved] = useState(null)
    const [saveError, setSaveError] = useState(null)

    const handleSave = async () => {
      setSaving(true)
      setSaveError(null)
      try {
        if (selectedNote) {
          // Update existing note
          await api.updateNote(selectedNote.id, title, content)
        } else {
          // Create new note
          await api.createNote(title, content)
        }
        setLastSaved(new Date())
        loadNotes()
      } catch (err) {
        console.error('Failed to save note:', err)
        setSaveError(err.message || 'Failed to save note')
      } finally {
        setSaving(false)
      }
    }

    const autoSave = useMemo(
      () =>
        debounce(() => {
          if (title || content) {
            handleSave()
          }
        }, AUTOSAVE_DELAY),
      [handleSave, title, content]
    )

    useEffect(() => {
      autoSave()
    }, [autoSave])

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
          <div className="flex items-center mt-2 text-sm text-gray-400" aria-live="polite">
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
            <span className="ml-auto flex items-center" aria-label="Encryption status">
              <svg className="w-4 h-4 mr-1 text-green-500" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              Encrypted
            </span>
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
        
        <div className="flex-1 p-6">
          <label htmlFor="note-content" className="sr-only">
            Note content
          </label>
          <textarea
            id="note-content"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Start writing your secure note..."
            className="w-full h-full bg-transparent text-gray-200 placeholder-gray-500 focus:outline-none resize-none focus:ring-2 focus:ring-blue-500/50 rounded p-2 -m-2"
            aria-describedby="editor-help"
          />
          <p id="editor-help" className="sr-only">
            This note is automatically encrypted and saved as you type.
          </p>
        </div>
      </div>
    )
  }

  // Notes List Component
  const NotesList = () => {
    const [searchQuery, setSearchQuery] = useState('')
    
    const filteredNotes = notes.filter(note =>
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase())
    )

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
                setSelectedNote(note)
                // On mobile, switch to editor view when selecting a note
                if (window.innerWidth < 768) {
                  setCurrentView('editor')
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
              setSelectedNote(null)
              setCurrentView('editor')
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
    )
  }

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
                <div className={`w-2 h-2 rounded-full ${encryptionStatus === 'unlocked' ? 'bg-green-500' : 'bg-red-500'}`} aria-hidden="true" />
                <span className="text-sm text-gray-400">
                  {encryptionStatus === 'unlocked' ? 'Encryption Active' : 'Locked'}
                </span>
                <span className="sr-only">
                  {encryptionStatus === 'unlocked' ? 'Your notes are encrypted and secure' : 'Encryption is not active'}
                </span>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <button
                onClick={() => {
                  api.clearToken()
                  cryptoService.masterKey = null
                  setIsAuthenticated(false)
                  setCurrentView('login')
                  setEncryptionStatus('locked')
                }}
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
    )
  }

  if (initializing) {
    return <LoadingOverlay message="Starting Secure Notes" />;
  }

  return (
    <>
      {isAuthenticated ? <AppLayout /> : <LoginView />}
      {showOnboarding && isAuthenticated && (
        <OnboardingOverlay 
          step={onboardingStep}
          onNext={handleOnboardingNext}
          onPrev={handleOnboardingPrev}
          onSkip={handleOnboardingSkip}
          onComplete={handleOnboardingComplete}
        />
      )}
    </>
  )
}

// Utility function for debouncing
function debounce(func, wait) {
  let timeout
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }
    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }
}