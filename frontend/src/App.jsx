import React, { useState, useEffect, useCallback, useMemo } from 'react';
import * as sodium from 'libsodium-wrappers';

// Initialize libsodium
await sodium.ready;

// Secure Crypto Service for E2E Encryption
class CryptoService {
  constructor() {
    this.masterKey = null;
    this.derivedKey = null;
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
    if (!this.masterKey) throw new Error('No encryption key set');
    
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const messageBytes = sodium.from_string(plaintext);
    const ciphertext = sodium.crypto_secretbox_easy(messageBytes, nonce, this.masterKey);
    
    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);
    
    return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL);
  }

  async decryptData(encryptedData) {
    if (!this.masterKey) throw new Error('No decryption key set');
    
    const combined = sodium.from_base64(encryptedData, sodium.base64_variants.ORIGINAL);
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES);
    
    const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, this.masterKey);
    return sodium.to_string(decrypted);
  }

  generateSalt() {
    return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  }

  async setMasterKey(key) {
    this.masterKey = key;
  }
}

const cryptoService = new CryptoService();

// Secure API Service with encryption
class SecureAPI {
  constructor(baseURL = '/api/v1') {
    this.baseURL = baseURL;
    this.token = localStorage.getItem('secure_token');
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

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include',
        mode: 'cors'
      });

      if (!response.ok) {
        if (response.status === 401) {
          this.handleUnauthorized();
        }
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  handleUnauthorized() {
    localStorage.removeItem('secure_token');
    window.location.href = '/login';
  }

  setToken(token) {
    this.token = token;
    localStorage.setItem('secure_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('secure_token');
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
    const notes = await this.request('/notes');
    
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
  const [error, setError] = useState(null);

  useEffect(() => {
    // Check if user has a valid session
    const token = localStorage.getItem('secure_token');
    if (token) {
      setIsAuthenticated(true);
      setCurrentView('notes');
      loadNotes();
    }
  }, []);

  const loadNotes = async () => {
    try {
      setLoading(true);
      const fetchedNotes = await api.getNotes();
      setNotes(fetchedNotes);
    } catch (err) {
      setError('Failed to load notes');
    } finally {
      setLoading(false);
    }
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
        if (isRegistering) {
          if (password.length < 12) {
            setError('Password must be at least 12 characters');
            return;
          }
          
          const response = await api.register(email, password);
          
          // Derive encryption key from password
          const salt = sodium.from_base64(response.salt || sodium.to_base64(cryptoService.generateSalt()));
          const key = await cryptoService.deriveKeyFromPassword(password, salt);
          await cryptoService.setMasterKey(key);
          
          setIsAuthenticated(true);
          setCurrentView('notes');
          setEncryptionStatus('unlocked');
        } else {
          const response = await api.login(email, password, mfaCode);
          
          if (response.mfa_required) {
            setMfaRequired(true);
            return;
          }
          
          // Derive encryption key from password
          const salt = sodium.from_base64(response.salt || sodium.to_base64(cryptoService.generateSalt()));
          const key = await cryptoService.deriveKeyFromPassword(password, salt);
          await cryptoService.setMasterKey(key);
          
          setIsAuthenticated(true);
          setCurrentView('notes');
          setEncryptionStatus('unlocked');
          loadNotes();
        }
      } catch (err) {
        setError(isRegistering ? 'Registration failed' : 'Login failed');
      } finally {
        setLoading(false);
      }
    };

    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-lg shadow-xl p-8 w-full max-w-md">
          <div className="flex items-center justify-center mb-8">
            <div className="flex items-center space-x-2">
              <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <h1 className="text-2xl font-bold text-white">Secure Notes</h1>
            </div>
          </div>
          
          <div className="bg-yellow-900/50 border border-yellow-600 rounded-lg p-4 mb-6">
            <p className="text-yellow-200 text-sm">
              🔐 End-to-end encrypted • Zero-knowledge architecture • Your data stays private
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
                required
                autoComplete="email"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={handlePasswordChange}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
                required
                minLength={12}
                autoComplete={isRegistering ? "new-password" : "current-password"}
              />
              {isRegistering && (
                <div className="mt-2">
                  <div className="flex space-x-1">
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
                      />
                    ))}
                  </div>
                  <p className="text-xs text-gray-400 mt-1">
                    Use 12+ characters with mixed case, numbers & symbols
                  </p>
                </div>
              )}
            </div>

            {mfaRequired && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  2FA Code
                </label>
                <input
                  type="text"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
                  placeholder="000000"
                  maxLength={6}
                  required={mfaRequired}
                />
              </div>
            )}

            {error && (
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-3">
                <p className="text-red-200 text-sm">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
            >
              {loading ? 'Processing...' : isRegistering ? 'Create Secure Account' : 'Login Securely'}
            </button>

            <button
              type="button"
              onClick={() => setIsRegistering(!isRegistering)}
              className="w-full text-gray-400 hover:text-white text-sm"
            >
              {isRegistering ? 'Already have an account? Login' : 'Need an account? Register'}
            </button>
          </form>
        </div>
      </div>
    );
  };

  // Notes Editor Component
  const NotesEditor = () => {
    const [title, setTitle] = useState(selectedNote?.title || '');
    const [content, setContent] = useState(selectedNote?.content || '');
    const [saving, setSaving] = useState(false);
    const [lastSaved, setLastSaved] = useState(null);

    const handleSave = async () => {
      setSaving(true);
      try {
        if (selectedNote) {
          // Update existing note
          await api.updateNote(selectedNote.id, title, content);
        } else {
          // Create new note
          await api.createNote(title, content);
        }
        setLastSaved(new Date());
        loadNotes();
      } catch (err) {
        setError('Failed to save note');
      } finally {
        setSaving(false);
      }
    };

    const autoSave = useMemo(
      () =>
        debounce(() => {
          if (title || content) {
            handleSave();
          }
        }, 2000),
      [title, content]
    );

    useEffect(() => {
      autoSave();
    }, [title, content]);

    return (
      <div className="flex-1 flex flex-col">
        <div className="bg-gray-800 border-b border-gray-700 px-6 py-4">
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Note title..."
            className="w-full bg-transparent text-xl font-semibold text-white placeholder-gray-500 focus:outline-none"
          />
          <div className="flex items-center mt-2 text-sm text-gray-400">
            {saving && (
              <span className="flex items-center">
                <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Saving...
              </span>
            )}
            {!saving && lastSaved && (
              <span>Last saved {lastSaved.toLocaleTimeString()}</span>
            )}
            <span className="ml-auto flex items-center">
              <svg className="w-4 h-4 mr-1 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              Encrypted
            </span>
          </div>
        </div>
        
        <div className="flex-1 p-6">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Start writing your secure note..."
            className="w-full h-full bg-transparent text-gray-200 placeholder-gray-500 focus:outline-none resize-none"
          />
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
      <div className="w-80 bg-gray-800 border-r border-gray-700 flex flex-col">
        <div className="p-4 border-b border-gray-700">
          <div className="relative">
            <svg className="absolute left-3 top-2.5 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search notes..."
              className="w-full pl-10 pr-4 py-2 bg-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
        
        <div className="flex-1 overflow-y-auto">
          {filteredNotes.map(note => (
            <div
              key={note.id}
              onClick={() => setSelectedNote(note)}
              className={`p-4 border-b border-gray-700 cursor-pointer hover:bg-gray-700 transition ${
                selectedNote?.id === note.id ? 'bg-gray-700' : ''
              }`}
            >
              <h3 className="font-medium text-white mb-1">{note.title || 'Untitled'}</h3>
              <p className="text-sm text-gray-400 line-clamp-2">
                {note.content || 'No content'}
              </p>
              <p className="text-xs text-gray-500 mt-2">
                {new Date(note.updated_at).toLocaleDateString()}
              </p>
            </div>
          ))}
          
          {filteredNotes.length === 0 && (
            <div className="p-4 text-center text-gray-500">
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
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
          >
            New Encrypted Note
          </button>
        </div>
      </div>
    );
  };

  // Main App Layout
  const AppLayout = () => {
    return (
      <div className="h-screen flex bg-gray-900">
        <NotesList />
        
        <div className="flex-1 flex flex-col">
          <div className="bg-gray-800 border-b border-gray-700 px-6 py-3 flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${encryptionStatus === 'unlocked' ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm text-gray-400">
                  {encryptionStatus === 'unlocked' ? 'Encryption Active' : 'Locked'}
                </span>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <button
                onClick={() => {
                  api.clearToken();
                  cryptoService.masterKey = null;
                  setIsAuthenticated(false);
                  setCurrentView('login');
                  setEncryptionStatus('locked');
                }}
                className="text-gray-400 hover:text-white transition"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
              </button>
            </div>
          </div>
          
          {selectedNote || currentView === 'editor' ? (
            <NotesEditor />
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <svg className="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <p className="text-gray-500">Select a note or create a new one</p>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  return isAuthenticated ? <AppLayout /> : <LoginView />;
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