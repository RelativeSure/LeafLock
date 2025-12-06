import { http, HttpResponse } from 'msw'

// Base API URL
const API_BASE = 'http://localhost:8080/api/v1'

export const handlers = [
  // Auth endpoints
  http.post(`${API_BASE}/auth/login`, () => {
    return HttpResponse.json({
      message: 'Login handled by Clerk - this endpoint is deprecated',
      deprecated: true,
    })
  }),

  http.post(`${API_BASE}/auth/register`, () => {
    return HttpResponse.json({
      success: true,
      message: 'User registered successfully',
    })
  }),

  http.post(`${API_BASE}/auth/forgot-password`, () => {
    return HttpResponse.json({
      success: true,
      message: 'Password reset email sent',
    })
  }),

  http.post(`${API_BASE}/auth/mfa/verify`, () => {
    return HttpResponse.json({
      message: 'MFA verification handled by Clerk - this endpoint is deprecated',
      deprecated: true,
    })
  }),

  // Notes endpoints
  http.get(`${API_BASE}/notes`, () => {
    return HttpResponse.json({
      notes: [],
      total: 0,
    })
  }),

  http.get(`${API_BASE}/notes/trash`, () => {
    return HttpResponse.json({
      notes: [],
      total: 0,
    })
  }),

  http.post(`${API_BASE}/notes`, () => {
    return HttpResponse.json({
      id: 'mock-note-id',
      title: 'New Note',
      content: 'Mock content',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    })
  }),

  // Templates endpoints
  http.get(`${API_BASE}/templates`, () => {
    return HttpResponse.json({
      templates: [],
      total: 0,
    })
  }),

  http.post(`${API_BASE}/templates`, () => {
    return HttpResponse.json({
      id: 'mock-template-id',
      name: 'New Template',
      content: 'Mock template content',
      createdAt: new Date().toISOString(),
    })
  }),

  // Collaborators endpoints
  http.get(`${API_BASE}/notes/:noteId/collaborators`, () => {
    return HttpResponse.json({
      collaborators: [],
    })
  }),

  // Share links endpoints
  http.get(`${API_BASE}/share-links`, () => {
    return HttpResponse.json({
      shareLinks: [],
      total: 0,
    })
  }),

  // Health check
  http.get(`${API_BASE}/health`, () => {
    return HttpResponse.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
    })
  }),

  // Catch-all for unhandled requests - return empty success
  http.all(`${API_BASE}/*`, () => {
    return HttpResponse.json({ success: true, data: null }, { status: 200 })
  }),
]
