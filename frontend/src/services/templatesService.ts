import { resolveApiBaseUrl } from '@/utils/network'
import { getStoredAuthToken } from '@/utils/auth'

/**
 * Templates service for managing note templates
 */

export interface Template {
  id: string
  name: string
  description?: string
  content?: string
  tags: string[]
  icon: string
  is_public: boolean
  usage_count: number
  created_at: string
  updated_at: string
}

export interface CreateTemplateRequest {
  name: string
  description?: string
  content: string
  tags?: string[]
  icon?: string
  is_public?: boolean
}

export interface UpdateTemplateRequest {
  name: string
  description?: string
  content: string
  tags?: string[]
  icon?: string
  is_public?: boolean
}

export interface UseTemplateRequest {
  title?: string
  folder_id?: string
}

export interface TemplatesResponse {
  templates: Template[]
}

export interface UseTemplateResponse {
  id: string
  message: string
}

class TemplatesService {
  private baseUrl: string

  constructor() {
    this.baseUrl = resolveApiBaseUrl()
  }

  private getAuthHeaders(): Record<string, string> {
    const token = getStoredAuthToken()
    const csrfToken = localStorage.getItem('csrf_token')

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken
    }

    return headers
  }

  /**
   * Get all templates for the current user (including public templates)
   */
  async getTemplates(): Promise<Template[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/templates`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to fetch templates')
    }

    const data: TemplatesResponse = await response.json()
    return data.templates
  }

  /**
   * Get a specific template with full content
   */
  async getTemplate(templateId: string): Promise<Template> {
    const response = await fetch(`${this.baseUrl}/api/v1/templates/${templateId}`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to fetch template')
    }

    return response.json()
  }

  /**
   * Create a new template
   */
  async createTemplate(template: CreateTemplateRequest): Promise<{ id: string; message: string }> {
    const response = await fetch(`${this.baseUrl}/api/v1/templates`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(template),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to create template')
    }

    return response.json()
  }

  /**
   * Update an existing template
   */
  async updateTemplate(templateId: string, template: UpdateTemplateRequest): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v1/templates/${templateId}`, {
      method: 'PUT',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(template),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to update template')
    }
  }

  /**
   * Delete a template
   */
  async deleteTemplate(templateId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v1/templates/${templateId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to delete template')
    }
  }

  /**
   * Create a note from a template
   */
  async useTemplate(templateId: string, options: UseTemplateRequest = {}): Promise<UseTemplateResponse> {
    const response = await fetch(`${this.baseUrl}/api/v1/templates/${templateId}/use`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(options),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to create note from template')
    }

    return response.json()
  }

  /**
   * Get templates filtered by tags
   */
  async getTemplatesByTags(tags: string[]): Promise<Template[]> {
    const templates = await this.getTemplates()
    return templates.filter(template =>
      tags.some(tag => template.tags.includes(tag))
    )
  }

  /**
   * Get the most used templates
   */
  async getPopularTemplates(limit = 10): Promise<Template[]> {
    const templates = await this.getTemplates()
    return templates
      .sort((a, b) => b.usage_count - a.usage_count)
      .slice(0, limit)
  }

  /**
   * Search templates by name or description
   */
  async searchTemplates(query: string): Promise<Template[]> {
    const templates = await this.getTemplates()
    const lowercaseQuery = query.toLowerCase()

    return templates.filter(template =>
      template.name.toLowerCase().includes(lowercaseQuery) ||
      template.description?.toLowerCase().includes(lowercaseQuery) ||
      template.tags.some(tag => tag.toLowerCase().includes(lowercaseQuery))
    )
  }
}

export const templatesService = new TemplatesService()
