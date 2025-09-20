/**
 * Search service for finding notes
 */

export interface SearchResult {
  id: string
  title: string
  content: string
  created_at: string
  updated_at: string
  snippet: string
}

export interface SearchResponse {
  results: SearchResult[]
  total: number
  query: string
}

interface SearchRequest {
  query: string
  limit?: number
}

class SearchService {
  private baseUrl: string

  constructor() {
    this.baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8080'
  }

  private getAuthHeaders(): Record<string, string> {
    const token = localStorage.getItem('auth_token')
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
   * Search for notes
   */
  async searchNotes(query: string, limit: number = 20): Promise<SearchResponse> {
    if (!query.trim()) {
      return {
        results: [],
        total: 0,
        query: query,
      }
    }

    const searchRequest: SearchRequest = {
      query: query.trim(),
      limit,
    }

    const response = await fetch(`${this.baseUrl}/api/v1/search/notes`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(searchRequest),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to search notes')
    }

    return response.json()
  }

  /**
   * Highlight search terms in text
   */
  highlightSearchTerms(text: string, query: string): string {
    if (!query.trim()) return text

    const queryLower = query.toLowerCase()
    const textLower = text.toLowerCase()

    let highlightedText = ''
    let lastIndex = 0

    let index = textLower.indexOf(queryLower)
    while (index !== -1) {
      // Add text before the match
      highlightedText += text.slice(lastIndex, index)

      // Add highlighted match
      const match = text.slice(index, index + query.length)
      highlightedText += `<mark class="bg-yellow-200 text-yellow-900 px-1 rounded">${match}</mark>`

      lastIndex = index + query.length
      index = textLower.indexOf(queryLower, lastIndex)
    }

    // Add remaining text
    highlightedText += text.slice(lastIndex)

    return highlightedText
  }
}

export const searchService = new SearchService()