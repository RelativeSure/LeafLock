import React, { useState, useCallback, useEffect } from 'react'
import { Search, X, Loader2 } from 'lucide-react'
import { searchService, SearchResult } from '../services/searchService'
import { Input } from './ui/input'
import { Button } from './ui/button'

interface SearchBarProps {
  onSearchResults: (results: SearchResult[], query: string) => void
  onClear: () => void
  placeholder?: string
  className?: string
}

export const SearchBar: React.FC<SearchBarProps> = ({
  onSearchResults,
  onClear,
  placeholder = 'Search notes...',
  className = '',
}) => {
  const [query, setQuery] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Debounced search function
  const performSearch = useCallback(async (searchQuery: string) => {
    if (!searchQuery.trim()) {
      onSearchResults([], '')
      setError(null)
      return
    }

    setIsSearching(true)
    setError(null)

    try {
      const response = await searchService.searchNotes(searchQuery, 50)
      onSearchResults(response.results, searchQuery)
    } catch (err) {
      console.error('Search failed:', err)
      setError(err instanceof Error ? err.message : 'Search failed')
      onSearchResults([], searchQuery)
    } finally {
      setIsSearching(false)
    }
  }, [onSearchResults])

  // Debounce search requests
  useEffect(() => {
    const timer = setTimeout(() => {
      performSearch(query)
    }, 300) // 300ms debounce

    return () => clearTimeout(timer)
  }, [query, performSearch])

  const handleClear = () => {
    setQuery('')
    setError(null)
    onClear()
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      handleClear()
    }
  }

  return (
    <div className={`relative ${className}`}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />

        <Input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          className="pl-10 pr-10"
          disabled={isSearching}
        />

        <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex items-center">
          {isSearching && (
            <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
          )}

          {query && !isSearching && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleClear}
              className="h-6 w-6 p-0 hover:bg-gray-200"
            >
              <X className="w-3 h-3" />
            </Button>
          )}
        </div>
      </div>

      {error && (
        <div className="absolute top-full left-0 right-0 mt-1 p-2 bg-red-50 border border-red-200 rounded text-red-600 text-sm">
          {error}
        </div>
      )}
    </div>
  )
}

export default SearchBar