import React from 'react'
import { SearchResult, searchService } from '../services/searchService'
import { FileText, Calendar } from 'lucide-react'
import { Card, CardContent } from './ui/card'

interface SearchResultsProps {
  results: SearchResult[]
  query: string
  onSelectNote: (noteId: string) => void
  className?: string
}

export const SearchResults: React.FC<SearchResultsProps> = ({
  results,
  query,
  onSelectNote,
  className = '',
}) => {
  if (!query) {
    return null
  }

  if (results.length === 0) {
    return (
      <div className={`text-center py-8 text-gray-500 ${className}`}>
        <FileText className="w-12 h-12 mx-auto mb-4 text-gray-300" />
        <p className="text-lg font-medium mb-2">No notes found</p>
        <p className="text-sm">
          Try searching for different keywords or check your spelling.
        </p>
      </div>
    )
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  return (
    <div className={className}>
      <div className="mb-4 text-sm text-gray-600">
        Found {results.length} note{results.length !== 1 ? 's' : ''} for "{query}"
      </div>

      <div className="space-y-3">
        {results.map((result) => (
          <Card
            key={result.id}
            className="cursor-pointer hover:bg-gray-50 transition-colors"
            onClick={() => onSelectNote(result.id)}
          >
            <CardContent className="p-4">
              <div className="flex items-start justify-between mb-2">
                <h3
                  className="font-medium text-gray-900 flex-1"
                  dangerouslySetInnerHTML={{
                    __html: searchService.highlightSearchTerms(result.title, query),
                  }}
                />
                <div className="flex items-center text-xs text-gray-500 ml-4">
                  <Calendar className="w-3 h-3 mr-1" />
                  {formatDate(result.updated_at)}
                </div>
              </div>

              {result.snippet && (
                <p
                  className="text-sm text-gray-600 line-clamp-3"
                  dangerouslySetInnerHTML={{
                    __html: searchService.highlightSearchTerms(result.snippet, query),
                  }}
                />
              )}

              <div className="mt-2 flex items-center text-xs text-gray-400">
                <FileText className="w-3 h-3 mr-1" />
                <span>Note</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

export default SearchResults