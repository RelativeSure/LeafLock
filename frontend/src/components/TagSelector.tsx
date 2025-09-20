import React, { useState, useEffect } from 'react'
import { Hash, Plus, X, ChevronDown } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Input } from './ui/input'
import { tagsService, Tag } from '../services/tagsService'

interface TagSelectorProps {
  noteId?: string
  selectedTags?: string[] // Tag IDs
  onTagsChange?: (tagIds: string[]) => void
  className?: string
  size?: 'sm' | 'md'
}

export const TagSelector: React.FC<TagSelectorProps> = ({
  noteId,
  selectedTags = [],
  onTagsChange,
  className = '',
  size = 'md'
}) => {
  const [availableTags, setAvailableTags] = useState<Tag[]>([])
  const [isOpen, setIsOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [quickCreateName, setQuickCreateName] = useState('')
  const [isCreating, setIsCreating] = useState(false)

  const loadTags = async () => {
    try {
      setError(null)
      setLoading(true)
      const tags = await tagsService.getTags()
      setAvailableTags(tags)
    } catch (err) {
      console.error('Failed to load tags:', err)
      setError(err instanceof Error ? err.message : 'Failed to load tags')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isOpen) {
      loadTags()
    }
  }, [isOpen])

  const selectedTagObjects = availableTags.filter(tag => selectedTags.includes(tag.id))

  const filteredTags = availableTags.filter(tag =>
    !selectedTags.includes(tag.id) &&
    tag.name.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const handleTagToggle = async (tag: Tag) => {
    const isSelected = selectedTags.includes(tag.id)

    try {
      setError(null)

      if (noteId) {
        // If we have a note ID, update the backend
        if (isSelected) {
          await tagsService.removeTagFromNote(noteId, tag.id)
        } else {
          await tagsService.assignTagToNote(noteId, tag.id)
        }
      }

      // Update local state
      const newSelectedTags = isSelected
        ? selectedTags.filter(id => id !== tag.id)
        : [...selectedTags, tag.id]

      onTagsChange?.(newSelectedTags)
    } catch (err) {
      console.error('Failed to toggle tag:', err)
      setError(err instanceof Error ? err.message : 'Failed to update tag')
    }
  }

  const handleQuickCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!quickCreateName.trim()) return

    try {
      setError(null)
      setIsCreating(true)

      const newTag = await tagsService.createTag({
        name: quickCreateName.trim(),
        color: '#3b82f6' // Default blue color
      })

      setAvailableTags(prev => [...prev, newTag])
      setQuickCreateName('')

      // Auto-select the newly created tag
      if (noteId) {
        await tagsService.assignTagToNote(noteId, newTag.id)
      }
      onTagsChange?.([...selectedTags, newTag.id])

    } catch (err) {
      console.error('Failed to create tag:', err)
      setError(err instanceof Error ? err.message : 'Failed to create tag')
    } finally {
      setIsCreating(false)
    }
  }

  const iconSize = size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'
  const textSize = size === 'sm' ? 'text-xs' : 'text-sm'
  const badgeSize = size === 'sm' ? 'text-xs px-1.5 py-0.5' : ''

  return (
    <div className={`relative ${className}`}>
      {/* Selected Tags Display */}
      <div className="flex flex-wrap gap-1 mb-2">
        {selectedTagObjects.map(tag => (
          <Badge
            key={tag.id}
            style={{ backgroundColor: tag.color, color: 'white' }}
            className={`flex items-center gap-1 ${badgeSize}`}
          >
            <Hash className={iconSize} />
            <span className={textSize}>{tag.name}</span>
            <button
              onClick={() => handleTagToggle(tag)}
              className="ml-1 hover:bg-black/20 rounded-full p-0.5"
            >
              <X className="w-2.5 h-2.5" />
            </button>
          </Badge>
        ))}
      </div>

      {/* Add Tags Button */}
      <Button
        variant="outline"
        size={size}
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2"
      >
        <Hash className={iconSize} />
        <span className={textSize}>
          {selectedTags.length > 0 ? 'Edit Tags' : 'Add Tags'}
        </span>
        <ChevronDown className={`${iconSize} transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </Button>

      {/* Tags Dropdown */}
      {isOpen && (
        <div className="absolute z-50 mt-1 w-72 bg-white border border-gray-200 rounded-md shadow-lg">
          <div className="p-3 space-y-3">
            {error && (
              <div className="p-2 bg-red-50 border border-red-200 rounded text-red-600 text-xs">
                {error}
              </div>
            )}

            {/* Search */}
            <Input
              type="text"
              placeholder="Search tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="text-sm"
            />

            {/* Quick Create */}
            <form onSubmit={handleQuickCreate} className="flex gap-2">
              <Input
                type="text"
                placeholder="Create new tag..."
                value={quickCreateName}
                onChange={(e) => setQuickCreateName(e.target.value)}
                className="text-sm flex-1"
                maxLength={50}
                disabled={isCreating}
              />
              <Button
                type="submit"
                size="sm"
                disabled={!quickCreateName.trim() || isCreating}
              >
                {isCreating ? (
                  <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white"></div>
                ) : (
                  <Plus className="w-3 h-3" />
                )}
              </Button>
            </form>

            {/* Available Tags */}
            <div className="max-h-40 overflow-y-auto space-y-1">
              {loading ? (
                <div className="flex items-center justify-center py-4">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                </div>
              ) : filteredTags.length === 0 ? (
                <div className="text-center py-4 text-gray-500 text-sm">
                  {searchQuery ? 'No tags match your search' : 'No available tags'}
                </div>
              ) : (
                filteredTags.map(tag => (
                  <button
                    key={tag.id}
                    onClick={() => handleTagToggle(tag)}
                    className="w-full flex items-center gap-2 p-2 text-left hover:bg-gray-50 rounded text-sm"
                  >
                    <Hash className="w-3 h-3" style={{ color: tag.color }} />
                    <span className="flex-1">{tag.name}</span>
                    <Plus className="w-3 h-3 text-gray-400" />
                  </button>
                ))
              )}
            </div>

            {/* Close Button */}
            <div className="pt-2 border-t">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setIsOpen(false)}
                className="w-full"
              >
                Done
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default TagSelector