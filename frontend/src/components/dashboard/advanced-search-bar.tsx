'use client'

import { useState, useEffect } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Search,
  X,
  Filter,
  Calendar,
  Folder,
  Tag,
  Clock,
  Pin,
  Lock,
  FileText,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

interface SearchFilters {
  query: string
  folderId: string | null
  tags: string[]
  dateRange: 'all' | 'today' | 'week' | 'month' | 'year'
  sortBy: 'relevance' | 'updated' | 'created' | 'title'
  includeContent: boolean
  encryptedOnly: boolean
  pinnedOnly: boolean
}

export function AdvancedSearchBar() {
  const { notes, folders, tags, selectNote } = useNotesStore()
  const [isOpen, setIsOpen] = useState(false)
  const [results, setResults] = useState<any[]>([])
  const [filters, setFilters] = useState<SearchFilters>({
    query: '',
    folderId: null,
    tags: [],
    dateRange: 'all',
    sortBy: 'relevance',
    includeContent: true,
    encryptedOnly: false,
    pinnedOnly: false,
  })

  const activeNotes = (notes || []).filter((note) => !note.isTrashed)

  const performSearch = () => {
    let filteredNotes = [...activeNotes]

    // Text search
    if (filters.query.trim()) {
      const query = filters.query.toLowerCase()
      filteredNotes = filteredNotes.filter((note) => {
        const titleMatch = note.title.toLowerCase().includes(query)
        const contentMatch = filters.includeContent &&
          note.content.toLowerCase().includes(query)
        const tagMatch = note.tags.some((tag: string) =>
          tag.toLowerCase().includes(query)
        )
        return titleMatch || contentMatch || tagMatch
      })
    }

    // Folder filter
    if (filters.folderId) {
      filteredNotes = filteredNotes.filter((note) =>
        note.folderId === filters.folderId
      )
    }

    // Tag filter
    if (filters.tags.length > 0) {
      filteredNotes = filteredNotes.filter((note) =>
        filters.tags.every((tag) => note.tags.includes(tag))
      )
    }

    // Date range filter
    if (filters.dateRange !== 'all') {
      const now = new Date()
      const cutoff = new Date()

      switch (filters.dateRange) {
        case 'today':
          cutoff.setHours(0, 0, 0, 0)
          break
        case 'week':
          cutoff.setDate(now.getDate() - 7)
          break
        case 'month':
          cutoff.setMonth(now.getMonth() - 1)
          break
        case 'year':
          cutoff.setFullYear(now.getFullYear() - 1)
          break
      }

      filteredNotes = filteredNotes.filter((note) =>
        new Date(note.updatedAt) >= cutoff
      )
    }

    // Additional filters
    if (filters.encryptedOnly) {
      filteredNotes = filteredNotes.filter((note) => note.encrypted)
    }

    if (filters.pinnedOnly) {
      filteredNotes = filteredNotes.filter((note) => note.pinned)
    }

    // Sorting
    filteredNotes.sort((a, b) => {
      switch (filters.sortBy) {
        case 'updated':
          return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
        case 'created':
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
        case 'title':
          return a.title.localeCompare(b.title)
        case 'relevance':
        default:
          // Simple relevance: pinned first, then by title match, then by update date
          if (a.pinned && !b.pinned) return -1
          if (!a.pinned && b.pinned) return 1
          if (filters.query.trim()) {
            const aTitleMatch = a.title.toLowerCase().includes(filters.query.toLowerCase())
            const bTitleMatch = b.title.toLowerCase().includes(filters.query.toLowerCase())
            if (aTitleMatch && !bTitleMatch) return -1
            if (!aTitleMatch && bTitleMatch) return 1
          }
          return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
      }
    })

    setResults(filteredNotes)
  }

  useEffect(() => {
    // Use setTimeout to avoid synchronous setState in effect
    const timeoutId = setTimeout(() => {
      performSearch()
    }, 0)

    return () => clearTimeout(timeoutId)
  }, [filters, activeNotes])

  const handleSelectNote = (noteId: string) => {
    selectNote(noteId)
    setIsOpen(false)
  }

  const clearFilters = () => {
    setFilters({
      query: '',
      folderId: null,
      tags: [],
      dateRange: 'all',
      sortBy: 'relevance',
      includeContent: true,
      encryptedOnly: false,
      pinnedOnly: false,
    })
  }

  const addTagFilter = (tagName: string) => {
    if (!filters.tags.includes(tagName)) {
      setFilters(prev => ({ ...prev, tags: [...prev.tags, tagName] }))
    }
  }

  const removeTagFilter = (tagName: string) => {
    setFilters(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagName)
    }))
  }

  const hasActiveFilters = filters.folderId ||
    filters.tags.length > 0 ||
    filters.dateRange !== 'all' ||
    filters.encryptedOnly ||
    filters.pinnedOnly

  return (
    <>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search notes..."
          className="pl-9 pr-20 bg-background"
          value={filters.query}
          onChange={(e) => setFilters(prev => ({ ...prev, query: e.target.value }))}
          onFocus={() => setIsOpen(true)}
        />
        <div className="absolute right-1 top-1/2 -translate-y-1/2 flex gap-1">
          {hasActiveFilters && (
            <Badge variant="secondary" className="text-xs">
              {[filters.folderId && 'Folder', filters.tags.length && `${filters.tags.length} tags`,
                filters.dateRange !== 'all' && filters.dateRange, filters.encryptedOnly && 'Encrypted',
                filters.pinnedOnly && 'Pinned'].filter(Boolean).length} filters
            </Badge>
          )}
          <Dialog open={isOpen} onOpenChange={setIsOpen}>
            <DialogTrigger asChild>
              <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                <Filter className="h-4 w-4" />
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[80vh]">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  Advanced Search
                </DialogTitle>
              </DialogHeader>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Filters Panel */}
                <div className="space-y-4">
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm">Filters</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {/* Folder Filter */}
                      <div className="space-y-2">
                        <label className="text-sm font-medium flex items-center gap-2">
                          <Folder className="h-4 w-4" />
                          Folder
                        </label>
                        <Select
                          value={filters.folderId || 'all'}
                          onValueChange={(value) =>
                            setFilters(prev => ({
                              ...prev,
                              folderId: value === 'all' ? null : value
                            }))
                          }
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="All folders" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All folders</SelectItem>
                            {(folders || []).map((folder) => (
                              <SelectItem key={folder.id} value={folder.id}>
                                {folder.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>

                      {/* Tags Filter */}
                      <div className="space-y-2">
                        <label className="text-sm font-medium flex items-center gap-2">
                          <Tag className="h-4 w-4" />
                          Tags
                        </label>
                        <div className="space-y-2">
                          {filters.tags.map((tag) => (
                            <Badge key={tag} variant="secondary" className="gap-1">
                              {tag}
                              <button
                                onClick={() => removeTagFilter(tag)}
                                className="ml-1 hover:text-destructive"
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </Badge>
                          ))}
                          <Select
                            onValueChange={(value) => addTagFilter(value)}
                            value=""
                          >
                            <SelectTrigger>
                              <SelectValue placeholder="Add tag filter" />
                            </SelectTrigger>
                            <SelectContent>
                              {(tags || [])
                                .filter(tag => !filters.tags.includes(tag.name))
                                .map((tag) => (
                                  <SelectItem key={tag.id} value={tag.name}>
                                    {tag.name}
                                  </SelectItem>
                                ))}
                            </SelectContent>
                          </Select>
                        </div>
                      </div>

                      {/* Date Range */}
                      <div className="space-y-2">
                        <label className="text-sm font-medium flex items-center gap-2">
                          <Calendar className="h-4 w-4" />
                          Date Range
                        </label>
                        <Select
                          value={filters.dateRange}
                          onValueChange={(value: any) =>
                            setFilters(prev => ({ ...prev, dateRange: value }))
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All time</SelectItem>
                            <SelectItem value="today">Today</SelectItem>
                            <SelectItem value="week">Past week</SelectItem>
                            <SelectItem value="month">Past month</SelectItem>
                            <SelectItem value="year">Past year</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      {/* Additional Filters */}
                      <div className="space-y-3">
                        <label className="text-sm font-medium">Additional Filters</label>
                        <div className="space-y-2">
                          <label className="flex items-center gap-2 text-sm">
                            <input
                              type="checkbox"
                              checked={filters.includeContent}
                              onChange={(e) =>
                                setFilters(prev => ({ ...prev, includeContent: e.target.checked }))
                              }
                              className="rounded"
                            />
                            Search in content
                          </label>
                          <label className="flex items-center gap-2 text-sm">
                            <input
                              type="checkbox"
                              checked={filters.encryptedOnly}
                              onChange={(e) =>
                                setFilters(prev => ({ ...prev, encryptedOnly: e.target.checked }))
                              }
                              className="rounded"
                            />
                            <Lock className="h-3 w-3" />
                            Encrypted only
                          </label>
                          <label className="flex items-center gap-2 text-sm">
                            <input
                              type="checkbox"
                              checked={filters.pinnedOnly}
                              onChange={(e) =>
                                setFilters(prev => ({ ...prev, pinnedOnly: e.target.checked }))
                              }
                              className="rounded"
                            />
                            <Pin className="h-3 w-3" />
                            Pinned only
                          </label>
                        </div>
                      </div>

                      {/* Sort Options */}
                      <div className="space-y-2">
                        <label className="text-sm font-medium flex items-center gap-2">
                          <Clock className="h-4 w-4" />
                          Sort by
                        </label>
                        <Select
                          value={filters.sortBy}
                          onValueChange={(value: any) =>
                            setFilters(prev => ({ ...prev, sortBy: value }))
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="relevance">Relevance</SelectItem>
                            <SelectItem value="updated">Last updated</SelectItem>
                            <SelectItem value="created">Date created</SelectItem>
                            <SelectItem value="title">Title</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={clearFilters}
                        className="w-full"
                      >
                        Clear Filters
                      </Button>
                    </CardContent>
                  </Card>
                </div>

                {/* Results Panel */}
                <div className="lg:col-span-2">
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm">
                        Results ({results.length})
                      </CardTitle>
                      <CardDescription>
                        {filters.query ? `Searching for "${filters.query}"` : 'All notes'}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="max-h-[400px]">
                        {results.length === 0 ? (
                          <div className="text-center py-8 text-muted-foreground">
                            <FileText className="h-12 w-12 mx-auto mb-2 opacity-50" />
                            <p>No notes found</p>
                            <p className="text-sm">Try adjusting your search criteria</p>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {results.map((note) => (
                              <button
                                key={note.id}
                                onClick={() => handleSelectNote(note.id)}
                                className="w-full text-left p-3 rounded-lg hover:bg-accent transition-smooth border border-border"
                              >
                                <div className="flex items-start justify-between gap-2 mb-1">
                                  <div className="flex items-center gap-2 flex-1 min-w-0">
                                    {note.pinned && <Pin className="h-3 w-3 text-primary flex-shrink-0 mt-0.5" />}
                                    <h3 className="font-medium text-sm line-clamp-1">{note.title}</h3>
                                  </div>
                                  <div className="flex items-center gap-1 flex-shrink-0">
                                    {note.encrypted && (
                                      <Lock className="h-3 w-3 text-muted animate-pulse" />
                                    )}
                                  </div>
                                </div>

                                <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                                  {(note.content || '')
                                    .replace(/<[^>]*>/g, ' ')
                                    .replace(/\s+/g, ' ')
                                    .trim() || 'No content'}
                                </p>

                                <div className="flex items-center justify-between gap-2">
                                  <div className="flex items-center gap-1 flex-wrap">
                                    {(note.tags || []).slice(0, 2).map((tag: string) => (
                                      <Badge key={tag} variant="outline" className="text-xs">
                                        {tag}
                                      </Badge>
                                    ))}
                                    {(note.tags || []).length > 2 && (
                                      <span className="text-xs text-muted">+{(note.tags || []).length - 2}</span>
                                    )}
                                  </div>

                                  <span className="text-xs text-muted-foreground flex-shrink-0">
                                    {formatDistanceToNow(new Date(note.updatedAt), { addSuffix: true })}
                                  </span>
                                </div>
                              </button>
                            ))}
                          </div>
                        )}
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>
    </>
  )
}
