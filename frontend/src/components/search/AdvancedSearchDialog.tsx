import { useState } from 'react'
import { Search, Filter, X, Calendar, Tag, Lock, Pin } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { SearchFilters } from '@/services/api/searchService'

interface AdvancedSearchDialogProps {
  onSearch: (filters: SearchFilters) => void
  currentFilters: SearchFilters
}

export function AdvancedSearchDialog({ onSearch, currentFilters }: AdvancedSearchDialogProps) {
  const [open, setOpen] = useState(false)
  const [filters, setFilters] = useState<SearchFilters>(currentFilters)

  const handleApplyFilters = () => {
    onSearch(filters)
    setOpen(false)
  }

  const handleClearFilters = () => {
    const emptyFilters: SearchFilters = {}
    setFilters(emptyFilters)
    onSearch(emptyFilters)
    setOpen(false)
  }

  const hasActiveFilters = Object.keys(currentFilters).length > 0

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="relative">
          <Filter className="mr-2 h-4 w-4" />
          Advanced Filters
          {hasActiveFilters && (
            <Badge className="ml-2 h-5 w-5 rounded-full p-0" variant="destructive">
              {Object.keys(currentFilters).length}
            </Badge>
          )}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Advanced Search Filters</DialogTitle>
          <DialogDescription>
            Filter notes by metadata. Content search is performed locally after fetching results.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Tags Filter */}
          <div className="space-y-2">
            <Label htmlFor="tags">
              <Tag className="mr-2 inline h-4 w-4" />
              Tags (comma-separated)
            </Label>
            <Input
              id="tags"
              placeholder="work, personal, urgent"
              value={filters.tags?.join(', ') || ''}
              onChange={(e) => {
                const tags = e.target.value
                  .split(',')
                  .map((t) => t.trim())
                  .filter(Boolean)
                setFilters({ ...filters, tags: tags.length > 0 ? tags : undefined })
              }}
            />
          </div>

          {/* Date Range */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="start-date">
                <Calendar className="mr-2 inline h-4 w-4" />
                Start Date
              </Label>
              <Input
                id="start-date"
                type="date"
                value={
                  filters.start_date ? new Date(filters.start_date).toISOString().split('T')[0] : ''
                }
                onChange={(e) => {
                  const value = e.target.value
                  setFilters({
                    ...filters,
                    start_date: value ? new Date(value).toISOString() : undefined,
                  })
                }}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="end-date">
                <Calendar className="mr-2 inline h-4 w-4" />
                End Date
              </Label>
              <Input
                id="end-date"
                type="date"
                value={
                  filters.end_date ? new Date(filters.end_date).toISOString().split('T')[0] : ''
                }
                onChange={(e) => {
                  const value = e.target.value
                  setFilters({
                    ...filters,
                    end_date: value ? new Date(value).toISOString() : undefined,
                  })
                }}
              />
            </div>
          </div>

          {/* Status Filters */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="pinned-filter">
                <Pin className="mr-2 inline h-4 w-4" />
                Pinned Status
              </Label>
              <Select
                value={
                  filters.is_pinned === undefined ? 'all' : filters.is_pinned ? 'true' : 'false'
                }
                onValueChange={(value) =>
                  setFilters({
                    ...filters,
                    is_pinned: value === 'all' ? undefined : value === 'true',
                  })
                }
              >
                <SelectTrigger id="pinned-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Notes</SelectItem>
                  <SelectItem value="true">Pinned Only</SelectItem>
                  <SelectItem value="false">Not Pinned</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="locked-filter">
                <Lock className="mr-2 inline h-4 w-4" />
                Locked Status
              </Label>
              <Select
                value={
                  filters.is_locked === undefined ? 'all' : filters.is_locked ? 'true' : 'false'
                }
                onValueChange={(value) =>
                  setFilters({
                    ...filters,
                    is_locked: value === 'all' ? undefined : value === 'true',
                  })
                }
              >
                <SelectTrigger id="locked-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Notes</SelectItem>
                  <SelectItem value="true">Locked Only</SelectItem>
                  <SelectItem value="false">Not Locked</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Include Trashed */}
          <div className="space-y-2">
            <Label htmlFor="trashed-filter">Include Trashed Notes</Label>
            <Select
              value={
                filters.is_trashed === undefined ? 'false' : filters.is_trashed ? 'true' : 'false'
              }
              onValueChange={(value) =>
                setFilters({
                  ...filters,
                  is_trashed: value === 'true',
                })
              }
            >
              <SelectTrigger id="trashed-filter">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="false">Active Notes Only</SelectItem>
                <SelectItem value="true">Include Trashed</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Sort Options */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="sort-by">Sort By</Label>
              <Select
                value={filters.sort_by || 'updated_at'}
                onValueChange={(value: 'created_at' | 'updated_at') =>
                  setFilters({ ...filters, sort_by: value })
                }
              >
                <SelectTrigger id="sort-by">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="updated_at">Last Updated</SelectItem>
                  <SelectItem value="created_at">Date Created</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sort-order">Sort Order</Label>
              <Select
                value={filters.sort_order || 'desc'}
                onValueChange={(value: 'asc' | 'desc') =>
                  setFilters({ ...filters, sort_order: value })
                }
              >
                <SelectTrigger id="sort-order">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="desc">Newest First</SelectItem>
                  <SelectItem value="asc">Oldest First</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={handleClearFilters}>
            <X className="mr-2 h-4 w-4" />
            Clear All
          </Button>
          <Button onClick={handleApplyFilters}>
            <Search className="mr-2 h-4 w-4" />
            Apply Filters
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
