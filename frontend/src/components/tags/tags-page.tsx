'use client'

import { useState } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tag, Plus, Search, Edit2, Trash2 } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export function TagsPage() {
  const { tags, notes, createTag, deleteTag } = useNotesStore()
  const [searchQuery, setSearchQuery] = useState('')
  const [newTagName, setNewTagName] = useState('')
  const [newTagColor, setNewTagColor] = useState('#3b82f6')

  const activeNotes = (notes || []).filter((note) => !note.isTrashed)

  const filterTags = (tagList: any[]) => {
    if (!searchQuery) return tagList
    return tagList.filter((tag) => tag.name.toLowerCase().includes(searchQuery.toLowerCase()))
  }

  const handleCreateTag = async () => {
    if (newTagName.trim()) {
      await createTag({
        name: newTagName.trim(),
        color: newTagColor,
      })
      setNewTagName('')
    }
  }

  const getTagUsageCount = (tagName: string) => {
    return activeNotes.filter((note) => (note.tags || []).includes(tagName)).length
  }

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <Tag className="h-8 w-8" />
          Tags
        </h1>
        <p className="text-muted-foreground mt-2">
          Organize your notes with custom tags and categories.
        </p>
      </div>

      <div className="space-y-6">
        {/* Create New Tag */}
        <Card>
          <CardHeader>
            <CardTitle>Create New Tag</CardTitle>
            <CardDescription>Add a new tag to organize your notes.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label htmlFor="tag-name">Tag Name</Label>
                <Input
                  id="tag-name"
                  placeholder="Enter tag name..."
                  value={newTagName}
                  onChange={(e) => setNewTagName(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="tag-color">Color</Label>
                <div className="flex gap-2">
                  <Input
                    id="tag-color"
                    type="color"
                    value={newTagColor}
                    onChange={(e) => setNewTagColor(e.target.value)}
                    className="w-16 h-10 p-1"
                  />
                  <div className="flex gap-2">
                    {['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#6366f1'].map(
                      (color) => (
                        <Button
                          key={color}
                          variant="ghost"
                          size="sm"
                          className="w-8 h-8 rounded-full p-0 border-2 border-border hover:border-primary transition-colors"
                          style={{ backgroundColor: color }}
                          onClick={() => setNewTagColor(color)}
                        />
                      )
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-end">
                <Button onClick={handleCreateTag} disabled={!newTagName.trim()}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Tag
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Search */}
        <div className="flex gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search tags..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>
        </div>

        {/* Tags List */}
        <Card>
          <CardHeader>
            <CardTitle>All Tags</CardTitle>
            <CardDescription>
              Manage your tags and see usage statistics ({tags?.length || 0} total)
            </CardDescription>
          </CardHeader>
          <CardContent>
            {filterTags(tags || []).length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                {searchQuery ? 'No tags match your search.' : "You haven't created any tags yet."}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filterTags(tags || []).map((tag) => {
                  const usageCount = getTagUsageCount(tag.name)
                  return (
                    <Card key={tag.id} className="hover:shadow-md transition-shadow">
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between">
                          <div className="flex items-center gap-2">
                            <Tag className="h-4 w-4" style={{ color: tag.color }} />
                            <CardTitle className="text-lg">{tag.name}</CardTitle>
                          </div>
                          <div className="flex items-center gap-1">
                            <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                              <Edit2 className="h-3 w-3" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-8 w-8 p-0 text-destructive hover:text-destructive"
                              onClick={() => deleteTag(tag.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <div className="flex items-center justify-between">
                          <div className="text-sm text-muted-foreground">
                            Used in {usageCount} note{usageCount !== 1 ? 's' : ''}
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {tag.createdAt
                              ? formatDistanceToNow(new Date(tag.createdAt), { addSuffix: true })
                              : 'Unknown'}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  )
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
