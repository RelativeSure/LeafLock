import React, { useState, useEffect } from 'react'
import { Plus, X, Hash, Palette } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { tagsService, Tag, CreateTagRequest } from '@/services/data/tagsService'
import { Spinner } from '@/components/ui/spinner'
import { motion, AnimatePresence } from 'framer-motion'

interface TagsManagerProps {
  onClose?: () => void
  onTagsChange?: (tags: Tag[]) => void
}

const defaultColors = [
  '#3b82f6', // blue
  '#ef4444', // red
  '#10b981', // green
  '#f59e0b', // yellow
  '#8b5cf6', // purple
  '#f97316', // orange
  '#06b6d4', // cyan
  '#84cc16', // lime
  '#ec4899', // pink
  '#6b7280', // gray
]

export const TagsManager: React.FC<TagsManagerProps> = ({ onClose, onTagsChange }) => {
  const [tags, setTags] = useState<Tag[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [newTag, setNewTag] = useState<CreateTagRequest>({ name: '', color: defaultColors[0] })

  const loadTags = async () => {
    try {
      setError(null)
      const fetchedTags = await tagsService.getTags()
      setTags(fetchedTags)
      onTagsChange?.(fetchedTags)
    } catch (err) {
      console.error('Failed to load tags:', err)
      setError(err instanceof Error ? err.message : 'Failed to load tags')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTags()
  }, [])

  const handleCreateTag = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newTag.name.trim()) return

    try {
      setError(null)
      setIsCreating(true)
      const createdTag = await tagsService.createTag(newTag)
      const updatedTags = [...tags, createdTag]
      setTags(updatedTags)
      setNewTag({ name: '', color: defaultColors[0] })
      onTagsChange?.(updatedTags)
    } catch (err) {
      console.error('Failed to create tag:', err)
      setError(err instanceof Error ? err.message : 'Failed to create tag')
    } finally {
      setIsCreating(false)
    }
  }

  const handleDeleteTag = async (tagId: string) => {
    if (!confirm('Are you sure you want to delete this tag? It will be removed from all notes.')) {
      return
    }

    try {
      setError(null)
      await tagsService.deleteTag(tagId)
      const updatedTags = tags.filter((tag) => tag.id !== tagId)
      setTags(updatedTags)
      onTagsChange?.(updatedTags)
    } catch (err) {
      console.error('Failed to delete tag:', err)
      setError(err instanceof Error ? err.message : 'Failed to delete tag')
    }
  }

  if (loading) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Hash className="w-5 h-5" />
            Tags
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <Spinner className="h-6 w-6 text-primary" />
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <CardTitle className="flex items-center gap-2">
          <Hash className="w-5 h-5" />
          Tags
        </CardTitle>
        {onClose && (
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="w-4 h-4" />
          </Button>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <div className="p-3 bg-destructive/10 border border-destructive/20 rounded text-destructive text-sm">
            {error}
          </div>
        )}

        {/* Create New Tag Form */}
        <form onSubmit={handleCreateTag} className="space-y-3">
          <div>
            <Label htmlFor="tag-name">Tag Name</Label>
            <Input
              id="tag-name"
              type="text"
              value={newTag.name}
              onChange={(e) => setNewTag({ ...newTag, name: e.target.value })}
              placeholder="Enter tag name..."
              maxLength={50}
              disabled={isCreating}
            />
          </div>

          <div>
            <Label>Color</Label>
            <div className="flex gap-2 mt-2">
              {defaultColors.map((color) => (
                <button
                  key={color}
                  type="button"
                  className={`w-6 h-6 rounded-full border-2 ${
                    newTag.color === color ? 'border-foreground' : 'border-border'
                  }`}
                  style={{ backgroundColor: color }}
                  onClick={() => setNewTag({ ...newTag, color })}
                  disabled={isCreating}
                />
              ))}
              <button
                type="button"
                className="w-6 h-6 rounded-full border-2 border-border flex items-center justify-center text-muted-foreground hover:bg-muted"
                onClick={() => {
                  const customColor = prompt('Enter hex color (e.g., #ff0000):')
                  if (customColor && /^#[0-9A-F]{6}$/i.test(customColor)) {
                    setNewTag({ ...newTag, color: customColor })
                  }
                }}
                disabled={isCreating}
              >
                <Palette className="w-3 h-3" />
              </button>
            </div>
          </div>

          <Button type="submit" disabled={!newTag.name.trim() || isCreating} className="w-full">
            {isCreating ? (
              <div className="flex items-center gap-2">
                <Spinner className="h-4 w-4 text-white" aria-hidden="true" />
                Creating...
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Plus className="w-4 h-4" />
                Create Tag
              </div>
            )}
          </Button>
        </form>

        {/* Existing Tags */}
        <div>
          <Label>Your Tags ({tags.length})</Label>
          {tags.length === 0 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.4 }}
              className="text-center py-6 text-muted-foreground"
            >
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
              >
                <Hash className="w-8 h-8 mx-auto mb-2 text-muted-foreground/30" />
              </motion.div>
              <motion.p
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="text-foreground"
              >
                No tags yet
              </motion.p>
              <motion.p
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
                className="text-sm"
              >
                Create your first tag above
              </motion.p>
            </motion.div>
          ) : (
            <div className="space-y-2 mt-2 max-h-60 overflow-y-auto">
              <AnimatePresence>
                {tags.map((tag, index) => (
                  <motion.div
                    key={tag.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ duration: 0.2, delay: index * 0.05 }}
                    className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border/50 hover:bg-muted transition-colors"
                  >
                    <Badge
                      style={{ backgroundColor: tag.color, color: 'white' }}
                      className="flex items-center gap-1.5 px-2 py-1"
                    >
                      <Hash className="w-3 h-3" />
                      {tag.name}
                    </Badge>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDeleteTag(tag.id)}
                      className="text-destructive hover:text-destructive hover:bg-destructive/10 p-1 h-6 w-6"
                    >
                      <X className="w-3 h-3" />
                    </Button>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export default TagsManager
