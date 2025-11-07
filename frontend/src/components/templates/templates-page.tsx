'use client'

import { useEffect, useState } from 'react'
import { useShallow } from 'zustand/react/shallow'
import { useTemplatesStore } from '../../stores/templatesStore'
import { useAuthStore } from '../../stores/authStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { FileText, Plus, Search, Globe, Lock } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import type { Template } from '@/types'

export function TemplatesPage() {
  const { templates, starterTemplates, communityTemplates } = useTemplatesStore(
    useShallow((state) => ({
      templates: state.templates,
      starterTemplates: state.starterTemplates,
      communityTemplates: state.communityTemplates,
    }))
  )
  const { user } = useAuthStore()
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    void useTemplatesStore.getState().loadTemplates()
  }, [])

  const myTemplates = templates || []
  const starter = starterTemplates || []
  const community = (communityTemplates || []).filter((t) => t.userId !== user?.id)

  const stripHtml = (value: string) => value.replace(/<[^>]*>/g, '')
  const truncateText = (value: string, limit = 140) => {
    if (!value) return ''
    return value.length > limit ? `${value.slice(0, limit)}…` : value
  }

  const getTemplatePreview = (template: Template) => {
    const raw = template.description || template.content || ''
    return truncateText(stripHtml(raw), 140)
  }

  const filterTemplates = (templateList: Template[]) => {
    if (!searchQuery) return templateList
    const lowerQuery = searchQuery.toLowerCase()
    return templateList.filter((template) => {
      const inName = template.name.toLowerCase().includes(lowerQuery)
      const inDescription = (template.description || '').toLowerCase().includes(lowerQuery)
      const inContent = (template.content || '').toLowerCase().includes(lowerQuery)
      const inTags = (template.tags || []).some((tag) => tag.toLowerCase().includes(lowerQuery))
      return inName || inDescription || inContent || inTags
    })
  }

  const formatTimestamp = (value?: string) => {
    if (!value) {
      return 'Unknown'
    }

    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
      return 'Unknown'
    }

    return formatDistanceToNow(date, { addSuffix: true })
  }

  const filteredStarter = filterTemplates(starter)
  const filteredMyTemplates = filterTemplates(myTemplates)
  const filteredCommunity = filterTemplates(community)

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <FileText className="h-8 w-8" />
          Templates
        </h1>
        <p className="text-muted-foreground mt-2">
          Create and manage note templates for quick note creation.
        </p>
      </div>

      <div className="space-y-6">
        {/* Search */}
        <div className="flex gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search templates..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            Create Template
          </Button>
        </div>

        {/* Starter Templates */}
        <Card>
          <CardHeader>
            <CardTitle>Starter Templates</CardTitle>
            <CardDescription>
              Built-in templates provided by LeafLock ({starter.length})
            </CardDescription>
          </CardHeader>
          <CardContent>
            {filteredStarter.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No starter templates found.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredStarter.map((template) => {
                  const preview = getTemplatePreview(template)
                  return (
                    <Card key={template.id} className="hover:shadow-md transition-shadow">
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between">
                          <CardTitle className="text-lg flex items-center gap-2">
                            <span role="img" aria-label={template.name}>
                              {template.icon || '✨'}
                            </span>
                            {template.name}
                          </CardTitle>
                          <Badge variant="secondary" className="text-xs">
                            Starter
                          </Badge>
                        </div>
                        <CardDescription className="line-clamp-2">
                          {preview || 'No preview available'}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <div className="flex items-center justify-between">
                          <div className="flex flex-wrap gap-1">
                            {(template.tags || []).slice(0, 2).map((tag: string) => (
                              <Badge
                                key={`${template.id}-${tag}`}
                                variant="outline"
                                className="text-xs"
                              >
                                {tag}
                              </Badge>
                            ))}
                          </div>
                          <span className="text-xs text-muted-foreground">Starter</span>
                        </div>
                      </CardContent>
                    </Card>
                  )
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* My Templates */}
        <Card>
          <CardHeader>
            <CardTitle>My Templates</CardTitle>
            <CardDescription>Templates you've created ({myTemplates.length})</CardDescription>
          </CardHeader>
          <CardContent>
            {filteredMyTemplates.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                {searchQuery
                  ? 'No templates match your search.'
                  : "You haven't created any templates yet."}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredMyTemplates.map((template) => {
                  const preview = getTemplatePreview(template)
                  return (
                    <Card key={template.id} className="hover:shadow-md transition-shadow">
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between">
                          <CardTitle className="text-lg flex items-center gap-2">
                            <span role="img" aria-label={template.name}>
                              {template.icon || '📝'}
                            </span>
                            {template.name}
                          </CardTitle>
                          <div className="flex items-center gap-1">
                            {template.isPublic ? (
                              <Globe className="h-4 w-4 text-green-600" />
                            ) : (
                              <Lock className="h-4 w-4 text-muted-foreground" />
                            )}
                          </div>
                        </div>
                        <CardDescription className="line-clamp-2">
                          {preview || 'No preview available'}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <div className="flex items-center justify-between">
                          <div className="flex flex-wrap gap-1">
                            {(template.tags || []).slice(0, 2).map((tag: string) => (
                              <Badge
                                key={`${template.id}-${tag}`}
                                variant="secondary"
                                className="text-xs"
                              >
                                {tag}
                              </Badge>
                            ))}
                            {(template.tags || []).length > 2 && (
                              <Badge variant="outline" className="text-xs">
                                +{(template.tags || []).length - 2}
                              </Badge>
                            )}
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {formatTimestamp(template.createdAt)}
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

        {/* Community Templates */}
        <Card>
          <CardHeader>
            <CardTitle>Community Templates</CardTitle>
            <CardDescription>
              Public templates shared by other users ({community.length})
            </CardDescription>
          </CardHeader>
          <CardContent>
            {filteredCommunity.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                {searchQuery
                  ? 'No templates match your search.'
                  : 'No community templates available.'}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredCommunity.map((template) => {
                  const preview = getTemplatePreview(template)
                  return (
                    <Card key={template.id} className="hover:shadow-md transition-shadow">
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between">
                          <CardTitle className="text-lg flex items-center gap-2">
                            <span role="img" aria-label={template.name}>
                              {template.icon || '🌍'}
                            </span>
                            {template.name}
                          </CardTitle>
                          <Globe className="h-4 w-4 text-green-600" />
                        </div>
                        <CardDescription className="line-clamp-2">
                          {preview || 'No preview available'}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <div className="flex items-center justify-between">
                          <div className="flex flex-wrap gap-1">
                            {(template.tags || []).slice(0, 2).map((tag: string) => (
                              <Badge
                                key={`${template.id}-${tag}`}
                                variant="secondary"
                                className="text-xs"
                              >
                                {tag}
                              </Badge>
                            ))}
                            {(template.tags || []).length > 2 && (
                              <Badge variant="outline" className="text-xs">
                                +{(template.tags || []).length - 2}
                              </Badge>
                            )}
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {formatTimestamp(template.createdAt)}
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
