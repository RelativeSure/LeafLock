'use client'

import { useState } from 'react'
import { useTemplatesStore } from '../../stores/templatesStore'
import { useAuthStore } from '../../stores/authStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { FileText, Plus, Search, Globe, Lock } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export function TemplatesPage() {
  const { templates, publicTemplates } = useTemplatesStore()
  const { user } = useAuthStore()
  const [searchQuery, setSearchQuery] = useState('')

  const myTemplates = (templates || []).filter((t) => t.userId === user?.id)
  const communityTemplates = (publicTemplates || []).filter((t) => t.userId !== user?.id)

  const filterTemplates = (templateList: any[]) => {
    if (!searchQuery) return templateList
    return templateList.filter((template) =>
      template.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.content.toLowerCase().includes(searchQuery.toLowerCase())
    )
  }

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

        {/* My Templates */}
        <Card>
          <CardHeader>
            <CardTitle>My Templates</CardTitle>
            <CardDescription>
              Templates you've created ({myTemplates.length})
            </CardDescription>
          </CardHeader>
          <CardContent>
            {filterTemplates(myTemplates).length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                {searchQuery ? 'No templates match your search.' : 'You haven\'t created any templates yet.'}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filterTemplates(myTemplates).map((template) => (
                  <Card key={template.id} className="hover:shadow-md transition-shadow">
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between">
                        <CardTitle className="text-lg">{template.name}</CardTitle>
                        <div className="flex items-center gap-1">
                          {template.isPublic ? (
                            <Globe className="h-4 w-4 text-green-600" />
                          ) : (
                            <Lock className="h-4 w-4 text-muted-foreground" />
                          )}
                        </div>
                      </div>
                      <CardDescription className="line-clamp-2">
                        {template.content.replace(/<[^>]*>/g, '').substring(0, 100)}...
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="flex items-center justify-between">
                        <div className="flex flex-wrap gap-1">
                          {(template.tags || []).slice(0, 2).map((tag: string) => (
                            <Badge key={tag} variant="secondary" className="text-xs">
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
                          {template.createdAt ? formatDistanceToNow(new Date(template.createdAt), { addSuffix: true }) : 'Unknown'}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Community Templates */}
        <Card>
          <CardHeader>
            <CardTitle>Community Templates</CardTitle>
            <CardDescription>
              Public templates shared by other users ({communityTemplates.length})
            </CardDescription>
          </CardHeader>
          <CardContent>
            {filterTemplates(communityTemplates).length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                {searchQuery ? 'No templates match your search.' : 'No community templates available.'}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filterTemplates(communityTemplates).map((template) => (
                  <Card key={template.id} className="hover:shadow-md transition-shadow">
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between">
                        <CardTitle className="text-lg">{template.name}</CardTitle>
                        <Globe className="h-4 w-4 text-green-600" />
                      </div>
                      <CardDescription className="line-clamp-2">
                        {template.content.replace(/<[^>]*>/g, '').substring(0, 100)}...
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="flex items-center justify-between">
                        <div className="flex flex-wrap gap-1">
                          {(template.tags || []).slice(0, 2).map((tag: string) => (
                            <Badge key={tag} variant="secondary" className="text-xs">
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
                          {template.createdAt ? formatDistanceToNow(new Date(template.createdAt), { addSuffix: true }) : 'Unknown'}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
