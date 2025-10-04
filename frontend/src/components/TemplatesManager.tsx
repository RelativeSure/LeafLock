import React, { useState, useEffect } from 'react'
import { Plus, X, FileText, Edit3, Trash2, Eye, Copy, Search, Users, Clock } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Label } from './ui/label'
// import { Textarea } from './ui/textarea'
import { Switch } from './ui/switch'
// import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs'
import { templatesService, Template, CreateTemplateRequest, UpdateTemplateRequest } from '../services/templatesService'

interface TemplatesManagerProps {
  onClose?: () => void
  onTemplateSelect?: (template: Template) => void
  mode?: 'manage' | 'select'
}

const defaultIcons = ['📝', '📋', '📄', '📊', '🗒️', '📑', '🔖', '📌', '🗃️', '📚']

export const TemplatesManager: React.FC<TemplatesManagerProps> = ({
  onClose,
  onTemplateSelect,
  mode = 'manage'
}) => {
  const [templates, setTemplates] = useState<Template[]>([])
  const [filteredTemplates, setFilteredTemplates] = useState<Template[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [editingTemplate, setEditingTemplate] = useState<Template | null>(null)
  const [viewingTemplate, setViewingTemplate] = useState<Template | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [activeTab, setActiveTab] = useState('my-templates')

  const [formData, setFormData] = useState<CreateTemplateRequest>({
    name: '',
    description: '',
    content: '',
    tags: [],
    icon: defaultIcons[0],
    is_public: false,
  })

  const loadTemplates = async () => {
    try {
      setError(null)
      const fetchedTemplates = await templatesService.getTemplates()
      setTemplates(fetchedTemplates)
      filterTemplates(fetchedTemplates, searchQuery, activeTab)
    } catch (err) {
      console.error('Failed to load templates:', err)
      setError(err instanceof Error ? err.message : 'Failed to load templates')
    } finally {
      setLoading(false)
    }
  }

  const filterTemplates = (templateList: Template[], query: string, tab: string) => {
    let filtered = templateList

    // Filter by tab
    if (tab === 'my-templates') {
      // Show user's own templates (non-public or user-owned)
      filtered = filtered.filter(t => !t.is_public || true) // Adjust based on user ownership
    } else if (tab === 'public-templates') {
      filtered = filtered.filter(t => t.is_public)
    } else if (tab === 'popular') {
      filtered = filtered.sort((a, b) => b.usage_count - a.usage_count).slice(0, 20)
    }

    // Filter by search query
    if (query) {
      const lowercaseQuery = query.toLowerCase()
      filtered = filtered.filter(template =>
        template.name.toLowerCase().includes(lowercaseQuery) ||
        template.description?.toLowerCase().includes(lowercaseQuery) ||
        template.tags.some(tag => tag.toLowerCase().includes(lowercaseQuery))
      )
    }

    setFilteredTemplates(filtered)
  }

  useEffect(() => {
    loadTemplates()
  }, [])

  useEffect(() => {
    filterTemplates(templates, searchQuery, activeTab)
  }, [searchQuery, activeTab, templates])

  const handleCreateTemplate = async () => {
    try {
      setError(null)
      await templatesService.createTemplate(formData)

      // Reset form
      setFormData({
        name: '',
        description: '',
        content: '',
        tags: [],
        icon: defaultIcons[0],
        is_public: false,
      })
      setIsCreating(false)

      // Reload templates
      await loadTemplates()
    } catch (err) {
      console.error('Failed to create template:', err)
      setError(err instanceof Error ? err.message : 'Failed to create template')
    }
  }

  const handleUpdateTemplate = async () => {
    if (!editingTemplate) return

    try {
      setError(null)
      const updateData: UpdateTemplateRequest = {
        name: formData.name,
        description: formData.description,
        content: formData.content,
        tags: formData.tags,
        icon: formData.icon,
        is_public: formData.is_public,
      }

      await templatesService.updateTemplate(editingTemplate.id, updateData)
      setEditingTemplate(null)
      setFormData({
        name: '',
        description: '',
        content: '',
        tags: [],
        icon: defaultIcons[0],
        is_public: false,
      })

      await loadTemplates()
    } catch (err) {
      console.error('Failed to update template:', err)
      setError(err instanceof Error ? err.message : 'Failed to update template')
    }
  }

  const handleDeleteTemplate = async (templateId: string) => {
    if (!confirm('Are you sure you want to delete this template?')) return

    try {
      setError(null)
      await templatesService.deleteTemplate(templateId)
      await loadTemplates()
    } catch (err) {
      console.error('Failed to delete template:', err)
      setError(err instanceof Error ? err.message : 'Failed to delete template')
    }
  }

  const handleUseTemplate = async (template: Template) => {
    if (mode === 'select' && onTemplateSelect) {
      onTemplateSelect(template)
      return
    }

    try {
      setError(null)
      const response = await templatesService.useTemplate(template.id)
      console.log('Note created from template:', response)

      // Optionally reload templates to update usage count
      await loadTemplates()

      // Close the modal or show success message
      if (onClose) onClose()
    } catch (err) {
      console.error('Failed to use template:', err)
      setError(err instanceof Error ? err.message : 'Failed to create note from template')
    }
  }

  const handleViewTemplate = async (template: Template) => {
    try {
      const fullTemplate = await templatesService.getTemplate(template.id)
      setViewingTemplate(fullTemplate)
    } catch (err) {
      console.error('Failed to load template content:', err)
      setError(err instanceof Error ? err.message : 'Failed to load template content')
    }
  }

  const startEdit = (template: Template) => {
    setEditingTemplate(template)
    setFormData({
      name: template.name,
      description: template.description || '',
      content: template.content || '',
      tags: template.tags,
      icon: template.icon,
      is_public: template.is_public,
    })
  }

  const handleTagInput = (value: string) => {
    const tags = value.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0)
    setFormData(prev => ({ ...prev, tags }))
  }

  if (loading) {
    return (
      <Card className="w-full max-w-4xl mx-auto">
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Loading templates...</span>
          </div>
        </CardContent>
      </Card>
    )
  }

  // Template form component
  const TemplateForm = () => (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2">
          <Label htmlFor="template-name">Template Name</Label>
          <Input
            id="template-name"
            value={formData.name}
            onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
            placeholder="Enter template name"
          />
        </div>
        <div>
          <Label htmlFor="template-icon">Icon</Label>
          <select
            id="template-icon"
            value={formData.icon}
            onChange={(e) => setFormData(prev => ({ ...prev, icon: e.target.value }))}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
          >
            {defaultIcons.map(icon => (
              <option key={icon} value={icon}>{icon} {icon}</option>
            ))}
          </select>
        </div>
      </div>

      <div>
        <Label htmlFor="template-description">Description (optional)</Label>
        <Input
          id="template-description"
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
          placeholder="Brief description of the template"
        />
      </div>

      <div>
        <Label htmlFor="template-tags">Tags (comma-separated)</Label>
        <Input
          id="template-tags"
          value={formData.tags.join(', ')}
          onChange={(e) => handleTagInput(e.target.value)}
          placeholder="meeting, project, daily, etc."
        />
      </div>

      <div>
        <Label htmlFor="template-content">Template Content</Label>
        <textarea
          id="template-content"
          value={formData.content}
          onChange={(e) => setFormData(prev => ({ ...prev, content: e.target.value }))}
          placeholder="Enter your template content here..."
          rows={8}
          className="w-full px-3 py-2 border border-gray-300 rounded-md resize-vertical"
        />
      </div>

      <div className="flex items-center space-x-2">
        <Switch
          id="is-public"
          checked={formData.is_public}
          onCheckedChange={(checked) => setFormData(prev => ({ ...prev, is_public: checked }))}
        />
        <Label htmlFor="is-public">Make this template public</Label>
      </div>

      <div className="flex justify-end space-x-2">
        <Button
          variant="outline"
          onClick={() => {
            setIsCreating(false)
            setEditingTemplate(null)
            setFormData({
              name: '',
              description: '',
              content: '',
              tags: [],
              icon: defaultIcons[0],
              is_public: false,
            })
          }}
        >
          Cancel
        </Button>
        <Button
          onClick={editingTemplate ? handleUpdateTemplate : handleCreateTemplate}
          disabled={!formData.name.trim() || !formData.content.trim()}
        >
          {editingTemplate ? 'Update Template' : 'Create Template'}
        </Button>
      </div>
    </div>
  )

  return (
    <Card className="w-full max-w-6xl mx-auto">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <FileText className="h-5 w-5" />
          {mode === 'select' ? 'Select Template' : 'Template Manager'}
        </CardTitle>
        <div className="flex items-center gap-2">
          {mode === 'manage' && (
            <Button onClick={() => setIsCreating(true)}>
              <Plus className="h-4 w-4 mr-2" />
              New Template
            </Button>
          )}
          {onClose && (
            <Button variant="outline" size="sm" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
            {error}
          </div>
        )}

        {(isCreating || editingTemplate) && (
          <Card>
            <CardHeader>
              <CardTitle>
                {editingTemplate ? 'Edit Template' : 'Create New Template'}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <TemplateForm />
            </CardContent>
          </Card>
        )}

        {viewingTemplate && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <span className="text-2xl">{viewingTemplate.icon}</span>
                {viewingTemplate.name}
              </CardTitle>
              <Button variant="outline" size="sm" onClick={() => setViewingTemplate(null)}>
                <X className="h-4 w-4" />
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              {viewingTemplate.description && (
                <p className="text-gray-600">{viewingTemplate.description}</p>
              )}
              <div className="flex flex-wrap gap-2">
                {viewingTemplate.tags.map(tag => (
                  <Badge key={tag} variant="secondary">{tag}</Badge>
                ))}
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <pre className="whitespace-pre-wrap text-sm">{viewingTemplate.content}</pre>
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setViewingTemplate(null)}>
                  Close
                </Button>
                <Button onClick={() => handleUseTemplate(viewingTemplate)}>
                  <Copy className="h-4 w-4 mr-2" />
                  {mode === 'select' ? 'Select' : 'Use Template'}
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {!isCreating && !editingTemplate && !viewingTemplate && (
          <div className="space-y-4">
            <div className="flex items-center space-x-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                <Input
                  placeholder="Search templates..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            <div className="space-y-4">
              <div className="flex space-x-2">
                <Button
                  variant={activeTab === 'my-templates' ? 'default' : 'outline'}
                  onClick={() => setActiveTab('my-templates')}
                >
                  My Templates
                </Button>
                <Button
                  variant={activeTab === 'public-templates' ? 'default' : 'outline'}
                  onClick={() => setActiveTab('public-templates')}
                >
                  <Users className="h-4 w-4 mr-2" />
                  Public
                </Button>
                <Button
                  variant={activeTab === 'popular' ? 'default' : 'outline'}
                  onClick={() => setActiveTab('popular')}
                >
                  <Clock className="h-4 w-4 mr-2" />
                  Popular
                </Button>
              </div>

              <div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {filteredTemplates.map(template => (
                    <Card key={template.id} className="hover:shadow-md transition-shadow">
                      <CardHeader className="pb-3">
                        <CardTitle className="flex items-center justify-between text-base">
                          <span className="flex items-center gap-2">
                            <span className="text-xl">{template.icon}</span>
                            <span className="truncate">{template.name}</span>
                          </span>
                          {template.is_public && (
                            <Badge variant="secondary" className="text-xs">
                              <Users className="h-3 w-3 mr-1" />
                              Public
                            </Badge>
                          )}
                        </CardTitle>
                        {template.description && (
                          <p className="text-sm text-gray-600 line-clamp-2">
                            {template.description}
                          </p>
                        )}
                      </CardHeader>
                      <CardContent className="pt-0 space-y-3">
                        {template.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {template.tags.slice(0, 3).map(tag => (
                              <Badge key={tag} variant="outline" className="text-xs">
                                {tag}
                              </Badge>
                            ))}
                            {template.tags.length > 3 && (
                              <Badge variant="outline" className="text-xs">
                                +{template.tags.length - 3}
                              </Badge>
                            )}
                          </div>
                        )}

                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <span>Used {template.usage_count} times</span>
                          <span>{new Date(template.created_at).toLocaleDateString()}</span>
                        </div>

                        <div className="flex justify-between gap-2">
                          <div className="flex gap-1">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleViewTemplate(template)}
                            >
                              <Eye className="h-3 w-3" />
                            </Button>
                            {mode === 'manage' && (
                              <>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => startEdit(template)}
                                >
                                  <Edit3 className="h-3 w-3" />
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => handleDeleteTemplate(template.id)}
                                  className="text-red-600 hover:text-red-700"
                                >
                                  <Trash2 className="h-3 w-3" />
                                </Button>
                              </>
                            )}
                          </div>
                          <Button
                            size="sm"
                            onClick={() => handleUseTemplate(template)}
                          >
                            <Copy className="h-3 w-3 mr-1" />
                            {mode === 'select' ? 'Select' : 'Use'}
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {filteredTemplates.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    {searchQuery
                      ? 'No templates found matching your search.'
                      : activeTab === 'my-templates'
                        ? 'No templates yet. Create your first template!'
                        : 'No templates available.'
                    }
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default TemplatesManager