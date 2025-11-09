import { useEffect, useState } from 'react'
import { useShallow } from 'zustand/react/shallow'
import { useTemplatesStore } from '../../stores/templatesStore'
import { useNotesStore } from '../../stores/notesStore'
import { useAuthStore } from '../../stores/authStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { FileText, Globe, Lock, Search, Trash2, Share2, Copy, TagIcon } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import type { Template } from '@/types'

interface TemplatesDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function TemplatesDialog({ open, onOpenChange }: TemplatesDialogProps) {
  const { user } = useAuthStore()
  const {
    templates,
    starterTemplates,
    communityTemplates,
    deleteTemplate,
    shareTemplate,
    applyTemplate,
    loadTemplates,
  } = useTemplatesStore(
    useShallow((state) => ({
      templates: state.templates,
      starterTemplates: state.starterTemplates,
      communityTemplates: state.communityTemplates,
      deleteTemplate: state.deleteTemplate,
      shareTemplate: state.shareTemplate,
      applyTemplate: state.applyTemplate,
      loadTemplates: state.loadTemplates,
    }))
  )
  const { createNote, selectNote } = useNotesStore()
  const [searchQuery, setSearchQuery] = useState('')

  const myTemplates = templates || []
  const starter = starterTemplates || []
  const community = (communityTemplates || []).filter((t) => t.userId !== user?.id)

  useEffect(() => {
    if (open) {
      void loadTemplates()
    }
  }, [open, loadTemplates])

  const filterTemplates = (templateList: Template[]) => {
    if (!searchQuery) return templateList
    const lowerQuery = searchQuery.toLowerCase()
    return templateList.filter((t) => {
      const inName = t.name.toLowerCase().includes(lowerQuery)
      const inDescription = (t.description || '').toLowerCase().includes(lowerQuery)
      const inContent = (t.content || '').toLowerCase().includes(lowerQuery)
      const inTags = (t.tags || []).some((tag) => tag.toLowerCase().includes(lowerQuery))
      return inName || inDescription || inContent || inTags
    })
  }

  const truncateText = (value: string, limit = 120) => {
    if (!value) return ''
    return value.length > limit ? `${value.slice(0, limit)}…` : value
  }

  const handleUseTemplate = async (templateId: string) => {
    try {
      const templateData = await applyTemplate(templateId)
      const note = await createNote({ content: templateData.content, tags: templateData.tags })
      selectNote(note.id)
      onOpenChange(false)
    } catch (error) {
      console.error('Failed to use template:', error)
    }
  }

  const handleToggleShare = async (templateId: string, currentIsPublic: boolean) => {
    try {
      await shareTemplate(templateId, !currentIsPublic)
    } catch (error) {
      console.error('Failed to toggle share:', error)
    }
  }

  const handleDeleteTemplate = async (templateId: string) => {
    try {
      await deleteTemplate(templateId)
    } catch (error) {
      console.error('Failed to delete template:', error)
    }
  }

  const TemplateCard = ({
    template,
    showActions = true,
    badge,
  }: {
    template: Template
    showActions?: boolean
    badge?: React.ReactNode
  }) => {
    const previewText = truncateText(template.description || template.content || '', 120)
    const createdAtLabel = template.createdAt
      ? formatDistanceToNow(new Date(template.createdAt), { addSuffix: true })
      : 'Unknown'

    return (
      <div className="p-4 border border-border rounded-lg hover:bg-surface-hover transition-colors group">
        <div className="flex items-start justify-between gap-3 mb-2">
          <div className="flex-1 min-w-0">
            <h3 className="font-medium text-sm mb-1 truncate flex items-center gap-2">
              <span role="img" aria-label={template.name}>
                {template.icon || '📝'}
              </span>
              {template.name}
            </h3>
            <p className="text-xs text-muted-foreground line-clamp-2">
              {previewText || 'No preview available'}
            </p>
          </div>

          {showActions && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100"
                >
                  <span className="sr-only">Open menu</span>
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <circle cx="12" cy="12" r="1" />
                    <circle cx="12" cy="5" r="1" />
                    <circle cx="12" cy="19" r="1" />
                  </svg>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => handleToggleShare(template.id, template.isPublic)}>
                  {template.isPublic ? (
                    <>
                      <Lock className="h-4 w-4 mr-2" />
                      Make Private
                    </>
                  ) : (
                    <>
                      <Share2 className="h-4 w-4 mr-2" />
                      Share Publicly
                    </>
                  )}
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => handleDeleteTemplate(template.id)}
                  className="text-danger"
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          {!showActions && badge}
        </div>

        <div className="flex items-center justify-between gap-2 mt-3">
          <div className="flex items-center gap-2 flex-wrap">
            {template.isPublic && (
              <Badge variant="secondary" className="text-xs">
                <Globe className="h-3 w-3 mr-1" />
                Public
              </Badge>
            )}
            {(template.tags || []).slice(0, 2).map((tag) => (
              <Badge key={`${template.id}-${tag}`} variant="outline" className="text-xs">
                <TagIcon className="h-2.5 w-2.5 mr-1" />
                {tag}
              </Badge>
            ))}
            {template.usageCount > 0 && (
              <span className="text-xs text-muted-foreground">{template.usageCount} uses</span>
            )}
          </div>

          <Button size="sm" variant="outline" onClick={() => handleUseTemplate(template.id)}>
            <Copy className="h-3 w-3 mr-1" />
            Use
          </Button>
        </div>

        <div className="text-xs text-muted-foreground mt-2">{createdAtLabel}</div>
      </div>
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Templates
          </DialogTitle>
        </DialogHeader>

        <div className="relative mb-4">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted" />
          <Input
            placeholder="Search templates..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>

        <Tabs
          defaultValue={starter.length > 0 ? 'starter-templates' : 'my-templates'}
          className="flex-1 flex flex-col min-h-0"
        >
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="starter-templates">Starter ({starter.length})</TabsTrigger>
            <TabsTrigger value="my-templates">My Templates ({myTemplates.length})</TabsTrigger>
            <TabsTrigger value="community">Community ({community.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="starter-templates" className="flex-1 mt-4 min-h-0">
            <ScrollArea className="h-full">
              {filterTemplates(starter).length === 0 ? (
                <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                  <FileText className="h-12 w-12 mb-3 opacity-50" />
                  <p className="text-sm">No starter templates available.</p>
                  <p className="text-xs mt-1">Default templates will appear here.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pb-4">
                  {filterTemplates(starter).map((template) => (
                    <TemplateCard
                      key={template.id}
                      template={template}
                      showActions={false}
                      badge={
                        <Badge variant="secondary" className="text-xs whitespace-nowrap">
                          Starter
                        </Badge>
                      }
                    />
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          <TabsContent value="my-templates" className="flex-1 mt-4 min-h-0">
            <ScrollArea className="h-full">
              {filterTemplates(myTemplates).length === 0 ? (
                <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                  <FileText className="h-12 w-12 mb-3 opacity-50" />
                  <p className="text-sm">No templates yet</p>
                  <p className="text-xs mt-1">Save a note as a template to get started</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pb-4">
                  {filterTemplates(myTemplates).map((template) => (
                    <TemplateCard key={template.id} template={template} />
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          <TabsContent value="community" className="flex-1 mt-4 min-h-0">
            <ScrollArea className="h-full">
              {filterTemplates(community).length === 0 ? (
                <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                  <Globe className="h-12 w-12 mb-3 opacity-50" />
                  <p className="text-sm">No community templates yet</p>
                  <p className="text-xs mt-1">Share your templates to help others</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pb-4">
                  {filterTemplates(community).map((template) => (
                    <TemplateCard
                      key={template.id}
                      template={template}
                      showActions={false}
                      badge={
                        <Badge variant="outline" className="text-xs whitespace-nowrap">
                          Community
                        </Badge>
                      }
                    />
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
