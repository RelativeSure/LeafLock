/**
 * Templates Store - Reusable Content Template Management
 * 
 * @description
 * Manages note templates for rapid content creation and standardization.
 * Supports user-created templates, system starter templates, and community-shared
 * templates. Provides template categorization, search, and application functionality.
 * 
 * @responsibilities
 * - Template CRUD operations (create, read, update, delete)
 * - Template categorization (user, system, community)
 * - Template search and filtering
 * - Template sharing and privacy controls
 * - Template application for note creation
 * - Starter template management for new users
 * 
 * @template-categories
 * - User Templates: Created by current user for personal use
 * - Starter Templates: System-provided templates for common use cases
 * - Community Templates: Publicly shared templates from other users
 * 
 * @sharing-functionality
 * - Templates can be marked as public for community sharing
 * - Privacy controls via isPublic flag
 * - Search includes community templates when available
 * - Attribution maintained for shared templates
 * 
 * @integration-patterns
 * - Consumed by template browser and selector components
 * - Used by notesStore for template-based note creation
 * - Provides content suggestions for new notes
 * - Integrates with content service for API operations
 * 
 * @content-management
 * - Templates contain name, description, content, and tags
 * - Content can include variables for dynamic substitution
 * - Support for rich text and markdown formatting
 * - Icon and visual customization options
 * 
 * @search-capabilities
 * - Multi-field search (name, description, content, tags)
   - Case-insensitive matching
   - Real-time search results
   - Cross-category search support
 */
import { create } from 'zustand'
import { contentService, type Template } from '@/services/api'

interface TemplatesState {
  /**
   * User-created templates for personal use
   * @type {Template[]} Templates created by current user
   * Private by default, can be shared publicly
   * Used for personal workflow optimization
   */
  templates: Template[]

  /**
   * System-provided starter templates
   * @type {Template[]} Pre-built templates for common use cases
   * Tagged with 'system' for identification
   * Available to all users for quick start
   */
  starterTemplates: Template[]

  /**
   * Publicly shared community templates
   * @type {Template[]} Templates shared by other users
   - Excludes user's own templates and system templates
   - Available for discovery and use
   - Maintains attribution to original creator
   */
  communityTemplates: Template[]

  /**
   * Loading state for template operations
   * @type {boolean} true during fetch/create/update/delete operations
   * Used by UI components to show loading indicators
   */
  isLoading: boolean

  /**
   * Create new template
   * @param template - Partial template data
   * @returns Promise resolving to created template
   * @throws {Error} On validation or creation failure
   *
   * @validation
   * - Name required and trimmed of whitespace
   * - Content required and non-empty
   * - User association from localStorage or provided userId
   *
   * @creation
   * - Creates template via contentService
   * - Refreshes template collections after creation
   * - Returns created template for immediate use
   *
   * @error-handling
   * - Validates input before API call
   * - Provides user-friendly error messages
   * - Graceful handling of authentication issues
   */
  createTemplate: (template: Partial<Template>) => Promise<Template>

  /**
   * Update existing template
   * @param id - Template ID to update
   * @param updates - Partial template data to modify
   * @throws {Error} On validation or update failure
   *
   * @update-strategy
   * - Merges updates with existing template data
   * - Fetches current template if not in local state
   * - Validates merged data before submission
   *
   * @validation
   * - Name required for updates
   * - Content availability verified
   * - Preserves existing properties if not provided
   *
   * @scope
   * - Updates across all template categories if present
   * - Refreshes template collections after update
   * - Maintains template ownership and sharing status
   */
  updateTemplate: (id: string, updates: Partial<Template>) => Promise<void>

  /**
   * Delete template and remove from collections
   * @param id - Template ID to delete
   * @throws {Error} On deletion failure
   *
   * @deletion
   * - Deletes template via contentService
   * - Removes from all local collections
   * - Maintains data integrity across categories
   *
   * @cleanup
   * - Removes from user, starter, and community collections
   * - No effect on notes created from template
   * - Immediate UI update for consistency
   */
  deleteTemplate: (id: string) => Promise<void>

  /**
   * Apply template to create new note content
   * @param templateId - Template ID to apply
   * @returns Promise resolving to template content and tags
   * @throws {Error} On template application failure
   *
   * @application
   * - Creates new note using template content
   * - Applies template tags to new note
   * - Supports variable substitution in template content
   *
   * @content-generation
   * - Returns content and tags for note creation
   * - Used by notesStore.createNote for template-based notes
   * - Supports rich text and markdown formatting
   */
  applyTemplate: (templateId: string) => Promise<{ content: string; tags: string[] }>

  /**
   * Share/unshare template with community
   * @param id - Template ID to share
   * @param isPublic - New sharing status
   * @throws {Error} On sharing status update failure
   *
   * @sharing
   * - Updates template visibility via updateTemplate
   * - Makes template available in community search
   * - Maintains attribution to original creator
   *
   * @privacy
   * - Public templates appear in community search
   * - Private templates only visible to creator
   * - Reversible operation - can be made private again
   */
  shareTemplate: (id: string, isPublic: boolean) => Promise<void>

  /**
   * Search templates across all categories
   * @param query - Search query string
   * @returns Array of matching templates
   *
   * @search-scope
   * - Searches name, description, content, and tags
   * - Case-insensitive matching
   * - Searches user, starter, and community templates
   *
   * @matching
   * - Partial string matching supported
   * - Multi-field search for comprehensive results
   * - Real-time search suitable for typeahead interfaces
   */
  searchTemplates: (query: string) => Template[]

  /**
   * Load and categorize all templates
   * @throws {Error} On template loading failure
   *
   * @loading
   * - Fetches all templates via contentService
   * - Categorizes into user, starter, and community collections
   * - Requires authenticated user for user templates
   *
   * @categorization
   * - User templates: created by current user
   * - Starter templates: tagged with 'system'
   * - Community templates: public templates from other users
   *
   * @logging
   * - Comprehensive logging for debugging
   * - Category counts for monitoring
   * - Error logging for troubleshooting
   */
  loadTemplates: () => Promise<void>
}

export const useTemplatesStore = create<TemplatesState>((set, get) => ({
  templates: [],
  starterTemplates: [],
  communityTemplates: [],
  isLoading: false,

  loadTemplates: async () => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) {
      console.log('📋 Templates: No user found in localStorage')
      return
    }

    const user = JSON.parse(storedUser)

    set({ isLoading: true })
    try {
      const templatesData = await contentService.getTemplates()
      console.log('📋 Templates: Loaded', templatesData.length, 'templates from API')

      const isStarterTemplate = (template: Template) =>
        (template.tags || []).map((tag) => tag.toLowerCase()).includes('system')

      const userTemplates = templatesData.filter((t) => t.userId === user.id)
      const starterTemplates = templatesData.filter((t) => isStarterTemplate(t))
      const communityTemplates = templatesData.filter(
        (t) => t.isPublic && !isStarterTemplate(t) && t.userId !== user.id
      )

      console.log('📋 Templates: Categorized -', {
        user: userTemplates.length,
        starter: starterTemplates.length,
        community: communityTemplates.length,
      })

      set({
        templates: userTemplates,
        starterTemplates,
        communityTemplates,
      })
    } catch (error) {
      console.error('❌ Templates: Failed to load templates:', error)
    } finally {
      set({ isLoading: false })
    }
  },

  createTemplate: async (template: Partial<Template>) => {
    const storedUser = localStorage.getItem('user')
    let userId: string | null = null
    if (storedUser) {
      try {
        const parsed = JSON.parse(storedUser)
        if (parsed?.id) {
          userId = parsed.id
        }
      } catch (error) {
        console.warn('Failed to parse stored user while creating template:', error)
      }
    }

    const trimmedName = template.name?.trim()
    if (!trimmedName) {
      throw new Error('Template name is required')
    }
    const content = template.content
    if (!content || content.trim().length === 0) {
      throw new Error('Template content is required')
    }

    try {
      const payload: Partial<Template> = {
        ...template,
        name: trimmedName,
        content,
        userId: userId ?? template.userId ?? undefined,
      }

      const newTemplate = await contentService.createTemplate(payload)
      await get().loadTemplates()
      return newTemplate
    } catch (error) {
      console.error('Failed to create template:', error)
      throw error
    }
  },

  updateTemplate: async (id: string, updates: Partial<Template>) => {
    try {
      const state = get()
      const existingTemplate =
        state.templates.find((template) => template.id === id) ||
        state.starterTemplates.find((template) => template.id === id) ||
        state.communityTemplates.find((template) => template.id === id)

      let baseTemplate = existingTemplate

      if (!baseTemplate || !baseTemplate.content) {
        try {
          baseTemplate = await contentService.getTemplate(id)
        } catch (error) {
          console.error('Failed to fetch template before update:', error)
        }
      }

      if (!baseTemplate) {
        throw new Error('Template not found')
      }

      const mergedName = updates.name ?? baseTemplate.name
      const mergedContent = updates.content ?? baseTemplate.content

      if (!mergedName) {
        throw new Error('Template name is required for update')
      }

      if (mergedContent === undefined) {
        throw new Error('Template content unavailable for update')
      }

      const payload: Partial<Template> = {
        ...baseTemplate,
        ...updates,
        name: mergedName,
        content: mergedContent,
        tags: updates.tags ?? baseTemplate.tags ?? [],
        description: updates.description ?? baseTemplate.description ?? '',
        icon: updates.icon ?? baseTemplate.icon ?? undefined,
        isPublic: updates.isPublic ?? baseTemplate.isPublic ?? false,
      }

      await contentService.updateTemplate(id, payload)
      await get().loadTemplates()
    } catch (error) {
      console.error('Failed to update template:', error)
      throw error
    }
  },

  deleteTemplate: async (id: string) => {
    try {
      await contentService.deleteTemplate(id)
      set((state) => ({
        templates: state.templates.filter((template) => template.id !== id),
        starterTemplates: state.starterTemplates.filter((template) => template.id !== id),
        communityTemplates: state.communityTemplates.filter((template) => template.id !== id),
      }))
    } catch (error) {
      console.error('Failed to delete template:', error)
      throw error
    }
  },

  applyTemplate: async (templateId: string) => {
    try {
      const note = await contentService.useTemplate(templateId)
      return {
        content: note.content,
        tags: note.tags,
      }
    } catch (error) {
      console.error('Failed to apply template:', error)
      throw error
    }
  },

  shareTemplate: async (id: string, isPublic: boolean) => {
    try {
      await get().updateTemplate(id, { isPublic })
    } catch (error) {
      console.error('Failed to share template:', error)
      throw error
    }
  },

  searchTemplates: (query: string) => {
    const { templates, starterTemplates, communityTemplates } = get()
    const lowerQuery = query.toLowerCase()
    const allTemplates = [...templates, ...starterTemplates, ...communityTemplates]
    return allTemplates.filter(
      (template) =>
        template.name.toLowerCase().includes(lowerQuery) ||
        (template.description || '').toLowerCase().includes(lowerQuery) ||
        (template.content || '').toLowerCase().includes(lowerQuery) ||
        (template.tags || []).some((tag) => tag.toLowerCase().includes(lowerQuery))
    )
  },
}))
