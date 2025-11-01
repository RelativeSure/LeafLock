import { create } from 'zustand'
import type { Template } from '../types'
import { apiClient } from '../services/api/secureApi'

interface TemplatesState {
  templates: Template[]
  starterTemplates: Template[]
  communityTemplates: Template[]
  isLoading: boolean
  createTemplate: (template: Partial<Template>) => Promise<Template>
  updateTemplate: (id: string, updates: Partial<Template>) => Promise<void>
  deleteTemplate: (id: string) => Promise<void>
  applyTemplate: (templateId: string) => Promise<{ content: string; tags: string[] }>
  shareTemplate: (id: string, isPublic: boolean) => Promise<void>
  searchTemplates: (query: string) => Template[]
  loadTemplates: () => Promise<void>
}

export const useTemplatesStore = create<TemplatesState>((set, get) => ({
  templates: [],
  starterTemplates: [],
  communityTemplates: [],
  isLoading: false,

  loadTemplates: async () => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) return

    const user = JSON.parse(storedUser)

    set({ isLoading: true })
    try {
      const templatesData = await apiClient.getTemplates()
      const isStarterTemplate = (template: Template) =>
        (template.tags || []).map((tag) => tag.toLowerCase()).includes('system')

      const userTemplates = templatesData.filter((t) => t.userId === user.id)
      const starterTemplates = templatesData.filter((t) => isStarterTemplate(t))
      const communityTemplates = templatesData.filter(
        (t) => t.isPublic && !isStarterTemplate(t) && t.userId !== user.id
      )

      set({
        templates: userTemplates,
        starterTemplates,
        communityTemplates,
      })
    } catch (error) {
      console.error('Failed to load templates:', error)
    } finally {
      set({ isLoading: false })
    }
  },

  createTemplate: async (template: Partial<Template>) => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) throw new Error('No user logged in')

    try {
      const newTemplate = await apiClient.createTemplate(template)
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
          baseTemplate = await apiClient.getTemplate(id)
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

      await apiClient.updateTemplate(id, payload)
      await get().loadTemplates()
    } catch (error) {
      console.error('Failed to update template:', error)
      throw error
    }
  },

  deleteTemplate: async (id: string) => {
    try {
      await apiClient.deleteTemplate(id)
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
      const note = await apiClient.useTemplate(templateId)
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
