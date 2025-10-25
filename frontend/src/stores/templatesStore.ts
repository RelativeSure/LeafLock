import { create } from 'zustand'
import type { Template } from '../types'
import { apiClient } from '../services/api/secureApi'

interface TemplatesState {
  templates: Template[]
  publicTemplates: Template[]
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
  publicTemplates: [],
  isLoading: false,

  loadTemplates: async () => {
    const { useAuthStore } = await import('./authStore')
    const { user } = useAuthStore.getState()
    if (!user) return

    set({ isLoading: true })
    try {
      const templatesData = await apiClient.getTemplates()
      // Filter templates by user and public status
      const userTemplates = templatesData.filter((t) => t.userId === user.id)
      const publicTemplatesData = templatesData.filter((t) => t.isPublic)

      set({ templates: userTemplates, publicTemplates: publicTemplatesData })
    } catch (error) {
      console.error('Failed to load templates:', error)
    } finally {
      set({ isLoading: false })
    }
  },

  createTemplate: async (template: Partial<Template>) => {
    const { user } = useAuthStore.getState()
    if (!user) throw new Error('No user logged in')

    try {
      const newTemplate = await apiClient.createTemplate({
        ...template,
        userId: user.id,
      })

      set((state) => {
        const updatedTemplates = [newTemplate, ...state.templates]
        const updatedPublicTemplates = newTemplate.isPublic
          ? [newTemplate, ...state.publicTemplates]
          : state.publicTemplates

        return {
          templates: updatedTemplates,
          publicTemplates: updatedPublicTemplates,
        }
      })

      return newTemplate
    } catch (error) {
      console.error('Failed to create template:', error)
      throw error
    }
  },

  updateTemplate: async (id: string, updates: Partial<Template>) => {
    try {
      const updatedTemplate = await apiClient.updateTemplate(id, updates)

      set((state) => {
        const updatedTemplates = state.templates.map((template) =>
          template.id === id ? updatedTemplate : template
        )

        let updatedPublicTemplates = state.publicTemplates
        if (updatedTemplate.isPublic) {
          updatedPublicTemplates = state.publicTemplates.map((template) =>
            template.id === id ? updatedTemplate : template
          )
        } else {
          updatedPublicTemplates = state.publicTemplates.filter((template) => template.id !== id)
        }

        return {
          templates: updatedTemplates,
          publicTemplates: updatedPublicTemplates,
        }
      })
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
        publicTemplates: state.publicTemplates.filter((template) => template.id !== id),
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
    const { templates, publicTemplates } = get()
    const lowerQuery = query.toLowerCase()
    const allTemplates = [...templates, ...publicTemplates]
    return allTemplates.filter(
      (template) =>
        template.name.toLowerCase().includes(lowerQuery) ||
        template.content.toLowerCase().includes(lowerQuery)
    )
  },
}))
