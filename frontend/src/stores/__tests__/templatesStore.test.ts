import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useTemplatesStore } from '../templatesStore'
import { contentService } from '@/services/api'
import type { Template } from '../../types'

// Mock dependencies
vi.mock('@/services/api', () => ({
  contentService: {
    getTemplates: vi.fn(),
    getTemplate: vi.fn(),
    createTemplate: vi.fn(),
    updateTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
    useTemplate: vi.fn(),
  },
}))

describe('templatesStore', () => {
  const mockUser = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
  }

  const mockUserTemplate: Template = {
    id: 'template-1',
    name: 'My Template',
    description: 'User template',
    content: 'Template content',
    userId: '123',
    tags: ['personal'],
    isPublic: false,
    icon: '📝',
    createdAt: new Date().toISOString(),
    usageCount: 0,
    updatedAt: new Date().toISOString(),
  }

  const mockStarterTemplate: Template = {
    id: 'template-starter',
    name: 'Meeting Notes',
    description: 'Starter template',
    content: 'Meeting content',
    userId: 'system',
    tags: ['system', 'meetings'],
    isPublic: true,
    icon: '🗓️',
    createdAt: new Date().toISOString(),
    usageCount: 0,
    updatedAt: new Date().toISOString(),
  }

  const mockCommunityTemplate: Template = {
    id: 'template-community',
    name: 'Community Template',
    description: 'Public community template',
    content: 'Community content',
    userId: '456',
    tags: ['community'],
    isPublic: true,
    icon: '🌐',
    createdAt: new Date().toISOString(),
    usageCount: 0,
    updatedAt: new Date().toISOString(),
  }

  beforeEach(() => {
    // Clear store state
    useTemplatesStore.setState({
      templates: [],
      starterTemplates: [],
      communityTemplates: [],
      isLoading: false,
    })

    // Clear localStorage
    localStorage.clear()

    // Reset all mocks
    vi.clearAllMocks()

    // Mock console methods to reduce noise
    vi.spyOn(console, 'log').mockImplementation(vi.fn())
    vi.spyOn(console, 'error').mockImplementation(vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Initial state', () => {
    it('should have correct initial state', () => {
      const state = useTemplatesStore.getState()
      expect(state.templates).toEqual([])
      expect(state.starterTemplates).toEqual([])
      expect(state.communityTemplates).toEqual([])
      expect(state.isLoading).toBe(false)
    })

    it('should have all required methods', () => {
      const state = useTemplatesStore.getState()
      expect(typeof state.loadTemplates).toBe('function')
      expect(typeof state.createTemplate).toBe('function')
      expect(typeof state.updateTemplate).toBe('function')
      expect(typeof state.deleteTemplate).toBe('function')
      expect(typeof state.applyTemplate).toBe('function')
      expect(typeof state.shareTemplate).toBe('function')
      expect(typeof state.searchTemplates).toBe('function')
    })
  })

  describe('loadTemplates', () => {
    it('should load and categorize templates correctly', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      vi.mocked(contentService.getTemplates).mockResolvedValue([
        mockUserTemplate,
        mockStarterTemplate,
        mockCommunityTemplate,
      ])

      await useTemplatesStore.getState().loadTemplates()

      const state = useTemplatesStore.getState()
      expect(state.templates).toEqual([mockUserTemplate])
      expect(state.starterTemplates).toEqual([mockStarterTemplate])
      expect(state.communityTemplates).toEqual([mockCommunityTemplate])
      expect(state.isLoading).toBe(false)
    })

    it('should identify starter templates by system tag', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      const systemTemplate = {
        ...mockUserTemplate,
        id: 'system-1',
        tags: ['System', 'notes'],
        userId: 'other-user',
      }

      vi.mocked(contentService.getTemplates).mockResolvedValue([systemTemplate])

      await useTemplatesStore.getState().loadTemplates()

      const state = useTemplatesStore.getState()
      expect(state.starterTemplates).toContainEqual(systemTemplate)
      expect(state.templates).toEqual([])
      expect(state.communityTemplates).toEqual([])
    })

    it('should not load templates if no user is logged in', async () => {
      await useTemplatesStore.getState().loadTemplates()

      expect(contentService.getTemplates).not.toHaveBeenCalled()
    })

    it('should set isLoading state correctly', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      let loadingDuringCall = false

      vi.mocked(contentService.getTemplates).mockImplementation(async () => {
        loadingDuringCall = useTemplatesStore.getState().isLoading
        return [mockUserTemplate]
      })

      await useTemplatesStore.getState().loadTemplates()

      expect(loadingDuringCall).toBe(true)
      expect(useTemplatesStore.getState().isLoading).toBe(false)
    })

    it('should handle API errors gracefully', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      vi.mocked(contentService.getTemplates).mockRejectedValue(new Error('API error'))

      await useTemplatesStore.getState().loadTemplates()

      expect(useTemplatesStore.getState().isLoading).toBe(false)
      expect(console.error).toHaveBeenCalledWith(
        '❌ Templates: Failed to load templates:',
        expect.any(Error)
      )
    })

    it('should separate user templates from community templates', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      const anotherUserTemplate = {
        ...mockCommunityTemplate,
        userId: '789',
      }

      vi.mocked(contentService.getTemplates).mockResolvedValue([
        mockUserTemplate,
        anotherUserTemplate,
      ])

      await useTemplatesStore.getState().loadTemplates()

      const state = useTemplatesStore.getState()
      expect(state.templates).toEqual([mockUserTemplate])
      expect(state.communityTemplates).toEqual([anotherUserTemplate])
    })
  })

  describe('createTemplate', () => {
    beforeEach(() => {
      localStorage.setItem('user', JSON.stringify(mockUser))
    })

    it('should create a template successfully', async () => {
      const templateInput = {
        name: 'New Template',
        description: 'Test description',
        content: 'Test content',
        tags: ['test'],
      }

      vi.mocked(contentService.createTemplate).mockResolvedValue(mockUserTemplate)
      vi.mocked(contentService.getTemplates).mockResolvedValue([mockUserTemplate])

      const result = await useTemplatesStore.getState().createTemplate(templateInput)

      expect(contentService.createTemplate).toHaveBeenCalledWith({
        ...templateInput,
        userId: '123',
      })
      expect(result).toEqual(mockUserTemplate)
      expect(contentService.getTemplates).toHaveBeenCalled()
    })

    it('should reload templates after creation', async () => {
      vi.mocked(contentService.createTemplate).mockResolvedValue(mockUserTemplate)
      vi.mocked(contentService.getTemplates).mockResolvedValue([mockUserTemplate])

      await useTemplatesStore.getState().createTemplate({ name: 'Test', content: 'Body' })

      expect(contentService.getTemplates).toHaveBeenCalled()
      expect(useTemplatesStore.getState().templates).toEqual([mockUserTemplate])
    })

    it('should create template without userId when no user is logged in', async () => {
      localStorage.removeItem('user')

      const templateWithoutUser = { ...mockUserTemplate, userId: undefined }
      vi.mocked(contentService.createTemplate).mockResolvedValue(templateWithoutUser)
      vi.mocked(contentService.getTemplates).mockResolvedValue([templateWithoutUser])

      const result = await useTemplatesStore
        .getState()
        .createTemplate({ name: 'Test', content: 'Test content' })

      expect(contentService.createTemplate).toHaveBeenCalledWith({
        name: 'Test',
        content: 'Test content',
        userId: undefined,
      })
      expect(result).toEqual(templateWithoutUser)
    })

    it('should handle API errors', async () => {
      vi.mocked(contentService.createTemplate).mockRejectedValue(new Error('Create failed'))

      await expect(
        useTemplatesStore.getState().createTemplate({ name: 'Test', content: 'Body' })
      ).rejects.toThrow('Create failed')

      expect(console.error).toHaveBeenCalledWith('Failed to create template:', expect.any(Error))
    })
  })

  describe('updateTemplate', () => {
    beforeEach(() => {
      useTemplatesStore.setState({ templates: [mockUserTemplate] })
    })

    it('should update a template successfully', async () => {
      localStorage.setItem('user', JSON.stringify({ id: '123', email: 'test@example.com' }))

      const updates = {
        name: 'Updated Name',
        description: 'Updated description',
      }

      const updatedTemplate = { ...mockUserTemplate, ...updates }
      vi.mocked(contentService.updateTemplate).mockResolvedValue(updatedTemplate)
      vi.mocked(contentService.getTemplates).mockResolvedValue([updatedTemplate])

      await useTemplatesStore.getState().updateTemplate('template-1', updates)

      expect(contentService.updateTemplate).toHaveBeenCalledWith(
        'template-1',
        expect.objectContaining({
          name: 'Updated Name',
          description: 'Updated description',
        })
      )
      expect(contentService.getTemplates).toHaveBeenCalled()
    })

    it('should fetch template if content is missing', async () => {
      const templateWithoutContent = { ...mockUserTemplate, content: undefined }
      useTemplatesStore.setState({ templates: [templateWithoutContent] })

      const updatedTemplate = { ...mockUserTemplate, name: 'New Name' }
      vi.mocked(contentService.getTemplate).mockResolvedValue(mockUserTemplate)
      vi.mocked(contentService.updateTemplate).mockResolvedValue(updatedTemplate)
      vi.mocked(contentService.getTemplates).mockResolvedValue([updatedTemplate])

      await useTemplatesStore.getState().updateTemplate('template-1', { name: 'New Name' })

      expect(contentService.getTemplate).toHaveBeenCalledWith('template-1')
    })

    it('should throw error if template is not found', async () => {
      useTemplatesStore.setState({ templates: [] })

      vi.mocked(contentService.getTemplate).mockRejectedValue(new Error('Not found'))

      await expect(
        useTemplatesStore.getState().updateTemplate('non-existent', { name: 'Test' })
      ).rejects.toThrow('Template not found')
    })

    it('should throw error if name is missing', async () => {
      const templateWithoutName = { ...mockUserTemplate, name: '' }
      useTemplatesStore.setState({ templates: [templateWithoutName] })

      await expect(
        useTemplatesStore.getState().updateTemplate('template-1', { description: 'Test' })
      ).rejects.toThrow('Template name is required for update')
    })

    it('should merge updates with existing template data', async () => {
      const updatedTemplate = { ...mockUserTemplate, description: 'New desc' }
      vi.mocked(contentService.updateTemplate).mockResolvedValue(updatedTemplate)
      vi.mocked(contentService.getTemplates).mockResolvedValue([updatedTemplate])

      await useTemplatesStore.getState().updateTemplate('template-1', { description: 'New desc' })

      expect(contentService.updateTemplate).toHaveBeenCalledWith(
        'template-1',
        expect.objectContaining({
          name: mockUserTemplate.name,
          content: mockUserTemplate.content,
          description: 'New desc',
        })
      )
    })

    it('should handle API errors', async () => {
      vi.mocked(contentService.updateTemplate).mockRejectedValue(new Error('Update failed'))

      await expect(
        useTemplatesStore.getState().updateTemplate('template-1', { name: 'Test' })
      ).rejects.toThrow('Update failed')
    })
  })

  describe('deleteTemplate', () => {
    beforeEach(() => {
      useTemplatesStore.setState({
        templates: [mockUserTemplate],
        starterTemplates: [mockStarterTemplate],
        communityTemplates: [mockCommunityTemplate],
      })
    })

    it('should delete a template successfully', async () => {
      vi.mocked(contentService.deleteTemplate).mockResolvedValue(undefined)

      await useTemplatesStore.getState().deleteTemplate('template-1')

      expect(contentService.deleteTemplate).toHaveBeenCalledWith('template-1')
      expect(useTemplatesStore.getState().templates).toEqual([])
    })

    it('should remove template from correct category', async () => {
      vi.mocked(contentService.deleteTemplate).mockResolvedValue(undefined)

      await useTemplatesStore.getState().deleteTemplate('template-starter')

      expect(useTemplatesStore.getState().starterTemplates).toEqual([])
      expect(useTemplatesStore.getState().templates).toEqual([mockUserTemplate])
      expect(useTemplatesStore.getState().communityTemplates).toEqual([mockCommunityTemplate])
    })

    it('should handle API errors', async () => {
      vi.mocked(contentService.deleteTemplate).mockRejectedValue(new Error('Delete failed'))

      await expect(useTemplatesStore.getState().deleteTemplate('template-1')).rejects.toThrow(
        'Delete failed'
      )
    })
  })

  describe('applyTemplate', () => {
    it('should apply a template successfully', async () => {
      const mockNote = {
        content: 'Applied content',
        tags: ['applied', 'template'],
      }

      vi.mocked(contentService.useTemplate).mockResolvedValue(mockNote as any)

      const result = await useTemplatesStore.getState().applyTemplate('template-1')

      expect(contentService.useTemplate).toHaveBeenCalledWith('template-1')
      expect(result).toEqual(mockNote)
    })

    it('should handle API errors', async () => {
      vi.mocked(contentService.useTemplate).mockRejectedValue(new Error('Apply failed'))

      await expect(useTemplatesStore.getState().applyTemplate('template-1')).rejects.toThrow(
        'Apply failed'
      )
    })
  })

  describe('shareTemplate', () => {
    beforeEach(() => {
      useTemplatesStore.setState({ templates: [mockUserTemplate] })
    })

    it('should share a template publicly', async () => {
      const updatedTemplate = { ...mockUserTemplate, isPublic: true }
      vi.mocked(contentService.updateTemplate).mockResolvedValue(updatedTemplate)
      vi.mocked(contentService.getTemplates).mockResolvedValue([updatedTemplate])

      await useTemplatesStore.getState().shareTemplate('template-1', true)

      expect(contentService.updateTemplate).toHaveBeenCalledWith(
        'template-1',
        expect.objectContaining({ isPublic: true })
      )
    })

    it('should make a template private', async () => {
      const updatedTemplate = { ...mockUserTemplate, isPublic: false }
      vi.mocked(contentService.updateTemplate).mockResolvedValue(updatedTemplate)
      vi.mocked(contentService.getTemplates).mockResolvedValue([updatedTemplate])

      await useTemplatesStore.getState().shareTemplate('template-1', false)

      expect(contentService.updateTemplate).toHaveBeenCalledWith(
        'template-1',
        expect.objectContaining({ isPublic: false })
      )
    })

    it('should handle API errors', async () => {
      vi.mocked(contentService.updateTemplate).mockRejectedValue(new Error('Share failed'))

      await expect(useTemplatesStore.getState().shareTemplate('template-1', true)).rejects.toThrow(
        'Share failed'
      )
    })
  })

  describe('searchTemplates', () => {
    beforeEach(() => {
      useTemplatesStore.setState({
        templates: [mockUserTemplate],
        starterTemplates: [mockStarterTemplate],
        communityTemplates: [mockCommunityTemplate],
      })
    })

    it('should search templates by name', () => {
      const results = useTemplatesStore.getState().searchTemplates('meeting')

      expect(results).toHaveLength(1)
      expect(results[0].name).toBe('Meeting Notes')
    })

    it('should search templates by description', () => {
      const results = useTemplatesStore.getState().searchTemplates('community')

      expect(results).toHaveLength(1)
      expect(results[0].description).toBe('Public community template')
    })

    it('should search templates by content', () => {
      const results = useTemplatesStore.getState().searchTemplates('Template content')

      expect(results).toHaveLength(1)
      expect(results[0].content).toBe('Template content')
    })

    it('should search templates by tags', () => {
      const results = useTemplatesStore.getState().searchTemplates('personal')

      expect(results).toHaveLength(1)
      expect(results[0].tags).toContain('personal')
    })

    it('should be case insensitive', () => {
      const results = useTemplatesStore.getState().searchTemplates('MEETING')

      expect(results).toHaveLength(1)
      expect(results[0].name).toBe('Meeting Notes')
    })

    it('should return all templates for empty query', () => {
      const results = useTemplatesStore.getState().searchTemplates('')

      expect(results).toHaveLength(3)
    })

    it('should return empty array for no matches', () => {
      const results = useTemplatesStore.getState().searchTemplates('nonexistent')

      expect(results).toEqual([])
    })

    it('should search across all template categories', () => {
      const results = useTemplatesStore.getState().searchTemplates('template')

      expect(results.length).toBeGreaterThan(0)
    })
  })
})
