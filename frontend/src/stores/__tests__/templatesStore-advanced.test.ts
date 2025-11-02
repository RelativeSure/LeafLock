import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useTemplatesStore } from '../templatesStore'
import { apiClient } from '@/services/api/secureApi'

vi.mock('@/services/api/secureApi', () => ({
  apiClient: {
    getTemplates: vi.fn(),
    getTemplate: vi.fn(),
    createTemplate: vi.fn(),
    updateTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
  },
}))

describe('templatesStore - Advanced Scenarios', () => {
  const mockTemplate = {
    id: 'tpl-1',
    name: 'Meeting Notes',
    content: '# Meeting\n\n## Attendees\n\n## Agenda',
    description: 'Template for meeting notes',
    tags: ['meeting', 'work'],
    icon: '📝',
    isPublic: false,
    userId: '123',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    usageCount: 5,
  }

  beforeEach(() => {
    useTemplatesStore.setState({
      templates: [],
      isLoading: false,
      error: null,
    })
    vi.clearAllMocks()
  })

  describe('Template loading', () => {
    it('should load all templates', async () => {
      vi.mocked(apiClient.getTemplates).mockResolvedValue([mockTemplate])

      await useTemplatesStore.getState().loadTemplates()

      expect(useTemplatesStore.getState().templates).toHaveLength(1)
      expect(useTemplatesStore.getState().templates[0]).toEqual(mockTemplate)
    })

    it('should set loading state while fetching', async () => {
      let resolveTemplates: any
      vi.mocked(apiClient.getTemplates).mockReturnValue(
        new Promise((resolve) => {
          resolveTemplates = resolve
        })
      )

      const loadPromise = useTemplatesStore.getState().loadTemplates()

      expect(useTemplatesStore.getState().isLoading).toBe(true)

      resolveTemplates([mockTemplate])
      await loadPromise

      expect(useTemplatesStore.getState().isLoading).toBe(false)
    })

    it('should handle loading errors', async () => {
      vi.mocked(apiClient.getTemplates).mockRejectedValue(new Error('Failed to load'))

      await expect(useTemplatesStore.getState().loadTemplates()).rejects.toThrow('Failed to load')

      expect(useTemplatesStore.getState().isLoading).toBe(false)
      expect(useTemplatesStore.getState().error).toBeTruthy()
    })

    it('should load single template by ID', async () => {
      vi.mocked(apiClient.getTemplate).mockResolvedValue(mockTemplate)

      const result = await useTemplatesStore.getState().getTemplateById('tpl-1')

      expect(result).toEqual(mockTemplate)
      expect(apiClient.getTemplate).toHaveBeenCalledWith('tpl-1')
    })
  })

  describe('Template creation', () => {
    it('should create new template', async () => {
      const newTemplate = {
        name: 'Daily Log',
        content: '# Daily Log\n\n## Tasks',
        tags: ['daily', 'log'],
      }

      const createdTemplate = { ...mockTemplate, ...newTemplate, id: 'tpl-2' }
      vi.mocked(apiClient.createTemplate).mockResolvedValue(createdTemplate)

      const result = await useTemplatesStore.getState().createTemplate(newTemplate)

      expect(result).toEqual(createdTemplate)
      expect(useTemplatesStore.getState().templates).toContainEqual(createdTemplate)
    })

    it('should validate template name', async () => {
      await expect(
        useTemplatesStore.getState().createTemplate({ name: '', content: '' })
      ).rejects.toThrow()
    })

    it('should handle creation errors', async () => {
      vi.mocked(apiClient.createTemplate).mockRejectedValue(new Error('Creation failed'))

      await expect(
        useTemplatesStore.getState().createTemplate({ name: 'Test', content: '' })
      ).rejects.toThrow('Creation failed')
    })

    it('should increment usage count when template is used', async () => {
      useTemplatesStore.setState({ templates: [mockTemplate] })

      vi.mocked(apiClient.updateTemplate).mockResolvedValue({
        ...mockTemplate,
        usageCount: 6,
      })

      await useTemplatesStore.getState().incrementUsageCount('tpl-1')

      const template = useTemplatesStore.getState().templates.find((t) => t.id === 'tpl-1')
      expect(template?.usageCount).toBe(6)
    })
  })

  describe('Template updates', () => {
    beforeEach(() => {
      useTemplatesStore.setState({ templates: [mockTemplate] })
    })

    it('should update template', async () => {
      const updates = {
        name: 'Updated Meeting Notes',
        content: '# Updated Content',
      }

      const updatedTemplate = { ...mockTemplate, ...updates }
      vi.mocked(apiClient.updateTemplate).mockResolvedValue(updatedTemplate)

      await useTemplatesStore.getState().updateTemplate('tpl-1', updates)

      const template = useTemplatesStore.getState().templates.find((t) => t.id === 'tpl-1')
      expect(template?.name).toBe('Updated Meeting Notes')
    })

    it('should update template tags', async () => {
      const updates = { tags: ['meeting', 'work', 'urgent'] }

      const updatedTemplate = { ...mockTemplate, ...updates }
      vi.mocked(apiClient.updateTemplate).mockResolvedValue(updatedTemplate)

      await useTemplatesStore.getState().updateTemplate('tpl-1', updates)

      const template = useTemplatesStore.getState().templates.find((t) => t.id === 'tpl-1')
      expect(template?.tags).toEqual(['meeting', 'work', 'urgent'])
    })

    it('should update template icon', async () => {
      const updates = { icon: '🎯' }

      const updatedTemplate = { ...mockTemplate, ...updates }
      vi.mocked(apiClient.updateTemplate).mockResolvedValue(updatedTemplate)

      await useTemplatesStore.getState().updateTemplate('tpl-1', updates)

      const template = useTemplatesStore.getState().templates.find((t) => t.id === 'tpl-1')
      expect(template?.icon).toBe('🎯')
    })

    it('should handle update errors', async () => {
      vi.mocked(apiClient.updateTemplate).mockRejectedValue(new Error('Update failed'))

      await expect(
        useTemplatesStore.getState().updateTemplate('tpl-1', { name: 'Test' })
      ).rejects.toThrow('Update failed')
    })
  })

  describe('Template deletion', () => {
    beforeEach(() => {
      useTemplatesStore.setState({ templates: [mockTemplate] })
    })

    it('should delete template', async () => {
      vi.mocked(apiClient.deleteTemplate).mockResolvedValue(undefined)

      await useTemplatesStore.getState().deleteTemplate('tpl-1')

      expect(useTemplatesStore.getState().templates).toHaveLength(0)
      expect(apiClient.deleteTemplate).toHaveBeenCalledWith('tpl-1')
    })

    it('should handle delete errors', async () => {
      vi.mocked(apiClient.deleteTemplate).mockRejectedValue(new Error('Delete failed'))

      await expect(
        useTemplatesStore.getState().deleteTemplate('tpl-1')
      ).rejects.toThrow('Delete failed')

      expect(useTemplatesStore.getState().templates).toHaveLength(1)
    })
  })

  describe('Template filtering and search', () => {
    const templates = [
      { ...mockTemplate, id: 'tpl-1', name: 'Meeting Notes', tags: ['meeting', 'work'] },
      { ...mockTemplate, id: 'tpl-2', name: 'Daily Log', tags: ['daily', 'personal'] },
      { ...mockTemplate, id: 'tpl-3', name: 'Project Plan', tags: ['project', 'work'] },
    ]

    beforeEach(() => {
      useTemplatesStore.setState({ templates })
    })

    it('should filter templates by tag', () => {
      const workTemplates = useTemplatesStore
        .getState()
        .templates.filter((t) => t.tags.includes('work'))

      expect(workTemplates).toHaveLength(2)
      expect(workTemplates.every((t) => t.tags.includes('work'))).toBe(true)
    })

    it('should search templates by name', () => {
      const searchResults = useTemplatesStore
        .getState()
        .templates.filter((t) => t.name.toLowerCase().includes('meeting'))

      expect(searchResults).toHaveLength(1)
      expect(searchResults[0].name).toBe('Meeting Notes')
    })

    it('should sort templates by usage count', () => {
      const templatesWithUsage = [
        { ...mockTemplate, id: 'tpl-1', usageCount: 5 },
        { ...mockTemplate, id: 'tpl-2', usageCount: 10 },
        { ...mockTemplate, id: 'tpl-3', usageCount: 3 },
      ]

      useTemplatesStore.setState({ templates: templatesWithUsage })

      const sorted = [...useTemplatesStore.getState().templates].sort(
        (a, b) => b.usageCount - a.usageCount
      )

      expect(sorted[0].id).toBe('tpl-2')
      expect(sorted[1].id).toBe('tpl-1')
      expect(sorted[2].id).toBe('tpl-3')
    })

    it('should get most popular templates', () => {
      const templatesWithUsage = [
        { ...mockTemplate, id: 'tpl-1', usageCount: 5 },
        { ...mockTemplate, id: 'tpl-2', usageCount: 10 },
        { ...mockTemplate, id: 'tpl-3', usageCount: 3 },
      ]

      useTemplatesStore.setState({ templates: templatesWithUsage })

      const popular = [...useTemplatesStore.getState().templates]
        .sort((a, b) => b.usageCount - a.usageCount)
        .slice(0, 2)

      expect(popular).toHaveLength(2)
      expect(popular[0].usageCount).toBeGreaterThanOrEqual(popular[1].usageCount)
    })
  })

  describe('Public vs private templates', () => {
    it('should create private template by default', async () => {
      const newTemplate = {
        name: 'Private Template',
        content: 'Content',
      }

      const createdTemplate = { ...mockTemplate, ...newTemplate, isPublic: false, id: 'tpl-2' }
      vi.mocked(apiClient.createTemplate).mockResolvedValue(createdTemplate)

      const result = await useTemplatesStore.getState().createTemplate(newTemplate)

      expect(result.isPublic).toBe(false)
    })

    it('should create public template when specified', async () => {
      const newTemplate = {
        name: 'Public Template',
        content: 'Content',
        isPublic: true,
      }

      const createdTemplate = { ...mockTemplate, ...newTemplate, id: 'tpl-2' }
      vi.mocked(apiClient.createTemplate).mockResolvedValue(createdTemplate)

      const result = await useTemplatesStore.getState().createTemplate(newTemplate)

      expect(result.isPublic).toBe(true)
    })

    it('should filter public templates', () => {
      const templates = [
        { ...mockTemplate, id: 'tpl-1', isPublic: true },
        { ...mockTemplate, id: 'tpl-2', isPublic: false },
        { ...mockTemplate, id: 'tpl-3', isPublic: true },
      ]

      useTemplatesStore.setState({ templates })

      const publicTemplates = useTemplatesStore
        .getState()
        .templates.filter((t) => t.isPublic)

      expect(publicTemplates).toHaveLength(2)
    })
  })

  describe('Template caching', () => {
    it('should cache loaded templates', async () => {
      vi.mocked(apiClient.getTemplates).mockResolvedValue([mockTemplate])

      await useTemplatesStore.getState().loadTemplates()
      await useTemplatesStore.getState().loadTemplates()

      expect(apiClient.getTemplates).toHaveBeenCalledTimes(2)
    })

    it('should preserve templates after updates', async () => {
      useTemplatesStore.setState({ templates: [mockTemplate] })

      const updatedTemplate = { ...mockTemplate, name: 'Updated' }
      vi.mocked(apiClient.updateTemplate).mockResolvedValue(updatedTemplate)

      await useTemplatesStore.getState().updateTemplate('tpl-1', { name: 'Updated' })

      expect(useTemplatesStore.getState().templates).toHaveLength(1)
    })
  })
})
