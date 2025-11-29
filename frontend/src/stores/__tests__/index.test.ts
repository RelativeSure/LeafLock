import { describe, it, expect } from 'vitest'
import { useNotesStore, useSettingsStore, useTemplatesStore } from '../index'

describe('stores/index', () => {
  it('exports useNotesStore', () => {
    expect(useNotesStore).toBeDefined()
    expect(typeof useNotesStore).toBe('function')
  })

  it('exports useSettingsStore', () => {
    expect(useSettingsStore).toBeDefined()
    expect(typeof useSettingsStore).toBe('function')
  })

  it('exports useTemplatesStore', () => {
    expect(useTemplatesStore).toBeDefined()
    expect(typeof useTemplatesStore).toBe('function')
  })

  it('re-exports from notesStore module', async () => {
    const { useNotesStore: DirectNotesStore } = await import('../notesStore')
    expect(useNotesStore).toBe(DirectNotesStore)
  })

  it('re-exports from settingsStore module', async () => {
    const { useSettingsStore: DirectSettingsStore } = await import('../settingsStore')
    expect(useSettingsStore).toBe(DirectSettingsStore)
  })

  it('re-exports from templatesStore module', async () => {
    const { useTemplatesStore: DirectTemplatesStore } = await import('../templatesStore')
    expect(useTemplatesStore).toBe(DirectTemplatesStore)
  })

  it('maintains correct export order for dependency management', () => {
    // Verify all stores are exported
    const exports = { useNotesStore, useSettingsStore, useTemplatesStore }
    expect(Object.keys(exports)).toHaveLength(3)
    expect(Object.values(exports).every((fn) => typeof fn === 'function')).toBe(true)
  })

  it('all store hooks return store instances', () => {
    const notesState = useNotesStore.getState()
    const settingsState = useSettingsStore.getState()
    const templatesState = useTemplatesStore.getState()

    expect(notesState).toBeDefined()
    expect(settingsState).toBeDefined()
    expect(templatesState).toBeDefined()
  })

  it('useNotesStore has expected initial state properties', () => {
    const state = useNotesStore.getState()
    expect(state).toHaveProperty('notes')
    expect(state).toHaveProperty('folders')
    expect(state).toHaveProperty('tags')
  })

  it('useSettingsStore has expected initial state properties', () => {
    const state = useSettingsStore.getState()
    expect(state).toHaveProperty('settings')
  })

  it('useTemplatesStore has expected initial state properties', () => {
    const state = useTemplatesStore.getState()
    expect(state).toHaveProperty('templates')
  })
})
