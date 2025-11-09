import { describe, it, expect } from 'vitest'
import type { User, Note, Folder, Tag, Template } from '../index'

describe('Types', () => {
  it('should define User type', () => {
    const user: User = {
      id: '123',
      email: 'test@example.com',
      name: 'Test User',
      role: 'user',
      isAdmin: false,
      mfaEnabled: false,
      createdAt: '2024-01-01',
    }

    expect(user.id).toBe('123')
    expect(user.email).toBe('test@example.com')
  })

  it('should define Note type', () => {
    const note: Note = {
      id: 'note-1',
      title: 'Test Note',
      content: 'Content',
      userId: '123',
      encrypted: true,
      encryptionVersion: 1,
      folderId: null,
      tags: [],
      pinned: false,
      isTrashed: false,
      sharedWith: [],
      isTemplate: false,
      createdAt: '2024-01-01',
      updatedAt: '2024-01-01',
    }

    expect(note.id).toBe('note-1')
    expect(note.title).toBe('Test Note')
  })

  it('should define Folder type', () => {
    const folder: Folder = {
      id: 'folder-1',
      name: 'My Folder',
      color: '#3b82f6',
      userId: '123',
      parentId: null,
      position: 0,
      depth: 0,
      path: '/My Folder',
      createdAt: '2024-01-01',
      updatedAt: '2024-01-01',
    }

    expect(folder.id).toBe('folder-1')
    expect(folder.name).toBe('My Folder')
  })

  it('should define Tag type', () => {
    const tag: Tag = {
      id: 'tag-1',
      name: 'work',
      color: '#ef4444',
      userId: '123',
    }

    expect(tag.id).toBe('tag-1')
    expect(tag.name).toBe('work')
  })

  it('should define Template type', () => {
    const template: Template = {
      id: 'template-1',
      name: 'Meeting Notes',
      content: 'Template content',
      tags: ['meetings', 'work'],
      isPublic: false,
      userId: '123',
      usageCount: 0,
      createdAt: '2024-01-01',
    }

    expect(template.id).toBe('template-1')
    expect(template.name).toBe('Meeting Notes')
  })
})
