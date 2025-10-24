"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"
import type { Template } from "./types"
import { useAuth } from "./auth-context"

interface TemplatesContextType {
  templates: Template[]
  publicTemplates: Template[]
  createTemplate: (template: Partial<Template>) => Template
  updateTemplate: (id: string, updates: Partial<Template>) => void
  deleteTemplate: (id: string) => void
  useTemplate: (templateId: string) => { content: string; tags: string[] }
  shareTemplate: (id: string, isPublic: boolean) => void
  searchTemplates: (query: string) => Template[]
}

const TemplatesContext = createContext<TemplatesContextType | undefined>(undefined)

export function TemplatesProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const [templates, setTemplates] = useState<Template[]>([])
  const [publicTemplates, setPublicTemplates] = useState<Template[]>([])

  // Load templates from localStorage
  useEffect(() => {
    if (user) {
      const storedTemplates = localStorage.getItem(`templates_${user.id}`)
      if (storedTemplates) setTemplates(JSON.parse(storedTemplates))
    }

    // Load public templates (shared across all users)
    const storedPublicTemplates = localStorage.getItem("public_templates")
    if (storedPublicTemplates) setPublicTemplates(JSON.parse(storedPublicTemplates))
  }, [user])

  // Save templates to localStorage
  useEffect(() => {
    if (user && templates.length > 0) {
      localStorage.setItem(`templates_${user.id}`, JSON.stringify(templates))
    }
  }, [templates, user])

  // Save public templates to localStorage
  useEffect(() => {
    if (publicTemplates.length > 0) {
      localStorage.setItem("public_templates", JSON.stringify(publicTemplates))
    }
  }, [publicTemplates])

  const createTemplate = (template: Partial<Template>) => {
    if (!user) throw new Error("No user logged in")

    const newTemplate: Template = {
      id: crypto.randomUUID(),
      name: template.name || "Untitled Template",
      content: template.content || "",
      tags: template.tags || [],
      isPublic: template.isPublic || false,
      userId: user.id,
      createdAt: new Date().toISOString(),
      usageCount: 0,
    }

    setTemplates((prev) => [newTemplate, ...prev])

    if (newTemplate.isPublic) {
      setPublicTemplates((prev) => [newTemplate, ...prev])
    }

    return newTemplate
  }

  const updateTemplate = (id: string, updates: Partial<Template>) => {
    setTemplates((prev) => prev.map((template) => (template.id === id ? { ...template, ...updates } : template)))

    // Update in public templates if it's public
    setPublicTemplates((prev) => prev.map((template) => (template.id === id ? { ...template, ...updates } : template)))
  }

  const deleteTemplate = (id: string) => {
    setTemplates((prev) => prev.filter((template) => template.id !== id))
    setPublicTemplates((prev) => prev.filter((template) => template.id !== id))
  }

  const useTemplate = (templateId: string) => {
    const template = [...templates, ...publicTemplates].find((t) => t.id === templateId)

    if (!template) {
      throw new Error("Template not found")
    }

    // Increment usage count
    updateTemplate(templateId, { usageCount: template.usageCount + 1 })

    return {
      content: template.content,
      tags: template.tags,
    }
  }

  const shareTemplate = (id: string, isPublic: boolean) => {
    const template = templates.find((t) => t.id === id)
    if (!template) return

    updateTemplate(id, { isPublic })

    if (isPublic) {
      // Add to public templates
      setPublicTemplates((prev) => {
        if (prev.find((t) => t.id === id)) return prev
        return [{ ...template, isPublic: true }, ...prev]
      })
    } else {
      // Remove from public templates
      setPublicTemplates((prev) => prev.filter((t) => t.id !== id))
    }
  }

  const searchTemplates = (query: string) => {
    const lowerQuery = query.toLowerCase()
    const allTemplates = [...templates, ...publicTemplates]
    return allTemplates.filter(
      (template) =>
        template.name.toLowerCase().includes(lowerQuery) || template.content.toLowerCase().includes(lowerQuery),
    )
  }

  return (
    <TemplatesContext.Provider
      value={{
        templates,
        publicTemplates,
        createTemplate,
        updateTemplate,
        deleteTemplate,
        useTemplate,
        shareTemplate,
        searchTemplates,
      }}
    >
      {children}
    </TemplatesContext.Provider>
  )
}

export function useTemplates() {
  const context = useContext(TemplatesContext)
  if (context === undefined) {
    throw new Error("useTemplates must be used within a TemplatesProvider")
  }
  return context
}
