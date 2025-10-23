"use client"

import type React from "react"

import { FileText, CheckSquare, Calendar, Lightbulb, BookOpen, Briefcase } from "lucide-react"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog"
import { Card } from "@/components/ui/card"

interface Template {
  id: string
  title: string
  description: string
  icon: React.ReactNode
  content: string
  tags: string[]
}

const templates: Template[] = [
  {
    id: "blank",
    title: "Blank Note",
    description: "Start with a clean slate",
    icon: <FileText className="h-5 w-5" />,
    content: "",
    tags: [],
  },
  {
    id: "meeting",
    title: "Meeting Notes",
    description: "Capture key points and action items",
    icon: <Briefcase className="h-5 w-5" />,
    content: `# Meeting Notes

**Date:** ${new Date().toLocaleDateString()}
**Attendees:**

## Agenda
-

## Discussion Points
-

## Action Items
- [ ]
- [ ]

## Next Steps
- `,
    tags: ["meeting", "work"],
  },
  {
    id: "todo",
    title: "To-Do List",
    description: "Organize your tasks",
    icon: <CheckSquare className="h-5 w-5" />,
    content: `# To-Do List

## Today
- [ ]
- [ ]
- [ ]

## This Week
- [ ]
- [ ]

## Later
- [ ]
- [ ] `,
    tags: ["tasks", "productivity"],
  },
  {
    id: "journal",
    title: "Daily Journal",
    description: "Reflect on your day",
    icon: <BookOpen className="h-5 w-5" />,
    content: `# Daily Journal

**Date:** ${new Date().toLocaleDateString()}

## How I'm Feeling


## Today's Highlights


## Grateful For
-
-
-

## Tomorrow's Goals
-
- `,
    tags: ["journal", "personal"],
  },
  {
    id: "ideas",
    title: "Ideas & Brainstorm",
    description: "Capture creative thoughts",
    icon: <Lightbulb className="h-5 w-5" />,
    content: `# Ideas & Brainstorm

## Main Concept


## Key Points
-
-
-

## Potential Applications


## Next Steps
- `,
    tags: ["ideas", "creative"],
  },
  {
    id: "weekly",
    title: "Weekly Planning",
    description: "Plan your week ahead",
    icon: <Calendar className="h-5 w-5" />,
    content: `# Weekly Planning

**Week of:** ${new Date().toLocaleDateString()}

## Goals for This Week
- [ ]
- [ ]
- [ ]

## Monday


## Tuesday


## Wednesday


## Thursday


## Friday


## Weekend Plans
`,
    tags: ["planning", "productivity"],
  },
]

interface TemplateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSelectTemplate: (template: { title: string; content: string; tags: string[] }) => void
  onCreateBlank: () => void
}

export function TemplateDialog({ open, onOpenChange, onSelectTemplate, onCreateBlank }: TemplateDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-2xl font-serif">Choose a Template</DialogTitle>
          <DialogDescription>Start with a template or create a blank note</DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          {templates.map((template) => (
            <Card
              key={template.id}
              className="p-5 cursor-pointer hover:shadow-lg transition-all duration-200 border-border hover:border-primary/20 group"
              onClick={() => {
                if (template.id === "blank") {
                  onCreateBlank()
                } else {
                  onSelectTemplate({
                    title: template.title,
                    content: template.content,
                    tags: template.tags,
                  })
                }
              }}
            >
              <div className="flex items-start gap-4">
                <div className="p-2.5 rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                  {template.icon}
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold text-foreground mb-1">{template.title}</h3>
                  <p className="text-sm text-muted-foreground text-pretty">{template.description}</p>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
