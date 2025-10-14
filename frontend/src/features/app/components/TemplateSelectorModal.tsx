import React, { Suspense, lazy } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import ComponentLoader from '@/components/loaders/ComponentLoader'
import { type Template } from '@/services/templatesService'

const TemplatesManager = lazy(() => import('@/components/TemplatesManager'))

interface TemplateSelectorModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onTemplateSelect: (template: Template) => void
}

export const TemplateSelectorModal: React.FC<TemplateSelectorModalProps> = ({
  open,
  onOpenChange,
  onTemplateSelect,
}) => {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-6xl max-h-[90vh] overflow-hidden p-0">
        <DialogHeader className="sr-only">
          <DialogTitle>Select a Template</DialogTitle>
          <DialogDescription>
            Choose a template to create a new note from. Templates provide pre-formatted structures
            for common note types.
          </DialogDescription>
        </DialogHeader>
        <Suspense fallback={<ComponentLoader />}>
          <TemplatesManager
            onClose={() => onOpenChange(false)}
            onTemplateSelect={onTemplateSelect}
            mode="select"
          />
        </Suspense>
      </DialogContent>
    </Dialog>
  )
}
