import React, { Suspense } from 'react'
import { ComponentLoader } from '@/components/loaders'

// Lazy load the TemplatesManager component
const TemplatesManager = React.lazy(
  () => import('@/features/templates/components/TemplatesManager')
)

interface TemplatesViewProps {
  onClose: () => void
}

export const TemplatesView: React.FC<TemplatesViewProps> = ({ onClose }) => {
  return (
    <div className="h-screen flex items-center justify-center bg-background">
      <Suspense fallback={<ComponentLoader />}>
        <TemplatesManager onClose={onClose} mode="manage" />
      </Suspense>
    </div>
  )
}

export default TemplatesView
