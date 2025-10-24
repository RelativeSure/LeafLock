import React, { Suspense } from 'react'
import { ComponentLoader } from '@/components/loaders'

// Lazy load the TagsManager component
const TagsManager = React.lazy(() => import('@/features/tags/components/TagsManager'))

interface TagsViewProps {
  onClose: () => void
}

export const TagsView: React.FC<TagsViewProps> = ({ onClose }) => {
  return (
    <div className="h-screen flex items-center justify-center bg-background">
      <Suspense fallback={<ComponentLoader />}>
        <TagsManager onClose={onClose} />
      </Suspense>
    </div>
  )
}

export default TagsView
