import React, { Suspense } from 'react'
import { ComponentLoader } from '@/components/loaders'

// Lazy load the FoldersManager component
const FoldersManager = React.lazy(() => import('@/features/folders/components/FoldersManager'))

interface FoldersViewProps {
  onClose: () => void
}

export const FoldersView: React.FC<FoldersViewProps> = ({ onClose }) => {
  return (
    <div className="h-screen flex items-center justify-center bg-background">
      <Suspense fallback={<ComponentLoader />}>
        <FoldersManager onClose={onClose} />
      </Suspense>
    </div>
  )
}

export default FoldersView
