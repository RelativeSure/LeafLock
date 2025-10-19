import React, { Suspense } from 'react'
import { ComponentLoader } from '@/components/loaders'
import { secureApi as api } from '@/services/api/secureApi'

// Lazy load the AdminPage component
const AdminPage = React.lazy(() => import('@/features/admin/components/AdminPage'))

interface AdminViewProps {
  onBack: () => void
}

export const AdminView: React.FC<AdminViewProps> = ({ onBack }) => {
  return (
    <Suspense fallback={<ComponentLoader />}>
      <AdminPage api={api} onBack={onBack} />
    </Suspense>
  )
}

export default AdminView
