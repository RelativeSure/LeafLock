import { Skeleton } from '@/components/ui/skeleton'

export const ComponentLoader: React.FC = () => (
  <div className="flex items-center justify-center p-4">
    <Skeleton className="h-6 w-6 rounded-full" />
  </div>
)

export default ComponentLoader
