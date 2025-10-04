import { Skeleton } from '@/components/ui/skeleton'

export const NoteSkeleton: React.FC = () => (
  <div className="p-4 border-b space-y-3">
    <Skeleton className="h-4 w-3/4" />
    <Skeleton className="h-3 w-full" />
    <Skeleton className="h-3 w-2/3" />
    <Skeleton className="h-3 w-1/4" />
  </div>
)

export const NoteListSkeleton: React.FC = () => (
  <div>
    {[...Array(5)].map((_, index) => (
      <NoteSkeleton key={index} />
    ))}
  </div>
)

export default NoteListSkeleton
