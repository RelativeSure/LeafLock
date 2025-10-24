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
  <div className="animate-in fade-in duration-300">
    {[...Array(5)].map((_, index) => (
      <div
        key={index}
        className="animate-in fade-in slide-in-from-left-2"
        style={{ animationDelay: `${index * 50}ms` }}
      >
        <NoteSkeleton />
      </div>
    ))}
  </div>
)

export default NoteListSkeleton
