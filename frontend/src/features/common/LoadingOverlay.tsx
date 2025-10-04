import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import type { FC } from 'react'

export interface LoadingOverlayProps {
  message?: string
}

export const LoadingOverlay: FC<LoadingOverlayProps> = ({ message = 'Loading...' }) => (
  <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50">
    <Card className="w-[250px]">
      <CardContent className="pt-6 flex flex-col items-center space-y-4">
        <Skeleton className="h-8 w-8 rounded-full" />
        <div className="text-center space-y-2">
          <p className="text-lg font-medium">{message}</p>
          <p className="text-sm text-muted-foreground">Initializing secure encryption...</p>
        </div>
      </CardContent>
    </Card>
  </div>
)
