import React, { Suspense } from 'react'

const NoteEditor = React.lazy(() =>
  import('./note-editor').then((m) => ({ default: m.NoteEditor }))
)

export function DashboardView() {
  return (
    <div className="h-full w-full flex flex-col bg-background">
      <Suspense
        fallback={
          <div className="flex h-full items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        }
      >
        <NoteEditor />
      </Suspense>
    </div>
  )
}
