import React, { Suspense } from 'react'
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '@/components/ui/resizable'
import { NoteList } from './note-list'

// Lazy load editor
const NoteEditor = React.lazy(() =>
  import('./note-editor').then((m) => ({ default: m.NoteEditor }))
)

export function DashboardView() {
  return (
    <ResizablePanelGroup direction="horizontal" className="h-full w-full rounded-lg border md:min-w-[450px]">
      <ResizablePanel defaultSize={30} minSize={20} maxSize={40} className="min-w-[250px]">
        <NoteList />
      </ResizablePanel>
      
      <ResizableHandle withHandle />
      
      <ResizablePanel defaultSize={70} className="min-w-[300px]">
        <div className="h-full w-full flex flex-col">
            <Suspense fallback={
                <div className="flex h-full items-center justify-center">
                     <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                </div>
            }>
                <NoteEditor />
            </Suspense>
        </div>
      </ResizablePanel>
    </ResizablePanelGroup>
  )
}
