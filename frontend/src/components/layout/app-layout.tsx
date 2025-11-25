import { SidebarInset, SidebarProvider, SidebarTrigger, useSidebar } from '@/components/ui/sidebar'
import { AppSidebar } from './app-sidebar'
import { Outlet } from '@tanstack/react-router'
import { Separator } from '@/components/ui/separator'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable'
import { useSidebarResize } from '@/hooks/use-sidebar-resize'

function AppLayoutContent() {
  const { state, isMobile } = useSidebar()
  const { widthPercentage, setWidth } = useSidebarResize()
  const isCollapsed = state === 'collapsed'

  // Disable resize on mobile or when sidebar is collapsed
  const resizeDisabled = isMobile || isCollapsed

  return (
    <ResizablePanelGroup direction="horizontal" className="h-screen">
      <ResizablePanel
        defaultSize={widthPercentage}
        minSize={15} // Slightly wider for notes list
        maxSize={40} // Allow more space for notes
        onResize={setWidth}
        collapsible={false}
        className={resizeDisabled ? 'pointer-events-none' : ''}
      >
        <AppSidebar />
      </ResizablePanel>

      {!resizeDisabled && (
        <ResizableHandle withHandle className="hover:bg-accent transition-colors" />
      )}

      <ResizablePanel defaultSize={100 - widthPercentage} minSize={30}>
        <SidebarInset>
          <header className="flex h-12 shrink-0 items-center gap-2 border-b px-4 bg-background">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="-ml-1" />
              <Separator orientation="vertical" className="mr-2 h-4" />
            </div>
          </header>
          <div className="flex flex-1 flex-col min-h-0 overflow-hidden bg-background">
            <Outlet />
          </div>
        </SidebarInset>
      </ResizablePanel>
    </ResizablePanelGroup>
  )
}

export default function AppLayout() {
  return (
    <SidebarProvider>
      <AppLayoutContent />
    </SidebarProvider>
  )
}
