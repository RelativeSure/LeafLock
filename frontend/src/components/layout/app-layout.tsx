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
        minSize={12.5} // 200px / 1600px viewport = 12.5%
        maxSize={37.5} // 600px / 1600px viewport = 37.5%
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
          <header className="flex h-14 shrink-0 items-center gap-2 transition-[width,height] ease-linear group-has-[[data-collapsible=icon]]/sidebar-wrapper:h-12 border-b px-4">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="-ml-1" />
              <Separator orientation="vertical" className="mr-2 h-4" />
              {/* Breadcrumbs or Page Title could go here */}
            </div>
          </header>
          <div className="flex flex-1 flex-col gap-4 p-4 pt-0 min-h-0 overflow-hidden">
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
